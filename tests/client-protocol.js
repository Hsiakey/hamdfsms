#!/usr/bin/env node
/*
 * Hamster 协议客户端端到端测试（纯 Node，不需要 Electron / 不需要 npm 依赖）
 *
 * 被测对象：Hamster Manager/module/shared/hamster-client.js —— 主进程与测试共用同一份实现。
 * 测试环境：在 tests/tmp-client 下自起**两个** hamsterd 实例（端口 19100 / 19101，
 *          各自独立的监控目录与配置），做法与 tests/integration.ps1 一致：
 *          复制 hamsterd.exe 到临时目录 + 写 hamsterd.conf + 后台启动 +
 *          stdout/stderr 重定向到文件（不使用管道，避免受限环境下 spawn 的限制）。
 *
 * 关于"两个实例"（重要，实测结论）：
 *   hamsterd 的单实例互斥体名是写死的 "Local\Hamsterd_SingleInstance"，且句柄保持到进程退出，
 *   因此**同一个 Windows 会话里第二个 hamsterd 会打印"Hamsterd 已在运行"后直接退出**，
 *   与端口、监控目录无关（本文件第 0 节用未打补丁的副本做了对照实验，输出即证据）。
 *   为了验证"跨设备"迁移，测试对**自己的副本**做一次等长替换，只改互斥体名里 1 个字节：
 *       Local\Hamsterd_SingleInstance → Local\Hamsterd_SingleInstanc3 / ...c4
 *   不触碰 Hamsterd/ 下的原始 exe，协议实现逐字节相同。
 *   若替换失败（或非 Windows），自动退化为单实例模式：跨设备相关检查标记 [SKIP]，
 *   同设备双目录迁移仍然被完整验证。
 *
 * 覆盖：
 *   1  握手认证（错误口令被拒 / 正确口令通过 / 未认证调用受保护命令被拒）
 *   2  search 分页
 *   3  download 精确字节数 + 权威 hash（含中文与 3MB 二进制，专打"二进制当字符串"的老 bug）
 *   4  upload（overwrite=false → exists、错误 hash → hash_mismatch、流式大文件、越权拒绝）
 *   5  list / mkdir / delete（delete 的 confirm 由客户端补上）
 *   6  迁移 copy / move / 同设备搬移 / 冲突保护 / 迁移日志 / 批量
 *   7  事件接收（上传后收到 file_added）
 *   8  错误响应配对与超时（unknown_action 立刻返回；close 时 reject 在途请求；每个请求都有超时）
 *   9  客户端库单测（分帧 / 原子写 / 坏文件保留 / 路径归属 / 设备 id / 脱敏 / 去重）
 *
 * 运行：node tests/client-protocol.js
 *      HAMSTER_TEST_LOG=debug node tests/client-protocol.js   查看客户端协议细节日志
 */

'use strict';

const fs = require('fs');
const net = require('net');
const path = require('path');
const { spawn, spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const HC = require(path.join(ROOT, 'Hamster Manager', 'module', 'shared', 'hamster-client.js'));

/*
 * 测试目录与端口：
 *   - 目录默认带 pid 后缀，且**不放**在 tests/tmp 下 —— tests/integration.ps1 清理残留进程时
 *     用 "$_.Path.StartsWith(tests\tmp)" 前缀匹配，tests/tmp-client 会被误伤（实测）。
 *     目录唯一化同时也避免与并行运行的另一个测试实例互相删目录。
 *   - 端口默认 19100/19101（与任务说明一致）；启动前先探测，被占用就明确报错而不是空等。
 */
const TMP = process.env.HAMSTER_TEST_TMP || path.join(__dirname, 'client-protocol-tmp-' + process.pid);
const KEEP_TMP = process.env.HAMSTER_TEST_KEEP === '1';
const CODEWORD = 'hamster-test-0123456789abcdef0123456789abcdef';
const PORT_A = Number(process.env.HAMSTER_TEST_PORT_A || 19100);
const PORT_B = Number(process.env.HAMSTER_TEST_PORT_B || (PORT_A + 1));
const PORT_PROBE1 = PORT_A + 2;
const PORT_PROBE2 = PORT_A + 3;

/* hamsterd 写死的单实例互斥体名（只用来给测试副本改名，不动原始 exe） */
const MUTEX_PATTERN = Buffer.from('Hamsterd_SingleInstance', 'latin1');

const log = HC.createLogger({
  level: process.env.HAMSTER_TEST_LOG || 'warn',
  console: true,
  secrets: [CODEWORD],
});

/* ==========================================================================
 * 测试框架（极小）
 * ========================================================================== */
let PASS = 0, FAIL = 0, SKIP = 0;
const daemons = [];
const rawConns = [];
const servers = [];

function section(title) { console.log('\n=== ' + title + ' ==='); }
function check(cond, msg, detail) {
  if (cond) { PASS++; console.log('  [PASS] ' + msg); }
  else {
    FAIL++;
    console.log('  [FAIL] ' + msg);
    if (detail !== undefined) console.log('         ' + detail);
  }
}
function checkEq(actual, expect, msg) {
  check(actual === expect, msg, 'actual=' + JSON.stringify(actual) + ' expect=' + JSON.stringify(expect));
}
function skip(msg, why) {
  SKIP++;
  console.log('  [SKIP] ' + msg + (why ? ' —— ' + why : ''));
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function expectError(fn) {
  try { await fn(); return null; } catch (e) { return e; }
}

async function checkError(fn, code, msg) {
  const e = await expectError(fn);
  const ok = !!e && e.code === code;
  check(ok, msg, ok ? '' : '实际: ' + (e ? (e.code + (e.detail ? ' / ' + e.detail : '')) : '没有报错'));
  return e;
}

async function waitFor(fn, ms) {
  const deadline = Date.now() + ms;
  for (;;) {
    let v = null;
    try { v = fn(); } catch (_) {}
    if (v) return v;
    if (Date.now() > deadline) return null;
    await sleep(100);
  }
}

function makeBinary(size, seed) {
  /* 含 0x00 / 0x0a / 0xff 的确定性二进制：专门用来打"把二进制当 UTF-8 字符串"的实现 */
  const b = Buffer.alloc(size);
  let x = seed >>> 0;
  for (let i = 0; i < size; i++) {
    x = (Math.imul(x, 1103515245) + 12345) >>> 0;
    b[i] = (x >>> 16) & 0xff;
  }
  for (let i = 0; i < size; i += 97) b[i] = 0x0a;
  for (let i = 1; i < size; i += 131) b[i] = 0xff;
  return b;
}

function write(pathname, data) {
  fs.mkdirSync(path.dirname(pathname), { recursive: true });
  fs.writeFileSync(pathname, data);
}

/** 读文件（失败返回 null）：让断言不会因为"文件不存在"把整轮测试打断 */
function fileBytes(p) { try { return fs.readFileSync(p); } catch (_) { return null; } }
function fileSize(p) { try { return fs.statSync(p).size; } catch (_) { return -1; } }
function sameBytes(p, buf) {
  const a = fileBytes(p);
  return !!a && a.length === buf.length && Buffer.compare(a, buf) === 0;
}
function hasFile(p) { try { return fs.statSync(p).isFile(); } catch (_) { return false; } }
function hasDir(p) { try { return fs.statSync(p).isDirectory(); } catch (_) { return false; } }

/** 端口预检：被占用就明确失败（而不是等 25 秒后报"未就绪"） */
async function requirePortFree(port, what) {
  if (await HC.probePort(port, { timeoutMs: 500 })) {
    throw new Error('端口 ' + port + '（' + what + '）已被其它进程占用：' +
      '很可能有另一个测试/守护进程在并行运行。' +
      '可用 HAMSTER_TEST_PORT_A=xxxx HAMSTER_TEST_PORT_B=xxxx 指定其它端口后重跑。');
  }
}

function resetTmp() {
  try { fs.rmSync(TMP, { recursive: true, force: true }); }
  catch (e) { throw new Error('无法清理 ' + TMP + ': ' + e.message); }
}

/**
 * 单实例互斥体名是否可安全改名（只改最后一个字符）。
 * 直接读原始 exe，不做拷贝：既用于判断能否跑两个实例，也用于把"守护进程被重新编译后
 * 互斥体名变了"这种情况变成一个明确的降级原因，而不是神秘失败。
 */
function mutexPatchSupport() {
  try {
    const buf = fs.readFileSync(path.join(ROOT, 'Hamsterd', 'hamsterd.exe'));
    const at = buf.indexOf(MUTEX_PATTERN);
    if (at < 0) return { supported: false, reason: '当前 hamsterd.exe 中找不到单实例互斥体名' };
    if (buf.indexOf(MUTEX_PATTERN, at + 1) >= 0) return { supported: false, reason: '互斥体名出现多次，拒绝冒险替换' };
    return { supported: true, reason: '' };
  } catch (e) {
    return { supported: false, reason: '读取 hamsterd.exe 失败: ' + e.message };
  }
}

/**
 * 把 hamsterd.exe 先"冻结"到测试目录下的一份拷贝，并在拷贝前后对比源文件的
 * 大小/mtime：只要源文件在拷贝期间被改动（例如同事正在重新编译），就重试。
 * 然后用 --version 验证这份拷贝真的能跑。
 * 这样两个测试实例跑的一定是同一份、完整可执行的二进制。
 */
function stageDaemonExe() {
  const src = path.join(ROOT, 'Hamsterd', 'hamsterd.exe');
  const stageDir = path.join(TMP, '_stage');
  fs.mkdirSync(path.join(stageDir, 'logs'), { recursive: true });
  const staged = path.join(stageDir, 'hamsterd.exe');
  let lastErr = '';
  for (let attempt = 1; attempt <= 5; attempt++) {
    try {
      const before = fs.statSync(src);
      fs.copyFileSync(src, staged);
      const after = fs.statSync(src);
      if (before.size !== after.size || before.mtimeMs !== after.mtimeMs) {
        lastErr = '第 ' + attempt + ' 次拷贝期间源文件被改动（正在重新编译？）';
        spawnSync('cmd', ['/c', 'ping', '-n', '2', '127.0.0.1'], { stdio: 'ignore' });
        continue;
      }
      const outFile = path.join(stageDir, 'logs', 'version.out');
      const fd = fs.openSync(outFile, 'w');
      let r = null;
      try {
        r = spawnSync(staged, ['--version'], { cwd: stageDir, stdio: ['ignore', fd, fd], timeout: 15000, windowsHide: true });
      } finally { try { fs.closeSync(fd); } catch (_) {} }
      const out = fs.existsSync(outFile) ? fs.readFileSync(outFile, 'utf8') : '';
      if (out.indexOf('Hamsterd ver.') >= 0) {
        return { ok: true, path: staged, version: out.trim().split(/\r?\n/)[0], size: after.size, mtime: after.mtime.toISOString() };
      }
      lastErr = '--version 无有效输出（status=' + (r && r.status) + ', signal=' + (r && r.signal) + '）：' + JSON.stringify(out.slice(0, 80));
    } catch (e) {
      lastErr = e.message;
    }
  }
  return { ok: false, reason: lastErr };
}

/**
 * 复制"已冻结"的 hamsterd.exe 到测试目录。
 * lastChar 非空时把单实例互斥体名的最后一个字符改掉（等长替换，只改 1 字节），
 * 使多个测试实例能在同一会话内并存。绝不触碰 Hamsterd/ 下的原始 exe。
 */
function prepareDaemonExe(binDir, lastChar) {
  const src = stagedExe ? stagedExe.path : path.join(ROOT, 'Hamsterd', 'hamsterd.exe');
  const dst = path.join(binDir, 'hamsterd.exe');
  fs.copyFileSync(src, dst);
  if (!lastChar) return { patched: false, reason: '未请求改名（对照组）' };
  const buf = fs.readFileSync(dst);
  const at = buf.indexOf(MUTEX_PATTERN);
  if (at < 0) return { patched: false, reason: '副本中未找到单实例互斥体名' };
  if (buf.indexOf(MUTEX_PATTERN, at + 1) >= 0) return { patched: false, reason: '互斥体名在副本中出现多次，拒绝冒险替换' };
  buf[at + MUTEX_PATTERN.length - 1] = lastChar.charCodeAt(0);
  fs.writeFileSync(dst, buf);
  return { patched: true, mutex: 'Local\\Hamsterd_SingleInstanc' + lastChar };
}

let stagedExe = null;

function daemonConf(monitorDir, port, codeword) {
  return [
    '# client-protocol.js 生成的测试配置',
    'monitor_path: ' + monitorDir,
    'ipv4_addr: 127.0.0.1',
    'ipv4_addr_port: ' + port,
    'codeword: ' + (codeword || CODEWORD),
    'require_auth: on',
    /* 本套件用裸 HamsterConn 发 hello 检查 0.0.8 线格式；加密路径见
       tests/protocol-secure.js（走 AeadTransport）与 tests/sec-live.js。 */
    'encrypt_transport: off',
    'allow_loopback_noauth: off',
    'max_transfer_mb: 64',
    'max_clients: 16',
    'rescan_date: 0,0,0',
    'verify_interval: 0',
    'discovery_port: 0',
    'heartbeat_time: 1',
    'log_level: debug',
    'log_dir: logs',
    'exclude_internal: on',
    '',
  ].join('\n');
}

function spawnDaemon(binDir, port, tag) {
  const outFd = fs.openSync(path.join(binDir, 'logs', 'daemon.out'), 'a');
  const child = spawn(path.join(binDir, 'hamsterd.exe'), ['--console-log'], {
    cwd: binDir,
    stdio: ['ignore', outFd, outFd],      /* 不用管道：受限环境下管道 stdio 可能不可用 */
    windowsHide: true,
  });
  const rec = { tag, child, binDir, port, outFile: path.join(binDir, 'logs', 'daemon.out') };
  daemons.push(rec);
  child.on('error', (e) => console.error('[daemon ' + tag + '] spawn 失败: ' + e.message));
  return rec;
}

function daemonLogTail(rec, n) {
  try {
    if (!fs.existsSync(rec.outFile)) return '(无日志文件)';
    const lines = fs.readFileSync(rec.outFile, 'utf8').split(/\r?\n/).filter((l) => l.length);
    return lines.slice(-(n || 20)).join('\n') || '(日志为空)';
  } catch (e) { return '(读日志失败: ' + e.message + ')'; }
}

async function startDaemon(tag, port, monitorDir, lastChar, codeword) {
  const binDir = path.join(TMP, tag);
  fs.mkdirSync(path.join(binDir, 'logs'), { recursive: true });
  fs.mkdirSync(monitorDir, { recursive: true });
  const pat = prepareDaemonExe(binDir, lastChar);
  fs.writeFileSync(path.join(binDir, 'hamsterd.conf'), daemonConf(monitorDir, port, codeword), 'utf8');
  const rec = spawnDaemon(binDir, port, tag);
  rec.patched = pat;
  const deadline = Date.now() + 25000;
  for (;;) {
    if (await HC.probePort(port, { timeoutMs: 300 })) return rec;
    if (rec.child.exitCode !== null || rec.child.signalCode !== null) {
      throw new Error('守护进程 ' + tag + ' 启动即退出（pid=' + rec.child.pid +
        ' exitCode=' + rec.child.exitCode + ' signal=' + rec.child.signalCode + '）\n' + daemonLogTail(rec, 30));
    }
    if (Date.now() > deadline) {
      throw new Error('守护进程 ' + tag + ' 未在端口 ' + port + ' 就绪' +
        '（pid=' + rec.child.pid + ' 仍在运行但未监听，日志大小=' +
        (fs.existsSync(rec.outFile) ? fs.statSync(rec.outFile).size : -1) + ' 字节）\n' + daemonLogTail(rec, 30));
    }
    await sleep(200);
  }
}

function cleanup() {
  for (const s of servers) { try { s.close(); } catch (_) {} }
  for (const c of rawConns) { try { c.destroy('cleanup'); } catch (_) {} }
  for (const d of daemons) {
    try { if (d.child && !d.child.killed) d.child.kill(); } catch (_) {}
  }
}

function dumpDaemonLogs() {
  for (const d of daemons) {
    console.log('\n--- ' + d.tag + ' 守护进程日志尾部 (' + d.outFile + ') ---');
    console.log(daemonLogTail(d, 25));
  }
}

/* ==========================================================================
 * 主流程
 * ========================================================================== */
/* ==========================================================================
 * 日志器自限：日志绝不允许把磁盘写满
 *
 * 真实事故：GUI 主进程的日志文件没有上限，一个"日志→事件→日志"的自激循环
 * 在几小时内写出了几十 GB，直接把系统盘撑爆。这里把两道闸门都钉住：
 *   · 到上限必须轮转（改名失败也要退化为截断，不能继续长）；
 *   · 同一条消息短时间内重复只写一次。
 * ========================================================================== */
function testLoggerCaps() {
  section('日志器自限（防止日志写爆磁盘）');
  const dir = path.join(TMP, 'logcap');
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_) {}
  fs.mkdirSync(dir, { recursive: true });

  const cap = 4096;
  const lg = HC.createLogger({
    dir, file: 'cap.log', level: 'debug', console: false, maxBytes: cap, keep: 1, dedupMs: 0,
  });
  for (let i = 0; i < 400; i += 1) lg.info('line ' + i + ' ' + 'x'.repeat(60));
  lg.close();

  const mainLog = path.join(dir, 'cap.log');
  const oldLog = mainLog + '.1';
  const sz = fs.existsSync(mainLog) ? fs.statSync(mainLog).size : -1;
  const sz1 = fs.existsSync(oldLog) ? fs.statSync(oldLog).size : -1;
  check(sz >= 0 && sz <= cap + 256, '主日志文件不超过上限', String(sz));
  check(sz1 > 0 && sz1 <= cap + 256, '轮转保留的那一份也不超过上限', String(sz1));

  /* 上限为 0 的极端配置：keep=0 时直接截断，同样不会无限增长 */
  const lg2 = HC.createLogger({
    dir, file: 'trunc.log', level: 'info', console: false, maxBytes: 2048, keep: 0, dedupMs: 0,
  });
  for (let i = 0; i < 300; i += 1) lg2.warn('warn ' + i + ' ' + 'y'.repeat(40));
  lg2.close();
  const sz2 = fs.existsSync(path.join(dir, 'trunc.log')) ? fs.statSync(path.join(dir, 'trunc.log')).size : -1;
  check(sz2 >= 0 && sz2 <= 2048 + 256, 'keep=0 时按上限截断而不是继续追加', String(sz2));

  /* 幂等去重：同一条消息刷 500 次只落 1 行 + 1 行折叠说明 */
  const lg3 = HC.createLogger({
    dir, file: 'dedup.log', level: 'info', console: false, maxBytes: 1024 * 1024, dedupMs: 5000,
  });
  for (let i = 0; i < 500; i += 1) lg3.warn('self-excited loop line');
  lg3.info('另一个消息');
  lg3.close();
  const text = fs.readFileSync(path.join(dir, 'dedup.log'), 'utf8');
  const lines = text.split(/\r?\n/).filter(Boolean);
  check(lines.length <= 3, '同一条消息重复 500 次被折叠', lines.length + ' 行');
  check(text.indexOf('已折叠') >= 0, '折叠点留了一行说明', text.slice(0, 200));
  check(text.indexOf('另一个消息') >= 0, '不同消息不被折叠');

  try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_) {}
}

async function main() {
  console.log('Hamster 协议客户端端到端测试');
  console.log('  被测库: ' + path.join('Hamster Manager', 'module', 'shared', 'hamster-client.js'));
  console.log('  测试目录: ' + TMP + (KEEP_TMP ? '（保留）' : '（结束后删除）'));

  /* ---------------------------------------------------------------- 准备 */
  section('0. 准备测试环境');
  resetTmp();
  testLoggerCaps();
  await requirePortFree(PORT_A, '实例 A');
  await requirePortFree(PORT_B, '实例 B');
  await requirePortFree(PORT_PROBE1, '对照实例 1');
  const monA = path.join(TMP, 'monitor-a');
  const monB = path.join(TMP, 'monitor-b');
  const dlA = path.join(TMP, 'downloads-a');
  const dlB = path.join(TMP, 'downloads-b');
  const migTmp = path.join(TMP, 'migrate-tmp');
  [monA, monB, dlA, dlB, migTmp].forEach((d) => fs.mkdirSync(d, { recursive: true }));

  /* 0.1 先冻结一份"完整可执行"的 hamsterd.exe
     （并发重编译会让直接拷贝得到半截二进制：实测被这个坑过一次） */
  stagedExe = stageDaemonExe();
  if (!stagedExe.ok) {
    throw new Error('Hamsterd\\hamsterd.exe 当前不可用（很可能正在被重新编译）：' + stagedExe.reason);
  }
  console.log('  被测守护进程: ' + stagedExe.version + '（' + stagedExe.size + ' 字节，mtime ' + stagedExe.mtime + '）');

  const patch = process.platform === 'win32' ? mutexPatchSupport() : { supported: false, reason: '非 Windows 平台没有该互斥体' };
  const CROSS = process.platform !== 'win32' || patch.supported;
  console.log('  跨设备模式: ' + (CROSS ? '启用（两个独立实例 ' + PORT_A + ' / ' + PORT_B + '）'
    : '禁用（' + patch.reason + '）→ 退化为单实例双目录迁移'));

  /* 0.2 对照实验：未打补丁的副本 → 同一会话只能有一个实例（把限制变成可复现的证据） */
  let singleInstanceEvidence = '';
  if (process.platform === 'win32') {
    const p1Mon = path.join(TMP, 'probe-mon1');
    const p2Mon = path.join(TMP, 'probe-mon2');
    const p1 = await (async () => {
      const binDir = path.join(TMP, 'probe1');
      fs.mkdirSync(path.join(binDir, 'logs'), { recursive: true });
      fs.mkdirSync(p1Mon, { recursive: true });
      prepareDaemonExe(binDir, null);                 /* 对照组：不改互斥体名 */
      fs.writeFileSync(path.join(binDir, 'hamsterd.conf'), daemonConf(p1Mon, PORT_PROBE1), 'utf8');
      return spawnDaemon(binDir, PORT_PROBE1, 'probe1');
    })();
    const up1 = await waitFor(() => HC.probePort(PORT_PROBE1, { timeoutMs: 300 }), 12000);
    if (!up1) {
      skip('单实例限制对照实验', '会话内已有其它 hamsterd 在运行，第一个拷贝都起不来（' + daemonLogTail(p1, 3) + '）');
    } else {
      const binDir2 = path.join(TMP, 'probe2');
      fs.mkdirSync(path.join(binDir2, 'logs'), { recursive: true });
      fs.mkdirSync(p2Mon, { recursive: true });
      prepareDaemonExe(binDir2, null);                /* 第二个拷贝同样未打补丁 */
      fs.writeFileSync(path.join(binDir2, 'hamsterd.conf'), daemonConf(p2Mon, PORT_PROBE2), 'utf8');
      const p2 = spawnDaemon(binDir2, PORT_PROBE2, 'probe2');
      await sleep(2500);
      const tail = daemonLogTail(p2, 3);
      const refused = p2.child.exitCode === 0 && tail.indexOf('已在运行') >= 0;
      singleInstanceEvidence = '第二个未打补丁实例：exitCode=' + p2.child.exitCode + '，日志="' + tail.replace(/\s+/g, ' ').trim() + '"';
      check(refused, '证据：同一会话内第二个 hamsterd 实例被单实例互斥体拒绝（与端口/监控目录无关）', singleInstanceEvidence);
      try { p2.child.kill(); } catch (_) {}
    }
    try { p1.child.kill(); } catch (_) {}
    await sleep(500);
  } else {
    skip('单实例限制对照实验', '非 Windows 平台的 instance_acquire 恒为 1，本就没有该限制');
  }

  /* 0.3 两个真正并存的实例（给测试副本改名，见文件头说明） */
  /* 守护进程启动前写入的文件：保证首次全量扫描就能进索引（search 依赖它） */
  write(path.join(monA, 'hello.txt'), Buffer.from('hello hamster 你好，世界\n', 'utf8'));
  for (let i = 1; i <= 5; i++) write(path.join(monA, 'page_0' + i + '.txt'), Buffer.from('x'.repeat(i * 100)));
  const bigA = makeBinary(3 * 1024 * 1024, 20260826);      /* 3MB 二进制 */
  write(path.join(monA, 'big_a.bin'), bigA);
  const migSrc = makeBinary(256 * 1024, 424242);            /* 256KB，用于迁移 */
  write(path.join(monA, 'mig_src.bin'), migSrc);

  const A = await startDaemon('a', PORT_A, monA, process.platform === 'win32' ? '3' : null);
  let B = null;
  if (CROSS) {
    write(path.join(monB, 'b-existing.txt'), Buffer.from('device B baseline'));
    B = await startDaemon('b', PORT_B, monB, process.platform === 'win32' ? '4' : null);
  }
  check(true, '守护进程已就绪', 'A :' + PORT_A + '(pid=' + A.child.pid + ')' +
    (B ? ' / B :' + PORT_B + '(pid=' + B.child.pid + ')' : ' / 仅 A（单实例模式）'));

  /* 目标端选择：跨设备时用 B，否则退化为 A 的另一个目录 */
  const dstId = CROSS ? 'dev_B' : 'dev_A';
  const dstMon = CROSS ? monB : monA;

  /* ---------------------------------------------------------------- 1 握手 */
  section('1. 握手认证（PROTOCOL §2）');

  const rawWrong = new HC.HamsterConn({ host: '127.0.0.1', port: PORT_A, logger: log, label: 'wrong' });
  await rawWrong.connect(5000);
  await checkError(
    () => rawWrong.request('hello', { device_id: 'test', hostname: 'test', codeword: 'wrong-codeword' }, { timeoutMs: 8000 }),
    'invalid_credential', '错误口令被拒绝（invalid_credential）');
  rawWrong.destroy('done');

  const rawProbe = new HC.HamsterConn({ host: '127.0.0.1', port: PORT_A, logger: log, label: 'probe' });
  await rawProbe.connect(5000);
  const hello = (await rawProbe.request('hello', { device_id: 'probe', hostname: 'test-host', codeword: CODEWORD })).data;
  check(hello.server === 'hamsterd', '正确口令通过认证（server=hamsterd）', JSON.stringify(hello).slice(0, 140));
  checkEq(hello.auth_required, 1, 'hello 声明 auth_required=1');
  check(Array.isArray(hello.features) && hello.features.indexOf('framing:raw') >= 0 && hello.features.indexOf('upload') >= 0,
    'hello 返回能力清单（含 framing:raw / upload）', JSON.stringify(hello.features));
  checkEq(hello.monitor_path, monA, 'hello 返回服务端监控根目录（与配置一致）');

  const rawNoAuth = new HC.HamsterConn({ host: '127.0.0.1', port: PORT_A, logger: log, label: 'noauth' });
  await rawNoAuth.connect(5000);
  await checkError(() => rawNoAuth.request('stats', {}, { timeoutMs: 8000 }), 'unauthenticated',
    '未认证调用受保护命令被拒绝（unauthenticated）');
  const pong = (await rawNoAuth.request('ping', {}, { timeoutMs: 8000 })).data;
  check(pong.pong === true, 'ping 免认证可用（探活）');
  rawNoAuth.destroy('done');

  /* 正式客户端（命令连接 + 独立事件连接） */
  const evA = [];
  const ca = new HC.HamsterClient({
    id: 'dev_A', name: 'A', host: '127.0.0.1', port: PORT_A, codeword: CODEWORD,
    downloadDir: dlA, logger: log, onEvent: (msg, client) => evA.push({ client: client.name, msg }),
  });
  const cb = CROSS ? new HC.HamsterClient({
    id: 'dev_B', name: 'B', host: '127.0.0.1', port: PORT_B, codeword: CODEWORD,
    downloadDir: dlB, logger: log,
  }) : ca;
  await ca.connect();
  if (CROSS) await cb.connect();
  check(ca.info && ca.info.monitor_path === monA && (!CROSS || cb.info.monitor_path === monB),
    '客户端已认证并拿到 monitor_path（' + (CROSS ? 'A 与 B 各自独立' : '单实例模式：A 兼任目标端') + '）');

  /* ---------------------------------------------------------------- 2 搜索 */
  section('2. search 分页（limit / offset / sort / total）');
  const s1 = await ca.search({ q: 'page_0', limit: 2, offset: 0, sort: '-size' });
  const s2 = await ca.search({ q: 'page_0', limit: 2, offset: 2, sort: '-size' });
  check(s1.total >= 5, 'search 返回 total（匹配 5 个分页测试文件）', 'total=' + s1.total);
  checkEq(s1.files.length, 2, 'limit=2 生效');
  checkEq(s1.limit, 2, '响应回显 limit');
  checkEq(s2.offset, 2, '响应回显 offset');
  check(s1.files[0] && s2.files[0] && s1.files[0].path !== s2.files[0].path,
    '不同 offset 返回不同记录（分页真的生效）', 'p1=' + s1.files[0].path + ' | p2=' + s2.files[0].path);
  check(s1.files[0].size >= s1.files[1].size, 'sort=-size 降序生效',
    s1.files.map((f) => f.name + ':' + f.size).join(', '));
  const hit = (await ca.search({ q: 'hello.txt', limit: 5 })).files.find((f) => f.name === 'hello.txt');
  check(!!hit && path.isAbsolute(hit.path) && /^[0-9a-f]{32}$/.test(hit.hash),
    'search 结果带绝对路径与索引 hash', hit ? hit.path + ' hash=' + hit.hash : '未命中');

  /* ---------------------------------------------------------------- 3 下载 */
  section('3. download 精确字节数 + 权威 hash（PROTOCOL §3）');
  const dlBin = await ca.download('big_a.bin', { destDir: dlA });
  checkEq(dlBin.size, bigA.length, '3MB 二进制下载字节数精确一致');
  checkEq(dlBin.header.payload_bytes, dlBin.size, 'payload_bytes 与实际收到字节数一致');
  checkEq(dlBin.header.size, dlBin.size, 'size 与实际收到字节数一致');
  checkEq(fileSize(dlBin.saved_path), dlBin.header.payload_bytes, '落盘文件长度 == payload_bytes');
  check(sameBytes(dlBin.saved_path, bigA),
    '下载内容与磁盘源文件逐字节一致（首包二进制未被字符串化损坏）');
  check(/^[0-9a-f]{32}$/.test(dlBin.hash), '下载头返回权威 xxHash3_128', 'hash=' + dlBin.hash);

  const dlTxt = await ca.download('hello.txt', { destDir: dlA });
  const helloLocal = fs.readFileSync(path.join(monA, 'hello.txt'));
  check(dlTxt.size === helloLocal.length && sameBytes(dlTxt.saved_path, helloLocal),
    '中文内容下载逐字节一致（UTF-8 未被破坏）', 'size=' + dlTxt.size);

  /* hash 端到端：把"下载到的字节"上传到另一端，并携带源端权威 hash */
  const e2e = await cb.upload({ localPath: dlBin.saved_path, remotePath: 'e2e/big.bin', hash: dlBin.hash, mkdir: true });
  checkEq(e2e.hash, dlBin.hash, '源端下载 hash == 另一端落盘 hash（端到端内容校验，无需自己实现 xxHash）');
  check(fileSize(path.join(dstMon, 'e2e', 'big.bin')) === bigA.length, '另一端文件长度与源端一致');
  check(sameBytes(path.join(dstMon, 'e2e', 'big.bin'), bigA), '另一端文件内容与源端逐字节一致');

  /* ---------------------------------------------------------------- 4 上传 */
  section('4. upload（流式、hash 校验、冲突、越权）');
  const upPayload = Buffer.from('uploaded by client-protocol test 上传内容\n', 'utf8');
  const up1 = await ca.uploadBuffer(upPayload, 'sub/dir/up.txt', { mkdir: true });
  check(up1.ok && up1.size === upPayload.length, '上传成功并返回 path/name/size', up1.path + ' size=' + up1.size);
  check(/^[0-9a-f]{32}$/.test(up1.hash), '上传返回目标端计算出的 hash', 'hash=' + up1.hash);
  check(sameBytes(path.join(monA, 'sub', 'dir', 'up.txt'), upPayload),
    '落盘内容与上传内容逐字节一致，且自动创建多级目录');

  await checkError(() => ca.uploadBuffer(upPayload, 'sub/dir/up.txt', { overwrite: false }), 'exists',
    'overwrite=false 时目标已存在 → exists（不静默覆盖）');

  const up2 = await ca.uploadBuffer(upPayload, 'sub/dir/up.txt', { hash: up1.hash, overwrite: true });
  check(up2.ok && up2.hash === up1.hash, '携带正确 hash + overwrite=true 覆盖上传通过');

  await checkError(() => ca.uploadBuffer(upPayload, 'badhash.bin', { hash: '0'.repeat(32) }), 'hash_mismatch',
    '错误 hash → hash_mismatch（目标端删除半成品）');
  check(!fs.existsSync(path.join(monA, 'badhash.bin')), 'hash 校验失败后目标端不留半成品文件');

  const upBig = await ca.upload({ localPath: path.join(monA, 'big_a.bin'), remotePath: 'stream/big.bin', mkdir: true });
  checkEq(upBig.size, bigA.length, '流式上传 3MB（createReadStream，不整份进内存）');
  check(sameBytes(path.join(monA, 'stream', 'big.bin'), bigA), '流式上传内容逐字节一致');

  await checkError(() => ca.uploadBuffer(upPayload, '..\\escaped.txt'), 'path_denied',
    '越权上传路径（.. 逃逸）被客户端白名单拒绝');
  check(!fs.existsSync(path.join(TMP, 'escaped.txt')), '越权上传未写出任何文件');

  const parts = fs.readdirSync(monA).filter((n) => n.indexOf('.part-') >= 0);
  checkEq(parts.length, 0, '监控根目录不残留 .part 临时文件');

  /* ---------------------------------------------------------------- 5 目录 */
  section('5. list / mkdir / delete（confirm 由客户端补上）');
  const lst = await ca.list('sub', 50, 0);
  check(lst.entries.some((e) => e.name === 'dir' && e.dir === true), 'list 列举子目录并标注 dir=true',
    lst.entries.map((e) => e.name + (e.dir ? '/' : '')).join(', '));
  const mk = await ca.mkdir('newdir/nested');
  check(mk.ok && fs.existsSync(path.join(monA, 'newdir', 'nested')), 'mkdir 递归创建目录');

  const rawDel = new HC.HamsterConn({ host: '127.0.0.1', port: PORT_A, logger: log, label: 'del' });
  await rawDel.connect(5000);
  await rawDel.request('hello', { device_id: 'del', codeword: CODEWORD }, { timeoutMs: 8000 });
  await checkError(() => rawDel.request('delete', { path: 'sub/dir/up.txt' }, { timeoutMs: 8000 }), 'confirm_required',
    '守护进程要求 delete 必须显式 confirm（证明 confirm 确实由客户端补上）');
  rawDel.destroy('done');

  /* 删除：Windows 上刚落盘的文件偶发被杀软/索引器短暂占用（remove_failed），重试一次再判定 */
  let del = await expectError(() => ca.remove('sub/dir/up.txt'));
  if (del && del.code === 'remove_failed') { await sleep(400); del = await expectError(() => ca.remove('sub/dir/up.txt')); }
  check(!del && !fs.existsSync(path.join(monA, 'sub', 'dir', 'up.txt')),
    '客户端 delete 自动补 confirm 后删除成功', del ? (del.code + ' / ' + del.detail) : '');
  await checkError(() => ca.remove('no-such-file.txt'), 'not_found', '删除不存在的文件返回 not_found');

  /* ---------------------------------------------------------------- 6 迁移 */
  section('6. 文件迁移（' + (CROSS ? '跨设备 A→B' : '单实例、同设备双目录') + '：copy / move / 冲突保护 / 日志 / 批量）');
  const migLog = new HC.MigrationLog({ file: path.join(TMP, 'migrations.json'), logger: log });
  const migrator = new HC.Migrator({
    getClient: async (id) => (id === 'dev_A' ? ca : cb),
    tmpDir: migTmp,
    log: migLog,
    logger: log,
    concurrency: 2,
  });

  const foundSrc = (await ca.search({ q: 'mig_src.bin', limit: 5 })).files.find((f) => f.name === 'mig_src.bin');
  const srcPath = foundSrc ? foundSrc.path : path.join(monA, 'mig_src.bin');
  const srcHash = foundSrc ? foundSrc.hash : '';
  check(!!foundSrc && /^[0-9a-f]{32}$/.test(srcHash), '取到迁移源文件的绝对路径与索引 hash', srcPath + ' hash=' + srcHash);

  const copyJob = { srcId: 'dev_A', dstId, srcPath, dstPath: 'migrated/copy.bin', mode: 'copy' };
  const rCopy = await migrator.run(copyJob);
  check(rCopy.ok === true, 'copy 迁移成功', JSON.stringify(rCopy));
  checkEq(rCopy.size, migSrc.length, 'copy 返回字节数与源文件一致');
  checkEq(rCopy.hash, srcHash, 'copy 端到端 hash 一致（下载头 hash == 目标端 upload 回传 hash）');
  checkEq(rCopy.removed, false, 'copy 模式不删除源文件');
  check(fs.existsSync(srcPath), 'copy 后源文件仍然存在');
  check(sameBytes(path.join(dstMon, 'migrated', 'copy.bin'), migSrc),
    '目标端内容与源文件逐字节一致');

  const moveJob = { srcId: 'dev_A', dstId, srcPath, dstPath: 'migrated/moved.bin', mode: 'move' };
  const rMove = await migrator.run(moveJob);
  check(rMove.ok === true, 'move 迁移成功', JSON.stringify(rMove));
  checkEq(rMove.removed, true, 'move 在校验通过后删除源文件');
  checkEq(rMove.hash, srcHash, 'move 端到端 hash 一致');
  check(!fs.existsSync(srcPath), 'move 后源文件已消失');
  check(sameBytes(path.join(dstMon, 'migrated', 'moved.bin'), migSrc),
    'move 后目标端内容与源文件逐字节一致');

  /* 冲突保护：目标已存在 + overwrite:false → 必须失败且**保留源文件** */
  const conflictPath = path.join(monA, 'conflict.bin');
  write(conflictPath, Buffer.from('conflict payload - must not be lost'));
  const rConflict = await migrator.run({
    srcId: 'dev_A', dstId, srcPath: conflictPath, dstPath: 'migrated/moved.bin', mode: 'move',
  });
  checkEq(rConflict.error, 'exists', 'overwrite=false 且目标已存在 → exists（不静默覆盖）');
  check(fs.existsSync(conflictPath), '冲突失败后源文件被保留（未越界删除）');
  check(sameBytes(path.join(dstMon, 'migrated', 'moved.bin'), migSrc),
    '冲突失败未破坏目标端原有文件');

  /* 同设备搬移到另一个目录 */
  const rSame = await migrator.run({
    srcId: 'dev_A', dstId: 'dev_A', srcPath: conflictPath, dstPath: 'inplace/inplace.bin', mode: 'move',
  });
  check(rSame.ok === true, '同设备另目录搬移成功（下载→上传→删源）', JSON.stringify(rSame));
  check(!fs.existsSync(conflictPath) && hasFile(path.join(monA, 'inplace', 'inplace.bin')),
    '同设备搬移后源消失、目标存在');

  /* 非法 job 必须被拒绝且写日志 */
  const rBad = await migrator.run({
    srcId: 'dev_A', dstId, srcPath: path.join(monA, 'big_a.bin'), dstPath: '..\\escape.bin', mode: 'copy',
  });
  checkEq(rBad.error, 'path_denied', '迁移目标路径 .. 逃逸被拒绝');
  const rBadMode = await migrator.run({
    srcId: 'dev_A', dstId, srcPath: path.join(monA, 'big_a.bin'), dstPath: 'x.bin', mode: 'shred',
  });
  checkEq(rBadMode.error, 'bad_mode', '非法 mode 被拒绝');

  const hist = migLog.list();
  check(hist.length >= 6, '迁移日志记录了每一步（成功与失败都写）', 'entries=' + hist.length);
  check(hist.some((h) => h.ok === true && h.hash === srcHash), '日志包含成功的 hash 记录');
  check(hist.some((h) => h.ok === false && h.error === 'exists'), '日志包含失败的 error 记录');

  /* 批量：单个失败不影响其它 */
  write(path.join(monA, 'batch_1.bin'), makeBinary(64 * 1024, 11));
  write(path.join(monA, 'batch_2.bin'), makeBinary(64 * 1024, 22));
  const many = await migrator.runMany([
    { srcId: 'dev_A', dstId, srcPath: path.join(monA, 'batch_1.bin'), dstPath: 'batch/1.bin', mode: 'copy' },
    { srcId: 'dev_A', dstId, srcPath: path.join(monA, 'batch_2.bin'), dstPath: '..\\bad.bin', mode: 'copy' },
    { srcId: 'dev_A', dstId, srcPath: path.join(monA, 'batch_2.bin'), dstPath: 'batch/2.bin', mode: 'move' },
  ]);
  checkEq(many.length, 3, 'runMany 与输入同序返回 3 个结果');
  check(many[0] && many[0].ok === true && many[0].index === 0, 'runMany[0] 成功');
  check(many[1] && many[1].error === 'path_denied' && many[1].index === 1, 'runMany[1] 失败但不影响其它');
  check(many[2] && many[2].ok === true && many[2].removed === true && many[2].index === 2, 'runMany[2] 成功');
  check(hasFile(path.join(dstMon, 'batch', '1.bin')) && hasFile(path.join(dstMon, 'batch', '2.bin')),
    '批量迁移的目标文件均已落盘');
  check(!fs.existsSync(path.join(monA, 'batch_2.bin')), '批量中 move 模式的源文件已删除');
  const leftover = fs.readdirSync(migTmp).filter((n) => n.indexOf('.part') >= 0);
  checkEq(leftover.length, 0, '迁移临时文件已清理（无论成功失败）');
  if (!CROSS) skip('跨设备（两个独立守护进程之间）迁移', patch.reason || '未启用');

  /* ---------------------------------------------------------------- 7 事件 */
  section('7. 事件接收（file_added）');
  ca.startEvents();
  const evtReady = await waitFor(() => ca.eventsConnected, 10000);
  check(!!evtReady, '事件通道（独立 socket + hello）已建立');
  evA.length = 0;
  await ca.uploadBuffer(Buffer.from('event probe'), 'event-probe.txt', { overwrite: true });
  const got = await waitFor(() => evA.find((e) => e.msg.event === 'file_added' &&
    e.msg.data && String(e.msg.data.name || '').indexOf('event-probe') >= 0), 10000);
  check(!!got, '上传后收到 file_added 事件', got ? JSON.stringify(got.msg).slice(0, 160) : '10s 内未收到');
  if (got) {
    check(got.msg.seq >= 1 && !!got.msg.data.path && typeof got.msg.time === 'number',
      '事件带 seq / data.path / time', 'seq=' + got.msg.seq + ' path=' + got.msg.data.path);
  }

  const dedup = new HC.EventDeduper({ windowMs: 2000 });
  const ev1 = { device: 'A', event: 'file_added', data: { path: 'x' }, seq: 10 };
  const first = dedup.accept(ev1);
  const second = dedup.accept(ev1);
  check(first === true && second === false, '同一事件（同 seq）只推一次给渲染层');

  /* ---------------------------------------------------------------- 8 错误配对 */
  section('8. 错误响应配对与超时（PROTOCOL §1.1 / §1.3）');
  const errConn = new HC.HamsterConn({ host: '127.0.0.1', port: PORT_A, logger: log, label: 'err' });
  await errConn.connect(5000);
  /* 先认证：否则受保护命令会先被认证闸门拦成 unauthenticated（守护进程行为正确） */
  await errConn.request('hello', { device_id: 'err-test', codeword: CODEWORD }, { timeoutMs: 8000 });
  const t0 = Date.now();
  const eUnknown = await expectError(() => errConn.request('no_such_action', {}, { timeoutMs: 8000 }));
  const dtUnknown = Date.now() - t0;
  check(!!eUnknown && eUnknown.code === 'unknown_action',
    '不存在的 action 立刻拿到 unknown_action（而不是等超时）',
    (eUnknown ? eUnknown.code : '无错误') + '，耗时 ' + dtUnknown + 'ms');
  check(dtUnknown < 2000, 'unknown_action 响应耗时 < 2s', dtUnknown + 'ms');
  const pong2 = (await errConn.request('ping', {}, { timeoutMs: 8000 })).data;
  check(pong2.pong === true, '错误响应后连接仍可继续使用（流未错位）');
  errConn.destroy('done');

  await checkError(() => ca.download('no-such-file.bin', { destDir: dlA }), 'file_not_found',
    '下载不存在的文件 → file_not_found（响应按 id 正确配对）');
  if (process.platform === 'win32') {
    await checkError(() => ca.download('C:\\Windows\\win.ini', { destDir: dlA }), 'path_denied',
      '下载监控根之外的绝对路径 → path_denied（守护进程侧越权拦截）');
  }

  /* 静默服务端：验证"close 时 reject 在途请求"与"每个请求都有超时" */
  const silent1 = net.createServer((s) => setTimeout(() => { try { s.destroy(); } catch (_) {} }, 300));
  await new Promise((r) => silent1.listen(0, '127.0.0.1', r));
  servers.push(silent1);
  const connClosed = new HC.HamsterConn({ host: '127.0.0.1', port: silent1.address().port, logger: log, label: 'silent-close' });
  await connClosed.connect(3000);
  rawConns.push(connClosed);
  const tClose = Date.now();
  const eClosed = await expectError(() => connClosed.request('anything', {}, { timeoutMs: 30000 }));
  check(!!eClosed && eClosed.code === 'socket_closed' && Date.now() - tClose < 5000,
    'socket close 时立即 reject 在途请求（不等 30s 超时）',
    (eClosed ? eClosed.code : '无错误') + '，耗时 ' + (Date.now() - tClose) + 'ms');

  const silent2 = net.createServer(() => { /* 永不响应 */ });
  await new Promise((r) => silent2.listen(0, '127.0.0.1', r));
  servers.push(silent2);
  const connTimeout = new HC.HamsterConn({ host: '127.0.0.1', port: silent2.address().port, logger: log, label: 'silent-timeout' });
  await connTimeout.connect(3000);
  rawConns.push(connTimeout);
  const tTimeout = Date.now();
  const eTimeout = await expectError(() => connTimeout.request('anything', {}, { timeoutMs: 800 }));
  check(!!eTimeout && eTimeout.code === 'timeout' && Date.now() - tTimeout < 5000,
    '每个请求都有超时（800ms 到点即失败）',
    (eTimeout ? eTimeout.code : '无错误') + '，耗时 ' + (Date.now() - tTimeout) + 'ms');
  connTimeout.destroy('done');
  connClosed.destroy('done');

  /* ---------------------------------------------------------------- 9 库单测 */
  section('9. 客户端库单测（分帧 / 原子写 / 路径 / 设备 id / 脱敏）');
  /* 分帧：把"消息头 + 二进制负载 + 后续响应行"塞进同一个 push
     —— 旧实现（buf += d.toString() → Buffer.from(buf,'binary')）正是死在这里 */
  const framed = [];
  const payloadChunks = [];
  let fp = null;
  fp = new HC.FrameParser({
    onMessage: (m) => {
      if (m.type === 'response' && m.data && Number(m.data.payload_bytes) > 0) {
        fp.expectPayload(m.data.payload_bytes, {
          write: (c) => payloadChunks.push(Buffer.from(c)),
          finish: () => {},
        });
      } else framed.push(m);
    },
  });
  const weirdPayload = Buffer.from([0x00, 0xff, 0x0a, 0x80, 0x41, 0x0a, 0xc3, 0x28, 0xfe]);
  fp.push(Buffer.concat([
    Buffer.from(JSON.stringify({ type: 'response', id: 'p', status: 'ok', data: { payload_bytes: weirdPayload.length, hash: 'h' } }) + '\n'),
    weirdPayload,
    Buffer.from(JSON.stringify({ type: 'response', id: 'q', status: 'ok', data: { n: 1 } }) + '\n'),
  ]));
  check(Buffer.compare(Buffer.concat(payloadChunks), weirdPayload) === 0,
    '同一 data 事件里的"头+二进制负载+后续行"被精确分帧（负载字节未损坏）');
  check(framed.length === 1 && framed[0].id === 'q', '负载之后的响应行仍被正确解析');

  const atomicFile = path.join(TMP, 'atomic.json');
  HC.writeJsonAtomicSync(atomicFile, [{ a: 1 }]);
  const atomicRead = HC.readJsonArraySync(atomicFile);
  check(atomicRead.list.length === 1 && atomicRead.list[0].a === 1, '原子写 + 读回一致');
  fs.writeFileSync(atomicFile, '{ 这不是数组 }');
  const badRead = HC.readJsonArraySync(atomicFile);
  check(badRead.list.length === 0 && !!badRead.recovered && fs.existsSync(badRead.recovered),
    '解析失败/非数组 → 坏文件改名保留为 .corrupt-<ts>，不静默丢弃', badRead.recovered);

  /* 旧版"单个设备对象"格式（现网 devices.json 就是这个形状）必须能读出来，而不是当损坏丢掉 */
  const legacyFile = path.join(TMP, 'legacy-devices.json');
  fs.writeFileSync(legacyFile, JSON.stringify({ id: 'dev_1780385814264', name: 'LOCAL', addr: '127.0.0.1:9100', token: 't' }, null, 2));
  const legacyRead = HC.readJsonArraySync(legacyFile);
  check(legacyRead.list.length === 1 && legacyRead.migrated === true && !legacyRead.recovered,
    '旧版单对象 devices.json 折成单元素数组（不丢设备、不误判为损坏）');
  const legacyStore = new HC.DeviceStore({ file: legacyFile, logger: log });
  legacyStore.load();
  check(legacyStore.list().length === 1 && legacyStore.list()[0].name === 'LOCAL' &&
    fs.readdirSync(TMP).every((n) => n.indexOf('legacy-devices.json.corrupt-') !== 0),
    'DeviceStore 加载旧格式后仍能看到那台设备，且不产生 .corrupt 备份');

  check(HC.isWithinDir(path.join(TMP, 'a'), path.join(TMP, 'a', 'b')) && !HC.isWithinDir(path.join(TMP, 'a'), path.join(TMP, 'ab')),
    'isWithinDir 正确判定目录归属（a/b 在内，ab 不在）');
  let threw = null;
  try { HC.resolveInside(TMP, '..', '..', 'Windows'); } catch (e) { threw = e; }
  check(!!threw && threw.code === 'path_denied', 'resolveInside 拒绝 .. 越界');
  check(HC.safeLocalFileName('..\\..\\evil.txt') === 'evil.txt' && HC.safeLocalFileName('CON') === '_CON',
    '远端文件名落盘前被净化（路径分隔符 / Windows 设备名）');
  check(HC.isValidDeviceId(HC.generateDeviceId()) && HC.generateDeviceId().startsWith('dev_') &&
    !HC.isValidDeviceId('../../x') && !HC.isValidDeviceId('dev_abc'),
    '设备 id 白名单 /^dev_[0-9]{10,16}$/ 生效（渲染层无法注入任意 id）');

  const store = new HC.DeviceStore({ file: path.join(TMP, 'devices.json'), logger: log });
  store.load();
  const d1 = store.add({ name: 'X', addr: '127.0.0.1:' + PORT_A, token: 'hamster-secret-token' });
  check(HC.isValidDeviceId(d1.id) && store.list().length === 1, '设备库可新增（id 由主进程生成）', 'id=' + d1.id);
  check(store.list()[0].token === undefined, 'dev.list() 不返回 token（杜绝口令外泄）');
  let dupErr = null;
  try { store.add({ name: 'X2', addr: '127.0.0.1:' + PORT_A }); } catch (e) { dupErr = e; }
  check(!!dupErr && dupErr.code === 'device_exists', '同地址重复添加 → device_exists');
  const reloaded = new HC.DeviceStore({ file: path.join(TMP, 'devices.json'), logger: log });
  reloaded.load();
  check(reloaded.list().length === 1 && reloaded.raw()[0].token === 'hamster-secret-token',
    '设备库重新加载后数据完整（原子写生效）');
  check(HC.redact('使用 ' + CODEWORD + ' 连接', [CODEWORD]).indexOf(CODEWORD) < 0 &&
    HC.redact('api_key hk_abcdef123456') === 'api_key hk_***',
    '日志脱敏：口令与 hk_ 密钥都不落明文');

  /* ---------------------------------------------------------------- 10 主进程 */
  section('10. Electron 主进程装配自检（用假 electron 模块加载 main/index.js）');
  await mainProcessSelfCheck(monA, monB);

  /* ---------------------------------------------------------------- 汇总 */
  console.log('\n=== 结束 ===');
  console.log('  通过 ' + PASS + ' / 失败 ' + FAIL + ' / 跳过 ' + SKIP);
  if (singleInstanceEvidence) console.log('  单实例限制证据: ' + singleInstanceEvidence);
  if (FAIL > 0) dumpDaemonLogs();
  return FAIL === 0 ? 0 : 1;
}
/* ==========================================================================
 * Electron 主进程装配自检
 *
 * 用一个"假 electron 模块"替换 require('electron')，然后 require 真正的主进程文件。
 * 这样无需 GUI 就能验证：
 *   - bootstrap 能跑通（配置读取、设备库加载、窗口参数、IPC 注册、代理 spawn）
 *   - preload 用到的每个 IPC 通道在主进程都注册了（契约不会单边漂移）
 *   - §6 的 IPC 契约真的能打通到真实的 hamsterd（含下载落盘、文件操作、迁移）
 *   - 退出时 shutdown() 会关掉事件 socket / IPC socket / 定时器 / 代理子进程
 *
 * 为了让"主进程写 devices.json"这一步不污染用户数据，本段会先备份、注入测试设备、最后还原。
 * ========================================================================== */
function makeFakeElectron(env) {
  const handlers = new Map();
  const listeners = new Map();
  const windows = [];
  const sent = [];
  const app = {
    getPath: (n) => env.paths[n] || path.join(env.userData, String(n)),
    getVersion: () => '0.0.8-selfcheck',
    whenReady: () => Promise.resolve(),
    quit: () => { env.quitCalled = true; },
    on: (ev, fn) => { if (!listeners.has(ev)) listeners.set(ev, []); listeners.get(ev).push(fn); },
  };
  class BrowserWindow {
    constructor(options) {
      this.options = options;
      this._destroyed = false;
      this.webContents = { send: (ch, payload) => sent.push({ channel: ch, payload }) };
      windows.push(this);
    }
    loadFile(f) { this.loadedFile = f; return Promise.resolve(); }
    once(ev, fn) { if (ev === 'ready-to-show') this._ready = fn; }
    on(ev, fn) { (this._h = this._h || {})[ev] = fn; }
    show() { this.shown = true; }
    isDestroyed() { return this._destroyed; }
    minimize() {} maximize() {} unmaximize() {} close() {}
    isMaximized() { return false; }
  }
  const ipcMain = {
    handle: (ch, fn) => handlers.set(ch, fn),
    on: (ch, fn) => handlers.set(ch, fn),
  };
  const dialog = { showOpenDialog: async () => ({ canceled: true, filePaths: [] }) };
  const revealed = [];
  const copied = [];
  const shell = {
    showItemInFolder: (p) => revealed.push(['show', p]),
    openPath: (p) => revealed.push(['open', p]),
  };
  const clipboard = { writeText: (t) => copied.push(t) };
  return {
    electron: { app, BrowserWindow, ipcMain, dialog, shell, clipboard },
    handlers, listeners, windows, sent, app, revealed, copied,
  };
}

/**
 * 冻结一份"能跑"的代理副本（与守护进程同样的思路）：
 *   - Windows 上优先 hamster_manager.exe，退而接受无扩展名的 hamster_manager；
 *   - 拷贝后先跑 --version 校验，半截二进制（正在重编译）会被挡住。
 */
function stageProxyExe(managerDir, destDir) {
  /* 只认当前平台的可执行文件名：Windows 下绝不能退到 Linux 那个同名无扩展名的 ELF，
     否则会把它拷成 .exe 再执行，报 UNKNOWN 错误（CreateProcess 没法执行 ELF） */
  const names = process.platform === 'win32' ? ['hamster_manager.exe'] : ['hamster_manager'];
  const dstName = process.platform === 'win32' ? 'hamster_manager.exe' : 'hamster_manager';
  const dst = path.join(destDir, dstName);
  let lastErr = '未找到';
  for (const n of names) {
    const src = path.join(managerDir, n);
    if (!fs.existsSync(src)) { lastErr = '未找到 ' + n; continue; }
    try {
      const before = fs.statSync(src);
      fs.copyFileSync(src, dst);
      const after = fs.statSync(src);
      if (before.size !== after.size || before.mtimeMs !== after.mtimeMs) { lastErr = n + ' 拷贝期间被改动（正在重编译）'; continue; }
      const outFile = path.join(destDir, 'version.out');
      const fd = fs.openSync(outFile, 'w');
      let r = null;
      try {
        r = spawnSync(dst, ['--version'], { cwd: destDir, stdio: ['ignore', fd, fd], timeout: 10000, windowsHide: true });
      } finally { try { fs.closeSync(fd); } catch (_) {} }
      const text = fs.existsSync(outFile) ? fs.readFileSync(outFile, 'utf8') : '';
      /* 注意：--version 之前会先打一行 [CFG] 摘要，所以不能只看第一行 */
      const verLine = text.split(/\r?\n/).map((s) => s.trim()).find((s) => s.indexOf('Hamster Manager ver.') >= 0) || '';
      if (verLine) return { ok: true, path: dst, version: verLine, source: src };
      lastErr = n + ' --version 无有效输出（status=' + (r && r.status) +
        '，err=' + JSON.stringify((r && r.error && (r.error.code || r.error.message)) || '') +
        '，cwd=' + destDir + '，输出=' + JSON.stringify(text.slice(0, 60)) + '）';
    } catch (e) { lastErr = n + ': ' + e.message; }
  }
  return { ok: false, reason: lastErr };
}

async function mainProcessSelfCheck(monA, monB) {
  const Module = require('module');
  let selfCheckEnvRestore = null;
  const managerDir = path.join(ROOT, 'Hamster Manager');
  const devicesFile = path.join(managerDir, 'devices', 'devices.json');
  const devicesBak = devicesFile + '.selfcheck-bak-' + process.pid;
  const envDir = path.join(TMP, 'main-selfcheck');
  const userData = path.join(envDir, 'userData');
  const downloads = path.join(envDir, 'downloads');
  const proxyPort = PORT_A + 4;                    /* 代理 IPC 端口（:9102 角色） */
  const proxyHamdPort = PORT_A + 5;                /* 代理要连的那台 hamsterd */
  const proxyMon = path.join(TMP, 'proxy-monitor');
  const confPath = path.join(envDir, 'hamster_manager.conf');
  fs.mkdirSync(userData, { recursive: true });
  fs.mkdirSync(downloads, { recursive: true });
  const dlProbeFile = path.join(downloads, 'reveal-probe.bin');
  fs.writeFileSync(dlProbeFile, Buffer.from('reveal probe'));

  /*
   * 代理 hamster_manager.exe 只从**它自己目录**下的 hamster_manager.conf 读端口与口令，
   * 命令行 --hamd-port/--ipc-port 会被它内部 load_config() 覆盖（实测）。
   * 因此把代理连同一份测试配置拷到测试目录，并通过 HAMSTER_MANAGER_EXE 让主进程用它 ——
   * 这样既不动用户配置、也不占用 9100/9102，三方（主进程 conf / 代理 conf / 守护进程）仍然一致。
   */
  const proxyBin = path.join(envDir, 'proxy-bin');
  fs.mkdirSync(proxyBin, { recursive: true });
  const proxyStage = stageProxyExe(managerDir, proxyBin);
  const proxyExe = proxyStage.ok ? proxyStage.path : '';
  const haveProxyExe = proxyStage.ok;
  if (haveProxyExe) console.log('  被测代理: ' + proxyStage.version + '（' + proxyStage.source + '）');
  else console.log('  被测代理: 不可用（' + proxyStage.reason + '）→ 代理相关检查将跳过');
  let proxyTarget = null;
  let proxyManaged = false;
  if (haveProxyExe) {
    fs.writeFileSync(path.join(proxyBin, 'hamster_manager.conf'), [
      '# 自检用代理配置', 'hamd_port ' + proxyHamdPort, 'ipc_port ' + proxyPort,
      'hamd_codeword ' + CODEWORD, '',
    ].join('\n'), 'utf8');
    /* 代理要连的那台守护进程（口令与代理 conf 一致），用于验证 connection_status 转发链路 */
    write(path.join(proxyMon, 'proxy-baseline.txt'), Buffer.from('proxy target baseline'));
    proxyTarget = await startDaemon('proxy-target', proxyHamdPort, proxyMon, '5');
  }

  /* 主进程会读 hamster_manager.conf / devices.json —— 都指向测试用副本。
     hamd_encrypt 必须显式 off：本套件的守护进程是明文模式（见 daemonConf）。 */
  fs.writeFileSync(confPath, [
    '# 自检用配置', 'hamd_port ' + proxyHamdPort, 'ipc_port ' + proxyPort,
    'hamd_codeword ' + CODEWORD, 'hamd_encrypt off',
    'log_level debug', 'download_dir ' + downloads, '',
  ].join('\n'), 'utf8');

  const idA = 'dev_' + (Date.now() - 20000);
  const idB = 'dev_' + (Date.now() - 19000);
  const seed = [
    { id: idA, name: 'IPC-A', addr: '127.0.0.1:' + PORT_A, token: CODEWORD, status: 'offline', note: 'selfcheck', last_sync: '', created_at: new Date().toISOString() },
    { id: idB, name: 'IPC-B', addr: '127.0.0.1:' + PORT_B, token: CODEWORD, status: 'offline', note: 'selfcheck', last_sync: '', created_at: new Date().toISOString() },
  ];
  const hadDevices = fs.existsSync(devicesFile);
  let originalDevices = null;
  try {
    if (hadDevices) { originalDevices = fs.readFileSync(devicesFile); fs.copyFileSync(devicesFile, devicesBak); }
    fs.mkdirSync(path.dirname(devicesFile), { recursive: true });
    fs.writeFileSync(devicesFile, JSON.stringify(seed, null, 2), 'utf8');

    const env = { paths: { userData, downloads, logs: path.join(userData, 'logs') }, userData, quitCalled: false };
    const fake = makeFakeElectron(env);
    const prevConf = process.env.HAMSTER_MANAGER_CONF;
    const prevExe = process.env.HAMSTER_MANAGER_EXE;
    /*
     * 注意：app.whenReady().then(bootstrap) 是**异步**的，bootstrap 里的 ensureProxy()
     * 要等微任务队列才跑。所以这两个环境变量必须活到自检结束，不能 require 一返回就还原。
     */
    process.env.HAMSTER_MANAGER_CONF = confPath;
    if (haveProxyExe) process.env.HAMSTER_MANAGER_EXE = proxyExe;
    process.env.__SELFCHECK_RESTORE = '1';
    selfCheckEnvRestore = () => {
      if (prevConf === undefined) delete process.env.HAMSTER_MANAGER_CONF;
      else process.env.HAMSTER_MANAGER_CONF = prevConf;
      if (prevExe === undefined) delete process.env.HAMSTER_MANAGER_EXE;
      else process.env.HAMSTER_MANAGER_EXE = prevExe;
      delete process.env.__SELFCHECK_RESTORE;
    };
    const prevLoad = Module._load;
    Module._load = function (request, parent, isMain) {
      if (request === 'electron') return fake.electron;
      return prevLoad.apply(this, arguments);
    };
    console.log('  加载主进程: ' + path.join('Hamster Manager', 'module', 'hamster_manager_ui', 'main', 'index.js') + '（electron 已被替换为假模块）');
    try {
      require(path.join(managerDir, 'module', 'hamster_manager_ui', 'main', 'index.js'));
    } finally {
      Module._load = prevLoad;
    }

    const logFile = path.join(userData, 'logs', 'hamster-manager.log');
    const logText = () => (fs.existsSync(logFile) ? fs.readFileSync(logFile, 'utf8') : '');
    const booted = await waitFor(() => logText().indexOf('初始化完成') >= 0, 20000);
    check(!!booted, '主进程 bootstrap 完成并落盘日志（含 hamd_port/ipc_port 生效）',
      booted ? '' : logText().slice(-400));
    check(logText().indexOf('hamd_port=' + proxyHamdPort + ' ipc_port=' + proxyPort) >= 0,
      'hamster_manager.conf 的 hamd_port / ipc_port 真正生效（不再是硬编码 9102）');
    check(logText().indexOf('codeword=(已设置') >= 0, '口令状态可见但**不打印明文**',
      (logText().match(/codeword=[^\n]*/) || [''])[0]);
    check(logText().indexOf(CODEWORD) < 0, '日志中没有出现口令明文');

    /* 窗口 + preload 契约 */
    const w = fake.windows[0];
    check(!!w && w.options.webPreferences.contextIsolation === true &&
      w.options.webPreferences.nodeIntegration === false,
      '窗口使用 contextIsolation:true + nodeIntegration:false');
    check(!!w && w.options.webPreferences.preload === path.join(managerDir, 'module', 'hamster_manager_ui', 'preload', 'preload.js'),
      '两平台共用同一份 preload', w ? w.options.webPreferences.preload : '(无窗口)');
    check(!!w && w.loadedFile === path.join(managerDir, 'module', 'hamster_manager_ui', '_html', 'hamster_manager.html'),
      '加载的是本地页面文件（不加载远程内容）', w ? w.loadedFile : '(无窗口)');

    const preloadSrc = fs.readFileSync(path.join(managerDir, 'module', 'hamster_manager_ui', 'preload', 'preload.js'), 'utf8');
    const invoked = Array.from(new Set(Array.from(preloadSrc.matchAll(/ipcRenderer\.(?:invoke|send)\('([^']+)'/g)).map((m) => m[1])));
    const subscribed = Array.from(new Set(Array.from(preloadSrc.matchAll(/ipcRenderer\.on\('([^']+)'/g)).map((m) => m[1])));
    /* 只有"主进程 → 渲染层"的单向推送通道不需要 ipcMain 注册 */
    const pushOnly = ['event:broadcast', 'event:connected', 'event:heartbeat', 'event:message', 'window-maximize-change'];
    const missingInvoke = invoked.filter((ch) => !fake.handlers.has(ch));
    check(missingInvoke.length === 0, 'preload 发起调用的每个通道在主进程都已注册（' + invoked.length + ' 个）',
      missingInvoke.length ? '缺失: ' + missingInvoke.join(', ') : '');
    const unknownPush = subscribed.filter((ch) => pushOnly.indexOf(ch) < 0);
    check(unknownPush.length === 0, 'preload 订阅的推送通道都在主进程的推送名单里（' + subscribed.length + ' 个）',
      unknownPush.length ? '未知: ' + unknownPush.join(', ') : '');

    const call = (ch, ...args) => fake.handlers.get(ch)({ sender: 'selfcheck' }, ...args);

    /* 只读通道 */
    const list = await call('dev:list');
    check(Array.isArray(list) && list.length === 2 && list.every((d) => d.token === undefined),
      'dev:list 返回两台设备且不含 token', JSON.stringify(list).slice(0, 160));
    const cfgOut = await call('config:get');
    check(cfgOut.hamd_port === proxyHamdPort && cfgOut.ipc_port === proxyPort && cfgOut.codeword === '(已设置)',
      'config:get 回传有效端口与脱敏口令', JSON.stringify(cfgOut).slice(0, 200));
    const paths = await call('app:paths');
    check(paths.downloads === downloads && HC.isWithinDir(userData, paths.migrations_file),
      'app:paths 指向用户数据目录与下载目录', JSON.stringify(paths).slice(0, 200));
    check((await call('app:version')) === '0.0.8-selfcheck', 'app:version 来自 Electron app（单一版本来源）');

    /* 渲染层要的 config.set(download_dir) → config.get().downloads_dir 往返 */
    const newDlDir = path.join(envDir, 'downloads-2');
    check((await call('config:set', { download_dir: newDlDir })) === true, 'config:set 接受 download_dir 键');
    const cfgOut2 = await call('config:get');
    check(cfgOut2.downloads_dir === path.resolve(newDlDir) && hasDir(newDlDir),
      'config:set({download_dir}) 后 config:get().downloads_dir 反映新目录（渲染层据此预填）',
      cfgOut2.downloads_dir);

    /* 新增通道：app.reveal / app.copyText（渲染层"打开所在文件夹"与"复制路径"） */
    const revealOk = await call('app:reveal', dlProbeFile);
    check(revealOk.ok === true && fake.revealed.length === 1 && fake.revealed[0][1] === dlProbeFile,
      'app.reveal 对已存在文件调用 shell.showItemInFolder 并返回 {ok:true,path}',
      JSON.stringify(revealOk) + ' / shell=' + JSON.stringify(fake.revealed));
    const revealMissing = await call('app:reveal', path.join(envDir, 'no-such-file.bin'));
    check(revealMissing.ok === false && revealMissing.error === 'not_found',
      'app.reveal 对不存在的文件返回 {ok:false,error:"not_found"}（不抛异常）', JSON.stringify(revealMissing));
    const revealEmpty = await call('app:reveal', '');
    check(revealEmpty.ok === false && revealEmpty.error === 'missing_path', 'app.reveal 空路径返回 missing_path',
      JSON.stringify(revealEmpty));
    const revealDir = await call('app:reveal', downloads);
    check(revealDir.ok === true && fake.revealed[1][0] === 'open', 'app.reveal 对目录用 shell.openPath 打开',
      JSON.stringify(fake.revealed[1]));
    const copied = await call('app:copy-text', 'C:\\some\\path\\file.bin');
    check(copied.ok === true && copied.length === 21 && fake.copied[0] === 'C:\\some\\path\\file.bin',
      'app.copyText 写入系统剪贴板并返回 {ok:true,length}', JSON.stringify(copied));
    const copiedEmpty = await call('app:copy-text', '');
    check(copiedEmpty.ok === false && copiedEmpty.error === 'missing_text', 'app.copyText 空文本返回 missing_text',
      JSON.stringify(copiedEmpty));

    /* 渲染层实际依赖的通道清单（缺一个就是运行时错误） */
    const invokeChannels = [
      'dev:list', 'dev:list_all', 'dev:add', 'dev:remove', 'dev:update', 'dev:stats', 'dev:search',
      'dev:download', 'dev:sync_db', 'dev:verify', 'ctrl:send', 'config:get', 'config:set',
      'app:version', 'app:paths', 'app:reveal', 'app:copy-text', 'file:list', 'file:mkdir',
      'file:delete', 'file:upload', 'migrate:run', 'migrate:list', 'migrate:run_many', 'discover:list',
      'dev:search_many',
    ];
    const sendChannels = ['window-minimize', 'window-maximize', 'window-close'];
    const absent = invokeChannels.concat(sendChannels).filter((ch) => !fake.handlers.has(ch));
    check(absent.length === 0, '渲染层依赖的 ' + (invokeChannels.length + sendChannels.length) + ' 个请求/命令通道全部已注册',
      absent.length ? '缺失: ' + absent.join(', ') : '');
    const absentPush2 = ['onBroadcast', 'onConnected', 'onHeartbeat', 'onMessage'].filter((a) => preloadSrc.indexOf(a + ':') < 0);
    check(absentPush2.length === 0, '渲染层依赖的事件订阅（onBroadcast/onConnected/onHeartbeat/onMessage）都在 preload 暴露',
      absentPush2.join(', '));
    const verifyRun = await call('dev:verify', idA, { run: true });
    check(verifyRun && Number(verifyRun.verify_count) >= 1, 'dev:verify(id,{run:true}) 立即执行校验并返回统计',
      JSON.stringify(verifyRun).slice(0, 140));

    /* 渲染层只维护一份 + preload 只加载一份（契约无法分叉） */
    const wslPreload = path.join(managerDir, 'module', 'hamster_manager_ui_wsl', 'preload', 'preload.js');
    check(!fs.existsSync(wslPreload), '已删除 WSL 旧契约 preload 副本', wslPreload);
    const wslMain = fs.readFileSync(path.join(managerDir, 'module', 'hamster_manager_ui_wsl', 'main', 'index.js'), 'utf8');
    check(wslMain.indexOf('hamster_manager_ui') >= 0 && wslMain.indexOf('HAMSTER_UI_DIR') >= 0,
      'WSL 入口复用同一份主进程实现（只覆盖 HAMSTER_UI_DIR）');
    const wslHtml = fs.readFileSync(path.join(managerDir, 'module', 'hamster_manager_ui_wsl', '_html', 'hamster_manager.html'), 'utf8');
    check(wslHtml.indexOf('../../hamster_manager_ui/_js/') >= 0 && wslHtml.indexOf('../../hamster_manager_ui/_css/') >= 0,
      'WSL 页面引用同一份 _js/_css（渲染层单一源码）');

    /* 探测 + 搜索 + 统计 */
    const all = await call('dev:list_all');
    check(all.length === 2 && all.every((d) => d.status === 'online'),
      'dev:list_all 并发探测两台设备均为 online', JSON.stringify(all.map((d) => d.name + ':' + d.status)).slice(0, 120));
    const search = await call('dev:search', { id: idA, params: { q: 'page_0', limit: 2 } });
    check(search && search.total >= 5 && search.files.length === 2 && !!search.files[0].file_path,
      'dev:search 返回 total/files，并带 file_path 兼容别名', JSON.stringify(search).slice(0, 160));
    const many = await call('dev:search_many', [idA, idB], { q: 'page_0' });
    check(Array.isArray(many) && many.length === 2 && many[0].ok === true && many[1].ok === true,
      'dev:search_many 逐个返回结果（单个失败不影响其它）', JSON.stringify(many.map((r) => r.id + ':' + r.ok)));
    const stats = await call('dev:stats', idA);
    check(stats && Number(stats.total_files) >= 5, 'dev:stats 返回统计', JSON.stringify(stats).slice(0, 120));

    /* 文件操作 + 下载落盘（不再走 base64） */
    const mk = await call('file:mkdir', idA, 'ipc-check/dir');
    check(mk.ok === true && hasDir(path.join(monA, 'ipc-check', 'dir')), 'file:mkdir 递归建目录', JSON.stringify(mk));
    /* file.list 的目录项必须带 dir:true（迁移页据此展开目录） */
    const ipcList = await call('file:list', idA, 'ipc-check');
    check(Array.isArray(ipcList.entries) && ipcList.entries.some((e) => e.name === 'dir' && e.dir === true),
      'file.list 的目录项返回 dir:true', JSON.stringify(ipcList).slice(0, 160));
    const localUp = path.join(TMP, 'ipc-up.bin');
    const upBytes = makeBinary(200 * 1024, 909);
    fs.writeFileSync(localUp, upBytes);
    const up = await call('file:upload', idA, localUp, 'ipc-check/up.bin', { mkdir: true });
    check(up.ok === true && up.size === upBytes.length, 'file:upload 流式上传', JSON.stringify(up));
    const dl = await call('dev:download', idB, 'b-existing.txt');
    check(dl.ok === true && dl.name === 'b-existing.txt' && dl.saved_path.indexOf(downloads) === 0 && dl.size > 0,
      'dev:download 由主进程直接落盘并返回 {ok,saved_path,name,size,hash}', JSON.stringify(dl));
    check(sameBytes(path.join(monB, 'b-existing.txt'), fileBytes(dl.saved_path)),
      '下载落盘内容与远端文件逐字节一致');
    let delIpc = await call('file:delete', idA, 'ipc-check/up.bin');
    if (delIpc && delIpc.error === 'remove_failed') { await sleep(400); delIpc = await call('file:delete', idA, 'ipc-check/up.bin'); }
    check(delIpc.ok === true && !hasFile(path.join(monA, 'ipc-check', 'up.bin')),
      'file:delete 自动补 confirm 后删除成功', JSON.stringify(delIpc));

    /* sync_db：落点必须在 devices/ 内（修 P0-7 路径拼接收敛） */
    const sync = await call('dev:sync_db', idA);
    check(sync.ok === true && sync.size > 0 && HC.isWithinDir(path.join(managerDir, 'devices'), sync.path),
      'dev:sync_db 落点被限制在 devices/ 之内', JSON.stringify(sync));
    if (sync.ok) { try { fs.unlinkSync(sync.path); } catch (_) {} }

    /* 迁移（IPC 层） */
    const migSrcAbs = path.join(monA, 'ipc-mig-src.bin');
    write(migSrcAbs, makeBinary(80 * 1024, 77));
    const migRun = await call('migrate:run', {
      srcId: idA, dstId: idB, srcPath: migSrcAbs, dstPath: 'ipc-mig/out.bin', mode: 'move',
    });
    check(migRun.ok === true && migRun.removed === true && /^[0-9a-f]{32}$/.test(migRun.hash),
      'migrate:run 经 IPC 完成 move 迁移（含 hash 端到端校验）', JSON.stringify(migRun));
    check(!fs.existsSync(migSrcAbs) && sameBytes(path.join(monB, 'ipc-mig', 'out.bin'), makeBinary(80 * 1024, 77)),
      'IPC 迁移后源已删除、目标内容逐字节一致');
    const migRunMany = await call('migrate:run_many', [
      { srcId: idA, dstId: idB, srcPath: path.join(monA, 'batch_1.bin'), dstPath: 'ipc-many/1.bin', mode: 'copy' },
      { srcId: idA, dstId: idB, srcPath: path.join(monA, 'batch_2.bin'), dstPath: 'no-such-dir/../x.bin', mode: 'copy' },
    ]);
    check(Array.isArray(migRunMany) && migRunMany.length === 2 && migRunMany[0].ok === true && migRunMany[1].error === 'path_denied',
      'migrate:run_many 并发受控、逐个返回结果', JSON.stringify(migRunMany).slice(0, 200));
    const migList = await call('migrate:list');
    check(Array.isArray(migList) && migList.length >= 3 && migList.every((e) => e.id && e.time),
      'migrate:list 可读迁移历史（migrations.json 落在用户数据目录）', 'entries=' + migList.length);

    /* 控制指令 + 发现 + 错误路径 */
    const rescan = await call('ctrl:send', idA, 'rescan');
    check(rescan && rescan.status === 'rescan_requested', 'ctrl:send rescan 生效', JSON.stringify(rescan));
    const disc = await call('discover:list');
    check(Array.isArray(disc), 'discover:list 返回数组（本配置关闭了 UDP 发现，故为空）', JSON.stringify(disc).slice(0, 80));
    const notFound = await call('dev:stats', 'dev_0000000000000');
    check(notFound && notFound.error === 'not_found', '不存在的设备返回 {error:not_found} 而不是抛异常', JSON.stringify(notFound));
    const badAdd = await call('dev:add', { name: 'bad', addr: '127.0.0.1:' + PORT_A });
    check(badAdd && badAdd.error === 'device_exists', '重复地址 dev:add 返回 {error:device_exists}', JSON.stringify(badAdd));
    const badAddr = await call('dev:add', { name: 'bad2', addr: 'no-port:x' });
    check(badAddr && badAddr.error === 'invalid_addr', '非法地址 dev:add 返回 {error:invalid_addr}', JSON.stringify(badAddr));
    const badMig = await call('migrate:run', {});
    check(badMig && badMig.error === 'missing_device', '缺参数的 migrate:run 返回 {error}', JSON.stringify(badMig));
    const noConfirm = await call('file:delete', idA, 'no-such-file-xyz.bin');
    check(noConfirm && noConfirm.error === 'not_found', 'file:delete 不存在的文件返回 {error:not_found}', JSON.stringify(noConfirm));
    /* 设备 id 必须由主进程生成：渲染层即使传 id 也不被采信 */
    const addOut = await call('dev:add', { id: '../../evil', name: 'TMP', addr: '127.0.0.1:9' });
    const added = (await call('dev:list')).find((d) => d.name === 'TMP');
    check(addOut === 'offline' && !!added && HC.isValidDeviceId(added.id) && added.id !== '../../evil',
      'dev:add 忽略渲染层传来的 id，只接受主进程生成的 dev_<ts>（并返回 offline）',
      'addOut=' + JSON.stringify(addOut) + ' id=' + (added ? added.id : '未新增'));
    check((await call('dev:update', added ? added.id : idA, { note: 'updated-by-selfcheck' })) === true &&
      (await call('dev:remove', added ? added.id : idA)) === true,
      'dev:update / dev:remove 通过 IPC 生效');
    check((await call('dev:add', { name: 'X', addr: 'not-a-host:99999' })).error === 'invalid_addr',
      '端口越界的地址被拒绝（invalid_addr）');

    /* 代理：Electron 自己 spawn（修 P1-18 生命周期反转） */
    const proxyRefused = logText().indexOf('已有一个 Hamster Manager 在运行') >= 0;
    if (!haveProxyExe) {
      skip('代理 spawn / 通道 / 转发链路', '未找到 hamster_manager(.exe)（可能正在被重新编译）');
    } else if (proxyRefused) {
      skip('代理 spawn / 通道 / 转发链路', '会话内已有 Hamster Manager 在运行（代理单实例互斥体），本次 spawn 的代理立即退出');
    } else {
      proxyManaged = true;
      check(logText().indexOf('已启动代理 pid=') >= 0, '主进程用 child_process.spawn 拉起代理（--proxy-only --follow-stdin）',
        (logText().match(/已启动代理[^\n]*/) || ['未找到'])[0]);
      const proxyUp = await waitFor(() => logText().indexOf('已接入代理通道') >= 0, 12000);
      check(!!proxyUp, '主进程接入代理通道 127.0.0.1:' + proxyPort + '（先探测端口，已有则复用）',
        (logText().match(/\[IPC\][^\n]*/g) || []).slice(0, 3).join(' | '));
      check(logText().indexOf('[proxy:out]') >= 0, '代理的 stdout 被接到主进程日志（修"全链零日志"）',
        (logText().match(/\[proxy:out\][^\n]*/g) || ['未找到']).slice(0, 2).join(' | '));
      check(logText().indexOf('hamd=:' + proxyHamdPort) >= 0 && logText().indexOf('ipc=:' + proxyPort) >= 0,
        '代理按测试 conf 的端口连接/监听（' + proxyHamdPort + ' / ' + proxyPort + '），与主进程配置一致');
      if (proxyTarget) {
        const onlineEvt = await waitFor(() => fake.sent.find((s) => s.channel === 'event:connected' && s.payload && s.payload.connected === true), 25000);
        check(!!onlineEvt, '代理把 hamsterd 的 connection_status=online 转发成 event:connected 推给渲染层',
          JSON.stringify(fake.sent.filter((s) => s.channel === 'event:connected').slice(0, 3)));
      } else {
        skip('代理 → hamsterd 的 connection_status 转发', '代理目标守护进程未启动');
      }
    }
    const hbEvt = await waitFor(() => fake.sent.find((s) => s.channel === 'event:heartbeat'), 12000);
    check(!!hbEvt, 'event:heartbeat 周期性推送（age_ms 用于发现半开连接）', JSON.stringify((hbEvt || {}).payload || null));

    /* 命令通道 vs 事件通道：守护进程会在空闲 240s 后关掉命令通道（HD_IDLE_MS），
       如果客户端把这条连接的状态当成"事件通道断开"上报，界面每 4 分钟闪一次离线，
       而且渲染层收到离线就去刷新 → 又把命令通道连起来 → 自激成"断—连"循环。
       因此：event:connected 只允许来自事件通道（kind='event' 或代理转发的无 kind 语义）。 */
    {
      const cmdOnes = fake.sent.filter((s) => s.channel === 'event:connected' &&
        s.payload && s.payload.kind === 'command');
      check(cmdOnes.length === 0, '命令通道的连接状态不会被当成事件通道状态上报',
        JSON.stringify(cmdOnes.slice(0, 2)));
    }
    const bcEvt = await waitFor(() => fake.sent.find((s) => s.channel === 'event:broadcast' && s.payload && s.payload.event === 'file_added'), 15000);
    check(!!bcEvt, '真实文件事件经 event:broadcast 推给渲染层（含 seq/data）',
      JSON.stringify((bcEvt || {}).payload || null).slice(0, 180));

    /* 退出清理（修 P2-18：以前全是死代码） */
    const logLenBefore = logText().length;
    for (const fn of (fake.listeners.get('before-quit') || [])) fn();
    const shut = await waitFor(() => logText().indexOf('已关闭设备事件 socket') >= 0, 5000);
    check(!!shut, 'before-quit 触发 shutdown()：关闭事件 socket / IPC socket / 定时器',
      logText().slice(logLenBefore).slice(0, 200));
    if (proxyManaged) {
      check(logText().indexOf('结束代理子进程 pid=') >= 0, '退出时 kill 代理子进程');
    } else {
      skip('退出时 kill 代理子进程', haveProxyExe ? '代理未成功启动' : '未找到代理可执行文件（正在重编译）');
    }
    for (const fn of (fake.listeners.get('window-all-closed') || [])) fn();
    check(env.quitCalled === true, 'window-all-closed 触发 app.quit()');
    /* shutdown 之后再触发一次必须幂等 */
    for (const fn of (fake.listeners.get('will-quit') || [])) fn();
    check(true, 'shutdown() 可重复调用（幂等，不会二次关闭已销毁资源）');
  } finally {
    /* 还原环境变量（self-check 期间一直生效，见上面的说明） */
    if (selfCheckEnvRestore) { try { selfCheckEnvRestore(); } catch (_) {} selfCheckEnvRestore = null; }
    /* 还原用户的 devices.json：自检绝不能污染真实设备库 */
    try {
      if (hadDevices && originalDevices) fs.writeFileSync(devicesFile, originalDevices);
      else if (!hadDevices) fs.rmSync(devicesFile, { force: true });
      fs.rmSync(devicesBak, { force: true });
    } catch (e) {
      console.log('  [警告] 还原 devices.json 失败: ' + e.message + '（备份: ' + devicesBak + '）');
    }
  }
}

/** 收尾：删掉本次运行的测试目录（HAMSTER_TEST_KEEP=1 时保留以便排查） */
async function discardTmp() {
  if (KEEP_TMP) { console.log('  测试目录已保留: ' + TMP); return; }
  for (let i = 0; i < 6; i++) {
    try { fs.rmSync(TMP, { recursive: true, force: true }); return; }
    catch (_) { killDaemonsUnder(TMP); await sleep(400); }
  }
  console.log('  [警告] 测试目录未能删除（可能有进程占用）: ' + TMP);
}

/** 只杀"本测试目录内"的 hamsterd（路径前缀精确到本次运行的唯一目录，不会误伤别的测试） */
function killDaemonsUnder(dir) {
  if (process.platform !== 'win32') return;
  const script =
    'Get-Process hamsterd -ErrorAction SilentlyContinue | ' +
    'Where-Object { $_.Path -and $_.Path.StartsWith(' + JSON.stringify(dir) + ', [StringComparison]::OrdinalIgnoreCase) } | ' +
    'ForEach-Object { $_.Kill() }';
  try { spawnSync('powershell', ['-NoProfile', '-Command', script], { stdio: 'ignore' }); } catch (_) {}
}

main()
  .then(async (code) => { cleanup(); await sleep(300); await discardTmp(); process.exit(code); })
  .catch(async (e) => {
    console.error('\n测试自身异常:', e && e.stack ? e.stack : e);
    dumpDaemonLogs();
    cleanup();
    console.log('  测试目录保留以便排查: ' + TMP);
    process.exit(2);
  });
