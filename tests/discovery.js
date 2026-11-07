/*
 * tests/discovery.js — 局域网发现协议的端到端测试（PROTOCOL §7）
 *
 * 覆盖的是"必须静默丢弃"这一类**只能靠真实网络行为验证**的规则：
 *   1. 暗号正确 → 能发现，且应答里的端口/名称/版本齐全
 *   2. 暗号错误 → 一个字节都不回（无枚举oracle）
 *   3. 重放同一个探测帧 → 只回一次
 *   4. 篡改 MAC → 不回
 *   5. 超速 → 被限速（不回）
 *   6. discovery_respond=off → 收得到但不回
 *   7. 服务端 stats.peers 恒为 [] （发现已完全搬到客户端侧）
 *
 * 运行：node tests/discovery.js
 * 退出码：0 = 全通过，1 = 有失败
 */
'use strict';

const crypto = require('crypto');
const dgram = require('dgram');
const fs = require('fs');
const net = require('net');
const path = require('path');
const { spawn } = require('child_process');

const ROOT = path.join(__dirname, '..');
const HC = require(path.join(ROOT, 'Hamster Manager', 'module', 'shared', 'hamster-client.js'));

const TCP_PORT = 19301;
const UDP_PORT = 19311;
const CODEWORD = 'test-discovery-codeword-' + 'a'.repeat(16);
const TMP = path.join(__dirname, 'tmp', 'discovery');
const BIN_DIR = path.join(TMP, 'bin');
const MON_DIR = path.join(TMP, 'monitor');
const EXE_SRC = path.join(ROOT, 'Hamsterd', 'hamsterd.exe');
const EXE = path.join(BIN_DIR, 'hamsterd.exe');

let pass = 0;
let fail = 0;
const procs = [];

function check(cond, name, detail) {
  if (cond) { pass += 1; console.log('  \u2713 ' + name); }
  else { fail += 1; console.log('  \u2717 ' + name + (detail ? '  → ' + detail : '')); }
  return !!cond;
}

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

function rmrf(p) {
  try { fs.rmSync(p, { recursive: true, force: true }); } catch (_) {}
}

function mkdirp(p) { fs.mkdirSync(p, { recursive: true }); }

/* ---------------------------------------------------------------- 环境准备 */
function prepare() {
  rmrf(TMP);
  mkdirp(BIN_DIR);
  mkdirp(MON_DIR);
  fs.writeFileSync(path.join(MON_DIR, 'hello.txt'), 'discovery test', 'utf8');
  fs.copyFileSync(EXE_SRC, EXE);
  const dll = path.join(ROOT, 'Hamsterd', 'sqlite3.dll');
  if (fs.existsSync(dll)) fs.copyFileSync(dll, path.join(BIN_DIR, 'sqlite3.dll'));

  const conf = [
    'monitor_path: ' + MON_DIR,
    'ipv4_addr: 127.0.0.1',
    'ipv4_addr_port: ' + TCP_PORT,
    'codeword: ' + CODEWORD,
    'require_auth: on',
    'allow_loopback_noauth: off',
    'max_transfer_mb: 64',
    'max_clients: 8',
    'rescan_date: 0,0,0',
    'verify_interval: 0',
    'discovery_port: ' + UDP_PORT,
    'discovery_respond: on',
    'heartbeat_time: 1',
    'log_level: debug',
    'log_dir: logs',
    'exclude_internal: on',
    '',
  ].join('\n');
  fs.writeFileSync(path.join(BIN_DIR, 'hamsterd.conf'), conf, 'utf8');
}

function startDaemon(label) {
  const p = spawn(EXE, ['--console-log'], {
    cwd: BIN_DIR,
    stdio: 'ignore',          /* 不抓管道：沙箱下 pipe 可能被拒 */
    windowsHide: true,
  });
  p.__label = label;
  procs.push(p);
  return p;
}

async function waitTcp(port, timeoutMs) {
  const deadline = Date.now() + (timeoutMs || 15000);
  while (Date.now() < deadline) {
    const ok = await new Promise((resolve) => {
      const s = net.connect({ host: '127.0.0.1', port }, () => { s.destroy(); resolve(true); });
      s.on('error', () => { try { s.destroy(); } catch (_) {} resolve(false); });
      s.setTimeout(500, () => { try { s.destroy(); } catch (_) {} resolve(false); });
    });
    if (ok) return true;
    await sleep(250);
  }
  return false;
}

function stopDaemon(p) {
  if (!p) return Promise.resolve();
  return new Promise((resolve) => {
    if (p.exitCode !== null) return resolve();
    p.once('exit', () => resolve());
    try { p.kill(); } catch (_) {}
    setTimeout(() => { try { p.kill('SIGKILL'); } catch (_) {} resolve(); }, 3000);
  });
}

/* ---------------------------------------------------------------- 探针工具 */
/** 极简手工探针：只发一个帧、收集一段时间内的所有应答 */
function rawProbe(frameBuf, waitMs) {
  return new Promise((resolve) => {
    const s = dgram.createSocket('udp4');
    const got = [];
    s.on('message', (buf, rinfo) => {
      got.push({ text: buf.toString('utf8'), size: buf.length, from: rinfo.address, raw: buf });
    });
    s.bind(0, () => {
      try { s.setBroadcast(true); } catch (_) {}
      for (const f of (Array.isArray(frameBuf) ? frameBuf : [frameBuf])) {
        try { s.send(f, UDP_PORT, '127.0.0.1'); } catch (_) {}
      }
      setTimeout(() => { try { s.close(); } catch (_) {} resolve(got); }, waitMs);
    });
  });
}

function makeFrame(codeword, id, nonce, forceMac) {
  const m = forceMac || HC.discProbeMac(codeword, id, nonce);
  return Buffer.from(JSON.stringify({ t: 'hp', v: 1, id, n: nonce, m }), 'utf8');
}

function newNonce() { return crypto.randomBytes(16).toString('hex'); }

const CLIENT_ID = 'discovery-' + 'c'.repeat(8);

/* ---------------------------------------------------------------- 用例 */
async function caseDiscoverOk() {
  console.log('\n=== 1. 暗号正确 → 能发现 ===');
  const d = new HC.Discovery({
    codeword: CODEWORD, deviceId: CLIENT_ID, port: UDP_PORT,
    intervalMs: 300, ttlMs: 2000, targets: ['127.0.0.1'],
  });
  const ok = d.start();
  check(ok, 'Discovery 启动成功', 'start() 返回 false');
  await sleep(1200);
  const list = d.list();
  const st = d.stats;
  check(list.length === 1, '发现 1 台设备', '实际 ' + list.length + ' 台，stats=' + JSON.stringify(st));
  if (list.length) {
    const p = list[0];
    check(p.port === TCP_PORT, '应答里的 TCP 端口正确', '得到 ' + p.port);
    check(p.ip === '127.0.0.1', 'IP 取自 recvfrom 源地址', '得到 ' + p.ip);
    check(typeof p.name === 'string' && p.name.length > 0, '带回了服务端显示名', JSON.stringify(p.name));
    check(p.ver === '0.0.8', '带回了版本号', JSON.stringify(p.ver));
    check(p.age_ms < 2000, 'age_ms 在合理范围', String(p.age_ms));
    check(p.addr === p.ip + ':' + p.port, 'addr 可直接喂给 dev.add()', p.addr);
    check(/^[0-9a-f]{16}$/.test(p.id), '服务端 id 是 16 位十六进制', p.id);
  }
  check(st.recv > 0, '统计里记到了有效应答', JSON.stringify(st));
  d.stop();
  check(d.list().length === 0, 'stop() 之后列表清空');
}

async function caseWrongCode() {
  console.log('\n=== 2. 暗号错误 → 一个字节都不回 ===');
  const d = new HC.Discovery({
    codeword: 'definitely-not-the-codeword', deviceId: CLIENT_ID, port: UDP_PORT,
    intervalMs: 300, ttlMs: 2000, targets: ['127.0.0.1'],
  });
  d.start();
  await sleep(1500);
  const st = d.stats;
  check(d.list().length === 0, '错误暗号发现不到任何设备');
  check(st.recv === 0, '一个有效应答都没收到', JSON.stringify(st));
  check(st.sent > 0, '确实发出了探测（不是没发）', JSON.stringify(st));
  d.stop();
}

async function caseReplay() {
  console.log('\n=== 3. 重放同一个探测帧 → 只回一次 ===');
  const nonce = newNonce();
  const frame = makeFrame(CODEWORD, CLIENT_ID, nonce);
  const first = await rawProbe(frame, 700);
  check(first.length === 1, '首帧得到 1 个应答', '实际 ' + first.length);

  if (first.length === 1) {
    let f = null;
    try { f = JSON.parse(first[0].text); } catch (_) {}
    check(!!f, '应答是合法 JSON');
    if (f) {
      check(f.t === 'hr' && f.v === 1, '应答 t=hr v=1', first[0].text.slice(0, 80));
      check(f.n === nonce, '应答原样回显 nonce');
      check(f.port === TCP_PORT, '应答携带服务端 TCP 端口', String(f.port));
    }
  }

  /* 隔 120ms 再发一次完全相同的帧：重放窗口命中，静默丢弃 */
  await sleep(120);
  const second = await rawProbe(frame, 700);
  check(second.length === 0, '重放的帧没有应答', '实际 ' + second.length);
}

async function caseTamperedMac() {
  console.log('\n=== 4. 篡改 MAC → 不回 ===');
  const nonce = newNonce();
  const good = HC.discProbeMac(CODEWORD, CLIENT_ID, nonce);
  const bad = (good[0] === 'a' ? 'b' : 'a') + good.slice(1);
  const got = await rawProbe(makeFrame(CODEWORD, CLIENT_ID, nonce, bad), 700);
  check(got.length === 0, 'MAC 被改 → 静默丢弃', '实际 ' + got.length);
}

async function caseEnabledOff() {
  console.log('\n=== 5. discovery_respond=off → 收得到但不回 ===');
  await stopDaemon(procs[0]);
  await sleep(400);

  const confPath = path.join(BIN_DIR, 'hamsterd.conf');
  let conf = fs.readFileSync(confPath, 'utf8');
  conf = conf.replace('discovery_respond: on', 'discovery_respond: off');
  fs.writeFileSync(confPath, conf, 'utf8');

  const p = startDaemon('respond-off');
  procs[0] = p;
  const ready = await waitTcp(TCP_PORT, 15000);
  check(ready, '守护进程（应答关闭）已就绪');

  const d = new HC.Discovery({
    codeword: CODEWORD, deviceId: CLIENT_ID, port: UDP_PORT,
    intervalMs: 300, ttlMs: 2000, targets: ['127.0.0.1'],
  });
  d.start();
  await sleep(1200);
  check(d.list().length === 0, '回应关闭时发现不到设备', JSON.stringify(d.stats));
  d.stop();

  /* 恢复配置，供后面的用例使用 */
  await stopDaemon(p);
  await sleep(400);
  conf = conf.replace('discovery_respond: off', 'discovery_respond: on');
  fs.writeFileSync(confPath, conf, 'utf8');
  const p2 = startDaemon('respond-on');
  procs[0] = p2;
  const ready2 = await waitTcp(TCP_PORT, 15000);
  check(ready2, '守护进程（应答开启）已重新就绪');
}

async function caseStatsPeersEmpty() {
  console.log('\n=== 6. 服务端 stats.peers 恒为 [] ===');
  const c = new HC.HamsterClient({
    id: 'test-stats', name: 'test-stats',
    host: '127.0.0.1', port: TCP_PORT, codeword: CODEWORD,
  });
  try {
    await c.connect(8000);
    const st = await c.stats(8000);
    check(Array.isArray(st.peers), 'peers 仍然是数组（协议兼容）', JSON.stringify(st.peers));
    check(st.peers.length === 0, 'peers 恒为空（发现已搬到客户端侧）', JSON.stringify(st.peers));
  } catch (e) {
    check(false, '连接并读取 stats 失败', e && e.message);
  } finally {
    try { c.close('done'); } catch (_) {}
  }
}

async function caseRateLimit() {
  console.log('\n=== 7. 超速 → 被限速 ===');
  await sleep(2500);                       /* 让令牌桶回满，免得被上一批用例影响 */

  const frames = [];
  for (let i = 0; i < 100; i++) {
    frames.push(makeFrame(CODEWORD, CLIENT_ID, newNonce()));
  }
  const got = await rawProbe(frames, 1200);
  /* 突发上限 40，回填 20/s，1.2s 内最多约 40+24 个；给足余量后仍然必须明显少于 100 */
  check(got.length >= 20, '限速仍然放行了突发额度', '实际 ' + got.length);
  check(got.length < 100, '超速的探测被丢弃', '实际 ' + got.length + ' / 100');

  /* 静默期后应恢复：等 3s（回满）再发一个单帧 */
  await sleep(3000);
  const one = await rawProbe(makeFrame(CODEWORD, CLIENT_ID, newNonce()), 700);
  check(one.length === 1, '限速静默后恢复正常', '实际 ' + one.length);
}

/* ---------------------------------------------------------------- main */
(async () => {
  console.log('=== 局域网发现端到端测试（PROTOCOL §7）===');
  console.log('TCP ' + TCP_PORT + ' / UDP ' + UDP_PORT + ' / 目录 ' + TMP);

  prepare();
  startDaemon('main');
  const ready = await waitTcp(TCP_PORT, 15000);
  check(ready, '守护进程已就绪');
  if (!ready) {
    const log = path.join(BIN_DIR, 'logs', 'hamsterd.log');
    if (fs.existsSync(log)) {
      console.log('  日志尾部：');
      for (const line of fs.readFileSync(log, 'utf8').split('\n').slice(-20)) console.log('    ' + line);
    }
    throw new Error('daemon not ready');
  }

  await caseDiscoverOk();
  await caseWrongCode();
  await caseReplay();
  await caseTamperedMac();
  await caseStatsPeersEmpty();
  await caseEnabledOff();
  await caseRateLimit();

  console.log('\n=== 结果: 通过 ' + pass + ', 失败 ' + fail + ' ===');
  await Promise.all(procs.map(stopDaemon));
  process.exit(fail === 0 ? 0 : 1);
})().catch(async (e) => {
  console.error('\n测试异常: ' + ((e && e.stack) || e));
  await Promise.all(procs.map(stopDaemon));
  process.exit(1);
});
