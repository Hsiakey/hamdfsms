/*
 * tests/verify-parallel.js — 并行完整性校验的计数正确性回归
 *
 * 并行化（hd_db.c 的 verify_worker / verify_ctx）只改「谁来算哈希」，不该改口径：
 *   正常 / 内容不一致 / 缺失 三个计数，多线程下必须和单线程完全一样，也不能重复统计。
 *
 * 造场景不改磁盘内容，避免和实时监控线程（ReadDirectoryChangesW → 重新哈希入库）打架：
 *   直接用 node:sqlite 以 WAL 并发写索引库
 *     1) 把 f10 的 xxHash3_128 改成错值  → 期望「内容不一致」+1
 *     2) 插一条指向不存在路径的记录      → 期望「缺失」+1
 * 然后通过协议发 verify(run:true) 连跑两轮，两轮结果必须一致（上一轮的数不会被累加）。
 *
 * 运行：node tests/verify-parallel.js   （VERIFY_FILES=3000 可改文件数）
 * 产物在 tests/tmp/verify-parallel/（已被 gitignore）。
 */
'use strict';

const fs = require('fs');
const net = require('net');
const path = require('path');
const { spawn } = require('child_process');
const { DatabaseSync } = require('node:sqlite');

const ROOT = path.join(__dirname, '..');
const TMP = path.join(__dirname, 'tmp', 'verify-parallel');
const BIN = path.join(TMP, 'bin');
const MON = path.join(TMP, 'mon');
const EXE = path.join(BIN, 'hamsterd.exe');
const DB = path.join(BIN, 'hamster.db');
const PORT = 19415;
const CODEWORD = 'verify-codeword-' + 'v'.repeat(24);
const N_FILES = Number(process.env.VERIFY_FILES || 3000);
const THREADS = Number(process.env.VERIFY_THREADS || 4);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let pass = 0;
let fail = 0;
function check(cond, name, detail) {
  if (cond) { pass += 1; console.log('  \u2713 ' + name); }
  else { fail += 1; console.log('  \u2717 ' + name + (detail === undefined ? '' : '  \u2192 ' + detail)); }
  return !!cond;
}

function prepare() {
  fs.rmSync(TMP, { recursive: true, force: true });
  fs.mkdirSync(BIN, { recursive: true });
  fs.mkdirSync(MON, { recursive: true });
  fs.copyFileSync(path.join(ROOT, 'Hamsterd', 'hamsterd.exe'), EXE);
  const dll = path.join(ROOT, 'Hamsterd', 'sqlite3.dll');
  if (fs.existsSync(dll)) fs.copyFileSync(dll, path.join(BIN, 'sqlite3.dll'));

  /* mtime 调到 1 小时前：避开「上次扫描时刻 − 5s」窗口，本用例关掉了跳过以保证全部入库哈希 */
  const old = Date.now() / 1000 - 3600;
  const buf = Buffer.alloc(4096, 0x61);
  for (let i = 0; i < N_FILES; i += 1) {
    const p = path.join(MON, 'f' + i + '.dat');
    buf.fill(i & 0xff, 0, 64);
    fs.writeFileSync(p, buf);
    fs.utimesSync(p, old, old);
  }

  fs.writeFileSync(path.join(BIN, 'hamsterd.conf'), [
    'monitor_path: ' + MON,
    'ipv4_addr: 127.0.0.1',
    'ipv4_addr_port: ' + PORT,
    'codeword: ' + CODEWORD,
    'require_auth: on',
    'allow_loopback_noauth: off',
    'encrypt_transport: off',
    'max_transfer_mb: 8192',
    'max_clients: 16',
    'scan_threads: ' + THREADS,
    'scan_skip_unchanged: off',
    'rescan_date: 0,0,0',
    'verify_interval: 0',
    'discovery_port: 0',
    'heartbeat_time: 3600',
    'log_level: info',
    'log_dir: logs',
    'exclude_internal: on',
    '',
  ].join('\n'), 'utf8');
}

async function waitTcp(ms) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    const ok = await new Promise((resolve) => {
      const s = net.connect({ host: '127.0.0.1', port: PORT }, () => { s.destroy(); resolve(true); });
      s.on('error', () => { try { s.destroy(); } catch (_) {} resolve(false); });
    });
    if (ok) return true;
    await sleep(20);
  }
  return false;
}

function logText() {
  const log = path.join(BIN, 'logs', 'hamsterd.log');
  return fs.existsSync(log) ? fs.readFileSync(log, 'utf8') : '';
}

async function waitLog(re, ms, what) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    const m = re.exec(logText());
    if (m) return m;
    await sleep(30);
  }
  throw new Error('日志等待超时: ' + what);
}

/** 直接改索引库（WAL 允许其它进程并发写），造出「库里的哈希/记录」和磁盘不一致 */
function tamper() {
  const db = new DatabaseSync(DB);
  try {
    db.exec('PRAGMA busy_timeout=5000');
    db.prepare('UPDATE file_in SET xxHash3_128=? WHERE file_path=?')
      .run('f'.repeat(32), path.join(MON, 'f10.dat'));
    db.prepare("INSERT INTO file_in(file_path,file_name,file_type,xxHash3_128) VALUES(?,?,?,?)")
      .run(path.join(MON, 'ghost.dat'), 'ghost.dat', 'file', '0'.repeat(32));
  } finally {
    try { db.close(); } catch (_) {}
  }
}

function runVerify(id) {
  return new Promise((resolve, reject) => {
    const sock = net.connect({ host: '127.0.0.1', port: PORT });
    let buf = '';
    let done = false;
    sock.setNoDelay(true);
    sock.on('connect', () => {
      sock.write(JSON.stringify({ type: 'request', id: 'hello_v',
        action: 'hello', params: { device_id: 'dev_verify_parallel', codeword: CODEWORD } }) + '\n');
    });
    sock.on('data', (d) => {
      buf += d.toString('utf8');
      let nl;
      while ((nl = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        let msg;
        try { msg = JSON.parse(line); } catch (_) { continue; }
        if (msg.id === 'hello_v' && msg.status === 'ok') {
          sock.write(JSON.stringify({ type: 'request', id, action: 'verify', params: { run: true } }) + '\n');
        } else if (msg.id === id) {
          done = true;
          try { sock.destroy(); } catch (_) {}
          resolve(msg);
        }
      }
    });
    sock.on('error', (e) => { if (!done) reject(e); });
    sock.on('close', () => { if (!done) reject(new Error('连接提前关闭')); });
  });
}

(async () => {
  console.log('hamsterd 并行完整性校验计数回归');
  prepare();

  const p = spawn(EXE, ['--console-log'], { cwd: BIN, stdio: 'ignore', windowsHide: true });
  if (!(await waitTcp(60000))) { try { p.kill(); } catch (_) {} throw new Error('守护进程未就绪'); }

  let scan = null;
  try {
    scan = await waitLog(/完成\(并行 (\d+) 线程, 跳过未变=\d+\): 访问=(\d+) 入库=(\d+) 失败=(\d+)/, 120000, '启动扫描');
  } catch (e) {
    try { p.kill(); } catch (_) {}
    throw e;
  }
  check(Number(scan[3]) === N_FILES, '启动扫描全部入库（indexed=' + N_FILES + '）', scan[0]);
  await sleep(300);

  tamper();

  const r1 = await runVerify('verify_1');
  const d1 = r1.data || {};
  check(r1.status === 'ok', 'verify(run:true) 成功', JSON.stringify(r1).slice(0, 160));
  check(Number(d1.verified_files) === N_FILES - 1, '正常计数 = 总数−1（' + (N_FILES - 1) + '）',
    JSON.stringify(d1));
  check(Number(d1.corrupt_count) === 1, '内容不一致计数 = 1', JSON.stringify(d1));
  check(Number(d1.missing_count) === 1, '缺失计数 = 1', JSON.stringify(d1));
  check(Number(d1.verify_count) >= 1, 'verify_count 已递增', JSON.stringify(d1));

  const vlog = /完整性校验完成\(并行 (\d+) 线程\): 总计=(\d+) 正常=(\d+) 内容不一致=(\d+) 缺失=(\d+) 耗时=(\d+)ms/.exec(logText());
  check(!!vlog, '守护进程记录了校验汇总行');
  if (vlog) {
    check(Number(vlog[1]) === THREADS, '实际使用 ' + THREADS + ' 个哈希线程（配置 scan_threads）', vlog[0]);
    check(Number(vlog[2]) === N_FILES + 1, '汇总结论 总计=' + (N_FILES + 1) + '（含伪造的那条）', vlog[0]);
    check(Number(vlog[4]) === 1 && Number(vlog[5]) === 1, '汇总 内容不一致=1 缺失=1', vlog[0]);
  }
  check(logText().includes('内容不一致: ' + path.join(MON, 'f10.dat')),
    '内容不一致的文件被逐条记进日志');

  /* 第二轮：同一批数据，计数必须完全一样（不能把上一轮的数累加进来） */
  const r2 = await runVerify('verify_2');
  const d2 = r2.data || {};
  check(Number(d2.verified_files) === N_FILES - 1 && Number(d2.corrupt_count) === 1
    && Number(d2.missing_count) === 1, '第二轮计数与第一轮一致（无跨轮累加）',
    JSON.stringify({ first: d1, second: d2 }));
  check(Number(d2.verify_count) === Number(d1.verify_count) + 1, 'verify_count 每轮 +1',
    Number(d1.verify_count) + ' -> ' + Number(d2.verify_count));

  try { p.kill(); } catch (_) {}
  await sleep(500);

  console.log('\n  通过 ' + pass + ' / 失败 ' + fail);
  process.exit(fail === 0 ? 0 : 1);
})().catch((e) => { console.error('测试失败: ' + (e && e.stack ? e.stack : e)); process.exit(1); });
