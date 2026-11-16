/*
 * tests/scan-skip.js — 「跳过未变文件」的正确性回归
 *
 * 规则（见 hd_db.c 的 skip_* / scan_can_skip）：
 *   未变 = (size, mtime_ms, ctime_ms, file_id) 全部一致，且 mtime 早于「上次扫描时刻 − 5s」。
 * 这里逐条验证四种情形：
 *   1) 首次扫描：全部要哈希
 *   2) 一个文件都没动：全部跳过
 *   3) 同大小改内容、把 mtime 原样写回：**不能跳过**（靠 ctime / file_id 抓）
 *   4) 只改 mtime（内容没变）：不能跳过（宁可多算，不可漏算）
 *
 * 运行：node tests/scan-skip.js
 * 产物在 tests/tmp/scan-skip/（已被 gitignore）。
 */
'use strict';

const fs = require('fs');
const net = require('net');
const path = require('path');
const { spawn } = require('child_process');

const ROOT = path.join(__dirname, '..');
const TMP = path.join(__dirname, 'tmp', 'scan-skip');
const BIN = path.join(TMP, 'bin');
const MON = path.join(TMP, 'mon');
const EXE = path.join(BIN, 'hamsterd.exe');
const PORT = 19413;
const CODEWORD = 'skip-codeword-' + 'k'.repeat(24);
const N_FILES = Number(process.env.SKIP_FILES || 2000);

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

  /* 把 mtime 统一调到 1 小时前：否则「上次扫描时刻 − 5s」这个分辨率保护窗口
     会把刚创建的文件全部判成"可能被时间戳分辨率掩盖"，一条都跳不过去。 */
  const old = Date.now() / 1000 - 3600;
  for (let i = 0; i < N_FILES; i += 1) {
    const p = path.join(MON, 'f' + i + '.dat');
    fs.writeFileSync(p, Buffer.alloc(64, 0x61));
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
    'scan_threads: 4',
    'scan_skip_unchanged: on',
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

function lastScanLog() {
  const log = path.join(BIN, 'logs', 'hamsterd.log');
  if (!fs.existsSync(log)) return null;
  const lines = fs.readFileSync(log, 'utf8').split('\n').filter((l) => l.includes('完成(并行'));
  if (!lines.length) return null;
  const m = /跳过未变=(\d+)\): 访问=(\d+) 入库=(\d+) 失败=(\d+)/.exec(lines[lines.length - 1]);
  if (!m) return null;
  return { skipped: Number(m[1]), visited: Number(m[2]), indexed: Number(m[3]), failed: Number(m[4]) };
}

async function scanOnce() {
  const t0 = Date.now();
  const p = spawn(EXE, ['--console-log'], { cwd: BIN, stdio: 'ignore', windowsHide: true });
  if (!(await waitTcp(60000))) { try { p.kill(); } catch (_) {} throw new Error('守护进程未就绪'); }
  await sleep(250);
  const r = lastScanLog();
  const wall = Date.now() - t0;
  try { p.kill(); } catch (_) {}
  await sleep(500);
  return { ...(r || {}), wall };
}

(async () => {
  console.log('hamsterd 跳过未变文件回归');
  prepare();

  const r1 = await scanOnce();
  check(r1.visited === N_FILES && r1.skipped === 0, '首次扫描：全部哈希（visited=' + N_FILES + '）',
    JSON.stringify(r1));

  const r2 = await scanOnce();
  check(r2.skipped === N_FILES && r2.visited === 0, '全部未变：全部跳过',
    JSON.stringify(r2));
  check(r2.wall < r1.wall, '第二次扫描更快（' + r2.wall + 'ms < ' + r1.wall + 'ms）',
    JSON.stringify({ first: r1.wall, second: r2.wall }));

  /* 同大小改内容 + 把 mtime 原样写回：ctime 会变，必须抓出来 */
  {
    const p = path.join(MON, 'f0.dat');
    const old = new Date(Date.now() - 3600 * 1000);
    fs.writeFileSync(p, Buffer.alloc(64, 0x62));
    fs.utimesSync(p, old, old);
  }
  const r3 = await scanOnce();
  check(r3.visited === 1 && r3.skipped === N_FILES - 1, '同大小改内容 + 回写 mtime：不能跳过（靠 ctime）',
    JSON.stringify(r3));

  /* 只动 mtime，内容不变：宁可多算不可漏算 */
  {
    const p = path.join(MON, 'f1.dat');
    const t = new Date(Date.now() - 1800 * 1000);
    fs.utimesSync(p, t, t);
  }
  const r4 = await scanOnce();
  check(r4.visited === 1 && r4.skipped === N_FILES - 1, '只改 mtime：不能跳过',
    JSON.stringify(r4));

  console.log('\n  通过 ' + pass + ' / 失败 ' + fail);
  process.exit(fail === 0 ? 0 : 1);
})().catch((e) => { console.error('测试失败: ' + (e && e.stack ? e.stack : e)); process.exit(1); });
