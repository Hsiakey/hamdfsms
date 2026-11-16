/*
 * tests/media-auto.js — scan_threads: auto 的启动行为回归
 *
 * 判定本身由 build/test_media.exe 覆盖（纯逻辑 + 本机自洽）。这里只验真实守护进程：
 *   1. auto  → 按监控目录所在介质解析成一个具体线程数，并真的用这个数去扫描
 *   2. 显式值 → 不被 auto 逻辑覆盖（日志写明是显式配置）
 *   3. 非法值 → 退回默认 4，不崩
 * 断言只看"自洽"（解析结果 == 实际扫描线程数），不写死本机是 SSD 还是 HDD。
 *
 * 运行：node tests/media-auto.js
 */
'use strict';

const fs = require('fs');
const net = require('net');
const path = require('path');
const { spawn } = require('child_process');

const ROOT = path.join(__dirname, '..');
const TMP = path.join(__dirname, 'tmp', 'media-auto');
const BIN = path.join(TMP, 'bin');
const MON = path.join(TMP, 'mon');
const EXE = path.join(BIN, 'hamsterd.exe');
const PORT = 19416;
const CODEWORD = 'media-codeword-' + 'm'.repeat(24);

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

  for (let i = 0; i < 200; i += 1) {
    fs.writeFileSync(path.join(MON, 'f' + i + '.dat'), Buffer.alloc(64, 0x61));
  }
}

function writeConf(scanThreadsLine) {
  fs.writeFileSync(path.join(BIN, 'hamsterd.conf'), [
    'monitor_path: ' + MON,
    'ipv4_addr: 127.0.0.1',
    'ipv4_addr_port: ' + PORT,
    'codeword: ' + CODEWORD,
    'require_auth: on',
    'allow_loopback_noauth: off',
    'encrypt_transport: off',
    'max_transfer_mb: 8192',
    'max_clients: 8',
    scanThreadsLine,
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

/** 起一次守护进程，等扫描跑完就杀掉，返回日志与横幅 */
async function runOnce(label, scanThreadsLine) {
  writeConf(scanThreadsLine);
  fs.rmSync(path.join(BIN, 'logs'), { recursive: true, force: true });

  const p = spawn(EXE, ['--console-log'], { cwd: BIN, windowsHide: true });
  let stdout = '';
  p.stdout.on('data', (d) => { stdout += d.toString('utf8'); });
  p.stderr.on('data', (d) => { stdout += d.toString('utf8'); });

  if (!(await waitTcp(60000))) {
    try { p.kill(); } catch (_) {}
    throw new Error(label + ': 守护进程未就绪');
  }

  const logPath = path.join(BIN, 'logs', 'hamsterd.log');
  const deadline = Date.now() + 60000;
  let log = '';
  while (Date.now() < deadline) {
    log = fs.existsSync(logPath) ? fs.readFileSync(logPath, 'utf8') : '';
    if (/完成\(并行 \d+ 线程/.test(log)) break;
    await sleep(30);
  }
  await sleep(200);
  try { p.kill(); } catch (_) {}
  await sleep(400);
  log = fs.existsSync(logPath) ? fs.readFileSync(logPath, 'utf8') : '';
  return { log, stdout };
}

function mediaLine(log) {
  const lines = log.split('\n').filter((l) => /\] MEDIA /.test(l));
  return lines.length ? lines[lines.length - 1] : '';
}

function scanThreads(log) {
  const m = /完成\(并行 (\d+) 线程/.exec(log);
  return m ? Number(m[1]) : null;
}

(async () => {
  console.log('hamsterd scan_threads: auto 启动行为回归');
  prepare();

  /* 1) auto：解析出的线程数必须等于真实扫描线程数 */
  {
    const r = await runOnce('auto', 'scan_threads: auto');
    const ml = mediaLine(r.log);
    const auto = /->\s*scan_threads=auto 取 (\d+)/.exec(ml);
    const used = scanThreads(r.log);

    check(!!ml, 'auto：日志里有介质判定结论', ml);
    check(!!auto, 'auto：日志写明了 auto 解析结果', ml);
    if (auto) {
      const resolved = Number(auto[1]);
      check(resolved === 1 || resolved === 4, 'auto：解析结果只会是 1 或 4（' + resolved + '）', ml);
      check(used === resolved, 'auto：实际扫描线程数 == 解析结果（' + used + '）',
        JSON.stringify({ resolved, used }));
      check(/机械硬盘|固态|NVMe|网络盘|可移动/.test(ml), 'auto：日志给出了介质类型名', ml);
      const isHdd = /机械硬盘/.test(ml);
      check((resolved === 1) === isHdd, 'auto：只有机械盘才解析成 1', ml);
    }
    check(/扫描线程: \d+（.*auto 判定）/.test(r.stdout), 'auto：启动横幅标出 auto 判定',
      r.stdout.split('\n').filter((l) => l.includes('扫描线程')).join(' | '));
  }

  /* 2) 显式值不被覆盖 */
  {
    const r = await runOnce('explicit', 'scan_threads: 2');
    const ml = mediaLine(r.log);
    check(scanThreads(r.log) === 2, '显式 2：真的用 2 个线程扫描', ml);
    check(/scan_threads=2 为显式配置/.test(ml), '显式 2：日志写明是显式配置', ml);
    check(!/auto 取/.test(ml), '显式 2：不会被 auto 逻辑改写', ml);
  }

  /* 3) 非法值退回默认 4 */
  {
    const r = await runOnce('invalid', 'scan_threads: 99');
    check(scanThreads(r.log) === 4, '非法值 99：退回默认 4', mediaLine(r.log));
  }

  console.log('\n  通过 ' + pass + ' / 失败 ' + fail);
  process.exit(fail === 0 ? 0 : 1);
})().catch((e) => { console.error('测试失败: ' + (e && e.stack ? e.stack : e)); process.exit(1); });
