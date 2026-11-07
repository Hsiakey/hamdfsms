/*
 * tests/gui-live.js — 真 Electron GUI ⇄ 真 hamsterd 的 §8 端到端检查
 *
 * 为什么需要它：其它套件要么用假 electron（client-protocol 里的 stub），
 * 要么只测协议层。这里跑的是**真的主进程 + 真的 preload + 真的渲染进程**，
 * 走 IPC → HamsterClient → 加密连接 → 守护进程 的完整链路。
 *
 * 用法（必须用 electron 运行，不能用 node）：
 *   electron tests/gui-live.js
 *
 * 它会：起一个 encrypt_transport=on 的临时 hamsterd → 用自己的临时 userData
 * 和 conf 启动真 GUI → 通过 preload 暴露的 window.hamster 调 IPC →
 * 校验设备在线、stats、下载 200KB 文件 → 退出并恢复 devices.json。
 */
'use strict';

const { app, BrowserWindow } = require('electron');
const fs = require('fs');
const net = require('net');
const path = require('path');
const { spawn } = require('child_process');

const ROOT = path.join(__dirname, '..');
const MANAGER_DIR = path.join(ROOT, 'Hamster Manager');
const TMP = path.join(__dirname, 'tmp', 'gui-live');
const BIN_DIR = path.join(TMP, 'bin');
const MON_DIR = path.join(TMP, 'monitor');
const DL_DIR = path.join(TMP, 'downloads');
const HAMD_PORT = 19311;
const IPC_PORT = 19312;
const CODEWORD = 'gui-live-' + 'd'.repeat(16);
const DEVICES_JSON = path.join(MANAGER_DIR, 'devices', 'devices.json');

/* 必须在 require 主进程之前改好，否则 USER_DATA / LOG_DIR 就落在真实目录里了 */
app.disableHardwareAcceleration();
app.commandLine.appendSwitch('disable-gpu');
app.setPath('userData', path.join(TMP, 'userData'));
process.env.HAMSTER_MANAGER_CONF = path.join(TMP, 'hamster_manager.conf');

let pass = 0;
let fail = 0;
let daemon = null;
let devicesBackup = null;

function check(cond, name, detail) {
  if (cond) { pass += 1; console.log('  ✓ ' + name); }
  else { fail += 1; console.log('  ✗ ' + name + (detail === undefined ? '' : '  → ' + detail)); }
  return !!cond;
}
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

function prepare() {
  try { fs.rmSync(TMP, { recursive: true, force: true }); } catch (_) {}
  fs.mkdirSync(BIN_DIR, { recursive: true });
  fs.mkdirSync(MON_DIR, { recursive: true });
  fs.mkdirSync(DL_DIR, { recursive: true });

  fs.writeFileSync(path.join(MON_DIR, 'probe.bin'), Buffer.alloc(200 * 1024, 0x6b));
  fs.copyFileSync(path.join(ROOT, 'Hamsterd', 'hamsterd.exe'), path.join(BIN_DIR, 'hamsterd.exe'));
  const dll = path.join(ROOT, 'Hamsterd', 'sqlite3.dll');
  if (fs.existsSync(dll)) fs.copyFileSync(dll, path.join(BIN_DIR, 'sqlite3.dll'));

  fs.writeFileSync(path.join(BIN_DIR, 'hamsterd.conf'), [
    'monitor_path: ' + MON_DIR,
    'ipv4_addr: 127.0.0.1',
    'ipv4_addr_port: ' + HAMD_PORT,
    'codeword: ' + CODEWORD,
    'require_auth: on',
    'encrypt_transport: on',
    'max_transfer_mb: 64',
    'rescan_date: 0,0,0',
    'verify_interval: 0',
    'discovery_port: 0',
    'heartbeat_time: 1',
    'log_level: debug',
    'log_dir: logs',
    'exclude_internal: on',
    '',
  ].join('\n'), 'utf8');

  fs.writeFileSync(process.env.HAMSTER_MANAGER_CONF, [
    'hamd_port ' + HAMD_PORT,
    'ipc_port ' + IPC_PORT,
    'hamd_codeword ' + CODEWORD,
    'hamd_encrypt on',
    'download_dir ' + DL_DIR,
    'log_level debug',
    '',
  ].join('\n'), 'utf8');

  /* 设备库在主进程里不是 userData，而是仓库路径：先备份，结束时还原 */
  fs.mkdirSync(path.dirname(DEVICES_JSON), { recursive: true });
  if (fs.existsSync(DEVICES_JSON)) devicesBackup = fs.readFileSync(DEVICES_JSON);  const id = 'dev_' + (Date.now() - 5000);
  fs.writeFileSync(DEVICES_JSON, JSON.stringify([{
    id, name: 'GUI-LIVE', addr: '127.0.0.1:' + HAMD_PORT, token: CODEWORD,
    status: 'offline', note: 'gui-live', last_sync: '', created_at: new Date().toISOString(),
  }], null, 2), 'utf8');

  /* 主进程会 spawn 代理；把它也隔离到临时目录，别去读仓库里那份真配置 */
  const proxyExe = path.join(BIN_DIR, 'hamster_manager.exe');
  const proxySrc = path.join(ROOT, 'Hamster Manager', 'hamster_manager.exe');
  if (fs.existsSync(proxySrc)) {
    fs.copyFileSync(proxySrc, proxyExe);
    fs.writeFileSync(path.join(BIN_DIR, 'hamster_manager.conf'), [
      'hamd_port ' + HAMD_PORT,
      'ipc_port ' + IPC_PORT,
      'hamd_codeword ' + CODEWORD,
      'hamd_encrypt on',
      '',
    ].join('\n'), 'utf8');
    process.env.HAMSTER_MANAGER_EXE = proxyExe;
  }

  return id;
}

function restoreDevices() {
  try {
    if (devicesBackup) fs.writeFileSync(DEVICES_JSON, devicesBackup);
    else fs.rmSync(DEVICES_JSON, { force: true });
  } catch (_) {}
}

async function waitTcp(port, timeoutMs) {
  const deadline = Date.now() + (timeoutMs || 15000);
  while (Date.now() < deadline) {
    const ok = await new Promise((resolve) => {
      const s = net.connect({ host: '127.0.0.1', port }, () => { s.destroy(); resolve(true); });
      s.on('error', () => { try { s.destroy(); } catch (_) {} resolve(false); });
    });
    if (ok) return true;
    await sleep(200);
  }
  return false;
}

function startDaemon() {
  daemon = spawn(path.join(BIN_DIR, 'hamsterd.exe'), ['--console-log'],
    { cwd: BIN_DIR, stdio: 'ignore', windowsHide: true });
}

async function waitFor(fn, ms, what) {
  const t0 = Date.now();
  while (Date.now() - t0 < (ms || 20000)) {
    try { if (await fn()) return true; } catch (_) {}
    await sleep(200);
  }
  throw new Error('等待超时: ' + what);
}

async function main() {
  const devId = prepare();
  startDaemon();
  const up = await waitTcp(HAMD_PORT, 15000);
  check(up, '加密守护进程已就绪 :' + HAMD_PORT);
  if (!up) throw new Error('daemon not ready');

  /* 启动真 GUI（主进程会在 require 时注册 whenReady） */
  require(path.join(MANAGER_DIR, 'module', 'hamster_manager_ui', 'main', 'index.js'));
  await waitFor(() => BrowserWindow.getAllWindows().length > 0, 20000, '主窗口');
  check(true, '主窗口已创建');

  const wins = BrowserWindow.getAllWindows();
  const win = wins[0];
  const js = (code) => win.webContents.executeJavaScript(code, true);

  await waitFor(async () => (await js('!!(window.hamster && window.hamster.dev)')) === true,
    20000, 'preload API');
  check(true, 'preload 暴露 window.hamster');

  /* 1) 配置：加密开关确实是从 conf 读进来的 */
  const cfg = await js('window.hamster.config.get()');
  check(!!cfg && cfg.encrypt === true, 'config:get 报告 encrypt=true', JSON.stringify(cfg && cfg.encrypt));

  /* 2) 设备列表 + 在线探测（走真加密连接） */
  const list = await js('window.hamster.dev.list()');
  check(Array.isArray(list) && list.length === 1, '设备库读到 1 台设备',
    Array.isArray(list) ? String(list.length) : typeof list);

  let online = false;
  for (let i = 0; i < 40 && !online; i += 1) {
    const all = await js('window.hamster.dev.listAll()');
    online = Array.isArray(all) && all.some((d) => d.id === devId && d.status === 'online');
    if (!online) await sleep(250);
  }
  check(online, '设备在真 GUI 里显示 online（§8 握手成功）');

  /* 3) 命令通道：stats */
  const st = await js('window.hamster.dev.stats(' + JSON.stringify(devId) + ')');
  check(!!st && typeof st.total_files === 'number', 'dev:stats 走加密连接返回',
    JSON.stringify(st).slice(0, 120));

  /* 4) 下载（跨多条 64 KiB 记录） */
  const dl = await js('window.hamster.dev.download(' + JSON.stringify(devId) + ', "probe.bin")');
  check(!!dl && dl.ok === true, 'dev:download 成功', JSON.stringify(dl).slice(0, 160));
  if (dl && dl.saved_path) {
    const sz = fs.statSync(dl.saved_path).size;
    check(sz === 200 * 1024, '下载文件 200 KiB', String(sz));
    const head = fs.readFileSync(dl.saved_path).subarray(0, 8);
    check(head.every((b) => b === 0x6b), '下载内容与源一致（0x6b 填充）');
  }

  /* 5) 事件通道：上传一个文件，看渲染层是否收到 file_added
     注意：executeJavaScript 的返回值必须可结构化克隆，订阅函数返回的是取消函数，
     所以用 IIFE 包一层只返回 true。 */
  await js('(function () {' +
    'window.__guiEvents = [];' +
    'window.hamster.event.onBroadcast(function (m) {' +
    '  if (m && m.event === "file_added") window.__guiEvents.push(m);' +
    '});' +
    'return true; })()');
  const src = path.join(TMP, 'upload.bin');
  fs.writeFileSync(src, Buffer.alloc(64 * 1024, 0x21));
  const upRes = await js('window.hamster.file.upload(' + JSON.stringify(devId) + ',' +
    JSON.stringify(src) + ', "gui-live-up.bin", { overwrite: true })');
  check(!!upRes && (upRes.ok === true || upRes === true), 'file:upload 成功',
    JSON.stringify(upRes).slice(0, 160));
  check(fs.existsSync(path.join(MON_DIR, 'gui-live-up.bin')), '服务端已落盘');

  let gotEvent = false;
  for (let i = 0; i < 30 && !gotEvent; i += 1) {
    const evs = await js('window.__guiEvents || []');
    gotEvent = Array.isArray(evs) && evs.length > 0;
    if (!gotEvent) await sleep(200);
  }
  check(gotEvent, '渲染层收到 file_added 事件（加密事件通道）');

  /* 6) 日志：真 GUI 的日志文件存在且远小于上限 */
  const logFile = path.join(TMP, 'userData', 'logs', 'hamster-manager.log');
  const lsz = fs.existsSync(logFile) ? fs.statSync(logFile).size : -1;
  check(lsz > 0 && lsz < 8 * 1024 * 1024, 'GUI 日志文件存在且在上限内', String(lsz));
  const logText = fs.existsSync(logFile) ? fs.readFileSync(logFile, 'utf8') : '';
  check(logText.indexOf(CODEWORD) < 0, '日志里没有口令明文');
}

app.whenReady().then(async () => {
  console.log('Hamster GUI 端到端检查（真 Electron + 加密守护进程）');
  let code = 1;
  try {
    await main();
    code = fail === 0 ? 0 : 1;
  } catch (e) {
    console.error('测试异常: ' + ((e && e.stack) || e));
    code = 1;
  } finally {
    console.log('\n=== 结果: 通过 ' + pass + ', 失败 ' + fail + ' ===');
    try { restoreDevices(); } catch (_) {}
    if (daemon) { try { daemon.kill(); } catch (_) {} }
    setTimeout(() => app.exit(code), 300);
  }
});

app.on('window-all-closed', () => { /* 由上面的 app.exit 收尾，避免提前退出 */ });
