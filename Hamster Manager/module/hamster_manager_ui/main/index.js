/*
 * Hamster Manager — Electron 主进程（ver.0.0.8）
 *
 * 职责边界（本文件只做三件事）：
 *   1) 进程生命周期：自己 spawn 代理 hamster_manager.exe（先探测 :9102，已有就直接用）、
 *      before-quit / window-all-closed 时统一 shutdown()；
 *   2) 窗口；
 *   3) IPC 注册（PROTOCOL §6 契约）。
 * 协议、二进制分帧、路径校验、设备库、迁移编排全部在 module/shared/hamster-client.js，
 * 因此它们可以被 tests/client-protocol.js 用纯 Node 验证。
 *
 * 两套 UI 目录（hamster_manager_ui / hamster_manager_ui_wsl）共用这一份实现：
 *   - hamster_manager_ui_wsl/main/index.js 只设置 HAMSTER_UI_DIR 后 require 本文件；
 *   - preload 只有一份（module/hamster_manager_ui/preload/preload.js），IPC 契约无法分叉。
 */

'use strict';

const { app, BrowserWindow, ipcMain, dialog, shell, clipboard } = require('electron');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const net = require('net');
const os = require('os');
const { spawn } = require('child_process');

const HC = require(path.join(__dirname, '..', '..', 'shared', 'hamster-client.js'));

/* ==========================================================================
 * 路径常量
 * ========================================================================== */
const MANAGER_DIR = path.join(__dirname, '..', '..', '..');            /* "Hamster Manager" */
const UI_DIR = process.env.HAMSTER_UI_DIR
  ? path.resolve(process.env.HAMSTER_UI_DIR)
  : path.join(__dirname, '..');
const PRELOAD_PATH = path.join(__dirname, '..', '..', 'hamster_manager_ui', 'preload', 'preload.js');
const DEVICES_DIR = path.join(MANAGER_DIR, 'devices');
const DEVICES_JSON = path.join(DEVICES_DIR, 'devices.json');
const USER_DATA = app.getPath('userData');
const LOG_DIR = path.join(USER_DATA, 'logs');
const LOG_FILE = path.join(LOG_DIR, 'hamster-manager.log');
const MIGRATIONS_JSON = path.join(USER_DATA, 'migrations.json');
const TMP_DIR = path.join(USER_DATA, 'tmp');

/* ==========================================================================
 * 配置与日志（日志落盘到用户数据目录；token/口令一律脱敏）
 * ========================================================================== */
const cfg = HC.loadManagerConfig(MANAGER_DIR);
const logger = HC.createLogger({
  dir: LOG_DIR, file: 'hamster-manager.log', level: cfg.log_level, secrets: [cfg.codeword],
});

/* ==========================================================================
 * 全局状态
 * ========================================================================== */
let win = null;
let proxyChild = null;
let ipcSock = null;
let ipcRetryTimer = null;
let ipcRetryDelay = 500;
let heartbeatTimer = null;
let shuttingDown = false;
let migLog = null;
let migrator = null;
let store = null;

const clients = new Map();                 /* device id → HamsterClient */

/* 局域网发现（PROTOCOL §7）：本进程自己广播探测，不再向已连接设备要 peers。
   本机标识只用于把应答的 MAC 绑定到这次请求，进程重启换一个也无妨。 */
let discovery = null;
const discDeviceId = 'disc-' + crypto.randomBytes(6).toString('hex');
const ownedTimers = new Set();
const dedup = new HC.EventDeduper({
  windowMs: 2000,
  /* PROTOCOL §1.4：seq 跳号说明中间有事件被丢弃，应主动重查一次。
     主进程在这里告警并给渲染层一个 seq_gap 提示（列表刷新由渲染层决定）。 */
  onGap: (g) => {
    logger.warn('[event] ' + g.device + ' 事件 seq 跳号: 期望 ' + g.expected + ' 实收 ' + g.got + '（有事件被丢弃，建议重查）');
    notify('event:broadcast', {
      event: 'seq_gap', type: 'seq_gap', device: g.device, device_id: '',
      data: { expected: g.expected, got: g.got }, time: Math.floor(Date.now() / 1000),
    });
  },
});

function track(handle) {
  ownedTimers.add(handle);
  return handle;
}
function trackSetInterval(fn, ms) {
  const h = setInterval(fn, ms);
  if (h.unref) h.unref();
  return track(h);
}
function trackSetTimeout(fn, ms) {
  const h = setTimeout(() => { ownedTimers.delete(h); fn(); }, ms);
  return track(h);
}
function clearTracked(h) {
  if (!h) return;
  ownedTimers.delete(h);
  try { clearTimeout(h); } catch (_) {}
  try { clearInterval(h); } catch (_) {}
}

/** 给 Promise 加超时；原 Promise 的迟到结果被吞掉，避免未处理拒绝 */
function withTimeout(promise, ms, code) {
  let timer = null;
  const guard = Promise.resolve(promise).then(
    (v) => { if (timer) clearTimeout(timer); return v; },
    (e) => { if (timer) clearTimeout(timer); throw e; }
  );
  guard.catch(() => {});
  return Promise.race([
    guard,
    new Promise((_, rej) => {
      timer = setTimeout(() => rej(new HC.HamsterError(code || 'timeout', '操作超时 ' + ms + 'ms')), ms);
    }),
  ]);
}

function notify(channel, payload) {
  if (!win || win.isDestroyed()) return;
  try { win.webContents.send(channel, payload); } catch (e) { logger.warn('[ipc] 推送 ' + channel + ' 失败: ' + e.message); }
}

/* ==========================================================================
 * 设备 → 客户端
 * ========================================================================== */
function downloadDir() {
  if (cfg.download_dir) {
    try { HC.ensureDir(cfg.download_dir); return path.resolve(cfg.download_dir); } catch (_) {}
  }
  try { return app.getPath('downloads'); } catch (_) { return os.homedir(); }
}

/** 建立/复用某台设备的客户端对象（不连接）；地址或口令变化时重建 */
function ensureClient(id) {
  const dev = store.find(id);
  if (!dev) throw new HC.HamsterError('not_found', '设备不存在: ' + id);
  const { host, port } = HC.parseAddr(dev.addr, cfg.hamd_port);
  const codeword = dev.token || cfg.codeword;
  const old = clients.get(id);
  if (old && old.host === host && old.port === port && old.codeword === codeword) return old;
  if (old) { old.close('rebuild'); clients.delete(id); }
  if (dev.token) logger.addSecret(dev.token);
  const c = new HC.HamsterClient({
    id, name: dev.name, host, port, codeword,
    downloadDir: downloadDir(),
    logger,
    commandTimeoutMs: cfg.command_timeout_ms,
    onEvent: (msg, client) => {
      pushEvent({
        device: client.name, device_id: client.id,
        event: msg.event, data: msg.data, seq: msg.seq, time: msg.time,
      });
    },
    onState: (s) => {
      /* 两条连接的状态必须分开看（见 hamster-client.js 的 kind 说明）：
         · kind='command'：命令通道。守护进程在空闲 240s 后按设计关闭它，下一条命令
           到达时自动重连——**这不是设备离线**。如果当成"事件通道断开"上报，界面会
           每 4 分钟闪一次离线，而且渲染层收到离线就去刷新 → 立刻又发命令 → 命令通道
           马上重连 → 4 分钟后再来一次，形成"断—连"死循环。
         · kind='event'：事件通道，真正的长连接，断开才代表事件流中断。 */
      if (s.kind !== 'event') {
        logger.debug('[conn] ' + s.device +
          (s.connected ? ' 命令通道就绪' : ' 命令通道已关闭（空闲超时；下次命令会重连）'));
        return;
      }
      logger.info('[event] ' + s.device + (s.connected ? ' 事件通道已连接' : ' 事件通道断开'));
      /* s.device 是 'name@host:port'；推给渲染层只要名字，否则界面上的通道标签会带上地址 */
      notify('event:connected', {
        connected: !!s.connected,
        device: String(s.device || '').split('@')[0],
        device_id: id,
        kind: 'event',
      });
    },
  });
  clients.set(id, c);
  c.startEvents();                 /* 事件通道独立重连，设备离线也不会丢 */
  return c;
}

/** 取得并**连接**（认证通过）的客户端；失败抛出可读错误码 */
async function onlineClient(id, timeoutMs) {
  const c = ensureClient(id);
  if (c.info && c._conn && c._conn.connected) return c;
  await withTimeout(c.connect(), timeoutMs || cfg.command_timeout_ms, 'con_timeout');
  return c;
}

function startEventsForAll() {
  for (const dev of store.list()) {
    try { ensureClient(dev.id); }
    catch (e) { logger.warn('[event] 为 ' + dev.name + ' 建立事件通道失败: ' + e.message); }
  }
}

/**
 * 发现命中 → 若该 IP:port 对应已登记的设备，直接把它的重连退避清零并立刻重连。
 * 这是"目标设备一上线就连上"的关键：否则最多要等 5s 的退避窗口。
 */
function onDiscovered(peer, isNew) {
  if (!peer || !peer.ip) return;
  let nudged = 0;
  for (const dev of store.list()) {
    let host = '';
    let port = cfg.hamd_port;
    try {
      const a = HC.parseAddr(dev.addr, cfg.hamd_port);
      host = a.host;
      port = a.port;
    } catch (_) { continue; }
    if (host !== peer.ip) continue;
    const c = clients.get(dev.id);
    if (!c) continue;
    try { if (c.nudgeEvents()) nudged += 1; } catch (_) {}
  }
  if (isNew) {
    logger.info('[discover] 发现 ' + (peer.name || peer.id) + ' @ ' + peer.addr +
      (nudged ? '（已催促 ' + nudged + ' 条事件通道立即重连）' : ''));
  }
}

/** 启动/重启本进程的探测广播；配置不全时只告警，不影响其它功能 */
function startDiscovery() {
  if (discovery) { try { discovery.stop(); } catch (_) {} discovery = null; }
  if (!(cfg.discovery_port > 0)) {
    logger.info('[discover] 已在配置里禁用（hamd_discovery_port=0）');
    return;
  }
  discovery = new HC.Discovery({
    codeword: cfg.codeword,
    deviceId: discDeviceId,
    port: cfg.discovery_port,
    intervalMs: 1000,
    ttlMs: 3000,
    logger,
    onFound: onDiscovered,
  });
  if (!discovery.start()) { discovery = null; return; }
  logger.info('[discover] 广播探测已启动：UDP ' + cfg.discovery_port + '，本机标识 ' + discDeviceId);
}

/* ==========================================================================
 * 事件推送到渲染层（去重 + 兼容旧字段）
 * ========================================================================== */
function pushEvent(ev) {
  if (!dedup.accept(ev)) return;
  const data = ev.data || {};
  notify('event:broadcast', {
    /* PROTOCOL §6.3 契约字段 */
    event: ev.event,
    data,
    seq: ev.seq,
    time: ev.time,
    device: ev.device,
    device_id: ev.device_id,
    /* 旧渲染层仍在读的字段（去重后仍保留，避免渲染层大改） */
    type: ev.event,
    file: (data && (data.path || data.name)) || '',
  });
}

/* ==========================================================================
 * 代理进程：Electron 自己 spawn（先探测 :9102，已有就直接用）
 * ========================================================================== */
function pumpProxyLog(stream, tag) {
  let buf = '';
  stream.on('data', (d) => {
    buf += Buffer.isBuffer(d) ? d.toString('utf8') : String(d);
    let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i).replace(/\r$/, '');
      buf = buf.slice(i + 1);
      if (line.trim()) logger.info('[proxy:' + tag + '] ' + line);
    }
    if (buf.length > 64 * 1024) buf = buf.slice(-4096);
  });
}

async function ensureProxy() {
  const inUse = await HC.probePort(cfg.ipc_port, { timeoutMs: 800 });
  if (inUse) {
    logger.info('检测到 127.0.0.1:' + cfg.ipc_port + ' 已有代理在运行，直接复用（兼容旧启动方式）');
    return;
  }
  /*
   * 代理路径：默认 <Manager>/hamster_manager(.exe)。
   * 注意：代理**只从它自己所在目录**的 hamster_manager.conf 读端口与口令，
   * 命令行 --hamd-port/--ipc-port 会被它内部的 load_config() 覆盖（已实测），
   * 所以主进程与代理必须读同一份 conf —— 生产环境两者本来就指向同一个文件。
   * HAMSTER_MANAGER_EXE 仅供测试/自定义部署指定代理位置（见 tests/client-protocol.js）。
   */
  const exeOverride = process.env.HAMSTER_MANAGER_EXE;
  const exe = exeOverride ? path.resolve(exeOverride) : HC.resolveManagerExe(MANAGER_DIR);
  if (!exe || !fs.existsSync(exe)) {
    logger.warn('未找到代理可执行文件 hamster_manager(.exe)，跳过启动；命令通道直连 hamsterd :' + cfg.hamd_port);
    return;
  }
  try {
    proxyChild = spawn(exe, [
      '--proxy-only', '--follow-stdin',
      '--hamd-port=' + cfg.hamd_port,
      '--ipc-port=' + cfg.ipc_port,
    ], {
      cwd: MANAGER_DIR,
      stdio: ['pipe', 'pipe', 'pipe'],   /* stdout/stderr 接到自己的日志；stdin 关闭即让代理退出 */
      windowsHide: true,
    });
    logger.info('已启动代理 pid=' + proxyChild.pid + ' (' + exe + ')');
    if (proxyChild.stdout) pumpProxyLog(proxyChild.stdout, 'out');
    if (proxyChild.stderr) pumpProxyLog(proxyChild.stderr, 'err');
    proxyChild.on('error', (e) => {
      logger.warn('代理进程错误: ' + e.message + '（命令通道直连 hamsterd，不受影响）');
      proxyChild = null;
    });
    proxyChild.on('exit', (code, signal) => {
      logger.info('代理进程退出 code=' + code + ' signal=' + signal);
      proxyChild = null;
    });
  } catch (e) {
    logger.warn('启动代理失败: ' + e.message);
    proxyChild = null;
  }
}

/**
 * 代理通道（:9102）：只用于接收代理转发的 connection_status / 广播事件，
 * 命令一律直连 hamsterd（代理连接是共享的，会把响应转发给所有 :9102 客户端）。
 */
function connectIpcProxy() {
  if (shuttingDown) return;
  if (ipcSock) { try { ipcSock.destroy(); } catch (_) {} ipcSock = null; }
  const sock = new net.Socket();
  ipcSock = sock;
  let buf = '';
  sock.connect(cfg.ipc_port, '127.0.0.1', () => {
    ipcRetryDelay = 500;
    logger.info('已接入代理通道 127.0.0.1:' + cfg.ipc_port);
  });
  sock.on('data', (d) => {
    buf += d.toString('utf8');
    const lines = buf.split('\n');
    buf = lines.pop();
    for (const line of lines) {
      if (!line.trim()) continue;
      let msg;
      try { msg = JSON.parse(line); } catch (_) { continue; }
      if (msg && msg.type === 'event') onProxyEvent(msg);
    }
  });
  sock.on('close', () => {
    if (ipcSock === sock) ipcSock = null;
    if (!shuttingDown) scheduleIpcRetry();
  });
  sock.on('error', (e) => {
    logger.debug('代理通道错误: ' + e.message);
    if (ipcSock === sock) ipcSock = null;
    if (!shuttingDown) scheduleIpcRetry();
  });
}

function scheduleIpcRetry() {
  if (ipcRetryTimer || shuttingDown) return;
  const delay = ipcRetryDelay;
  ipcRetryDelay = Math.min(Math.round(ipcRetryDelay * 2), 5000);
  ipcRetryTimer = trackSetTimeout(() => { ipcRetryTimer = null; connectIpcProxy(); }, delay);
}

function onProxyEvent(msg) {
  const ev = String(msg.event || '');
  /* 代理只管 127.0.0.1:hamd_port 这一台 hamsterd，据此找到对应设备名，才能与直连事件去重 */
  const dev = store.list().find((d) => {
    try { return HC.parseAddr(d.addr, cfg.hamd_port).port === cfg.hamd_port; } catch (_) { return false; }
  });
  if (ev === 'connection_status') {
    const online = String(msg.data) === 'online';
    notify('event:connected', { connected: online, device: dev ? dev.name : 'LOCAL', device_id: dev ? dev.id : '' });
    notify('event:broadcast', { type: 'connection_status', event: 'connection_status', status: online ? 'online' : 'offline', device: dev ? dev.name : 'LOCAL', device_id: dev ? dev.id : '' });
    return;
  }
  pushEvent({
    device: dev ? dev.name : 'LOCAL',
    device_id: dev ? dev.id : '',
    event: ev, data: msg.data, seq: msg.seq, time: msg.time,
  });
}

/* ==========================================================================
 * IPC 注册（PROTOCOL §6）
 * ========================================================================== */
/** 统一包装：任何异常都变成 {error, detail}，不让 IPC 抛成未捕获异常 */
function handle(channel, fn) {
  ipcMain.handle(channel, async (...args) => {
    try {
      return await fn(...args);
    } catch (e) {
      const r = HC.toErrorResult(e);
      logger.warn('[ipc] ' + channel + ' → ' + r.error + (r.detail ? ' (' + r.detail + ')' : ''));
      return r;
    }
  });
}

/** 兼容 dev.search(id, params) 与旧版 dev.search({id, params}) 两种调用 */
function normIdParams(a, b) {
  if (a && typeof a === 'object') return { id: String(a.id || ''), params: a.params || {} };
  return { id: String(a || ''), params: (b && typeof b === 'object') ? b : {} };
}

function registerIpc() {
  /* ---------------- 设备（§6.1） ---------------- */
  handle('dev:list', () => store.list());

  handle('dev:list_all', async () => {
    const list = store.list();
    const updates = [];
    const results = await Promise.all(list.map(async (d) => {
      const base = { id: d.id, name: d.name, addr: d.addr, note: d.note, status: 'offline' };
      try {
        const c = await onlineClient(d.id, 3000);
        const st = await withTimeout(c.stats(4000), 5000, 'timeout');
        const lastSync = new Date().toISOString();
        updates.push({ id: d.id, status: 'online', last_sync: lastSync });
        return Object.assign(base, {
          status: 'online', last_sync: lastSync,
          total_files: Number(st.total_files) || 0,
          total_size: Number(st.total_size) || 0,
          file_types_count: Number(st.file_type_count) || 0,
          file_types: Array.isArray(st.file_types) ? st.file_types : [],
          peers: Array.isArray(st.peers) ? st.peers : [],
          clients: Number(st.clients) || 0,
          monitor_path: st.monitor_path || '',
        });
      } catch (e) {
        updates.push({ id: d.id, status: 'offline' });
        return Object.assign(base, { total_files: 0, total_size: 0, file_types_count: 0, file_types: [], error: HC.toErrorResult(e).error });
      }
    }));
    store.applyStatusBatch(updates);       /* 批量落盘：不再并发整体覆盖写 */
    return results;
  });

  handle('dev:add', async (_, dev) => {
    const d = (dev && typeof dev === 'object') ? dev : {};
    const rec = store.add({ name: d.name, addr: d.addr, token: d.token, note: d.note });  /* id 由主进程生成 */
    logger.info('[ipc] dev:add → ' + rec.id + ' @ ' + rec.addr);
    ensureClient(rec.id);
    try {
      const c = await onlineClient(rec.id, 5000);
      await c.ping(4000);
      store.applyStatusBatch([{ id: rec.id, status: 'online', last_sync: new Date().toISOString() }]);
      return 'online';
    } catch (e) {
      store.applyStatusBatch([{ id: rec.id, status: 'offline' }]);
      logger.warn('[ipc] 新设备 ' + rec.id + ' 探测失败: ' + e.message);
      return 'offline';
    }
  });

  handle('dev:remove', (_, id) => {
    const key = String(id || '');
    const c = clients.get(key);
    if (c) { c.close('removed'); clients.delete(key); }
    dedup.reset(key);
    return store.remove(key);
  });

  handle('dev:update', (_, id, fields) => {
    const key = String(id || '');
    const before = store.find(key);
    const updated = store.update(key, fields || {});
    if (!updated) return false;
    if (!before || before.addr !== updated.addr || before.token !== updated.token) {
      const c = clients.get(key);
      if (c) { c.close('addr/token changed'); clients.delete(key); }
      ensureClient(key);                   /* 用新地址/口令重建（修 P2-22：旧 host/port 不再被闭包固化） */
    }
    return true;
  });

  handle('dev:stats', async (_, id) => {
    const key = String(id || '');
    const c = await onlineClient(key, 5000);
    return await c.stats(8000);
  });

  handle('dev:search', async (_, a, b) => {
    const { id, params } = normIdParams(a, b);
    if (!id) throw new HC.HamsterError('missing_id', 'id 必填');
    const c = await onlineClient(id, 5000);
    const r = await c.search(params, 30000);
    return Object.assign({}, r, {
      files: r.files.map((f) => ({
        hash: f.hash || '', name: f.name || '', path: f.path || '',
        type: f.type || '', size: Number(f.size) || 0, modified: f.modified || '',
        /* 旧渲染层字段别名 */
        file_path: f.path || '', mtime: f.modified || '',
      })),
    });
  });

  handle('dev:search_many', async (_, ids, params) => {
    const list = Array.isArray(ids) ? ids : [];
    const results = new Array(list.length);
    let next = 0;
    const worker = async () => {
      for (;;) {
        const i = next++;
        if (i >= list.length) return;
        const id = String(list[i] || '');
        try {
          const c = await onlineClient(id, 5000);
          const r = await c.search(params, 30000);
          results[i] = { id, ok: true, data: r };
        } catch (e) {
          results[i] = Object.assign({ id, ok: false }, HC.toErrorResult(e));
        }
      }
    };
    await Promise.all(Array.from({ length: Math.max(1, Math.min(4, list.length)) }, worker));
    return results;
  });

  handle('dev:download', async (_, a, b) => {
    let id, remotePath;
    if (a && typeof a === 'object') { id = String(a.id || ''); remotePath = a.path || a.filepath || a.file_path || ''; }
    else { id = String(a || ''); remotePath = b; }
    if (!remotePath) throw new HC.HamsterError('missing_path', 'path 必填');
    const c = await onlineClient(id, 5000);
    const r = await c.download(String(remotePath), { destDir: downloadDir() });
    logger.info('[ipc] 下载完成 ' + r.saved_path + ' (' + r.size + ' 字节, hash=' + r.hash + ')');
    return { ok: true, saved_path: r.saved_path, name: r.name, size: r.size, hash: r.hash };
  });

  handle('dev:sync_db', async (_, id) => {
    const key = String(id || '');
    const c = await onlineClient(key, 5000);
    /* 目录归属校验：id 已过白名单，再 resolve 一次确保落点就在 devices/ 内（修 P0-7） */
    HC.ensureDir(DEVICES_DIR);
    const dest = HC.resolveInside(DEVICES_DIR, key + '.db');
    const r = await c.syncDatabase({ destFile: dest });
    logger.info('[ipc] 数据库已同步 ' + r.path + ' (' + r.size + ' 字节)');
    return { ok: true, path: r.path, size: r.size };
  });

  handle('dev:sync', async (_, id) => {
    const key = String(id || '');
    const c = await onlineClient(key, 5000);
    const st = await c.stats(8000);
    store.applyStatusBatch([{ id: key, status: 'online', last_sync: new Date().toISOString() }]);
    return { ok: true, stats: st };
  });

  handle('dev:verify', async (_, id, params) => {
    const key = String(id || '');
    const c = await onlineClient(key, 5000);
    return await c.verify(params || {}, 60000);
  });

  /* ---------------- 文件操作（§6.2） ---------------- */
  handle('file:list', async (_, a, b, c2, d2) => {
    let id, p, limit, offset;
    if (a && typeof a === 'object') {
      id = String(a.id || ''); p = a.path; limit = a.limit; offset = a.offset;
    } else { id = String(a || ''); p = b; limit = c2; offset = d2; }
    const c = await onlineClient(id, 5000);
    const r = await c.list(p, limit, offset);
    return Object.assign({}, r, {
      entries: r.entries.map((e) => ({
        name: e.name || '', path: e.path || '', dir: !!e.dir,
        size: Number(e.size) || 0, mtime: Number(e.mtime) || 0,
        is_dir: !!e.dir,                       /* 渲染层别名 */
      })),
    });
  });

  handle('file:mkdir', async (_, idOrObj, maybePath) => {
    const id = (idOrObj && typeof idOrObj === 'object') ? String(idOrObj.id || '') : String(idOrObj || '');
    const p = (idOrObj && typeof idOrObj === 'object') ? idOrObj.path : maybePath;
    const c = await onlineClient(id, 5000);
    return await c.mkdir(p);
  });

  handle('file:delete', async (_, idOrObj, maybePath) => {
    const id = (idOrObj && typeof idOrObj === 'object') ? String(idOrObj.id || '') : String(idOrObj || '');
    const p = (idOrObj && typeof idOrObj === 'object') ? idOrObj.path : maybePath;
    const c = await onlineClient(id, 5000);
    return await c.remove(p);                  /* confirm:true 由客户端补上，渲染层拿不到这个开关 */
  });

  handle('file:upload', async (_, id, localPath, remotePath, opts) => {
    const key = String(id || '');
    const o = (opts && typeof opts === 'object') ? opts : {};
    const c = await onlineClient(key, 5000);
    if (localPath && fs.existsSync(String(localPath))) {
      return await c.upload({
        localPath: String(localPath),
        remotePath: remotePath,
        hash: o.hash, overwrite: !!o.overwrite, mkdir: o.mkdir !== false,
      });
    }
    if (o.base64) {
      const buf = Buffer.from(String(o.base64), 'base64');
      return await c.uploadBuffer(buf, remotePath, {
        hash: o.hash, overwrite: !!o.overwrite, mkdir: o.mkdir !== false,
        tmpDir: TMP_DIR, fileName: o.name,
      });
    }
    throw new HC.HamsterError('file_not_found', String(localPath || ''));
  });

  /* ---------------- 迁移（§6.2） ---------------- */
  handle('migrate:run', async (_, job) => {
    const r = await migrator.run(job || {});
    notify('event:broadcast', { type: 'migrate_done', event: 'migrate_done', data: r, device: '', device_id: '' });
    return r;
  });

  handle('migrate:run_many', async (_, jobs) => await migrator.runMany(jobs));

  handle('migrate:list', () => migLog.list(200));

  /* ---------------- 局域网发现（§6.1 / §7） ---------------- */
  handle('discover:list', () => (discovery ? discovery.list() : []));

  /* ---------------- 控制指令 ---------------- */
  handle('ctrl:send', async (_, id, action) => {
    const a = String(action || '');
    if (a !== 'rescan' && a !== 'sync') throw new HC.HamsterError('unknown_action', a);
    const c = await onlineClient(String(id || ''), 5000);
    return a === 'rescan' ? await c.rescan() : await c.sync();
  });

  /* ---------------- 配置与系统 ---------------- */
  handle('config:get', () => ({
    hamd_port: cfg.hamd_port,
    ipc_port: cfg.ipc_port,
    discovery_port: cfg.discovery_port,
    heartbeat_time: cfg.heartbeat_time,
    codeword: cfg.codeword ? '(已设置)' : '(未设置)',
    codeword_source: cfg.codeword_source,
    log_level: logger.level,
    conf_path: cfg.conf_path,
    daemon_conf_path: cfg.daemon_conf_path,
    downloads_dir: downloadDir(),
    devices_file: DEVICES_JSON,
    migrations_file: MIGRATIONS_JSON,
    log_file: LOG_FILE,
    warnings: cfg.warnings,
  }));

  handle('config:set', (_, c) => {
    const o = (c && typeof c === 'object') ? c : {};
    if (o.download_dir) { cfg.download_dir = String(o.download_dir); HC.ensureDir(cfg.download_dir); }
    if (o.log_level) logger.info('[ipc] 日志级别切换请求: ' + o.log_level + '（当前进程仅记录，重启后生效）');
    return true;
  });

  handle('app:version', () => app.getVersion());
  handle('app:paths', () => ({
    downloads: downloadDir(),
    devices: DEVICES_DIR,
    devices_file: DEVICES_JSON,
    user_data: USER_DATA,
    logs: LOG_DIR,
    log_file: LOG_FILE,
    migrations_file: MIGRATIONS_JSON,
    manager: MANAGER_DIR,
    ui: UI_DIR,
  }));
  handle('app:downloads-dir', () => downloadDir());

  /**
   * 在文件管理器里定位文件（下载完成后"打开所在文件夹"）。
   * 返回：{ok:true, path} | {ok:false, error:'missing_path'|'not_found', detail?}
   * 约束：文件不存在时**不抛异常**，只回错误对象（渲染层据此提示）。
   */
  handle('app:reveal', (_, p) => {
    const target = String(p === undefined || p === null ? '' : p).trim();
    if (!target) return { ok: false, error: 'missing_path' };
    let abs;
    try { abs = path.resolve(target); } catch (_) { return { ok: false, error: 'missing_path', detail: target }; }
    let st = null;
    try { st = fs.statSync(abs); } catch (_) { st = null; }
    if (!st) return { ok: false, error: 'not_found', detail: abs };
    /* 选中目录本身时打开它，选中文件时在父目录里高亮该文件 */
    if (st.isDirectory()) shell.openPath(abs);
    else shell.showItemInFolder(abs);
    logger.info('[ipc] reveal ' + abs);
    return { ok: true, path: abs };
  });

  /**
   * 复制文本到系统剪贴板（file:// 下 navigator.clipboard 不可靠，故走主进程）。
   * 返回：{ok:true, length} | {ok:false, error:'missing_text'}
   */
  handle('app:copy-text', (_, text) => {
    const s = (text === undefined || text === null) ? '' : String(text);
    if (!s) return { ok: false, error: 'missing_text' };
    clipboard.writeText(s);
    return { ok: true, length: s.length };
  });

  handle('dialog:pick-folder', async () => {
    const r = await dialog.showOpenDialog(win || undefined, { properties: ['openDirectory'] });
    return r.canceled ? null : r.filePaths[0];
  });

  /* ---------------- 窗口 ---------------- */
  ipcMain.on('window-minimize', () => { if (win && !win.isDestroyed()) win.minimize(); });
  ipcMain.on('window-maximize', () => {
    if (!win || win.isDestroyed()) return;
    if (win.isMaximized()) win.unmaximize(); else win.maximize();
    win.webContents.send('window-maximize-change', win.isMaximized());
  });
  ipcMain.on('window-close', () => { if (win && !win.isDestroyed()) win.close(); });
  handle('window-is-maximized', () => (win && !win.isDestroyed()) ? win.isMaximized() : false);
}

/* ==========================================================================
 * 窗口
 * ========================================================================== */
function createWindow() {
  win = new BrowserWindow({
    width: 1024, height: 720, minWidth: 800, minHeight: 600,
    frame: false, backgroundColor: '#f0f4f8', show: false,
    webPreferences: {
      preload: PRELOAD_PATH,
      contextIsolation: true,
      nodeIntegration: false,
    },
    title: 'Hamster Manager',
  });
  win.loadFile(path.join(UI_DIR, '_html', 'hamster_manager.html'));
  win.once('ready-to-show', () => { if (win && !win.isDestroyed()) win.show(); });
  win.on('closed', () => { win = null; });
  return win;
}

/* ==========================================================================
 * 心跳（把"最近一次收到事件的时间"暴露给渲染层，用于发现半开连接）
 * ========================================================================== */
function startHeartbeatTicker() {
  if (heartbeatTimer) clearTracked(heartbeatTimer);
  heartbeatTimer = trackSetInterval(() => {
    if (!win || win.isDestroyed()) return;
    for (const [id, c] of clients) {
      notify('event:heartbeat', {
        device: c.name, device_id: id,
        age_ms: c.eventAgeMs(),
        connected: c.eventsConnected,
      });
    }
  }, 5000);
}

/* ==========================================================================
 * 生命周期
 * ========================================================================== */
async function bootstrap() {
  logger.info('Hamster Manager 启动 version=' + app.getVersion() + ' platform=' + process.platform +
    ' electron=' + process.versions.electron + ' node=' + process.versions.node);
  for (const w of cfg.warnings) logger.warn('[cfg] ' + w);
  logger.info('[cfg] hamd_port=' + cfg.hamd_port + ' ipc_port=' + cfg.ipc_port +
    ' codeword=' + (cfg.codeword ? '(已设置，来源 ' + cfg.codeword_source + ')' : '(未设置)') +
    ' conf=' + cfg.conf_path);

  store = new HC.DeviceStore({ file: DEVICES_JSON, logger });
  store.load();
  for (const d of store.raw()) if (d.token) logger.addSecret(d.token);

  HC.ensureDir(TMP_DIR);
  migLog = new HC.MigrationLog({ file: MIGRATIONS_JSON, logger, limit: 500 });
  migrator = new HC.Migrator({
    getClient: (id) => onlineClient(id, 10000),
    tmpDir: TMP_DIR,
    log: migLog,
    logger,
    concurrency: 2,
  });

  registerIpc();
  createWindow();
  startHeartbeatTicker();
  startEventsForAll();
  startDiscovery();

  await ensureProxy();
  connectIpcProxy();

  logger.info('初始化完成：设备 ' + store.list().length + ' 台，下载目录 ' + downloadDir() +
    '，迁移日志 ' + MIGRATIONS_JSON);
}

/**
 * 统一退出清理：事件 socket / 重连定时器 / IPC socket / 代理子进程 / 全部定时器。
 * 幂等，可被 before-quit、window-all-closed、will-quit 多次调用。
 */
function shutdown(reason) {
  if (shuttingDown) return;
  shuttingDown = true;
  logger.info('开始关闭（触发者: ' + (reason || 'unknown') + '）');
  for (const h of Array.from(ownedTimers)) clearTracked(h);
  heartbeatTimer = null;
  ipcRetryTimer = null;
  if (discovery) { try { discovery.stop(); } catch (_) {} discovery = null; }
  for (const [id, c] of clients) {
    try { c.close('shutdown'); } catch (e) { logger.warn('关闭 ' + id + ' 失败: ' + e.message); }
  }
  clients.clear();
  if (ipcSock) { try { ipcSock.destroy(); } catch (_) {} ipcSock = null; }
  if (proxyChild) {
    try {
      logger.info('结束代理子进程 pid=' + proxyChild.pid);
      proxyChild.removeAllListeners('exit');
      proxyChild.kill();
    } catch (e) {
      logger.warn('结束代理失败: ' + e.message);
    }
    proxyChild = null;
  }
  logger.info('已关闭设备事件 socket、IPC socket、定时器与代理子进程');
  logger.close();
}

process.on('uncaughtException', (e) => {
  try { logger.error('未捕获异常: ' + ((e && e.stack) || e)); } catch (_) {}
});
process.on('unhandledRejection', (r) => {
  try { logger.error('未处理的 Promise 拒绝: ' + ((r && r.stack) || r)); } catch (_) {}
});

app.on('before-quit', () => shutdown('before-quit'));
app.on('will-quit', () => shutdown('will-quit'));
app.on('window-all-closed', () => {
  shutdown('window-all-closed');
  if (process.platform !== 'darwin') app.quit();
});

app.whenReady()
  .then(bootstrap)
  .catch((e) => {
    logger.error('启动失败: ' + ((e && e.stack) || e));
    shutdown('bootstrap failed');
    app.quit();
  });
