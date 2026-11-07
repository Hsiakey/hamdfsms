/*
 * tests/protocol-secure.js — 加密路径上的协议一致性（PROTOCOL §1/§3/§4 + §8）
 *
 * 为什么要有这一套：
 *   integration.ps1 用 PowerShell 手写明文客户端，覆盖不到 §8；
 *   sec-live.js 验证的是"能不能互通"，不覆盖协议边角。
 *   这里用真实 client 库 + 真守护进程，在**加密连接上**逐条检查 0.0.8 的命令语义
 *   是否原样保留 —— 记录层只是把字节流切块加密，上层语义一行都没变。
 *
 * 覆盖：
 *   1. 单行超长：报 line_too_long 后连接仍可继续使用（服务端要跨多条记录读完整行）
 *   2. 非法 JSON / 缺 action / 未知 action
 *   3. 同一连接上的请求流水线（3 个请求连发，按 id 配对）
 *   4. 上传：hash 不符 → hash_mismatch 且不留半成品；size 与 payload_bytes 不符 → bad_size
 *   5. 下载：文件不存在 / 路径穿越 → 对应的机器码
 *   6. 删除：缺 confirm → confirm_required
 *   7. 事件通道也走加密：上传后事件通道收到 file_added
 *
 * 运行前必须停掉正在运行的 hamsterd（单实例互斥锁是机器级的）：
 *   node tests/protocol-secure.js
 */
'use strict';

const fs = require('fs');
const net = require('net');
const path = require('path');
const { spawn } = require('child_process');

const ROOT = path.join(__dirname, '..');
const A = require(path.join(ROOT, 'Hamster Manager', 'module', 'shared', 'hamster-aead.js'));
const HC = require(path.join(ROOT, 'Hamster Manager', 'module', 'shared', 'hamster-client.js'));

const PORT = 19305;
const CODEWORD = 'test-sec-proto-' + 'c'.repeat(16);
const TMP = path.join(__dirname, 'tmp', 'protocol-secure');
const BIN_DIR = path.join(TMP, 'bin');
const MON_DIR = path.join(TMP, 'monitor');
const EXE_SRC = path.join(ROOT, 'Hamsterd', 'hamsterd.exe');
const EXE = path.join(BIN_DIR, 'hamsterd.exe');

const procs = [];
let pass = 0;
let fail = 0;

function check(cond, name, detail) {
  if (cond) { pass += 1; console.log('  \u2713 ' + name); }
  else { fail += 1; console.log('  \u2717 ' + name + (detail === undefined ? '' : '  \u2192 ' + detail)); }
  return !!cond;
}
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }
function rmrf(p) { try { fs.rmSync(p, { recursive: true, force: true }); } catch (_) {} }
function mkdirp(p) { fs.mkdirSync(p, { recursive: true }); }

function prepare() {
  rmrf(TMP);
  mkdirp(BIN_DIR);
  mkdirp(MON_DIR);
  fs.writeFileSync(path.join(MON_DIR, 'keep.txt'), 'protocol-secure', 'utf8');
  fs.copyFileSync(EXE_SRC, EXE);
  const dll = path.join(ROOT, 'Hamsterd', 'sqlite3.dll');
  if (fs.existsSync(dll)) fs.copyFileSync(dll, path.join(BIN_DIR, 'sqlite3.dll'));

  fs.writeFileSync(path.join(BIN_DIR, 'hamsterd.conf'), [
    'monitor_path: ' + MON_DIR,
    'ipv4_addr: 127.0.0.1',
    'ipv4_addr_port: ' + PORT,
    'codeword: ' + CODEWORD,
    'require_auth: on',
    'allow_loopback_noauth: off',
    'encrypt_transport: on',
    'max_transfer_mb: 64',
    'max_clients: 8',
    'rescan_date: 0,0,0',
    'verify_interval: 0',
    'discovery_port: 0',
    'heartbeat_time: 1',
    'log_level: debug',
    'log_dir: logs',
    'exclude_internal: on',
    '',
  ].join('\n'), 'utf8');
}

function startDaemon() {
  const p = spawn(EXE, ['--console-log'], { cwd: BIN_DIR, stdio: 'ignore', windowsHide: true });
  procs.push(p);
  return p;
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

/* ------------------------------------------------------- 加密连接的小客户端 */
function mkClient(t) {
  let buf = Buffer.alloc(0);
  let seq = 0;
  let closed = false;
  const events = [];

  t.on('data', (b) => { buf = Buffer.concat([buf, b]); });
  t.on('close', () => { closed = true; });

  async function waitFor(pred, ms, what) {
    const t0 = Date.now();
    while (Date.now() - t0 < (ms || 8000)) {
      if (pred()) return true;
      await sleep(10);
    }
    throw new Error('等待超时: ' + (what || '?') + '（已收 ' + buf.length + ' 字节）');
  }

  async function readLine() {
    await waitFor(() => buf.indexOf(0x0a) >= 0, 8000, '响应行');
    const i = buf.indexOf(0x0a);
    const line = buf.subarray(0, i).toString('utf8');
    buf = buf.subarray(i + 1);
    return line;
  }

  async function readResponse(id) {
    for (;;) {
      const m = JSON.parse(await readLine());
      if (m.type === 'event') { events.push(m); continue; }
      if (id && m.id !== id) throw new Error('响应 id 不匹配: ' + m.id + ' != ' + id);
      return m;
    }
  }

  return {
    events,
    get closed() { return closed; },
    send: (obj) => t.write(JSON.stringify(obj) + '\n'),
    /** 直接发一段裸字节（用于构造非法输入） */
    sendRaw: (bytes) => t.write(bytes),
    request: async (action, params) => {
      const id = 't' + (++seq);
      const body = { type: 'request', id, action };
      if (params !== undefined) body.params = params;
      t.write(JSON.stringify(body) + '\n');
      return readResponse(id);
    },
    /** 发请求头 + 裸负载，再等响应 */
    requestWithPayload: async (action, params, payload) => {
      const id = 't' + (++seq);
      t.write(JSON.stringify({ type: 'request', id, action, params: params || {}, payload_bytes: payload.length }) + '\n');
      t.write(payload);
      return readResponse(id);
    },
    /** 只发头（payload_bytes 由调用方在 params 里另行声明），再等响应 */
    sendHeader: async (id, action, params, payloadBytes) => {
      const body = { type: 'request', id, action, params: params || {} };
      if (payloadBytes !== undefined) body.payload_bytes = payloadBytes;
      t.write(JSON.stringify(body) + '\n');
    },
    readResponse,
    waitFor,
  };
}

async function openClient(deviceId) {
  const t = await A.AeadTransport.connect({
    port: PORT, secret: CODEWORD, deviceId: deviceId || 'dev_1700000000000',
    hostname: 'protocol-secure', timeoutMs: 5000,
  });
  return { t, c: mkClient(t) };
}

/* ------------------------------------------------------------------ 用例 */
async function caseLineTooLong() {
  console.log('\n[1] 单行超长（跨多条记录读一行）');
  const { t, c } = await openClient();
  /* 构造 > 256 KiB 的单行：记录层会切成 5 条 64 KiB 记录，服务端必须能读完整行 */
  const big = '{"type":"request","id":"big","action":"ping","params":{"x":"' + 'a'.repeat(300 * 1024) + '"}}';
  c.sendRaw(big + '\n');
  /* 服务端的 line_too_long 响应不带 id（它在读整行时就已判定） */
  const r = await c.readResponse(null);
  check(r.status === 'error' && r.data && r.data.error === 'line_too_long',
    '超长行报 line_too_long', JSON.stringify(r.data).slice(0, 120));

  const pong = await c.request('ping');
  check(pong.status === 'ok' && pong.data.pong === true, '超长行之后连接仍可使用');
  t.destroy();
  await sleep(100);
}

async function caseBadJson() {
  console.log('\n[2] 非法输入');
  const { t, c } = await openClient();

  c.sendRaw('这不是 JSON\n');
  const r1 = await c.readResponse('');
  check(r1.status === 'error' && r1.data.error === 'malformed_json', '非法 JSON → malformed_json',
    JSON.stringify(r1.data).slice(0, 120));

  c.sendRaw('{"type":"request","id":"noact"}\n');
  const r2 = await c.readResponse('noact');
  check(r2.status === 'error' && r2.data.error === 'missing_action', '缺 action → missing_action');

  const r3 = await c.request('definitely-not-an-action');
  check(r3.status === 'error' && r3.data.error === 'unknown_action', '未知 action → unknown_action');

  const pong = await c.request('ping');
  check(pong.status === 'ok', '以上错误都没有打断连接');
  t.destroy();
  await sleep(100);
}

async function casePipelining() {
  console.log('\n[3] 同一连接上的流水线请求');
  const { t, c } = await openClient();
  const ids = ['p-a', 'p-b', 'p-c'];
  for (const id of ids) {
    c.sendHeader(id, 'ping');
  }
  const got = [];
  for (let i = 0; i < ids.length; i += 1) got.push(await c.readResponse(null));
  const gotIds = got.map((m) => m.id).sort();
  check(gotIds.join(',') === ids.slice().sort().join(','), '3 个请求都按 id 配对返回', gotIds.join(','));
  check(got.every((m) => m.status === 'ok' && m.data.pong === true), '3 个都是合法 ping 响应');
  t.destroy();
  await sleep(100);
}

async function caseUpload() {
  console.log('\n[4] 上传的拒绝路径');
  const { t, c } = await openClient();

  /* hash 不符：服务端必须删除半成品 */
  const payload = Buffer.alloc(4096, 0x41);
  const bad = await c.requestWithPayload('upload',
    { path: 'bad-hash.bin', size: payload.length, hash: '0'.repeat(32), overwrite: true }, payload);
  check(bad.status === 'error' && bad.data.error === 'hash_mismatch', 'hash 不符 → hash_mismatch',
    JSON.stringify(bad.data).slice(0, 120));
  const leftovers = fs.readdirSync(MON_DIR).filter((f) => f.indexOf('.part-') >= 0);
  check(leftovers.length === 0, 'hash 不符时不留半成品', leftovers.join(','));

  /* size 与 payload_bytes 不符 */
  const body = { type: 'request', id: 'size-bad', action: 'upload',
    params: { path: 'size-bad.bin', size: 10 }, payload_bytes: 20 };
  t.write(JSON.stringify(body) + '\n');
  t.write(Buffer.alloc(20, 0x42));
  const sizeBad = await c.readResponse('size-bad');
  check(sizeBad.status === 'error' && sizeBad.data.error === 'bad_size', 'size≠payload_bytes → bad_size');

  /* 正常上传（验证加密下的负载分帧仍然正确） */
  const ok = await c.requestWithPayload('upload',
    { path: 'ok.bin', size: payload.length, overwrite: true }, payload);
  check(ok.status === 'ok', '正常上传成功');
  const onDisk = path.join(MON_DIR, 'ok.bin');
  check(fs.existsSync(onDisk) && fs.readFileSync(onDisk).equals(payload), '落盘内容一致');
  t.destroy();
  await sleep(100);
}

async function caseDownloadErrors() {
  console.log('\n[5] 下载与路径安全');
  const { t, c } = await openClient();

  const missing = await c.request('download', { path: 'no-such-file.bin' });
  check(missing.status === 'error' && missing.data.error === 'file_not_found',
    '文件不存在 → file_not_found', JSON.stringify(missing.data).slice(0, 120));

  const escape = await c.request('download', { path: '../../../windows/win.ini' });
  check(escape.status === 'error' && escape.data.error === 'path_denied',
    '路径穿越 → path_denied', JSON.stringify(escape.data).slice(0, 120));
  t.destroy();
  await sleep(100);
}

async function caseDeleteConfirm() {
  console.log('\n[6] 删除必须显式确认');
  const { t, c } = await openClient();
  const r = await c.request('delete', { path: 'keep.txt' });
  check(r.status === 'error' && r.data.error === 'confirm_required', '缺 confirm → confirm_required');
  check(fs.existsSync(path.join(MON_DIR, 'keep.txt')), '文件没有被删除');

  const del = await c.request('delete', { path: 'keep.txt', confirm: true });
  check(del.status === 'ok', '带 confirm 的删除成功');
  check(!fs.existsSync(path.join(MON_DIR, 'keep.txt')), '文件确实被删除');
  t.destroy();
  await sleep(100);
}

async function caseEventChannel() {
  console.log('\n[7] 事件通道也走加密');
  const noop = () => {};
  const log = { info: noop, warn: noop, error: noop, debug: noop };
  const ev = new HC.EventClient({
    host: '127.0.0.1', port: PORT, codeword: CODEWORD, deviceId: 'dev_evt_test',
    hostname: 'evt', encrypt: true, logger: log, label: 'evt-test', keepAliveMs: 30000,
  });
  const seen = [];
  ev.onEvent = (msg) => { seen.push(msg); };
  ev.start();
  try {
    for (let i = 0; i < 40 && !ev.connected; i += 1) await sleep(100);
    check(ev.connected === true, '加密的事件通道已连接');

    const { t, c } = await openClient('dev_writer');
    const payload = Buffer.alloc(1024, 0x5a);
    const up = await c.requestWithPayload('upload', { path: 'evt.bin', size: payload.length, overwrite: true }, payload);
    check(up.status === 'ok', '触发一次上传');

    for (let i = 0; i < 50 && !seen.some((m) => m.event === 'file_added'); i += 1) await sleep(100);
    check(seen.some((m) => m.event === 'file_added'), '收到 file_added 事件（密文通道）',
      seen.map((m) => m.event).join(',') || '(无事件)');
    t.destroy();
  } finally {
    ev.stop();
  }
}

/* ------------------------------------------------------------------ main */
(async () => {
  prepare();
  const p = startDaemon();
  const ready = await waitTcp(PORT);
  if (!ready) {
    const log = path.join(BIN_DIR, 'logs', 'hamsterd.log');
    if (fs.existsSync(log)) {
      console.log('  日志尾部：');
      for (const line of fs.readFileSync(log, 'utf8').split('\n').slice(-20)) console.log('    ' + line);
    }
    throw new Error('daemon not ready（单实例互斥锁是机器级的：请先停掉正在运行的 hamsterd）');
  }

  await caseLineTooLong();
  await caseBadJson();
  await casePipelining();
  await caseUpload();
  await caseDownloadErrors();
  await caseDeleteConfirm();
  await caseEventChannel();

  console.log('\n=== 结果: 通过 ' + pass + ', 失败 ' + fail + ' ===');
  await stopDaemon(p);
  process.exit(fail === 0 ? 0 : 1);
})().catch(async (e) => {
  console.error('\n测试异常: ' + ((e && e.stack) || e));
  await Promise.all(procs.map(stopDaemon));
  process.exit(1);
});
