/*
 * tests/sec-live.js — 传输加密（PROTOCOL §8）的端到端互通测试：C 守护进程 ⇄ JS 客户端
 *
 * 这个测试是"两份独立实现是否真的对得上"的唯一硬证据：
 *   · 密钥派生：C 侧 hd_sec.c，JS 侧 hamster-aead.js
 *   · 记录层：C 侧 hd_sec_seal/open + rd_fill_sec，JS 侧 RecordSealer/Opener
 *   · 握手：C 侧 sec_handshake，JS 侧 AeadTransport.connect
 * 上面的单测只能证明各自的实现自洽，只有这里能证明两端逐字节一致。
 *
 * 覆盖：
 *   1. 正确口令 → 握手成功，ping/info 走密文
 *   2. info 的 features 里有 framing:aead
 *   3. hello 动作已取消（§8.4）
 *   4. 错误口令 → 握手失败，连接被静默关闭，没收到任何错误对象
 *   5. 老客户端（直接发明文 hello）→ 被静默关闭
 *   6. 握手之后混入明文 → 连接被关闭
 *   7. 下载 > 64 KiB（触发多记录）
 *   8. 上传 > 64 KiB（触发多记录）并回读校验
 *   9. sync-database 的密文下载仍是合法 SQLite 文件
 *
 * 运行前必须停掉正在运行的 hamsterd（单实例互斥锁是机器级的）：
 *   node tests/sec-live.js
 */
'use strict';

const fs = require('fs');
const net = require('net');
const path = require('path');
const { spawn } = require('child_process');

const ROOT = path.join(__dirname, '..');
const A = require(path.join(ROOT, 'Hamster Manager', 'module', 'shared', 'hamster-aead.js'));

const PORT = 19303;
const IPC_PORT = 19304;
const CODEWORD = 'test-sec-codeword-' + 'b'.repeat(16);
const TMP = path.join(__dirname, 'tmp', 'sec-live');
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

/* ------------------------------------------------------------ 环境 */
function prepare() {
  rmrf(TMP);
  mkdirp(BIN_DIR);
  mkdirp(MON_DIR);
  fs.writeFileSync(path.join(MON_DIR, 'hello.txt'), 'sec-live test', 'utf8');
  /* 200 KiB：必然跨多条 64 KiB 记录 */
  fs.writeFileSync(path.join(MON_DIR, 'big.bin'), Buffer.alloc(200 * 1024, 0x5a));

  fs.copyFileSync(EXE_SRC, EXE);
  const dll = path.join(ROOT, 'Hamsterd', 'sqlite3.dll');
  if (fs.existsSync(dll)) fs.copyFileSync(dll, path.join(BIN_DIR, 'sqlite3.dll'));

  const conf = [
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
  ].join('\n');
  fs.writeFileSync(path.join(BIN_DIR, 'hamsterd.conf'), conf, 'utf8');
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

/* ------------------------------------------------ 加密连接的请求/响应小工具 */
function mkClient(t, onClose) {
  let buf = Buffer.alloc(0);
  let seq = 0;
  const events = [];
  let closed = false;

  if (onClose) onClose(() => { closed = true; });

  const feed = (b) => { buf = Buffer.concat([buf, b]); };

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

  async function readN(n) {
    await waitFor(() => buf.length >= n, 30000, n + ' 字节负载');
    const out = buf.subarray(0, n);
    buf = buf.subarray(n);
    return out;
  }

  async function readResponse(id) {
    for (;;) {
      const line = await readLine();
      const m = JSON.parse(line);
      if (m.type === 'event') { events.push(m); continue; }
      if (m.type !== 'response') throw new Error('意外的消息类型: ' + line.slice(0, 160));
      if (id && m.id !== id) throw new Error('id 不匹配: ' + m.id + ' != ' + id);
      return m;
    }
  }

  return {
    events,
    get closed() { return closed; },
    feed,
    request: async (action, params) => {
      const id = 't' + (++seq);
      const body = { type: 'request', id, action };
      if (params) body.params = params;
      t.write(JSON.stringify(body) + '\n');
      return readResponse(id);
    },
    /** 带裸负载的请求：先头后负载，再等响应 */
    requestWithPayload: async (action, params, payload) => {
      const id = 't' + (++seq);
      const body = { type: 'request', id, action, params: params || {}, payload_bytes: payload.length };
      t.write(JSON.stringify(body) + '\n');
      t.write(payload);
      return readResponse(id);
    },
    /** 只发头、等响应（响应的开销就是回复），用于 download */
    requestHeader: async (action, params) => {
      const id = 't' + (++seq);
      t.write(JSON.stringify({ type: 'request', id, action, params: params || {} }) + '\n');
      return readResponse(id);
    },
    readN,
    waitFor,
  };
}

async function encryptedClient(secret, opts) {
  const o = opts || {};
  let closeCb = null;
  const t = await A.AeadTransport.connect({
    port: PORT,
    secret: secret === undefined ? CODEWORD : secret,
    deviceId: o.deviceId || 'dev_1700000000000',
    hostname: 'sec-live-test',
    timeoutMs: o.timeoutMs || 4000,
    onData: (b) => { if (o.onData) o.onData(b); },
  });
  const cli = mkClient(t, (cb) => { closeCb = cb; });
  t.on('data', (b) => cli.feed(b));
  t.on('close', () => { if (closeCb) closeCb(); });
  return { t, cli };
}

/* ------------------------------------------------------------ 用例 */
async function caseHandshake() {
  console.log('\n[1] 握手 + ping/info');
  const { t, cli } = await encryptedClient();
  check(t.ready === true, '握手成功（proof_S 已验证）');
  check(/^\d+\.\d+\.\d+$/.test(String(t.peer && t.peer.version)),
    '服务端在挑战包里报了版本', t.peer && t.peer.version);

  const r = await cli.request('ping');
  check(r.status === 'ok' && r.data && r.data.pong === true, 'ping 走密文返回 pong');

  const info = await cli.request('info');
  const feats = (info.data && info.data.features) || [];
  check(info.status === 'ok', 'info 成功');
  check(feats.indexOf('framing:aead') >= 0, 'features 含 framing:aead', JSON.stringify(feats));
  check(feats.indexOf('framing:raw') >= 0, 'features 仍含 framing:raw（负载编码未变）');

  const hello = await cli.request('hello', { codeword: CODEWORD, device_id: 'dev_1700000000000' });
  check(hello.status === 'error' && hello.data && hello.data.error === 'unknown_action',
    'hello 动作已取消（§8.4）', JSON.stringify(hello.data));

  t.destroy();
  await sleep(100);
}

async function caseWrongCodeword() {
  console.log('\n[2] 错误口令 / 老客户端');
  let rejected = null;
  try {
    const t = await A.AeadTransport.connect({
      port: PORT, secret: 'wrong-codeword', deviceId: 'dev_1700000000000', timeoutMs: 3000,
    });
    t.destroy();
  } catch (e) { rejected = e; }
  check(!!rejected, '错误口令 → 连接被拒', rejected && rejected.code);

  /* 老客户端：直接发明文 hello，守护进程应该一声不响地断开 */
  const legacy = await new Promise((resolve) => {
    const s = net.connect({ host: '127.0.0.1', port: PORT }, () => {
      s.write(JSON.stringify({ type: 'request', id: '1', action: 'hello',
        params: { codeword: CODEWORD, device_id: 'dev_old' } }) + '\n');
    });
    let got = 0;
    s.on('data', (b) => { got += b.length; });
    s.on('close', () => resolve({ got }));
    s.on('error', () => resolve({ got, err: true }));
    setTimeout(() => { try { s.destroy(); } catch (_) {} resolve({ got, timeout: true }); }, 3000);
  });
  check(!legacy.timeout, '明文 hello → 连接被关闭');
  check(legacy.got === 0, '明文 hello 没换回任何字节（静默丢弃）', legacy.got + ' 字节');
}

async function casePlaintextAfterHandshake() {
  console.log('\n[3] 握手后混入明文');
  const { t } = await encryptedClient();
  let closed = false;
  t.on('close', () => { closed = true; });
  /* 直接往底层 socket 写明文：记录层会把它当成一条长度离谱的记录 */
  t._sock.write(Buffer.from('{"type":"response","id":"x"}\n'));
  await sleep(600);
  check(closed === true, '握手后的明文输入 → 连接被关闭');
  try { t.destroy(); } catch (_) {}
}

async function caseDownloadBig() {
  console.log('\n[4] 下载 200 KiB（跨多条记录）');
  const { t, cli } = await encryptedClient();
  const resp = await cli.requestHeader('download', { path: 'big.bin' });
  check(resp.status === 'ok', 'download 请求成功', JSON.stringify(resp.data).slice(0, 120));
  const n = resp.data && resp.data.payload_bytes;
  check(n === 200 * 1024, 'payload_bytes = 204800', String(n));
  const body = await cli.readN(n);
  const want = fs.readFileSync(path.join(MON_DIR, 'big.bin'));
  check(body.equals(want), '下载字节与源文件一致');
  t.destroy();
  await sleep(100);
}

async function caseUploadBig() {
  console.log('\n[5] 上传 150 KiB（跨多条记录）');
  const { t, cli } = await encryptedClient();
  const payload = Buffer.alloc(150 * 1024, 0x77);
  const resp = await cli.requestWithPayload('upload',
    { path: 'up-150k.bin', size: payload.length, overwrite: true }, payload);
  check(resp.status === 'ok', '上传成功', JSON.stringify(resp.data).slice(0, 160));

  const onDisk = path.join(MON_DIR, 'up-150k.bin');
  check(fs.existsSync(onDisk), '服务端落盘');
  if (fs.existsSync(onDisk)) {
    check(fs.readFileSync(onDisk).equals(payload), '落盘内容与上传字节一致');
  }

  /* 回读一遍，确认"上行加密"和"下行加密"各自独立计数都正确 */
  const back = await cli.requestHeader('download', { path: 'up-150k.bin' });
  check(back.status === 'ok', '回读请求成功');
  const body = await cli.readN(back.data.payload_bytes);
  check(body.equals(payload), '回读内容与上传一致');
  t.destroy();
  await sleep(100);
}

async function caseSyncDatabase() {
  console.log('\n[6] sync-database 密文传输');
  const { t, cli } = await encryptedClient();
  const resp = await cli.requestHeader('sync-database');
  if (resp.status !== 'ok') {
    check(false, 'sync-database 请求成功', JSON.stringify(resp.data).slice(0, 160));
    t.destroy();
    return;
  }
  check(resp.status === 'ok', 'sync-database 请求成功');
  const body = await cli.readN(resp.data.payload_bytes);
  check(body.length > 0, '收到数据库快照', body.length + ' 字节');
  check(body.length >= 16 && body.subarray(0, 15).toString('latin1') === 'SQLite format 3',
    '快照是合法 SQLite 文件头', body.subarray(0, 16).toString('latin1'));
  check(resp.data.name === 'hamster.db', '对外名字是 hamster.db', resp.data.name);
  t.destroy();
  await sleep(100);
}

/* ------------------------------------------------------------ main */
async function caseProxyEncrypted() {
  console.log('\n[7] C 代理 hamster_manager（§8 客户端）');
  const mgExe = path.join(ROOT, 'Hamster Manager', 'hamster_manager.exe');
  if (!fs.existsSync(mgExe)) {
    check(false, '找不到 hamster_manager.exe（先 make manager）');
    return;
  }
  fs.copyFileSync(mgExe, path.join(BIN_DIR, 'hamster_manager.exe'));
  /* 不写 hamd_encrypt：让它继承 hamsterd.conf 的 encrypt_transport（默认行为） */
  fs.writeFileSync(path.join(BIN_DIR, 'hamster_manager.conf'), [
    'hamd_port ' + PORT,
    'ipc_port ' + IPC_PORT,
    'hamd_codeword ' + CODEWORD,
    '',
  ].join('\n'), 'utf8');

  const proxy = spawn(path.join(BIN_DIR, 'hamster_manager.exe'), ['--proxy-only'],
    { cwd: BIN_DIR, stdio: 'ignore', windowsHide: true });
  procs.push(proxy);

  const up = await waitTcp(IPC_PORT, 12000);
  check(up, '代理已监听 :' + IPC_PORT);
  if (!up) return;

  /* 通过代理发 ping：能收到响应就说明代理真的完成了 §8 握手
     （守护进程开着加密时，明文 hello 会被静默断开） */
  const line = await new Promise((resolve) => {
    const s = net.connect({ host: '127.0.0.1', port: IPC_PORT }, () => {
      s.write(JSON.stringify({ type: 'request', id: 'p1', action: 'ping', params: {} }) + '\n');
    });
    let buf = '';
    const take = () => {
      for (;;) {
        const i = buf.indexOf('\n');
        if (i < 0) return null;
        const one = buf.slice(0, i);
        buf = buf.slice(i + 1);
        let m = null;
        try { m = JSON.parse(one); } catch (_) { continue; }
        if (m && m.type === 'event') continue;      /* 代理会先推 connection_status */
        if (m && m.type === 'response') return one;
      }
    };
    s.on('data', (b) => {
      buf += b.toString('utf8');
      const resp = take();
      if (resp !== null) { try { s.destroy(); } catch (_) {} resolve(resp); }
    });
    s.on('error', () => resolve(''));
    setTimeout(() => { try { s.destroy(); } catch (_) {} resolve(take() || buf.trim()); }, 5000);
  });
  let msg = null;
  try { msg = JSON.parse(line); } catch (_) {}
  check(!!msg && msg.type === 'response' && msg.status === 'ok',
    '代理转发 ping 成功（说明已走 §8 握手）', line.slice(0, 160));
  check(!!msg && msg.data && msg.data.pong === true, '响应里带 pong');

  /* 错误口令：代理不该把请求送达（守护进程静默断开） */
  fs.writeFileSync(path.join(BIN_DIR, 'hamster_manager.conf'), [
    'hamd_port ' + PORT,
    'ipc_port ' + IPC_PORT,
    'hamd_codeword wrong-codeword',
    'hamd_encrypt on',
    '',
  ].join('\n'), 'utf8');
  await stopDaemon(proxy);
  const bad = spawn(path.join(BIN_DIR, 'hamster_manager.exe'), ['--proxy-only'],
    { cwd: BIN_DIR, stdio: 'ignore', windowsHide: true });
  procs.push(bad);
  await waitTcp(IPC_PORT, 12000);
  const line2 = await new Promise((resolve) => {
    const s = net.connect({ host: '127.0.0.1', port: IPC_PORT }, () => {
      s.write(JSON.stringify({ type: 'request', id: 'p2', action: 'ping', params: {} }) + '\n');
    });
    let buf = '';
    s.on('data', (b) => { buf += b.toString('utf8'); });
    s.on('error', () => resolve(buf));
    setTimeout(() => { try { s.destroy(); } catch (_) {} resolve(buf); }, 4000);
  });
  check(line2.trim() === '', '错误口令下代理收不到任何响应（守护进程静默断开）');
  await stopDaemon(bad);
}

/* ------------------------------------------------------------ main */
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

  await caseHandshake();
  await caseWrongCodeword();
  await casePlaintextAfterHandshake();
  await caseDownloadBig();
  await caseUploadBig();
  await caseSyncDatabase();
  await caseProxyEncrypted();

  console.log('\n=== 结果: 通过 ' + pass + ', 失败 ' + fail + ' ===');
  await stopDaemon(p);
  process.exit(fail === 0 ? 0 : 1);
})().catch(async (e) => {
  console.error('\n测试异常: ' + ((e && e.stack) || e));
  await Promise.all(procs.map(stopDaemon));
  process.exit(1);
});
