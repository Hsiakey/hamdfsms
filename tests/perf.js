/*
 * tests/perf.js — hamsterd（C 守护进程）性能基准
 *
 * 目的：把"用起来快不快"变成数字。测的都是真实链路：
 *   · 握手耗时（§8 PSK 握手，含 TCP 建连）
 *   · 控制面延迟：ping / list / search 的 p50、p95（走索引，不是全树扫描）
 *   · 数据面吞吐：download / upload（大文件，必然跨多条 64 KiB 记录）
 *   · 并发下载：8 条连接同时拉 8 MiB
 *   · 事件通道延迟：文件落盘 → file_added/file_changed/file_removed 到达订阅端；
 *     以及一次写 100 个文件时"首个写入 → 最后一个事件到达"的突发吞吐
 *   · 索引建好要多久（从进程启动到精确 search 命中最后一个文件）
 *   · 守护进程常驻内存（RSS）与客户端/服务端各自烧的 CPU
 *
 * 同一份数据跑两遍：encrypt_transport: off（明文）与 on（§8 加密），
 * 差值就是加密层的代价（记录层 + 握手后全部密文）。
 *
 * 运行：node tests/perf.js
 *   可选环境变量：PERF_FILES（文件数，默认 5000）、PERF_BIG_MB（大文件 MiB，默认 64）
 *
 * 注意：hamsterd 的单实例锁是机器级的，跑之前不要有别的 hamsterd 在跑。
 * 所有产物都在 tests/tmp/perf/（已被 gitignore），report.json 里有全部原始数字。
 */
'use strict';

const fs = require('fs');
const os = require('os');
const net = require('net');
const path = require('path');
const { spawn, execFileSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const A = require(path.join(ROOT, 'Hamster Manager', 'module', 'shared', 'hamster-aead.js'));

const N_FILES = Number(process.env.PERF_FILES || 5000);
const BIG_MB = Number(process.env.PERF_BIG_MB || 64);
const PORT = 19410;
const CODEWORD = 'perf-codeword-' + 'p'.repeat(24);
const TMP = path.join(__dirname, 'tmp', 'perf');
const BIN_DIR = path.join(TMP, 'bin');
const MON_DIR = path.join(TMP, 'monitor');
const EXE_SRC = path.join(ROOT, 'Hamsterd', 'hamsterd.exe');
const EXE = path.join(BIN_DIR, 'hamsterd.exe');

const PING_ROUNDS = 200;
const CTRL_ROUNDS = 50;
const XFER_ROUNDS = 9;
const CONC = 8;
const CONC_MB = 8;
const EVENT_ROUNDS = 20;
const VERIFY_ROUNDS = 3;
const BURST_FILES = 100;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const toMiB = (n) => n / (1024 * 1024);
const DEBUG = process.env.PERF_DEBUG === '1';
const msSince = (t0) => Number(process.hrtime.bigint() - t0) / 1e6;
function sleepSync(ms) { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); }
/** Windows 上文件刚写完时可能还被守护进程的索引线程握着句柄，删除要重试 */
function unlinkRetry(p, tries) {
  for (let i = 0; i < (tries || 40); i += 1) {
    try { fs.unlinkSync(p); return true; } catch (_) { sleepSync(5); }
  }
  return false;
}

function percentile(sorted, p) {
  if (!sorted.length) return NaN;
  const i = Math.min(sorted.length - 1, Math.max(0, Math.round((p / 100) * (sorted.length - 1))));
  return sorted[i];
}
function stats(list) {
  const s = list.slice().sort((a, b) => a - b);
  const sum = s.reduce((a, b) => a + b, 0);
  return { n: s.length, min: s[0], p50: percentile(s, 50), p95: percentile(s, 95), max: s[s.length - 1], mean: sum / s.length };
}
function fmt(v, digits) {
  const d = digits === undefined ? 2 : digits;
  return Number.isFinite(v) ? v.toFixed(d) : 'n/a';
}

/* ------------------------------------------------------------------ 环境 */

function prepare() {
  fs.rmSync(TMP, { recursive: true, force: true });
  fs.mkdirSync(BIN_DIR, { recursive: true });
  fs.mkdirSync(MON_DIR, { recursive: true });

  const pad = String(N_FILES - 1).length;
  for (let i = 0; i < N_FILES; i += 1) {
    const name = 'perf_' + String(i).padStart(pad, '0') + '.dat';
    fs.writeFileSync(path.join(MON_DIR, name), Buffer.alloc(64, 0x61 + (i % 20)));
  }
  fs.writeFileSync(path.join(MON_DIR, 'hello.txt'), 'perf test file\n', 'utf8');
  // 小目录：用来对比 list 的耗时是不是随目录条目数线性增长
  fs.mkdirSync(path.join(MON_DIR, 'sub_small'), { recursive: true });
  for (let i = 0; i < 10; i += 1) {
    fs.writeFileSync(path.join(MON_DIR, 'sub_small', 's' + i + '.dat'), Buffer.alloc(32, 0x41));
  }
  fs.writeFileSync(path.join(MON_DIR, 'big.bin'), Buffer.alloc(BIG_MB * 1024 * 1024, 0x5a));
  for (let i = 0; i < CONC; i += 1) {
    fs.writeFileSync(path.join(MON_DIR, 'conc_' + i + '.bin'), Buffer.alloc(CONC_MB * 1024 * 1024, 0x30 + i));
  }

  fs.copyFileSync(EXE_SRC, EXE);
  const dll = path.join(ROOT, 'Hamsterd', 'sqlite3.dll');
  if (fs.existsSync(dll)) fs.copyFileSync(dll, path.join(BIN_DIR, 'sqlite3.dll'));
}

function writeConf(encryptOn) {
  const conf = [
    'monitor_path: ' + MON_DIR,
    'ipv4_addr: 127.0.0.1',
    'ipv4_addr_port: ' + PORT,
    'codeword: ' + CODEWORD,
    'require_auth: on',
    'allow_loopback_noauth: off',
    'encrypt_transport: ' + (encryptOn ? 'on' : 'off'),
    'max_transfer_mb: 512',
    'max_clients: 32',
    'rescan_date: 0,0,0',
    'verify_interval: 0',
    'discovery_port: 0',
    'heartbeat_time: 3600',      // 别在压测期间插心跳事件
    'log_level: ' + (process.env.PERF_LOG || 'warn'),
    'log_dir: logs',
    'exclude_internal: on',
    '',
  ].join('\n');
  fs.writeFileSync(path.join(BIN_DIR, 'hamsterd.conf'), conf, 'utf8');
}

let daemon = null;

async function startDaemon(encryptOn) {
  writeConf(encryptOn);
  const t0 = Date.now();
  const proc = spawn(EXE, ['--console-log'], { cwd: BIN_DIR, stdio: 'ignore', windowsHide: true });
  daemon = proc;
  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) {
    if (proc.exitCode !== null) {
      throw new Error('hamsterd 启动即退出（exitCode=' + proc.exitCode + '）：检查单实例锁或 19410 端口占用');
    }
    const ok = await new Promise((resolve) => {
      const s = net.connect({ host: '127.0.0.1', port: PORT }, () => { s.destroy(); resolve(true); });
      s.on('error', () => { try { s.destroy(); } catch (_) {} resolve(false); });
      s.setTimeout(500, () => { try { s.destroy(); } catch (_) {} resolve(false); });
    });
    if (ok) return t0;
    await sleep(20);
  }
  throw new Error('hamsterd 30s 内没起来');
}

async function stopDaemon() {
  if (!daemon) return;
  const p = daemon;
  daemon = null;
  if (p.exitCode !== null) return;
  p.kill();
  await new Promise((resolve) => {
    const t = setTimeout(() => { try { p.kill('SIGKILL'); } catch (_) {} resolve(); }, 5000);
    p.once('exit', () => { clearTimeout(t); resolve(); });
  });
}

function cpuSeconds(pid) {
  try {
    const out = execFileSync('powershell', ['-NoProfile', '-Command',
      '(Get-Process -Id ' + pid + ' -ErrorAction Stop).TotalProcessorTime.TotalSeconds'], { encoding: 'utf8', windowsHide: true });
    return Number(out.trim());
  } catch (_) {
    return NaN;
  }
}

function rssMiB(pid) {
  try {
    const out = execFileSync('powershell', ['-NoProfile', '-Command',
      '(Get-Process -Id ' + pid + ' -ErrorAction Stop).WorkingSet64'], { encoding: 'utf8', windowsHide: true });
    return Number(out.trim()) / (1024 * 1024);
  } catch (_) {
    return NaN;
  }
}

/** 跑一段测量并顺带记下客户端自己烧了多少 CPU（Node 侧 AEAD 的代价） */
async function withClientCpu(fn) {
  const c0 = process.cpuUsage();
  const v = await fn();
  const d = process.cpuUsage(c0);
  return { value: v, cpuSec: (d.user + d.system) / 1e6 };
}

/* ------------------------------------------------------------ 客户端小工具 */

/* 分块队列：下载大文件时不能每来一块就 Buffer.concat（那是 O(n^2) 的自我限速） */
function mkQueue() {
  const q = [];
  let avail = 0;
  return {
    push(b) { q.push(b); avail += b.length; },
    get length() { return avail; },
    indexOf(byte) {
      let off = 0;
      for (let i = 0; i < q.length; i += 1) {
        const k = q[i].indexOf(byte);
        if (k >= 0) return off + k;
        off += q[i].length;
      }
      return -1;
    },
    take(n) {
      const out = Buffer.allocUnsafe(n);
      let o = 0;
      while (o < n) {
        const c = q[0];
        const k = Math.min(c.length, n - o);
        c.copy(out, o, 0, k);
        o += k;
        if (k === c.length) q.shift();
        else q[0] = c.subarray(k);
      }
      avail -= n;
      return out;
    },
  };
}

/*
 * 客户端：一个常驻的读循环拥有整条流。事件要能在"没有请求在等"的时候也被派发
 * （这正是事件通道的语义），所以不能用"谁发请求谁读行"的写法。
 * 下载时响应头之后紧跟裸负载：读到带 payload_bytes 的响应后暂停读循环，
 * 交给 readN(n) 精确取走，再恢复。
 */
function mkClient(writeFn, onData, closeFn) {
  const q = mkQueue();
  let seq = 0;
  const events = [];
  let lastLineAt = Date.now();
  const respWaiters = new Map();
  const eventWaiters = [];
  let readerPaused = false;
  let resumeReaderResolve = null;
  let readerError = null;
  let maxSeq = 0;
  const debugLog = DEBUG;

  function checkEventWaiters(m) {
    for (let i = eventWaiters.length - 1; i >= 0; i -= 1) {
      const w = eventWaiters[i];
      if (!w.pred(m)) continue;
      w.seen += 1;
      w.last = m;
      if (w.seen >= w.need) {
        eventWaiters.splice(i, 1);
        clearTimeout(w.timer);
        w.resolve(w.single ? m : w.seen);
      }
    }
  }

  function waitFor(pred, ms, what) {
    return new Promise((resolve, reject) => {
      const w = { pred, resolve };
      w.timer = setTimeout(() => {
        const k = qWaiters.indexOf(w);
        if (k >= 0) qWaiters.splice(k, 1);
        reject(new Error('等待超时: ' + what + '（已收 ' + q.length + ' 字节）'));
      }, ms);
      qWaiters.push(w);
      checkQWaiters();
    });
  }
  const qWaiters = [];
  function checkQWaiters() {
    for (let i = qWaiters.length - 1; i >= 0; i -= 1) {
      const w = qWaiters[i];
      if (w.pred()) {
        qWaiters.splice(i, 1);
        clearTimeout(w.timer);
        w.resolve();
      }
    }
  }

  onData((b) => { q.push(b); checkQWaiters(); });

  async function readLine() {
    await waitFor(() => q.indexOf(0x0a) >= 0, 30000, '响应行');
    const i = q.indexOf(0x0a);
    const line = q.take(i).toString('utf8');
    q.take(1);
    return line;
  }

  function failAll(err) {
    readerError = err;
    for (const [, w] of respWaiters) { clearTimeout(w.timer); w.reject(err); }
    respWaiters.clear();
    for (const w of eventWaiters.splice(0)) { clearTimeout(w.timer); w.reject ? w.reject(err) : null; }
    for (const w of qWaiters.splice(0)) { clearTimeout(w.timer); w.reject ? w.reject(err) : null; }
  }

  async function readN(n) {
    await waitFor(() => q.length >= n, 120000, n + ' 字节负载');
    const out = q.take(n);
    resumeReader();
    return out;
  }

  function resumeReader() {
    if (!readerPaused) return;
    readerPaused = false;
    if (resumeReaderResolve) { const r = resumeReaderResolve; resumeReaderResolve = null; r(); }
  }

  (async () => {
    try {
      for (;;) {
        if (readerPaused) await new Promise((r) => { resumeReaderResolve = r; });
        const line = await readLine();
        if (line === '') continue;
        if (debugLog && Date.now() - lastLineAt > 200) {
          process.stderr.write('[gap] ' + ((Date.now() - lastLineAt) / 1000).toFixed(1) + 's 收到: ' + line.slice(0, 60) + '\n');
        }
        lastLineAt = Date.now();
        let m;
        try { m = JSON.parse(line); } catch (_) { continue; }
        if (m.type === 'event') {
          events.push(m);
          if (typeof m.seq === 'number' && m.seq > maxSeq) maxSeq = m.seq;
          checkEventWaiters(m);
          continue;
        }
        if (m.type === 'response') {
          const pb = m.data ? Number(m.data.payload_bytes) : NaN;
          if (Number.isFinite(pb) && pb > 0) readerPaused = true;
          const waiter = respWaiters.get(m.id);
          if (waiter) { respWaiters.delete(m.id); waiter.resolve(m); }
        }
      }
    } catch (e) {
      if (DEBUG) process.stderr.write('[client] reader loop 结束: ' + (e && e.message ? e.message : e) + '\n');
      failAll(e instanceof Error ? e : new Error(String(e)));
    }
  })();

  function requestRaw(action, params, payload) {
    const id = 'p' + (++seq);
    return new Promise((resolve, reject) => {
      if (readerError) return reject(readerError);
      const timer = setTimeout(() => {
        if (respWaiters.delete(id)) reject(new Error('响应超时: ' + action));
      }, 120000);
      respWaiters.set(id, { resolve, reject, timer });
      const head = { type: 'request', id, action };
      if (params) head.params = params;
      if (payload) head.payload_bytes = payload.length;
      writeFn(JSON.stringify(head) + '\n');
      if (payload) writeFn(payload);
    });
  }

  return {
    events,
    close: () => { try { if (closeFn) closeFn(); } catch (_) {} },
    request: (action, params) => requestRaw(action, params, null),
    requestWithPayload: (action, params, payload) => requestRaw(action, params, payload),
    requestHeader: (action, params) => requestRaw(action, params, null),
    /** 明文连接自己发 hello，要走响应通道 */
    sendAndRead: (rawLine, id) => new Promise((resolve, reject) => {
      const timer = setTimeout(() => { if (respWaiters.delete(id)) reject(new Error('响应超时: ' + id)); }, 30000);
      respWaiters.set(id, { resolve, reject, timer });
      writeFn(rawLine);
    }),
    nextEvent: (pred, ms, what) => new Promise((resolve, reject) => {
      const w = { pred, need: 1, seen: 0, single: true, resolve, reject };
      w.timer = setTimeout(() => {
        const k = eventWaiters.indexOf(w);
        if (k >= 0) eventWaiters.splice(k, 1);
        reject(new Error('事件等待超时: ' + (what || '')));
      }, ms || 20000);
      eventWaiters.push(w);
      for (const ev of events) checkEventWaiters(ev);
    }),
    /** 已收到的最大事件 seq（用来忽略"触发之前就已在队列里"的事件） */
    get lastSeq() { return maxSeq; },
    readN,
  };
}

async function connectEncrypted() {
  const t0 = process.hrtime.bigint();
  const t = await A.AeadTransport.connect({
    port: PORT,
    secret: CODEWORD,
    deviceId: 'dev_perf_enc',
    hostname: 'perf-enc',
    timeoutMs: 10000,
  });
  if (DEBUG) t.on('close', () => process.stderr.write('[aead] transport closed, t=' + Date.now() + '\n'));
  const cli = mkClient((b) => t.write(b), (cb) => t.on('data', cb), () => {
    if (typeof t.destroy === 'function') t.destroy();
    else t.end();
  });
  cli.handshakeMs = Number(process.hrtime.bigint() - t0) / 1e6;
  return cli;
}

async function connectPlain() {
  const t0 = process.hrtime.bigint();
  const sock = await new Promise((resolve, reject) => {
    const s = net.connect({ host: '127.0.0.1', port: PORT });
    s.once('connect', () => resolve(s));
    s.once('error', reject);
  });
  sock.setNoDelay(true);
  if (DEBUG) {
    sock.on('close', () => process.stderr.write('[plain] socket closed, t=' + Date.now() + '\n'));
    sock.on('error', (e) => process.stderr.write('[plain] socket error: ' + e.message + '\n'));
  }
  const cli = mkClient((b) => sock.write(b), (cb) => sock.on('data', cb), () => sock.destroy());
  const hello = await cli.sendAndRead(
    JSON.stringify({ type: 'request', id: 'hello_perf', action: 'hello', params: { device_id: 'dev_perf_plain', codeword: CODEWORD } }) + '\n',
    'hello_perf');
  if (hello.status !== 'ok') throw new Error('明文 hello 失败: ' + JSON.stringify(hello).slice(0, 160));
  cli.handshakeMs = Number(process.hrtime.bigint() - t0) / 1e6;
  return cli;
}

/* ---------------------------------------------------------------- 各项测量 */

async function measurePing(cli) {
  const out = [];
  for (let i = 0; i < PING_ROUNDS; i += 1) {
    const t0 = process.hrtime.bigint();
    const r = await cli.request('ping', {});
    out.push(msSince(t0));
    if (r.status !== 'ok') throw new Error('ping 失败');
  }
  return stats(out);
}

async function measureList(cli, relPath) {
  const out = [];
  const params = { limit: 100, offset: 0 };
  if (relPath) params.path = relPath;
  for (let i = 0; i < CTRL_ROUNDS; i += 1) {
    const t0 = process.hrtime.bigint();
    const r = await cli.request('list', params);
    out.push(msSince(t0));
    if (r.status !== 'ok') throw new Error('list 失败: ' + JSON.stringify(r).slice(0, 140));
  }
  return stats(out);
}

async function measureSearch(cli, q, limit) {
  const out = [];
  let total = null;
  for (let i = 0; i < CTRL_ROUNDS; i += 1) {
    const t0 = process.hrtime.bigint();
    const r = await cli.request('search', { q, limit });
    out.push(msSince(t0));
    if (r.status !== 'ok') throw new Error('search 失败: ' + JSON.stringify(r).slice(0, 140));
    if (total === null) total = r.data.total;
  }
  const s = stats(out);
  s.total = total;
  return s;
}

async function measureVerify(cli) {
  const out = [];
  let files = null;
  for (let i = 0; i < VERIFY_ROUNDS; i += 1) {
    const t0 = process.hrtime.bigint();
    const r = await cli.request('verify', { run: true });
    out.push(msSince(t0));
    if (r.status !== 'ok') throw new Error('verify 失败: ' + JSON.stringify(r).slice(0, 140));
    files = r.data.verified_files;
  }
  const s = stats(out);
  s.files = files;
  return s;
}

async function measureDownload(cli, remotePath, expectBytes) {
  const secs = [];
  const mbps = [];
  let size = 0;
  for (let i = 0; i < XFER_ROUNDS; i += 1) {
    const t0 = process.hrtime.bigint();
    const h = await cli.requestHeader('download', { path: remotePath });
    if (h.status !== 'ok') throw new Error('download 头失败: ' + JSON.stringify(h).slice(0, 160));
    const n = Number(h.data.payload_bytes);
    if (expectBytes && n !== expectBytes) throw new Error('download 字节数不符: ' + n + ' != ' + expectBytes);
    const body = await cli.readN(n);
    if (body.length !== n) throw new Error('download 负载长度不符');
    const sec = Number(process.hrtime.bigint() - t0) / 1e9;
    size = n;
    secs.push(sec);
    mbps.push(toMiB(n) / sec);
  }
  return { bytes: size, runs: XFER_ROUNDS, secs, mbps: stats(mbps) };
}

async function measureUpload(cli, payload, remoteName) {
  const secs = [];
  const mbps = [];
  for (let i = 0; i < XFER_ROUNDS; i += 1) {
    const t0 = process.hrtime.bigint();
    const r = await cli.requestWithPayload('upload',
      { path: 'perf_upload/' + remoteName, size: payload.length, overwrite: true, mkdir: true }, payload);
    const sec = Number(process.hrtime.bigint() - t0) / 1e9;
    if (r.status !== 'ok') throw new Error('upload 失败: ' + JSON.stringify(r).slice(0, 160));
    secs.push(sec);
    mbps.push(toMiB(payload.length) / sec);
  }
  return { bytes: payload.length, runs: XFER_ROUNDS, secs, mbps: stats(mbps) };
}

async function measureConcurrent(connect) {
  const one = async (i) => {
    const cli = await connect();
    const h = await cli.requestHeader('download', { path: 'conc_' + i + '.bin' });
    if (h.status !== 'ok') throw new Error('并发下载头失败');
    const n = Number(h.data.payload_bytes);
    const body = await cli.readN(n);
    cli.close();
    return body.length;
  };
  const t0 = process.hrtime.bigint();
  const results = await Promise.all(Array.from({ length: CONC }, (_, i) => one(i)));
  const sec = Number(process.hrtime.bigint() - t0) / 1e9;
  const bytes = results.reduce((a, b) => a + b, 0);
  return { conns: CONC, bytes, sec, mbps: toMiB(bytes) / sec };
}

/* ------------------------------------------------------------ 事件通道延迟 */

/* 从"文件落盘"到"订阅端收到事件"的端到端延迟。Windows 侧是
   ReadDirectoryChangesW + APC，检测本身是立即的；这里量的是完整链路：
   监控线程 → 广播 → 每个连接的写锁 → §8 记录层 → 客户端解析派发。 */
async function measureEvents(cli, tag) {
  const base = 'evt_' + tag + '_';
  const adds = [];
  const changes = [];
  const removes = [];
  const evt = (kind, name, afterSeq) => (m) => m.event === kind && m.data && m.data.name === name && (m.seq || 0) > afterSeq;

  async function step(pred, waitMs, trigger) {
    const waiter = cli.nextEvent(pred, waitMs, 'event');
    const t0 = process.hrtime.bigint();
    trigger();
    try { await waiter; return msSince(t0); } catch (_) { return NaN; }
  }

  for (let i = 0; i < EVENT_ROUNDS; i += 1) {
    const name = base + i + '.txt';
    const abs = path.join(MON_DIR, name);
    // 直接落盘的新文件，守护进程发的是 file_changed 而不是 file_added（见 README）
    adds.push(await step(evt('file_changed', name, cli.lastSeq), 6000, () => fs.writeFileSync(abs, 'a')));
    changes.push(await step(evt('file_changed', name, cli.lastSeq), 6000, () => fs.appendFileSync(abs, 'b')));
    removes.push(await step(evt('file_removed', name, cli.lastSeq), 6000, () => { unlinkRetry(abs); }));
  }

  // 突发：一次写 BURST_FILES 个文件，量到"每个名字都至少收到一条事件"
  const burstBase = base + 'burst_';
  const baseSeq = cli.lastSeq;
  const t0 = process.hrtime.bigint();
  for (let i = 0; i < BURST_FILES; i += 1) fs.writeFileSync(path.join(MON_DIR, burstBase + i + '.txt'), 'b');
  let burstMs = NaN;
  const deadline = Date.now() + 60000;
  while (Date.now() < deadline) {
    const names = new Set();
    for (const e of cli.events) {
      if ((e.seq || 0) <= baseSeq || !e.data) continue;
      const nm = String(e.data.name || '');
      if (nm.startsWith(burstBase)) names.add(nm);
    }
    if (names.size >= BURST_FILES) { burstMs = msSince(t0); break; }
    await sleep(5);
  }
  for (let i = 0; i < BURST_FILES; i += 1) unlinkRetry(path.join(MON_DIR, burstBase + i + '.txt'));

  const fin = (a) => a.filter(Number.isFinite);
  return {
    add: stats(fin(adds)), addTimeouts: adds.length - fin(adds).length,
    change: stats(fin(changes)), changeTimeouts: changes.length - fin(changes).length,
    remove: stats(fin(removes)), removeTimeouts: removes.length - fin(removes).length,
    burst: { n: BURST_FILES, totalMs: burstMs, eventsPerSec: Number.isFinite(burstMs) ? (BURST_FILES * 1000) / burstMs : NaN },
  };
}
/* ------------------------------------------------------------------ 主流程 */

const report = { env: {}, phases: [] };

async function runPhase(label, encryptOn) {
  process.stdout.write('\n=== ' + label + ' ===\n');
  const dbg = (s) => process.stdout.write('  · ' + s + '\n');
  const startedAt = await startDaemon(encryptOn);
  const connect = encryptOn ? connectEncrypted : connectPlain;
  dbg('daemon ready');
  const cli = await connect();
  const handshakeMs = cli.handshakeMs;
  dbg('handshake ' + fmt(handshakeMs) + ' ms');

  const pad = String(N_FILES - 1).length;
  const lastName = 'perf_' + String(N_FILES - 1).padStart(pad, '0') + '.dat';

  // 索引建好没有：精确搜最后一个文件，命中即认为索引可用
  let indexMs = NaN;
  const idxDeadline = Date.now() + 120000;
  while (Date.now() < idxDeadline) {
    const r = await cli.request('search', { q: lastName, limit: 5 });
    if (r.status === 'ok' && Number(r.data.total) > 0) { indexMs = Date.now() - startedAt; break; }
    await sleep(50);
  }
  if (!Number.isFinite(indexMs)) throw new Error('索引 120s 内没建好');

  dbg('index ' + fmt(indexMs,0) + ' ms');
  const ping = await measurePing(cli);
  dbg('ping done');
  const list = await measureList(cli);
  const listSmall = await measureList(cli, 'sub_small');
  const searchExact = await measureSearch(cli, lastName, 5);
  const searchWide = await measureSearch(cli, 'perf_', 50);

  const daemonCpu0 = cpuSeconds(daemon.pid);
  const dlRun = await withClientCpu(() => measureDownload(cli, 'big.bin', BIG_MB * 1024 * 1024));
  dbg('download done');
  const payload = Buffer.alloc(BIG_MB * 1024 * 1024, 0x42);
  const upRun = await withClientCpu(() => measureUpload(cli, payload, 'perf-' + BIG_MB + 'mb.bin'));
  const daemonCpu1 = cpuSeconds(daemon.pid);
  const dl = dlRun.value;
  const up = upRun.value;

  const rss = rssMiB(daemon.pid);
  dbg('upload done');
  const conc = await measureConcurrent(connect);
  dbg('concurrent done');
  const ev = await measureEvents(cli, encryptOn ? 'on' : 'off');
  dbg('events done (events=' + cli.events.length + ')');

  /* verify 放在最后：它会把整个监控目录重新读一遍（页面缓存因此变热），
     跑在吞吐测试前面会给后面的指标开挂。 */
  const verify = await measureVerify(cli);
  dbg('verify done (' + verify.files + ' files, p50 ' + fmt(verify.p50, 0) + ' ms)');

  dbg('request info...');
  const info = await cli.request('info', {});
  const sr = await cli.request('stats', {});
  cli.close();

  const p = {
    label,
    encrypt: encryptOn,
    indexMs,
    handshakeMs,
    ping,
    list,
    listSmall,
    searchExact,
    searchWide,
    dl,
    up,
    dlClientCpu: dlRun.cpuSec,
    upClientCpu: upRun.cpuSec,
    daemonCpuSec: Number.isFinite(daemonCpu0) && Number.isFinite(daemonCpu1) ? daemonCpu1 - daemonCpu0 : null,
    rss,
    conc,
    events: ev,
    verify,
    infoOk: info.status === 'ok',
    statsOk: sr.status === 'ok',
    totalFiles: sr.status === 'ok' ? sr.data.total_files : null,
  };
  report.phases.push(p);

  await stopDaemon();
  return p;
}

function line(name, value) {
  process.stdout.write('  ' + name.padEnd(32, ' ') + value + '\n');
}

function printPhase(p) {
  process.stdout.write('\n--- ' + p.label + ' ---\n');
  line('索引建好（' + N_FILES + ' 个文件）', fmt(p.indexMs, 0) + ' ms');
  line('握手（' + (p.encrypt ? '§8 PSK' : '明文 hello') + '）', fmt(p.handshakeMs) + ' ms');
  line('ping p50 / p95', fmt(p.ping.p50) + ' / ' + fmt(p.ping.p95) + ' ms');
  line('list 根目录(' + N_FILES + ' 条) p50', fmt(p.list.p50) + ' ms');
  line('list 小目录(10 条) p50', fmt(p.listSmall.p50) + ' ms');
  line('search 精确 p50 / p95', fmt(p.searchExact.p50) + ' / ' + fmt(p.searchExact.p95) + ' ms');
  line('search 前缀(总 ' + p.searchWide.total + ') p50', fmt(p.searchWide.p50) + ' ms');
  line('download ' + BIG_MB + ' MiB 吞吐 p50', fmt(p.dl.mbps.p50, 1) + ' MiB/s（' +
    fmt(p.dl.mbps.min, 0) + '~' + fmt(p.dl.mbps.max, 0) + '，' + p.dl.secs.length + ' 次）');
  line('upload ' + BIG_MB + ' MiB 吞吐 p50', fmt(p.up.mbps.p50, 1) + ' MiB/s（' +
    fmt(p.up.mbps.min, 0) + '~' + fmt(p.up.mbps.max, 0) + '）');
  line('并发 ' + CONC + '×' + CONC_MB + ' MiB 合计', fmt(p.conc.mbps, 1) + ' MiB/s（' + fmt(p.conc.sec, 2) + ' s）');
  const evp = p.events;
  line('事件 新建（file_changed） p50 / p95', fmt(evp.add.p50, 1) + ' / ' + fmt(evp.add.p95, 1) + ' ms' +
    (evp.addTimeouts ? '（漏 ' + evp.addTimeouts + ' 个）' : ''));
  line('事件 修改（file_changed） p50 / p95', fmt(evp.change.p50, 1) + ' / ' + fmt(evp.change.p95, 1) + ' ms' +
    (evp.changeTimeouts ? '（漏 ' + evp.changeTimeouts + ' 个）' : ''));
  line('事件 删除（file_removed） p50 / p95', fmt(evp.remove.p50, 1) + ' / ' + fmt(evp.remove.p95, 1) + ' ms' +
    (evp.removeTimeouts ? '（漏 ' + evp.removeTimeouts + ' 个）' : ''));
  line('事件突发 ' + evp.burst.n + ' 个（首写入→末事件）', fmt(evp.burst.totalMs, 0) + ' ms（' +
    fmt(evp.burst.eventsPerSec, 0) + ' 事件/秒）');
  line('verify 全量真哈希 p50 / p95', fmt(p.verify.p50, 0) + ' / ' + fmt(p.verify.p95, 0) + ' ms（' +
    p.verify.files + ' 个文件，' + fmt(p.verify.files / (p.verify.p50 / 1000) / 1000, 1) + ' k 文件/秒）');
  line('客户端 CPU（download）', fmt(p.dlClientCpu / (p.dl.bytes * p.dl.runs / 1048576) * 1000, 1) + ' ms/MiB');
  line('客户端 CPU（upload）', fmt(p.upClientCpu / (p.up.bytes * p.up.runs / 1048576) * 1000, 1) + ' ms/MiB');
  if (p.daemonCpuSec !== null) line('守护进程整轮 CPU', fmt(p.daemonCpuSec, 2) + ' s');
  line('守护进程 RSS', fmt(p.rss, 1) + ' MiB');
  line('stats.total_files', String(p.totalFiles));
}

(async () => {
  const cpus = os.cpus();
  report.env = {
    node: process.version,
    platform: process.platform + ' ' + process.arch,
    cpus: cpus.length + '× ' + (cpus[0] ? cpus[0].model.trim() : '?'),
    files: N_FILES,
    bigMB: BIG_MB,
    at: new Date().toISOString(),
  };
  process.stdout.write('hamsterd 性能基准\n');
  process.stdout.write('  node ' + report.env.node + ' / ' + report.env.platform + '\n');
  process.stdout.write('  ' + report.env.cpus + '\n');
  process.stdout.write('  ' + N_FILES + ' 个 64B 文件 + ' + BIG_MB + ' MiB 大文件；ping ' + PING_ROUNDS +
    ' 次、控制面 ' + CTRL_ROUNDS + ' 轮、传输 ' + XFER_ROUNDS + ' 轮、事件 ' + EVENT_ROUNDS +
    ' 轮 + 突发 ' + BURST_FILES + ' 个\n');

  prepare();
  const plainRun = await runPhase('明文（encrypt_transport: off）', false);
  const encRun = await runPhase('加密（encrypt_transport: on，§8）', true);

  printPhase(plainRun);
  printPhase(encRun);

  const delta = (a, b) => (a > 0 ? ((b - a) / a) * 100 : NaN);
  process.stdout.write('\n--- 加密代价（on 相对 off） ---\n');
  line('ping p50', fmt(delta(plainRun.ping.p50, encRun.ping.p50), 1) + ' %');
  line('list p50', fmt(delta(plainRun.list.p50, encRun.list.p50), 1) + ' %');
  line('search 精确 p50', fmt(delta(plainRun.searchExact.p50, encRun.searchExact.p50), 1) + ' %');
  line('download 吞吐', fmt(delta(plainRun.dl.mbps.p50, encRun.dl.mbps.p50), 1) + ' %');
  line('upload 吞吐', fmt(delta(plainRun.up.mbps.p50, encRun.up.mbps.p50), 1) + ' %');
  line('并发下载吞吐', fmt(delta(plainRun.conc.mbps, encRun.conc.mbps), 1) + ' %');
  line('事件新建延迟', fmt(delta(plainRun.events.add.p50, encRun.events.add.p50), 1) + ' %');
  line('事件突发吞吐', fmt(delta(plainRun.events.burst.eventsPerSec, encRun.events.burst.eventsPerSec), 1) + ' %');

  fs.writeFileSync(path.join(TMP, 'report.json'), JSON.stringify(report, null, 2), 'utf8');
  process.stdout.write('\n原始数据: ' + path.join(TMP, 'report.json') + '\n');
  process.exit(0);
})().catch(async (e) => {
  process.stderr.write('\n性能测试失败: ' + (e && e.stack ? e.stack : e) + '\n');
  await stopDaemon();
  process.exit(1);
});
