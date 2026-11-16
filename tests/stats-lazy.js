/*
 * tests/stats-lazy.js — 统计表改成"脏标 + 节流重算"后，数字必须还是准的
 *
 * 背景：file_total 的三个聚合是 O(文件数)，而事件路径一个文件一次 upsert/delete。
 * 以前每行都重算：突发 100 个文件在 10000 条索引上要 212ms，在 2000 条上 100ms。
 * 现在写路径只置脏标，由 stats 读取或主循环（500ms 一次）补算。
 *
 * 这个用例钉的是"省下来的不是准确性"：
 *   1. 事件造成的增删，stats 的 total_files / total_size / file_type_count 都要跟得上
 *   2. 跟上得有时限（不是永远滞后）：5s 内必须收敛到精确值
 *   3. 突发 30 个文件后一次读到的必须是 30 个都算进去（不能只算一部分）
 *
 * 运行：node tests/stats-lazy.js
 */
'use strict';

const fs = require('fs');
const net = require('net');
const path = require('path');
const { spawn } = require('child_process');

const ROOT = path.join(__dirname, '..');
const TMP = path.join(__dirname, 'tmp', 'stats-lazy');
const BIN = path.join(TMP, 'bin');
const MON = path.join(TMP, 'mon');
const EXE = path.join(BIN, 'hamsterd.exe');
const PORT = 19418;
const CODEWORD = 'stats-codeword-' + 's'.repeat(24);
const N_BASE = 200;
const BURST = 30;
const DEL = 10;
const FILE_SIZE = 64;

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

  for (let i = 0; i < N_BASE; i += 1) {
    fs.writeFileSync(path.join(MON, 'base' + i + '.dat'), Buffer.alloc(FILE_SIZE, 0x61));
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
    'max_clients: 8',
    'scan_threads: 4',
    'scan_skip_unchanged: off',
    'rescan_date: 0,0,0',
    'verify_interval: 0',
    'discovery_port: 0',
    'heartbeat_time: 3600',
    'log_level: warn',
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

function connect() {
  return new Promise((resolve, reject) => {
    const sock = net.connect({ host: '127.0.0.1', port: PORT });
    let buf = '';
    const waiters = new Map();
    const events = [];

    sock.on('connect', () => resolve(api));
    sock.on('error', reject);
    sock.on('data', (d) => {
      buf += d.toString('utf8');
      let nl;
      while ((nl = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        let msg;
        try { msg = JSON.parse(line); } catch (_) { continue; }
        if (msg.type === 'event') { events.push(msg); continue; }
        const w = waiters.get(msg.id);
        if (w) { waiters.delete(msg.id); w(msg); }
      }
    });

    const api = {
      request(action, params, id) {
        const rid = id || (action + '_' + Math.random().toString(16).slice(2));
        return new Promise((res, rej) => {
          const timer = setTimeout(() => { waiters.delete(rid); rej(new Error('响应超时: ' + rid)); }, 30000);
          waiters.set(rid, (m) => { clearTimeout(timer); res(m); });
          sock.write(JSON.stringify({ type: 'request', id: rid, action, params }) + '\n');
        });
      },
      close() { try { sock.destroy(); } catch (_) {} },
      events,
    };
  });
}

async function statsOf(cli) {
  const r = await cli.request('stats', {});
  if (r.status !== 'ok') throw new Error('stats 失败: ' + JSON.stringify(r).slice(0, 120));
  return r.data;
}

/** 轮询到 predicate 成立（模拟客户端 1 秒一次轮询的自然表现） */
async function waitStats(cli, pred, ms, what) {
  const deadline = Date.now() + ms;
  let last = null;
  while (Date.now() < deadline) {
    last = await statsOf(cli);
    if (pred(last)) return { ok: true, data: last, waited: ms - (deadline - Date.now()) };
    await sleep(100);
  }
  return { ok: false, data: last, waited: ms };
}

(async () => {
  console.log('hamsterd 惰性统计回归');
  prepare();

  const p = spawn(EXE, ['--console-log'], { cwd: BIN, stdio: 'ignore', windowsHide: true });
  if (!(await waitTcp(60000))) { try { p.kill(); } catch (_) {} throw new Error('守护进程未就绪'); }
  await sleep(2500);

  const cli = await connect();
  const hello = await cli.request('hello', { device_id: 'dev_stats_lazy', codeword: CODEWORD }, 'hello');
  if (hello.status !== 'ok') throw new Error('hello 失败');

  const s0 = await statsOf(cli);
  check(Number(s0.total_files) === N_BASE, '初始 total_files = ' + N_BASE, JSON.stringify(s0));
  check(Number(s0.total_size) === N_BASE * FILE_SIZE, '初始 total_size 正确', JSON.stringify(s0));
  const typeCount0 = Number(s0.file_type_count);

  /* 1) 突发 30 个文件：统计必须收敛到 +30，并且是一次全算进去 */
  for (let i = 0; i < BURST; i += 1) {
    fs.writeFileSync(path.join(MON, 'burst' + i + '.dat'), Buffer.alloc(FILE_SIZE, 0x62));
  }
  const w1 = await waitStats(cli,
    (s) => Number(s.total_files) === N_BASE + BURST && Number(s.total_size) === (N_BASE + BURST) * FILE_SIZE,
    8000, 'burst');
  check(w1.ok, '突发 ' + BURST + ' 个文件后 stats 收敛到精确值（total_files=' + (N_BASE + BURST) + '）',
    JSON.stringify(w1.data));
  check(w1.ok && Number(w1.data.total_size) === (N_BASE + BURST) * FILE_SIZE,
    'total_size 增量 = 30 × ' + FILE_SIZE + ' 字节', JSON.stringify(w1.data));

  /* 2) 删除 10 个：统计要相应减少 */
  for (let i = 0; i < DEL; i += 1) {
    fs.unlinkSync(path.join(MON, 'burst' + i + '.dat'));
  }
  const w2 = await waitStats(cli,
    (s) => Number(s.total_files) === N_BASE + BURST - DEL,
    8000, 'delete');
  check(w2.ok, '删除 ' + DEL + ' 个后 total_files 收敛到 ' + (N_BASE + BURST - DEL), JSON.stringify(w2.data));
  check(w2.ok && Number(w2.data.total_size) === (N_BASE + BURST - DEL) * FILE_SIZE,
    'total_size 也相应减少', JSON.stringify(w2.data));

  /* 3) 新增一种扩展名：file_type_count 也要跟上 */
  fs.writeFileSync(path.join(MON, 'types.zzz'), Buffer.alloc(FILE_SIZE, 0x63));
  const w3 = await waitStats(cli, (s) => Number(s.file_type_count) === typeCount0 + 1, 8000, 'type');
  check(w3.ok, '新扩展名后 file_type_count ' + typeCount0 + ' -> ' + (typeCount0 + 1),
    JSON.stringify(w3.data));

  /* 4) 没人查 stats 时主循环也会补算（500ms 节流）：停一会儿再读，数字同样精确 */
  await sleep(1200);
  const s4 = await statsOf(cli);
  check(Number(s4.total_files) === N_BASE + BURST - DEL + 1, '静置 1.2s 后 total_files 精确',
    JSON.stringify(s4));

  cli.close();
  try { p.kill(); } catch (_) {}
  await sleep(400);

  console.log('\n  通过 ' + pass + ' / 失败 ' + fail);
  process.exit(fail === 0 ? 0 : 1);
})().catch((e) => { console.error('测试失败: ' + (e && e.stack ? e.stack : e)); process.exit(1); });
