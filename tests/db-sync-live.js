/*
 * 数据库记录同步：对**正在运行的守护进程**做端到端核查（临时脚本）
 * 用法: node build/db-sync-check.js
 */
'use strict';
/*
 * 数据库记录同步的端到端核查 —— 针对**已在运行**的守护进程（127.0.0.1:9100）。
 * 用法: node tests/db-sync-live.js
 * 覆盖: 一致性快照 / 字节数与 WAL checkpoint / SQLite 自洽性 / 覆盖写 / 并发同步 / 未认证拒绝
 * 前置: hamsterd 在跑，且口令与下面 CW 一致（默认取本仓库 hamsterd.conf 的值）。
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const HC = require(path.join(ROOT, 'Hamster Manager', 'module', 'shared', 'hamster-client.js'));
const PY = 'C:\\Users\\Hsiak\\.dsh\\dsh-runtimes\\dsh-primary-runtime\\dependencies\\python\\python.exe';
const DB_SRC = path.join(ROOT, 'Hamsterd', 'hamster.db');
const WAL = DB_SRC + '-wal';
const OUT = path.join(ROOT, 'build', 'dbsync');
const CW = 'hamster-e05258d0ff46edc9601c2b3d585d463d';

let pass = 0, fail = 0;
function check(cond, name, detail) {
  if (cond) { pass++; console.log('  ✓ ' + name); }
  else { fail++; console.log('  ✗ ' + name + (detail ? '  → ' + detail : '')); }
}
const sha = (p) => crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
const walSize = () => { try { return fs.statSync(WAL).size; } catch (_) { return -1; } };

function logicalDigest(dbPath) {
  const code = `
import sqlite3, json, hashlib
p = r'''${dbPath}'''
con = sqlite3.connect('file:' + p + '?mode=ro', uri=True)
c = con.cursor()
tables = [r[0] for r in c.execute("select name from sqlite_master where type='table' order by name")]
h = hashlib.sha256()
for t in tables:
    h.update(t.encode())
    for row in c.execute('select * from "' + t + '" order by rowid'):
        h.update(json.dumps(row, default=str, ensure_ascii=False).encode())
con.close()
print(h.hexdigest())
`;
  return py(code);
}
function py(code) {
  return execFileSync(PY, ['-c', code], { encoding: 'utf8' }).trim();
}
function inspect(dbPath) {
  const code = `
import sqlite3, json, sys
p = r'''${dbPath}'''
con = sqlite3.connect('file:' + p + '?mode=ro', uri=True)
c = con.cursor()
out = {}
out['integrity'] = c.execute('PRAGMA integrity_check').fetchone()[0]
out['journal'] = c.execute('PRAGMA journal_mode').fetchone()[0]
out['page_size'] = c.execute('PRAGMA page_size').fetchone()[0]
out['page_count'] = c.execute('PRAGMA page_count').fetchone()[0]
out['tables'] = [r[0] for r in c.execute("select name from sqlite_master where type='table' order by name")]
try:
    out['file_in'] = c.execute('select count(*) from file_in').fetchone()[0]
except Exception as e:
    out['file_in'] = 'ERR:' + str(e)
try:
    out['total_row'] = c.execute('select total_file_num,total_sizeByte,total_type_num from file_total where id=1').fetchone()
except Exception as e:
    out['total_row'] = 'ERR:' + str(e)
con.close()
print(json.dumps(out))
`;
  return JSON.parse(py(code));
}

(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const c = new HC.HamsterClient({
    id: 'dbsync-check', name: 'dbsync-check',
    host: '127.0.0.1', port: 9100, codeword: CW,
  });

  console.log('=== 1. 认证与基线 ===');
  await c.connect(8000);
  const st = await c.stats(8000);
  check(typeof st.total_files === 'number', 'stats.total_files 可读', JSON.stringify(st.total_files));
  console.log('    服务端统计: files=' + st.total_files + ' size=' + st.total_size);

  const walBefore = walSize();
  const srcSize = fs.statSync(DB_SRC).size;
  console.log('    主库 ' + srcSize + ' 字节，WAL ' + walBefore + ' 字节');

  console.log('\n=== 2. 同步数据库 ===');
  const dest1 = path.join(OUT, 'sync1.db');
  try { fs.unlinkSync(dest1); } catch (_) {}
  const t0 = Date.now();
  const r1 = await c.syncDatabase({ destFile: dest1 });
  const ms = Date.now() - t0;
  check(r1.ok === true, 'syncDatabase 返回 ok');
  check(fs.existsSync(dest1), '落盘文件存在', dest1);
  const gotSize = fs.statSync(dest1).size;
  check(gotSize === r1.size, '落盘字节数 == 返回 size', gotSize + ' vs ' + r1.size);
  check(typeof r1.hash === 'string' && /^[0-9a-f]{32}$/.test(r1.hash), '返回 128 位 xxHash 十六进制', String(r1.hash));
  check(!!r1.path && r1.path.indexOf('.part') < 0, '返回的是最终路径而不是半成品', String(r1.path));
  check(!fs.existsSync(dest1 + '.part-' + process.pid), '不残留 .part 临时文件');
  console.log('    耗时 ' + ms + 'ms，' + gotSize + ' 字节');

  const walAfter = walSize();
  check(walAfter === 0, '发送前做了 WAL checkpoint（-wal 已截断为 0）', '之前 ' + walBefore + ' / 之后 ' + walAfter);

  console.log('\n=== 3. 内容一致性 ===');
  const selfChk = inspect(dest1);
  check(selfChk.total_row[0] === selfChk.file_in, '快照自洽：file_total.total_file_num == count(file_in)',
    JSON.stringify(selfChk.total_row) + ' vs ' + selfChk.file_in);

  const info = inspect(dest1);
  check(info.integrity === 'ok', 'PRAGMA integrity_check = ok', JSON.stringify(info.integrity));
  check(Array.isArray(info.tables) && info.tables.indexOf('file_in') >= 0, '表结构完整（含 file_in）', JSON.stringify(info.tables));
  check(info.file_in === st.total_files, 'file_in 行数 == stats.total_files',
    info.file_in + ' vs ' + st.total_files);
  console.log('    journal_mode=' + info.journal + ' page=' + info.page_size + '×' + info.page_count +
    ' 行数=' + info.file_in + ' total_row=' + JSON.stringify(info.total_row));

  console.log('\n=== 4. 覆盖已有文件 ===');
  let r2 = null, err2 = null;
  try { fs.writeFileSync(dest1, 'corrupt-me'); r2 = await c.syncDatabase({ destFile: dest1 }); }
  catch (e) { err2 = e; }
  check(!err2, '第二次同步（目标已存在且被写坏）成功覆盖', err2 && err2.message);
  if (r2) { const i4 = inspect(dest1); check(i4.integrity === 'ok' && i4.file_in === st.total_files, '覆盖后内容仍然正确（完整且行数一致）', JSON.stringify(i4.file_in)); }

  console.log('\n=== 5. 目标目录不存在时自动创建 ===');
  const deep = path.join(OUT, 'a', 'b', 'c', 'deep.db');
  let r3 = null, err3 = null;
  try { r3 = await c.syncDatabase({ destFile: deep }); } catch (e) { err3 = e; }
  check(!err3 && r3 && fs.existsSync(deep), '深层目录自动创建并落盘', err3 && err3.message);

  console.log('\n=== 6. 未认证不得取库 ===');
  const c2 = new HC.HamsterClient({ id: 'noauth', name: 'noauth', host: '127.0.0.1', port: 9100, codeword: 'wrong' });
  let e2 = null;
  try { await c2.syncDatabase({ destFile: path.join(OUT, 'nope.db') }); } catch (e) { e2 = e; }
  check(!!e2, '错误口令被拒', e2 && (e2.code || e2.message));
  check(!fs.existsSync(path.join(OUT, 'nope.db')), '被拒时不留任何文件');
  try { c2.close('done'); } catch (_) {}

  console.log('\n=== 7. 连续 5 次同步（稳定性 / 不泄漏 fd） ===');
  let okAll = true, hashes = new Set(), sizes = new Set();
  for (let i = 0; i < 5; i++) {
    const d = path.join(OUT, 'loop' + i + '.db');
    try {
      const rr = await c.syncDatabase({ destFile: d });
      hashes.add(logicalDigest(d)); sizes.add(rr.size);
    } catch (e) { okAll = false; console.log('    第 ' + i + ' 次失败: ' + (e.code || '') + ' ' + e.message); }
  }
  check(okAll, '连续 5 次全部成功');
  check(hashes.size === 1, '5 次内容逻辑一致', [...hashes].map(h => h.slice(0, 8)).join(','));

  const st2 = await c.stats(8000);
  check(st2.total_files === st.total_files, '同步过程没有改变索引统计', st2.total_files + ' vs ' + st.total_files);

  console.log('\n=== 8. 两个客户端同时同步（并发一致性） ===');
  {
    const cA = new HC.HamsterClient({ id: 'concA', name: 'concA', host: '127.0.0.1', port: 9100, codeword: CW });
    const cB = new HC.HamsterClient({ id: 'concB', name: 'concB', host: '127.0.0.1', port: 9100, codeword: CW });
    await Promise.all([cA.connect(8000), cB.connect(8000)]);
    let same = true, allOk = true, bad = '';
    for (let i = 0; i < 6; i++) {
      const dA = path.join(OUT, 'concA' + i + '.db');
      const dB = path.join(OUT, 'concB' + i + '.db');
      try {
        const [ra, rb] = await Promise.all([
          cA.syncDatabase({ destFile: dA }),
          cB.syncDatabase({ destFile: dB }),
        ]);
        if (ra.size !== rb.size || logicalDigest(dA) !== logicalDigest(dB)) { same = false; bad = 'A/B 不一致 size ' + ra.size + '/' + rb.size; }
      } catch (e) { allOk = false; bad = (e.code || '') + ' ' + e.message; }
    }
    check(allOk, '6 轮并发同步全部成功', bad);
    check(same, '并发同步得到的两份副本内容一致（逻辑摘要相同）', bad);
    const inA = inspect(path.join(OUT, 'concA5.db'));
    check(inA.integrity === 'ok', '并发副本 integrity_check = ok', JSON.stringify(inA.integrity));
    check(inA.file_in === st.total_files, '并发副本行数完整', inA.file_in + ' vs ' + st.total_files);
    const leftovers = fs.readdirSync(path.join(ROOT, 'Hamsterd')).filter((f) => f.indexOf('.snap-') >= 0);
    check(leftovers.length === 0, '不残留 .snap-* 快照文件', JSON.stringify(leftovers));
    try { cA.close('done'); cB.close('done'); } catch (_) {}
  }

  console.log('\n=== 结果: 通过 ' + pass + ', 失败 ' + fail + ' ===');
  try { c.close('done'); } catch (_) {}
  process.exit(fail === 0 ? 0 : 1);
})().catch((e) => { console.error('异常: ' + ((e && e.stack) || e)); process.exit(1); });
