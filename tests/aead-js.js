/*
 * tests/aead-js.js — 传输加密（PROTOCOL §8）的 JS 侧测试
 *
 * 三块，互相独立：
 *   A. §8.2 密钥派生：与 PROTOCOL 里的已知答案**逐字节**比对（跨实现锚点）
 *   B. §8.3 记录层：往返、分片、半包、篡改、重放、方向反射、长度上下限
 *   C. §8.2 握手：用 mock server 跑完整状态机（含 ok 同包下发记录这种真实边界）
 *
 * 运行：node tests/aead-js.js
 * 退出码：0 = 全通过，1 = 有失败
 */
'use strict';

const net = require('net');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const A = require(path.join(ROOT, 'Hamster Manager', 'module', 'shared', 'hamster-aead.js'));

let pass = 0;
let fail = 0;

function ok(name, cond, detail) {
  if (cond) { pass += 1; console.log('  ✓ ' + name); }
  else { fail += 1; console.log('  ✗ ' + name + (detail === undefined ? '' : '  → ' + detail)); }
}
function eq(name, got, want) {
  ok(name, got === want, 'got ' + JSON.stringify(got) + ' want ' + JSON.stringify(want));
}
function throwsWith(name, fn, code) {
  try {
    fn();
    ok(name, false, '没有抛异常');
  } catch (e) {
    ok(name, e && e.code === code, 'code=' + (e && e.code) + ' msg=' + (e && e.message));
  }
}
function once(emitter, ev, ms) {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('等待事件超时: ' + ev)), ms || 2500);
    emitter.once(ev, (v) => { clearTimeout(t); resolve(v); });
  });
}
function delay(ms) { return new Promise((r) => setTimeout(r, ms)); }

async function expectReject(name, p, allowed) {
  try {
    const v = await p;
    ok(name, false, '本应失败，却成功了');
    return null;
  } catch (e) {
    const code = (e && e.code) || 'unknown';
    const list = Array.isArray(allowed) ? allowed : [allowed];
    ok(name, list.indexOf(code) >= 0, 'code=' + code + ' 期望 ' + list.join('|') + ' msg=' + (e && e.message));
    return e;
  }
}

/* ==========================================================================
 * mock server：独立实现服务端流程（与客户端共用原语，但不共用状态机代码）
 * ========================================================================== */
function mkServer(opts) {
  const o = opts || {};
  const SALT = o.salt || 'aabbccddeeff00112233445566778899';
  const NS = o.ns || 'ffeeddccbbaa99887766554433221100';
  const st = {
    connects: 0, hellos: 0, proofs: 0, authFails: 0, oks: 0,
    bytesIn: 0, records: [], sockets: [], errors: [],
  };

  const srv = net.createServer((sock) => {
    st.connects += 1;
    st.sockets.push(sock);
    sock.setNoDelay(true);
    sock.on('error', (e) => st.errors.push(e.message));

    let phase = 'hello';
    let acc = Buffer.alloc(0);
    let keys = null;
    let sealer = null;
    let opener = null;
    const sess = {
      sock,
      writePlain: (b) => sock.write(sealer.seal(b)),
      writeRaw: (b) => sock.write(b),
      sealWith: (key, dir, counter, b) => {
        const s = new A.RecordSealer(key, dir);
        s.counter = BigInt(counter);
        return s.seal(b);
      },
      get keys() { return keys; },
      get opener() { return opener; },
    };

    const onLine = (line) => {
      let m;
      try { m = JSON.parse(line); } catch (_) { sock.destroy(); return; }
      if (phase === 'hello') {
        if (m.type !== 'auth' || m.step !== 'hello' || m.v !== 2) { sock.destroy(); return; }
        st.hellos += 1;
        phase = 'proof';
        keys = A.deriveSession({ secret: o.secret, salt: SALT, nc: m.nc, ns: NS, deviceId: m.device_id });
        sealer = new A.RecordSealer(keys.keyS2C, A.DIR_S2C);
        opener = new A.RecordOpener(keys.keyC2S, A.DIR_C2S);
        const chal = { type: 'auth', step: 'challenge', v: 2, salt: SALT, ns: NS, alg: 'chacha20poly1305',
          kdf: 'hkdf-sha256', server: 'hamsterd', version: '0.0.9', features: ['framing:aead', 'search'] };
        if (o.challengePatch) Object.assign(chal, o.challengePatch);
        sock.write(JSON.stringify(chal) + '\n');
        if (o.afterChallenge) o.afterChallenge(sess, st);
        return;
      }
      if (phase === 'proof') {
        st.proofs += 1;
        const good = typeof m.mac === 'string' && A.ctEqual(Buffer.from(m.mac, 'hex'), keys.proofC);
        if (!good || o.rejectProof) {
          st.authFails += 1;
          if (o.onBadProof) { o.onBadProof(sess, st); return; }
          sock.destroy();   /* §8.2：认证失败直接断开，不回错误对象 */
          return;
        }
        phase = 'record';
        st.oks += 1;
        st.lastKeys = keys;
        let macHex = keys.proofS.toString('hex');
        if (o.badProofS) macHex = '00'.repeat(32);
        const okLine = Buffer.from(JSON.stringify({ type: 'auth', step: 'ok', mac: macHex }) + '\n');
        if (o.pipeline && o.pipeline.length) {
          /* 关键边界：ok 与第一条记录挤在同一个 TCP 段里 */
          const parts = [okLine];
          for (const p of o.pipeline) parts.push(sealer.seal(p));
          sock.write(Buffer.concat(parts));
        } else if (o.splitWrites) {
          const all = Buffer.concat([okLine]);
          for (const b of all) sock.write(Buffer.from([b]));
        } else {
          sock.write(okLine);
        }
        if (o.afterOk) o.afterOk(sess, st);
        return;
      }
      /* record 阶段 */
      try {
        for (const p of opener.push(Buffer.from(line, 'binary'))) { st.records.push(p); if (o.onRecord) o.onRecord(sess, p, st); }
      } catch (e) { st.errors.push(e.code || e.message); sock.destroy(); }
    };

    sock.on('data', (chunk) => {
      st.bytesIn += chunk.length;
      if (phase === 'record') {
        try {
          for (const p of opener.push(chunk)) { st.records.push(p); if (o.onRecord) o.onRecord(sess, p, st); }
        } catch (e) { st.errors.push(e.code || e.message); sock.destroy(); }
        return;
      }
      acc = Buffer.concat([acc, chunk]);
      let i;
      while ((i = acc.indexOf(0x0a)) >= 0) {
        const line = acc.subarray(0, i).toString('utf8');
        acc = acc.subarray(i + 1);
        onLine(line);
        if (phase === 'record') {
          if (acc.length) {
            try {
              for (const p of opener.push(acc)) { st.records.push(p); if (o.onRecord) o.onRecord(sess, p, st); }
            } catch (e) { st.errors.push(e.code || e.message); sock.destroy(); }
          }
          acc = Buffer.alloc(0);
          return;
        }
      }
    });
    sock.on('close', () => { st.closed = (st.closed || 0) + 1; });
  });

  return new Promise((resolve) => {
    srv.listen(0, '127.0.0.1', () => {
      resolve({
        port: srv.address().port,
        st,
        close: () => new Promise((r) => {
          for (const s of st.sockets) { try { s.destroy(); } catch (_) {} }
          srv.close(() => r());
        }),
      });
    });
  });
}

/* ==========================================================================
 * A. §8.2 密钥派生
 * ========================================================================== */
async function partA() {
  console.log('\nA. §8.2 密钥派生（已知答案）');

  eq('KAT master', A.KAT.master, 'b70bcc8b6faaad27101a4fa3924bb179df10f6c1eb683c401ebd5899315b4093');

  const self = A.selfTest();
  for (const [name, f] of Object.entries(self.fields)) eq('selfTest.' + name, f.got, f.want);
  ok('selfTest 总判定', self.ok === true);

  /* 独立复算一次（不经过 selfTest），防止 KAT 常量与实现一起写错 */
  const k = A.deriveSession({ secret: A.KAT.codeword, salt: A.KAT.salt, nc: A.KAT.nc, ns: A.KAT.ns, deviceId: A.KAT.deviceId });
  eq('deriveSession.master', k.master.toString('hex'), A.KAT.master);
  eq('deriveSession.proofC', k.proofC.toString('hex'), A.KAT.proofC);
  eq('deriveSession.proofS', k.proofS.toString('hex'), A.KAT.proofS);
  eq('deriveSession.keyC2S', k.keyC2S.toString('hex'), A.KAT.keyC2S);
  eq('deriveSession.keyS2C', k.keyS2C.toString('hex'), A.KAT.keyS2C);

  /* 手工按 §8.2 的字符串拼接复算 proof_C，钉住"拼 hex 文本而不是原始字节" */
  const manualMaster = Buffer.from(require('crypto').hkdfSync('sha256', Buffer.from(A.KAT.codeword, 'utf8'),
    Buffer.from(A.KAT.salt, 'hex'), Buffer.from('hamster-auth/v1', 'utf8'), 32));
  const manualProofC = require('crypto').createHmac('sha256', manualMaster)
    .update('hamster-client-proof/v2\n' + A.KAT.nc + '\n' + A.KAT.ns + '\n' + A.KAT.deviceId, 'utf8').digest('hex');
  eq('手工拼接 proof_C 与实现一致', manualProofC, A.KAT.proofC);

  ok('c2s / s2c 密钥不同', k.keyC2S.toString('hex') !== k.keyS2C.toString('hex'));

  const k2 = A.deriveSession({ secret: A.KAT.codeword, salt: A.KAT.salt, nc: A.KAT.nc, ns: A.KAT.ns, deviceId: A.KAT.deviceId });
  eq('派生是确定性的', k2.master.toString('hex'), k.master.toString('hex'));

  const k3 = A.deriveSession({ secret: A.KAT.codeword, salt: A.KAT.salt, nc: A.KAT.nc, ns: A.KAT.ns, deviceId: 'other-device' });
  ok('device_id 进入 proof_C', k3.proofC.toString('hex') !== k.proofC.toString('hex'));
  eq('device_id 不进 proof_S', k3.proofS.toString('hex'), k.proofS.toString('hex'));

  const k4 = A.deriveSession({ secret: A.KAT.codeword, salt: 'aabbccddeeff00112233445566778898', nc: A.KAT.nc, ns: A.KAT.ns, deviceId: A.KAT.deviceId });
  ok('salt 变化 → 记录密钥变化', k4.keyC2S.toString('hex') !== k.keyC2S.toString('hex'));

  const k5 = A.deriveSession({ secret: A.KAT.codeword, salt: A.KAT.salt, nc: '0'.repeat(32), ns: A.KAT.ns, deviceId: A.KAT.deviceId });
  ok('nc 变化 → 记录密钥变化', k5.keyS2C.toString('hex') !== k.keyS2C.toString('hex'));

  throwsWith('拒绝空 secret', () => A.deriveSession({ secret: '', salt: A.KAT.salt, nc: A.KAT.nc, ns: A.KAT.ns, deviceId: 'x' }), 'bad_key_material');
  throwsWith('拒绝非 hex salt', () => A.deriveSession({ secret: 's', salt: 'zz', nc: A.KAT.nc, ns: A.KAT.ns, deviceId: 'x' }), 'bad_salt');
  throwsWith('拒绝短 ns', () => A.deriveSession({ secret: 's', salt: A.KAT.salt, nc: A.KAT.nc, ns: 'abcd', deviceId: 'x' }), 'bad_nonce');
  throwsWith('拒绝空 device_id', () => A.deriveSession({ secret: 's', salt: A.KAT.salt, nc: A.KAT.nc, ns: A.KAT.ns, deviceId: '' }), 'bad_device_id');

  ok('ctEqual 相等', A.ctEqual(Buffer.from('ab', 'hex'), Buffer.from('ab', 'hex')) === true);
  ok('ctEqual 不等', A.ctEqual(Buffer.from('ab', 'hex'), Buffer.from('ac', 'hex')) === false);
  ok('ctEqual 长度不同', A.ctEqual(Buffer.from('ab', 'hex'), Buffer.from('abcd', 'hex')) === false);
  ok('randomHex16 是 32 hex', /^[0-9a-f]{32}$/.test(A.randomHex16()));
}

/* ==========================================================================
 * B. §8.3 记录层
 * ========================================================================== */
async function partB() {
  console.log('\nB. §8.3 记录层');

  const key = Buffer.alloc(32, 0x11);
  const keyB = Buffer.alloc(32, 0x22);

  const s = new A.RecordSealer(key, A.DIR_C2S);
  const r = new A.RecordOpener(key, A.DIR_C2S);

  const one = Buffer.from('hello 世界', 'utf8');
  const rec = s.seal(one);
  eq('单条记录长度 = 12 + 明文 + 16', rec.length, 12 + one.length + 16);
  eq('记录 len 字段 = 明文字节数', rec.readUInt32BE(0), one.length);
  eq('记录 counter 字段 = 0', rec.readBigUInt64BE(4).toString(), '0');
  const out = r.push(rec);
  eq('解出 1 块', out.length, 1);
  ok('明文一致', out[0].equals(one));

  const two = s.seal(Buffer.from('second'));
  ok('第二条 counter = 1', two.readBigUInt64BE(4).toString() === '1');
  const out2 = r.push(two);
  ok('第二条解密正确', out2.length === 1 && out2[0].toString() === 'second');

  /* 上空记录 */
  throwsWith('seal 拒绝空输入', () => new A.RecordSealer(key, A.DIR_C2S).seal(Buffer.alloc(0)), 'empty_record');

  /* 64 KiB 边界与超限拆分 */
  const big = Buffer.alloc(A.MAX_PLAINTEXT + 100, 0x5a);
  const s2 = new A.RecordSealer(key, A.DIR_C2S);
  const bigRec = s2.seal(big);
  const r2 = new A.RecordOpener(key, A.DIR_C2S);
  const bigOut = r2.push(bigRec);
  eq('100 KiB 拆成 2 条记录', bigOut.length, 2);
  eq('第一块 = 64 KiB', bigOut[0].length, A.MAX_PLAINTEXT);
  eq('第二块 = 剩余 100 字节', bigOut[1].length, 100);
  ok('大块内容无损', Buffer.concat(bigOut).equals(big));

  /* 精确 64 KiB 只出一条 */
  const exact = new A.RecordSealer(key, A.DIR_C2S).seal(Buffer.alloc(A.MAX_PLAINTEXT, 7));
  eq('精确 64 KiB 只出一条记录', exact.length, 12 + A.MAX_PLAINTEXT + 16);

  /* 分片：逐字节喂 */
  const s3 = new A.RecordSealer(key, A.DIR_C2S);
  const r3 = new A.RecordOpener(key, A.DIR_C2S);
  const framed = Buffer.concat([s3.seal(Buffer.from('AAA')), s3.seal(Buffer.from('BBBB'))]);
  let got3 = [];
  for (const b of framed) got3 = got3.concat(r3.push(Buffer.from([b])));
  eq('逐字节喂也解出 2 块', got3.length, 2);
  eq('逐字节内容正确', got3.map((b) => b.toString()).join('|'), 'AAA|BBBB');

  /* 半包：前 10 字节不产出，补全后产出 */
  const s4 = new A.RecordSealer(key, A.DIR_C2S);
  const r4 = new A.RecordOpener(key, A.DIR_C2S);
  const rec4 = s4.seal(Buffer.from('half-packet'));
  eq('半包不产出明文', r4.push(rec4.subarray(0, 10)).length, 0);
  const rest = r4.push(rec4.subarray(10));
  ok('补全后产出明文', rest.length === 1 && rest[0].toString() === 'half-packet');

  /* 篡改密文 / tag */
  const sT = new A.RecordSealer(key, A.DIR_C2S);
  const recT = sT.seal(Buffer.from('tamper-me'));
  const bad1 = Buffer.from(recT); bad1[12] ^= 0xff;
  throwsWith('篡改密文 → aead_failed', () => new A.RecordOpener(key, A.DIR_C2S).push(bad1), 'aead_failed');
  const bad2 = Buffer.from(recT); bad2[bad2.length - 1] ^= 0x01;
  throwsWith('篡改 tag → aead_failed', () => new A.RecordOpener(key, A.DIR_C2S).push(bad2), 'aead_failed');

  /* 篡改 counter（AAD 绑定） */
  const sC = new A.RecordSealer(key, A.DIR_C2S);
  const recC = sC.seal(Buffer.from('counter-bound'));
  const bad3 = Buffer.from(recC); bad3.writeBigUInt64BE(5n, 4);
  throwsWith('篡改 counter → bad_counter', () => new A.RecordOpener(key, A.DIR_C2S).push(bad3), 'bad_counter');

  /* 方向反射：c2s 的记录用 s2c 打开必须失败 */
  const sR = new A.RecordSealer(key, A.DIR_C2S);
  const recR = sR.seal(Buffer.from('reflected'));
  throwsWith('方向反射 → aead_failed', () => new A.RecordOpener(key, A.DIR_S2C).push(recR), 'aead_failed');

  /* 密钥隔离 */
  const recK = new A.RecordSealer(key, A.DIR_C2S).seal(Buffer.from('wrong-key'));
  throwsWith('换个密钥解不开', () => new A.RecordOpener(keyB, A.DIR_C2S).push(recK), 'aead_failed');

  /* 伪造长度头 */
  const bogus0 = Buffer.alloc(12); bogus0.writeUInt32BE(0, 0);
  throwsWith('len=0 → bad_record_len', () => new A.RecordOpener(key, A.DIR_S2C).push(bogus0), 'bad_record_len');
  const bogusBig = Buffer.alloc(12); bogusBig.writeUInt32BE(A.MAX_PLAINTEXT + 1, 0);
  throwsWith('len>64KiB → bad_record_len', () => new A.RecordOpener(key, A.DIR_S2C).push(bogusBig), 'bad_record_len');

  /* 记录重放：同一记录喂两次 */
  const sP = new A.RecordSealer(key, A.DIR_S2C);
  const rP = new A.RecordOpener(key, A.DIR_S2C);
  const recP = sP.seal(Buffer.from('once'));
  rP.push(recP);
  throwsWith('重复喂同一条记录 → bad_counter', () => rP.push(recP), 'bad_counter');
}

/* ==========================================================================
 * C. §8.2 握手（mock server）
 * ========================================================================== */
async function partC() {
  console.log('\nC. §8.2 握手 + 记录层联调');

  const SECRET = 'unit-test-codeword-0123456789';
  const DEVICE = 'dev_1700000000000';

  /* --- C1 正常握手 --- */
  {
    const srv = await mkServer({ secret: SECRET, pipeline: [Buffer.from('early-bird')] });
    const got = [];
    const t = await A.AeadTransport.connect({ port: srv.port, secret: SECRET, deviceId: DEVICE, onData: (b) => got.push(b) });
    ok('握手成功', t.ready === true);
    eq('server 收到 1 次 hello', srv.st.hellos, 1);
    eq('server 收到 1 次 proof', srv.st.proofs, 1);
    eq('server 认证成功', srv.st.authFails, 0);
    eq('服务端版本可见', t.peer.version, '0.0.9');
    ok('两端派生密钥一致（c2s）', t.keys.keyC2S.equals(srv.st.lastKeys.keyC2S));
    ok('两端派生密钥一致（s2c）', t.keys.keyS2C.equals(srv.st.lastKeys.keyS2C));
    await delay(50);
    eq('ok 同包下发的记录没丢', got.length, 1);
    eq('同包记录内容正确', got[0] && got[0].toString(), 'early-bird');
    t.destroy();
    await srv.close();
  }

  /* --- C2 双向数据 --- */
  {
    const srv = await mkServer({ secret: SECRET });
    const got = [];
    const t = await A.AeadTransport.connect({ port: srv.port, secret: SECRET, deviceId: DEVICE, onData: (b) => got.push(b) });
    const msgs = [Buffer.from('one'), Buffer.alloc(1000, 0x41), Buffer.from('三')];
    for (const m of msgs) t.write(m);
    await delay(120);
    eq('服务端收到 3 条', srv.st.records.length, 3);
    ok('内容与顺序一致', srv.st.records.map((b) => b.toString('hex')).join(',') === msgs.map((b) => b.toString('hex')).join(','));

    /* 服务端回发两条（用同一会话密钥的独立 sealer，模拟服务端发送方向） */
    const sd = srv.st.sockets[0];
    const sealer = new A.RecordSealer(t.keys.keyS2C, A.DIR_S2C);
    sd.write(sealer.seal(Buffer.from('pong-1')));
    sd.write(sealer.seal(Buffer.from('pong-2')));
    await delay(120);
    eq('客户端收到 2 条', got.length, 2);
    eq('客户端内容正确', got.map((b) => b.toString()).join('|'), 'pong-1|pong-2');

    /* 超 64 KiB 自动分条 */
    const huge = Buffer.alloc(70000, 0x42);
    t.write(huge);
    await delay(150);
    eq('70 KB 被拆成 2 条', srv.st.records.length, 5);
    ok('70 KB 内容无损', Buffer.concat(srv.st.records.slice(3)).equals(huge));
    t.destroy();
    await srv.close();
  }

  /* --- C3 服务端 proof_S 错误 → 客户端必须拒绝 --- */
  {
    const srv = await mkServer({ secret: SECRET, badProofS: true });
    const err = await expectReject('proof_S 错 → server_auth_failed',
      A.AeadTransport.connect({ port: srv.port, secret: SECRET, deviceId: DEVICE, timeoutMs: 1500 }),
      ['server_auth_failed']);
    ok('错误对象带机器码', !!err && err.code === 'server_auth_failed');
    const before = srv.st.bytesIn;
    await delay(150);
    eq('客户端在 proof 之后没有再发一个字节', srv.st.bytesIn, before);
    eq('客户端发过的字节装得下 hello + proof', before > 0 && before < 400, true);
    await srv.close();
  }

  /* --- C4 口令不一致 → 服务端静默断开 --- */
  {
    const srv = await mkServer({ secret: SECRET });
    await expectReject('错口令 → 连接被关闭',
      A.AeadTransport.connect({ port: srv.port, secret: 'wrong-codeword', deviceId: DEVICE, timeoutMs: 1500 }),
      ['socket_closed', 'auth_timeout', 'socket_error']);
    eq('服务端判认证失败', srv.st.authFails, 1);
    eq('服务端从不发 ok', srv.st.oks, 0);
    await srv.close();
  }

  /* --- C5 挑战包参数不对 → 立刻失败 --- */
  {
    const cases = [
      [{ alg: 'aes-256-gcm' }, 'bad_auth_alg'],
      [{ kdf: 'pbkdf2' }, 'bad_auth_kdf'],
      [{ v: 3 }, 'bad_auth_version'],
      [{ salt: 'zzzz' }, 'bad_salt'],
      [{ ns: '00' }, 'bad_nonce'],
    ];
    for (const [patch, code] of cases) {
      const srv = await mkServer({ secret: SECRET, challengePatch: patch });
      await expectReject('挑战包 ' + Object.keys(patch)[0] + ' 非法 → ' + code,
        A.AeadTransport.connect({ port: srv.port, secret: SECRET, deviceId: DEVICE, timeoutMs: 1500 }), [code]);
      await srv.close();
    }
  }

  /* --- C6 握手阶段超长行 --- */
  {
    const srv = await mkServer({
      secret: SECRET,
      afterChallenge: (sess) => { sess.writeRaw(Buffer.alloc(2048, 0x41)); },
    });
    await expectReject('握手行超 1 KiB → auth_line_too_long',
      A.AeadTransport.connect({ port: srv.port, secret: SECRET, deviceId: DEVICE, timeoutMs: 1500 }),
      ['auth_line_too_long']);
    await srv.close();
  }

  /* --- C7 握手之后不得再出现明文行 --- */
  {
    const srv = await mkServer({
      secret: SECRET,
      afterOk: (sess) => { sess.writeRaw(Buffer.from('{"type":"response","id":"x"}\n')); },
    });
    const t = await A.AeadTransport.connect({ port: srv.port, secret: SECRET, deviceId: DEVICE, timeoutMs: 1500 });
    const pe = await once(t, 'protocol_error', 1500).catch(() => null);
    ok('握手后明文输入被判为记录层错误', !!pe && (pe.code === 'bad_record_len' || pe.code === 'aead_failed'), pe && pe.code);
    ok('连接已关闭', t.ready === false);
    await srv.close();
  }

  /* --- C8 服务端发错方向（用自己的 s2c 记录冒充 c2s 记录） --- */
  {
    const srv = await mkServer({ secret: SECRET });
    const t = await A.AeadTransport.connect({ port: srv.port, secret: SECRET, deviceId: DEVICE, timeoutMs: 1500 });
    const sd = srv.st.sockets[0];
    const wrongDir = new A.RecordSealer(t.keys.keyC2S, A.DIR_C2S).seal(Buffer.from('reflection'));
    sd.write(wrongDir);
    const pe = await once(t, 'protocol_error', 1500).catch(() => null);
    ok('方向反射被拒', !!pe && pe.code === 'aead_failed', pe && pe.code);
    await srv.close();
  }

  /* --- C9 客户端未就绪时写 → 抛错 --- */
  {
    const fake = new A.AeadTransport({ write() {}, destroy() {}, end() {}, pause() {}, resume() {}, listenerCount() { return 0; } },
      { keyC2S: Buffer.alloc(32), keyS2C: Buffer.alloc(32) }, {});
    throwsWith('未握手 write → not_ready', () => fake.write('x'), 'not_ready');
  }
}

/* ==========================================================================
 * D. 纯 JS 后备实现（Electron 上没有原生 chacha20-poly1305）
 *
 * Electron 28 的 Node 是 BoringSSL 构建，crypto.getCiphers() 里没有
 * chacha20-poly1305；GUI 必须靠纯 JS 路径。这里把两条路径用同一组向量
 * 各跑一遍，并要求"原生 vs JS"在随机数据上逐字节相同。
 * ========================================================================== */
async function partBackend() {
  console.log('\nD. 密码学后端（native / js）');
  const active = A.backend();
  ok('当前后端是 native 或 js', active === 'native' || active === 'js', active);

  /* 用 RecordSealer/Opener 走完整记录层，两条后端各来一遍 */
  const runRecord = (name) => {
    const k = A.deriveSession({
      secret: A.KAT.codeword, salt: A.KAT.salt, nc: A.KAT.nc, ns: A.KAT.ns, deviceId: A.KAT.deviceId,
    });
    const rec = Buffer.from(
      '0000001600000000000000009ce1a63ce456aa4daf9fa9a793e18801d750ccbdb2d56f8f1df473107be2361294d7523b599f', 'hex');
    const srv = new A.RecordOpener(k.keyC2S, A.DIR_C2S);
    const out = srv.push(rec);
    ok(name + '：能解开 C/JS 产出的固定记录',
      out.length === 1 && out[0].toString() === 'hamster-interop-vector',
      out.length ? JSON.stringify(out[0].toString()) : '(无输出)');
    const mine = new A.RecordSealer(k.keyC2S, A.DIR_C2S).seal(Buffer.from('hamster-interop-vector'));
    ok(name + '：重封的字节与固定向量完全相同', mine.equals(rec));

    /* 大块往返 */
    const data = Buffer.alloc(100 * 1024, 0x5a);
    const sealed = new A.RecordSealer(k.keyS2C, A.DIR_S2C).seal(data);
    const back = new A.RecordOpener(k.keyS2C, A.DIR_S2C).push(sealed);
    ok(name + '：100 KiB 往返一致', Buffer.concat(back).equals(data));
  };

  /* 1) 强制 JS 后端跑一遍（这就是 Electron 里的实际路径） */
  const prev = A.setBackend('js');
  eq('可以切到 js 后端', prev, 'js');
  runRecord('js');
  {
    const key = Buffer.from('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f', 'hex');
    const nonce = Buffer.from('070000004041424344454647', 'hex');
    const aad = Buffer.from('50515253c0c1c2c3c4c5c6c7', 'hex');
    const plain = Buffer.from("Ladies and Gentlemen of the class of '99: If I could offer you only one tip " +
      'for the future, sunscreen would be it.');
    const r = A.seal(key, nonce, aad, plain);
    eq('js 后端 §2.8.2 密文', r.ct.toString('hex'),
      'd31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6' +
      '3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36' +
      '92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc' +
      '3ff4def08e4b7a9de576d26586cec64b6116');
    eq('js 后端 §2.8.2 tag', r.tag.toString('hex'), '1ae10b594f09e26a7e902ecbd0600691');
    const open = A.open(key, nonce, aad, r.ct, r.tag);
    ok('js 后端解密还原', open.equals(plain));
  }

  /* 2) 有原生实现时，两种后端必须在随机数据上逐字节一致 */
  if (active === 'native') {
    A.setBackend('native');
    const key = require('crypto').randomBytes(32);
    const nonce = require('crypto').randomBytes(12);
    const aad = require('crypto').randomBytes(9);
    const data = require('crypto').randomBytes(7777);
    const nat = A.seal(key, nonce, aad, data);
    runRecord('native');
    A.setBackend('js');
    const jsr = A.seal(key, nonce, aad, data);
    ok('native 与 js 的密文完全相同', nat.ct.equals(jsr.ct));
    ok('native 与 js 的 tag 完全相同', nat.tag.equals(jsr.tag));
  } else {
    console.log('  （本运行时没有原生 chacha20-poly1305，跳过一致性对比）');
  }

  A.setBackend('auto');
}

/* ==========================================================================
 * main
 * ========================================================================== */
(async () => {
  await partA();
  await partB();
  await partC();
  await partBackend();
  console.log('\n=== 结果: 通过 ' + pass + ', 失败 ' + fail + ' ===');
  process.exit(fail === 0 ? 0 : 1);
})().catch((e) => {
  console.error('\n测试异常: ' + ((e && e.stack) || e));
  process.exit(1);
});
