/*
 * hamster-aead — Hamster 传输加密（PROTOCOL §8，目标 0.0.9，纯 Node）
 *
 * 本文件只做三件事，全部按 §8 逐字实现：
 *   §8.2  握手密钥派生（master / proof_C / proof_S / key_c2s / key_s2c）
 *   §8.3  记录层（len|counter|密文|tag，ChaCha20-Poly1305）
 *   §8.2  客户端握手状态机（sendHello → challenge → 验 proof_S → proof → ok）
 *
 * 约束：
 *   - **禁止 require('electron')**：主进程、tests/*.js、将来的 CLI 共用。
 *   - 上层语义不变：记录层只是把字节流切块加密，明文流内部仍然是
 *     0.0.8 的 JSON 行 + payload_bytes + 裸负载（§3），所以 FrameParser 不需要改。
 *   - 出错一律抛 AeadError（带机器码）；握手失败**不回错误对象**，直接断开（§8.2/§8.3），
 *     这是协议要求，不要在调用方"补一个更友好的错误"。
 *
 * 已知限制（§8.0 已声明）：PSK 握手，不做前向保密、不做证书、不做密钥轮换。
 * 另外：任何一次握手被完整录制后，攻击者都可以离线猜测口令（HMAC 输出可作为校验），
 * 这是所有 PSK 握手的共性，不是本实现的缺陷 —— 口令强度仍然是唯一的防线。
 */
'use strict';

const crypto = require('crypto');
const { EventEmitter } = require('events');

/* ==========================================================================
 * 常量（改动任何一个都要同步 PROTOCOL §8 与 C 侧 hd_net.c）
 * ========================================================================== */
const AUTH_VERSION = 2;
const AUTH_LINE_MAX = 1024;             /* §8.2 明文阶段单行上限 */
const SALT_LEN = 16;
const NONCE_LEN = 16;                   /* nc / ns：16 字节 */
const KEY_LEN = 32;
const TAG_LEN = 16;
const MAX_PLAINTEXT = 65536;            /* 单条记录明文上限（HD_CHUNK = 64 KiB） */
const REC_HDR_LEN = 12;                 /* len(4) + counter(8) */
const REC_OVERHEAD = REC_HDR_LEN + TAG_LEN;
const COUNTER_MAX = 0xffffffffffffffffn;

const DIR_C2S = 0x01;
const DIR_S2C = 0x02;

const AUTH_INFO = 'hamster-auth/v1';
const REC_C2S_INFO = 'hamster-rec-c2s/v2';
const REC_S2C_INFO = 'hamster-rec-s2c/v2';
const PROOF_C_PREFIX = 'hamster-client-proof/v2\n';
const PROOF_S_PREFIX = 'hamster-server-proof/v2\n';

const HEX16_RE = /^[0-9a-f]{32}$/;
const HEX64_RE = /^[0-9a-f]{64}$/;

/* ==========================================================================
 * 错误：机器码就是契约（与 HamsterError 的 code 同一套用法）
 * ========================================================================== */
class AeadError extends Error {
  constructor(code, detail) {
    super(detail ? (code + ': ' + detail) : String(code));
    this.name = 'AeadError';
    this.code = String(code || 'aead_error');
    this.detail = detail === undefined || detail === null ? '' : String(detail);
  }
}

/* ==========================================================================
 * 小工具
 * ========================================================================== */
function isHex(v, re) { return typeof v === 'string' && re.test(v); }

function asBuffer(v, what) {
  if (Buffer.isBuffer(v)) return v;
  if (typeof v === 'string') return Buffer.from(v, 'utf8');
  throw new AeadError('bad_key_material', what || 'expected string or Buffer');
}

/** 16 字节随机数（§8.2 的 nc / ns / salt） */
function randomHex16() { return crypto.randomBytes(NONCE_LEN).toString('hex'); }

/** 常量时间比较（长度不同直接 false，长度本身不是秘密） */
function ctEqual(a, b) {
  const x = asBuffer(a);
  const y = asBuffer(b);
  if (x.length !== y.length) return false;
  try { return crypto.timingSafeEqual(x, y); } catch (_) { return false; }
}

/* ==========================================================================
 * §8.2 密钥派生
 * ========================================================================== */
function hkdf32(salt, ikm, info) {
  const out = crypto.hkdfSync('sha256', asBuffer(ikm), asBuffer(salt), asBuffer(info), KEY_LEN);
  return Buffer.from(out);
}

function hmac32(key, text) {
  return crypto.createHmac('sha256', asBuffer(key)).update(Buffer.from(text, 'utf8')).digest();
}

/**
 * 一次连接的密钥材料。所有入参都必须是**已有的十六进制字符串**（16 字节 → 32 个 hex 字符），
 * 因为 §8.2 规定 info / proof 原文里拼的是 hex 文本，不是原始字节 —— 这里最容易写错。
 *
 * @param {{secret:string|Buffer, salt:string, nc:string, ns:string, deviceId:string}} o
 * @returns {{master:Buffer, proofC:Buffer, proofS:Buffer, keyC2S:Buffer, keyS2C:Buffer}}
 */
function deriveSession(o) {
  const opt = o || {};
  const secret = opt.secret;
  if (secret === undefined || secret === null || secret === '') {
    throw new AeadError('bad_key_material', 'secret (codeword / api_key) required');
  }
  if (!isHex(opt.salt, HEX16_RE)) throw new AeadError('bad_salt', 'salt must be 32 hex chars');
  if (!isHex(opt.nc, HEX16_RE)) throw new AeadError('bad_nonce', 'nc must be 32 hex chars');
  if (!isHex(opt.ns, HEX16_RE)) throw new AeadError('bad_nonce', 'ns must be 32 hex chars');
  const deviceId = opt.deviceId === undefined || opt.deviceId === null ? '' : String(opt.deviceId);
  if (!deviceId) throw new AeadError('bad_device_id', 'device_id required');

  const saltBin = Buffer.from(opt.salt, 'hex');
  const master = hkdf32(saltBin, secret, AUTH_INFO);

  const proofC = hmac32(master, PROOF_C_PREFIX + opt.nc + '\n' + opt.ns + '\n' + deviceId);
  const proofS = hmac32(master, PROOF_S_PREFIX + opt.nc + '\n' + opt.ns);

  const keyC2S = hkdf32(saltBin, master, REC_C2S_INFO + opt.nc + opt.ns);
  const keyS2C = hkdf32(saltBin, master, REC_S2C_INFO + opt.nc + opt.ns);

  return { master, proofC, proofS, keyC2S, keyS2C };
}

/* ==========================================================================
 * §8.3 记录层
 * ========================================================================== */
function nonceFor(counter) {
  const n = Buffer.alloc(12);
  n.writeBigUInt64BE(BigInt(counter), 4);
  return n;
}

function aadFor(dir, counter) {
  const a = Buffer.alloc(9);
  a[0] = dir;
  a.writeBigUInt64BE(BigInt(counter), 1);
  return a;
}

function sealOne(key, dir, counter, plain) {
  const c = crypto.createCipheriv('chacha20-poly1305', key, nonceFor(counter), { authTagLength: TAG_LEN });
  c.setAAD(aadFor(dir, counter));
  const ct = Buffer.concat([c.update(plain), c.final()]);
  return { ct, tag: c.getAuthTag() };
}

function openOne(key, dir, counter, ct, tag) {
  const d = crypto.createDecipheriv('chacha20-poly1305', key, nonceFor(counter), { authTagLength: TAG_LEN });
  d.setAAD(aadFor(dir, counter));
  d.setAuthTag(tag);
  /* final() 抛异常时 update() 已经返回过的明文只存在于局部变量里，不交给调用方 */
  return Buffer.concat([d.update(ct), d.final()]);
}

/** 发送方向：把任意长度的明文字节流切成 ≤64 KiB 的记录 */
class RecordSealer {
  /**
   * @param {Buffer} key 32 字节
   * @param {number} dir DIR_C2S | DIR_S2C
   */
  constructor(key, dir) {
    if (!Buffer.isBuffer(key) || key.length !== KEY_LEN) throw new AeadError('bad_key', 'sealer key must be 32 bytes');
    if (dir !== DIR_C2S && dir !== DIR_S2C) throw new AeadError('bad_direction', String(dir));
    this.key = key;
    this.dir = dir;
    this.counter = 0n;
  }

  /** @param {Buffer|string} data @returns {Buffer} 可能包含多条记录 */
  seal(data) {
    const plain = asBuffer(data, 'seal() expects Buffer or string');
    if (plain.length === 0) throw new AeadError('empty_record', 'refusing to seal an empty record');
    const parts = [];
    let off = 0;
    while (off < plain.length) {
      const n = Math.min(MAX_PLAINTEXT, plain.length - off);
      const cnt = this.counter;
      if (cnt > COUNTER_MAX) throw new AeadError('counter_exhausted');
      const chunk = plain.subarray(off, off + n);
      const { ct, tag } = sealOne(this.key, this.dir, cnt, chunk);
      const hdr = Buffer.alloc(REC_HDR_LEN);
      hdr.writeUInt32BE(n, 0);
      hdr.writeBigUInt64BE(cnt, 4);
      parts.push(hdr, ct, tag);
      this.counter += 1n;
      off += n;
    }
    return parts.length === 1 ? parts[0] : Buffer.concat(parts);
  }
}

/** 接收方向：严格按对端 counter 递增的顺序还原明文 */
class RecordOpener {
  /**
   * @param {Buffer} key 32 字节
   * @param {number} dir 期望收到的方向（DIR_C2S 表示"对端是客户端"）
   */
  constructor(key, dir) {
    if (!Buffer.isBuffer(key) || key.length !== KEY_LEN) throw new AeadError('bad_key', 'opener key must be 32 bytes');
    if (dir !== DIR_C2S && dir !== DIR_S2C) throw new AeadError('bad_direction', String(dir));
    this.key = key;
    this.dir = dir;
    this.expected = 0n;
    this._buf = Buffer.alloc(0);
  }

  /**
   * 喂入 socket 字节，返回本次解出的明文块（可能为空数组）。
   * 任何结构/认证错误都抛 AeadError —— 调用方必须直接断开，不解释（§8.3）。
   */
  push(chunk) {
    if (chunk && chunk.length) this._buf = this._buf.length ? Buffer.concat([this._buf, chunk]) : Buffer.from(chunk);
    const out = [];
    for (;;) {
      if (this._buf.length < REC_HDR_LEN) break;
      const len = this._buf.readUInt32BE(0);
      if (len === 0 || len > MAX_PLAINTEXT) {
        throw new AeadError('bad_record_len', 'len=' + len);
      }
      const total = REC_HDR_LEN + len + TAG_LEN;
      if (this._buf.length < total) break;

      const counter = this._buf.readBigUInt64BE(4);
      if (counter !== this.expected) {
        throw new AeadError('bad_counter', 'got ' + counter.toString() + ' want ' + this.expected.toString());
      }
      const ct = this._buf.subarray(REC_HDR_LEN, REC_HDR_LEN + len);
      const tag = this._buf.subarray(REC_HDR_LEN + len, total);
      let plain;
      try {
        plain = openOne(this.key, this.dir, counter, ct, tag);
      } catch (_) {
        /* 不把"哪一条坏了"告诉对端，也不把可能已解出的前缀交出去 */
        throw new AeadError('aead_failed', 'record ' + counter.toString() + ' failed authentication');
      }
      out.push(plain);
      this.expected += 1n;
      this._buf = this._buf.subarray(total);
    }
    return out;
  }
}

/* ==========================================================================
 * §8.2 客户端握手 + 记录层套接字
 * ========================================================================== */
/**
 * 一条已加密的连接。对外只暴露"明文字节流"，其余与 net.Socket 的用法一致：
 *   await AeadTransport.connect({host, port, secret, deviceId})
 *   t.write(buf) / t.on('data', b => ...) / t.pause() / t.resume() / t.destroy()
 *
 * 握手失败时 connect() 一定 reject，且不会向对端发送任何记录。
 */
class AeadTransport extends EventEmitter {
  constructor(sock, keys, peer) {
    super();
    this._sock = sock;
    this._sealer = new RecordSealer(keys.keyC2S, DIR_C2S);
    this._opener = new RecordOpener(keys.keyS2C, DIR_S2C);
    this._ready = false;
    this._closed = false;
    this.keys = keys;
    this.peer = peer || {};
    this.bytesIn = 0;
    this.bytesOut = 0;
    this._onData = null;                /* connect({onData}) 提前挂的消费者 */
    this._pendingOut = [];              /* 尚无 'data' 监听者时先缓存，避免丢首个记录 */
    this._closeEmitted = false;
    this._lastError = null;
    this.on('newListener', (ev) => {
      if (ev !== 'data' || this._pendingOut.length === 0) return;
      /* newListener 在监听器真正挂上之前触发，故推迟一拍再冲刷 */
      setImmediate(() => {
        const q = this._pendingOut;
        this._pendingOut = [];
        for (const b of q) if (this.listenerCount('data')) this.emit('data', b);
      });
    });
  }

  get ready() { return this._ready && !this._closed; }
  /** 供上层按 net.Socket 的语义判断（HamsterConn.connected 会读它） */
  get destroyed() { return this._closed; }

  /**
   * @param {{host?:string,port:number,secret:string|Buffer,deviceId:string,hostname?:string,
   *          timeoutMs?:number,logger?:object,nc?:string}} opts
   *        logger 需要 debug/warn 两个方法（可省略）
   * @returns {Promise<AeadTransport>}
   */
  static connect(opts) {
    const o = opts || {};
    const net = require('net');
    const timeoutMs = Number(o.timeoutMs) || 5000;
    const log = o.logger || null;
    const dbg = (m) => { if (log && log.debug) log.debug('[aead] ' + m); };

    const nc = isHex(o.nc, HEX16_RE) ? o.nc : randomHex16();
    const deviceId = String(o.deviceId || '');
    const onData = typeof o.onData === 'function' ? o.onData : null;
    if (!deviceId) return Promise.reject(new AeadError('bad_device_id', 'device_id required'));
    if (!o.secret) return Promise.reject(new AeadError('bad_key_material', 'secret required'));

    return new Promise((resolve, reject) => {
      const sock = new net.Socket();
      let settled = false;
      const finish = (err, v) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (err) {
          try { sock.destroy(); } catch (_) {}
          reject(err);
        } else {
          resolve(v);
        }
      };
      const timer = setTimeout(() => finish(new AeadError('auth_timeout', '握手超时 ' + timeoutMs + 'ms')), timeoutMs);

      sock.setNoDelay(true);
      sock.setKeepAlive(true, 15000);

      let t = null;
      let expectStep = 'challenge';   /* challenge → ok */
      let late = Buffer.alloc(0);

      const sendLine = (obj) => {
        const line = JSON.stringify(obj) + '\n';
        if (Buffer.byteLength(line, 'utf8') > AUTH_LINE_MAX) throw new AeadError('line_too_long', 'auth line > 1KiB');
        sock.write(line);
        if (t) t.bytesOut += Buffer.byteLength(line, 'utf8');
      };

      const fail = (code, detail) => {
        dbg('握手失败 ' + code + (detail ? ': ' + detail : ''));
        finish(new AeadError(code, detail));
      };

      const handleLine = (line) => {
        let msg;
        try { msg = JSON.parse(line); } catch (_) { fail('bad_auth_json'); return; }
        if (!msg || msg.type !== 'auth') { fail('unexpected_plaintext'); return; }
        if (expectStep === 'challenge') {
          if (msg.step !== 'challenge') { fail('bad_auth_step', String(msg.step)); return; }
          if (msg.v !== AUTH_VERSION) { fail('bad_auth_version', String(msg.v)); return; }
          if (msg.alg !== 'chacha20poly1305') { fail('bad_auth_alg', String(msg.alg)); return; }
          if (msg.kdf !== 'hkdf-sha256') { fail('bad_auth_kdf', String(msg.kdf)); return; }
          if (!isHex(msg.salt, HEX16_RE)) { fail('bad_salt', String(msg.salt)); return; }
          if (!isHex(msg.ns, HEX16_RE)) { fail('bad_nonce', String(msg.ns)); return; }

          let keys;
          try {
            keys = deriveSession({ secret: o.secret, salt: msg.salt, nc, ns: msg.ns, deviceId });
          } catch (e) { fail(e.code || 'kdf_failed', e.message); return; }

          sendLine({ type: 'auth', step: 'proof', mac: keys.proofC.toString('hex') });
          t = new AeadTransport(sock, keys, { salt: msg.salt, ns: msg.ns, nc, server: msg.server, version: msg.version });
          t._onData = onData;
          expectStep = 'ok';
          return;
        }
        if (msg.step !== 'ok') { fail('bad_auth_step', String(msg.step)); return; }
        if (!isHex(msg.mac, HEX64_RE)) { fail('bad_server_proof', String(msg.mac)); return; }
        /* 客户端必须先验服务端，再敢发任何命令（§8.2） */
        if (!ctEqual(Buffer.from(msg.mac, 'hex'), t.keys.proofS)) { fail('server_auth_failed'); return; }

        t._ready = true;
        dbg('握手完成 server=' + String(t.peer.version || '?'));
        finish(null, t);
      };

      sock.on('data', (chunk) => {
        sock.pause();
        try {
          if (t) t.bytesIn += chunk.length;
          /* 已进入记录层：整块交给解密器（含握手成功后同段残留） */
          if (t && t._ready) {
            try { t._feedRecord(chunk); } catch (e) { t._protocolError(e); }
            return;
          }
          if (settled) return;                  /* 已失败，等 destroy 落地 */

          /* 握手阶段：按行切（单行上限 1 KiB，§8.2） */
          const buf = late.length ? Buffer.concat([late, chunk]) : chunk;
          let start = 0;
          for (;;) {
            const nl = buf.indexOf(0x0a, start);
            if (nl < 0) break;
            const line = buf.subarray(start, nl);
            start = nl + 1;
            if (line.length > AUTH_LINE_MAX) { fail('auth_line_too_long'); return; }
            if (line.length === 0) continue;
            try {
              handleLine(line.toString('utf8'));
            } catch (e) {
              fail((e && e.code) || 'auth_internal', e && e.message);
              return;
            }
            if (settled && (!t || !t._ready)) return;   /* 失败即停 */
            if (t && t._ready) {
              /* 切换后剩余字节属于记录层：不丢一个字节（否则 counter 永远对不上） */
              const rest = buf.subarray(start);
              if (rest.length) {
                try { t._feedRecord(rest); } catch (e) { t._protocolError(e); return; }
              }
              return;
            }
          }
          late = Buffer.from(buf.subarray(start));
          if (late.length > AUTH_LINE_MAX) { fail('auth_line_too_long'); return; }
        } finally {
          if (!sock.destroyed) sock.resume();
        }
      });
      sock.on('error', (e) => {
        dbg('socket 错误 ' + (e && e.message));
        if (!settled) { fail('socket_error', e && e.message); return; }
        if (t) t._safeEmit('error', e);
      });
      sock.on('close', () => {
        if (!settled) { fail('socket_closed', '连接被关闭'); return; }
        if (t) t._onClose();
      });
      sock.on('drain', () => { if (t) t._safeEmit('drain'); });
      sock.connect(Number(o.port), o.host || '127.0.0.1', () => {
        try {
          const hello = { type: 'auth', step: 'hello', v: AUTH_VERSION, device_id: deviceId, nc };
          if (o.hostname) hello.hostname = String(o.hostname);
          sendLine(hello);
        } catch (e) { fail(e.code || 'hello_failed', e.message); }
      });
    });
  }

  /** 记录层输入的公共入口（也用于握手后残留字节） */
  _feedRecord(chunk) {
    const plains = this._opener.push(chunk);
    for (const p of plains) {
      if (this._closed) return;
      this._emitData(p);
    }
  }

  _emitData(p) {
    /* onData 与 'data' 事件是两条入口，同时用就都会收到（各自幂等，一起来也无害） */
    if (this._onData) {
      try { this._onData(p); } catch (e) { this._safeEmit('error', e); }
    }
    if (this.listenerCount('data') > 0) this.emit('data', p);
    else if (!this._onData) this._pendingOut.push(p);
  }

  /** Node 的 'error' 事件无监听者会把异常抛到进程级；库代码不能这么干 */
  _safeEmit(ev, arg) {
    if (this.listenerCount(ev) > 0) this.emit(ev, arg);
  }

  _protocolError(e) {
    if (this._closed) return;
    this._lastError = e;
    /* 推迟一拍：connect() 刚刚 resolve 时调用方还没来得及挂监听器 */
    setImmediate(() => this._safeEmit('protocol_error', e));
    this.destroy(e && e.code ? e.code : 'record_error');
  }

  _onClose(reason) {
    if (this._closeEmitted) return;
    this._closeEmitted = true;
    this._closed = true;
    setImmediate(() => this._safeEmit('close', reason));
  }

  /** 写入明文（自动分条加密）。返回值与 net.Socket.write 一致：false=需要等待 'drain' */
  write(data) {
    if (!this._ready || this._closed) throw new AeadError('not_ready', '握手未完成或连接已关闭');
    const buf = this._sealer.seal(data);
    this.bytesOut += buf.length;
    return this._sock.write(buf);
  }

  pause() { try { this._sock.pause(); } catch (_) {} }
  resume() { try { this._sock.resume(); } catch (_) {} }
  setNoDelay(v) { try { this._sock.setNoDelay(v); } catch (_) {} }

  end() {
    if (this._closed) return;
    this._closed = true;
    try { this._sock.end(); } catch (_) {}
  }

  destroy(reason) {
    if (this._closed) return;
    this._closed = true;
    try { this._sock.destroy(); } catch (_) {}
    this._onClose(reason);
  }
}

/* ==========================================================================
 * §8.2 的已知答案（跨实现对齐锚点：C / JS / Kotlin 必须逐字节一致）
 * ========================================================================== */
const KAT = {
  codeword: 'hamster-e05258d0ff46edc9601c2b3d585d463d',
  nc: '00112233445566778899aabbccddeeff',
  salt: 'aabbccddeeff00112233445566778899',
  ns: 'ffeeddccbbaa99887766554433221100',
  deviceId: 'fedcba9876543210',
  master: 'b70bcc8b6faaad27101a4fa3924bb179df10f6c1eb683c401ebd5899315b4093',
  proofC: 'b85d15d5ad541d3767c635503c4c6964d23c6df8814eb3367b8c9c3eea84b4f8',
  proofS: '4d37e2d5947a1266f607dc980a33802553547924f4edefdf00397f3c33d35405',
  keyC2S: '0afb9175f1763c701d993ca436c99fee97b2cc4bd46202cd07fcc8e0e197ed9a',
  keyS2C: '912dfe620fcd01e26e12df77ff0bfaedf5a788d975732e14ddfd037bf2843866',
};

/** 用 KAT 自检本文件；返回 {ok, fields:{name:{want,got,ok}}} */
function selfTest() {
  const k = deriveSession({ secret: KAT.codeword, salt: KAT.salt, nc: KAT.nc, ns: KAT.ns, deviceId: KAT.deviceId });
  const fields = {};
  const pairs = [['master', k.master], ['proofC', k.proofC], ['proofS', k.proofS], ['keyC2S', k.keyC2S], ['keyS2C', k.keyS2C]];
  let ok = true;
  for (const [name, got] of pairs) {
    const want = KAT[name];
    const gotHex = got.toString('hex');
    const good = gotHex === want;
    if (!good) ok = false;
    fields[name] = { want, got: gotHex, ok: good };
  }
  return { ok, fields };
}

module.exports = {
  AeadError,
  AeadTransport,
  RecordSealer,
  RecordOpener,
  deriveSession,
  hkdf32,
  hmac32,
  randomHex16,
  ctEqual,
  KAT,
  selfTest,
  MAX_PLAINTEXT,
  REC_OVERHEAD,
  AUTH_VERSION,
  DIR_C2S,
  DIR_S2C,
};
