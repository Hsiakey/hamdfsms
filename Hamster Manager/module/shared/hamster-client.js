/*
 * hamster-client — Hamster 协议客户端库（ver.0.0.8，纯 Node）
 *
 * 用途与约束：
 *   - **禁止 require('electron')**：Electron 主进程与 tests/client-protocol.js 共用本文件，
 *     因此协议编解码、二进制分帧、路径校验、设备库、迁移编排全部放在这里，可被纯 Node 单测。
 *   - 主进程 main/index.js 只做"IPC 注册 + 窗口 + 进程生命周期"。
 *
 * 对照 PROTOCOL.md（唯一权威依据）修掉的历史问题：
 *   §3   二进制分帧：一律 Buffer 累积 + indexOf(0x0a) 切消息头 + 按**字节**计数，
 *        且实收字节数必须严格等于 payload_bytes，否则视为失败（旧的 toString()/binary 方案
 *        会把首包二进制按 UTF-8 解码再按 latin1 写回，必然损坏，且用字符串长度当字节数）。
 *   §1.1 按 type 分流：事件可能与响应交错到达同一条连接。
 *   §1.3 错误一定是 status:"error" 的 response，按 id 配对后抛出可读的机器码。
 *   §5   迁移编排：下载 → 字节校验 → 上传（带源端权威 hash）→ 目标端 hash 比对 → 才允许删源。
 */

'use strict';

const crypto = require('crypto');
const dgram = require('dgram');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');

/* §8 传输加密（握手 + 记录层）。放在同目录，纯 Node，无 electron 依赖。 */
const Aead = require(path.join(__dirname, 'hamster-aead.js'));

/* ==========================================================================
 * 常量
 * ========================================================================== */
const LINE_MAX = 256 * 1024;            /* 协议单行上限（负载不计入） */
const OUT_MAX = 1024 * 1024;            /* 响应上限：超过它说明协议流已不可信 */
const DEFAULT_HAMD_PORT = 9100;
const DEFAULT_IPC_PORT = 9102;
const DEFAULT_TIMEOUT_MS = 15000;       /* 普通命令 */
const TRANSFER_IDLE_MS = 60000;         /* 传输：多久没有任何字节进展就判失败 */
const TRANSFER_MAX_MS = 30 * 60 * 1000; /* 传输：绝对上限，兜底 */
const KEEPALIVE_MS = 15000;             /* 事件 socket 保活（TCP keepalive + 应用层 ping） */
const IDLE_HALF_OPEN_MS = 30000;        /* 事件 socket 空闲看门狗：判半开并重连 */
const DEVICE_ID_RE = /^dev_[0-9]{10,16}$/;

/* ==========================================================================
 * 错误：协议里的机器码就是客户端决策依据（PROTOCOL §1.3 / §4.1）
 * ========================================================================== */
class HamsterError extends Error {
  /**
   * @param {string} code   协议错误码（unauthenticated / path_denied / exists / timeout ...）
   * @param {string} [detail] 可选细节（来自响应 data.detail）
   */
  constructor(code, detail, extra) {
    super(detail ? (code + ': ' + detail) : String(code));
    this.name = 'HamsterError';
    this.code = String(code || 'error');
    this.detail = detail === undefined || detail === null ? '' : String(detail);
    if (extra && typeof extra === 'object') Object.assign(this, extra);
  }

  /** 转成 IPC 契约里的 {error, detail} 形状 */
  toResult() {
    const r = { error: this.code };
    if (this.detail) r.detail = this.detail;
    return r;
  }
}

function isHamsterError(e) {
  return !!e && e instanceof HamsterError;
}

/** 把任意异常归一成 {error, detail}（IPC handler 统一出口） */
function toErrorResult(e) {
  if (isHamsterError(e)) return e.toResult();
  const code = (e && e.code) ? String(e.code) : 'error';
  const detail = (e && e.message) ? String(e.message) : String(e || 'unknown error');
  return { error: code, detail };
}

function errorFromData(data) {
  const d = (data && typeof data === 'object') ? data : {};
  return new HamsterError(d.error || 'error', d.detail || '');
}

/* ==========================================================================
 * 日志（含 token/口令脱敏；落盘到用户数据目录）
 * ========================================================================== */
const LEVELS = { error: 0, warn: 1, info: 2, debug: 3 };

/**
 * 脱敏：任何 hk_ 前缀的 API 密钥、以及显式登记的密文（口令/token）一律替换掉。
 * 约束：只在日志出口做，不改业务数据。
 */
function redact(text, secrets) {
  let s = String(text === undefined || text === null ? '' : text);
  if (!s) return s;
  s = s.replace(/hk_[A-Za-z0-9_\-]{6,}/g, 'hk_***');
  if (Array.isArray(secrets)) {
    for (const sec of secrets) {
      const v = String(sec || '');
      if (v.length >= 4) s = s.split(v).join('***');
    }
  }
  return s;
}

/**
 * 创建日志器。
 * @param {{dir?:string,file?:string,level?:string,console?:boolean,secrets?:string[]}} opts
 * 约束：写盘失败绝不能影响主流程（try/catch 吞掉）；关闭时释放 fd。
 */
function createLogger(opts) {
  const o = opts || {};
  const level = LEVELS[o.level] === undefined ? LEVELS.info : LEVELS[o.level];
  const secrets = Array.isArray(o.secrets) ? o.secrets.filter(Boolean) : [];
  const showConsole = o.console !== false;
  let fd = null;
  let filePath = '';

  if (o.dir && o.file) {
    try {
      ensureDir(o.dir);
      filePath = path.join(o.dir, o.file);
      fd = fs.openSync(filePath, 'a');
    } catch (e) {
      fd = null;
      filePath = '';
    }
  }

  function write(lvl, msg) {
    if (LEVELS[lvl] === undefined) lvl = 'info';
    if (LEVELS[lvl] > level) return;
    const line = '[' + new Date().toISOString() + '] [' + lvl.toUpperCase() + '] ' + redact(msg, secrets);
    if (showConsole) {
      try { (lvl === 'error' ? console.error : lvl === 'warn' ? console.warn : console.log)(line); } catch (_) {}
    }
    if (fd !== null) {
      try { fs.writeSync(fd, Buffer.from(line + os.EOL, 'utf8')); } catch (_) {}
    }
  }

  return {
    filePath,
    level: Object.keys(LEVELS).find((k) => LEVELS[k] === level) || 'info',
    /** 登记新的密文（例如设备 token / 口令），此后日志里出现即脱敏 */
    addSecret(sec) { if (sec && String(sec).length >= 4 && secrets.indexOf(String(sec)) < 0) secrets.push(String(sec)); },
    error(msg) { write('error', msg); },
    warn(msg) { write('warn', msg); },
    info(msg) { write('info', msg); },
    debug(msg) { write('debug', msg); },
    close() { if (fd !== null) { try { fs.closeSync(fd); } catch (_) {} fd = null; } },
  };
}

/* ==========================================================================
 * 文件与原子写
 * （devices.json / migrations.json 都必须"临时文件 + fsync + rename"，解析失败不得静默置空）
 * ========================================================================== */
function ensureDir(dir) {
  if (!dir) return;
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

/**
 * 原子写文本：同目录临时文件 → fsync → rename 覆盖。
 * Windows 上 fs.renameSync 走 MoveFileEx(REPLACE_EXISTING)，是原子替换。
 * 注意：目录本身的 rename 持久化在 Windows 上无法 fsync，这里只保证文件内容与替换的原子性。
 */
function writeFileAtomicSync(file, text) {
  const dir = path.dirname(file);
  ensureDir(dir);
  const tmp = file + '.tmp-' + process.pid + '-' + Date.now().toString(36);
  const data = Buffer.from(String(text), 'utf8');
  const fd = fs.openSync(tmp, 'w');
  try {
    let off = 0;
    while (off < data.length) off += fs.writeSync(fd, data, off, data.length - off);
    fs.fsyncSync(fd);            /* 先落盘再改名：断电也不会留下半截 JSON */
  } finally {
    try { fs.closeSync(fd); } catch (_) {}
  }
  try {
    fs.renameSync(tmp, file);
  } catch (e) {
    try { fs.unlinkSync(tmp); } catch (_) {}
    throw e;
  }
}

function writeJsonAtomicSync(file, value) {
  writeFileAtomicSync(file, JSON.stringify(value, null, 2) + '\n');
}

/**
 * 读 JSON 数组，带四重防护：
 *   1) 文件不存在 → 空数组（正常首启）
 *   2) 旧版"单个设备对象"格式（旧 main/index.js 会把对象当数组写回，实测现网就是这个形状）
 *      → 折成单元素数组（migrated=true），既不丢数据也不改盘上内容
 *   3) 解析失败 / 其它非数组形状 → 把坏文件改名保留为 .corrupt-<ts>（不再静默置空）
 *   4) 返回 recovered/migrated 让调用方写日志
 */
function readJsonArraySync(file) {
  const out = { list: [], recovered: null, migrated: false, existed: false, error: null };
  if (!fs.existsSync(file)) return out;
  out.existed = true;
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (e) {
    out.error = e;
    return out;
  }
  try {
    const v = JSON.parse(text.replace(/^\uFEFF/, ''));
    if (Array.isArray(v)) { out.list = v; return out; }
    if (v && typeof v === 'object' && typeof v.id === 'string' && v.id) {
      out.list = [v];
      out.migrated = true;
      return out;
    }
    throw new Error('顶层既不是数组，也不是单个设备对象');
  } catch (e) {
    out.error = e;
    const backup = file + '.corrupt-' + Date.now();
    try { fs.renameSync(file, backup); out.recovered = backup; } catch (_) {}
    return out;
  }
}

/** 落盘时不覆盖已有文件：a.txt → a (1).txt */
function uniquePath(p) {
  if (!fs.existsSync(p)) return p;
  const dir = path.dirname(p);
  const ext = path.extname(p);
  const base = path.basename(p, ext);
  for (let i = 1; i < 1000; i++) {
    const c = path.join(dir, base + ' (' + i + ')' + ext);
    if (!fs.existsSync(c)) return c;
  }
  return path.join(dir, base + '-' + Date.now() + ext);
}

/* ==========================================================================
 * 配置：hamster_manager.conf 的 hamd_port / ipc_port 必须真正生效
 * ========================================================================== */
/**
 * 解析 conf 文本，同时兼容两种写法：
 *   hamsterd.conf 风格   key: value
 *   hamster_manager 风格 key value
 * 注释以 '#' 开始（与 C 侧一致：'#' 前有空白才算注释）。
 */
function parseConfText(text) {
  const out = {};
  const lines = String(text || '').split(/\r?\n/);
  for (let raw of lines) {
    let line = raw;
    const h = line.indexOf('#');
    if (h >= 0) line = line.slice(0, h);
    line = line.trim();
    if (!line) continue;
    let m = line.match(/^([A-Za-z0-9_]+)\s*[:=]?\s+(.*)$/);
    if (!m) m = line.match(/^([A-Za-z0-9_]+)\s*:(.*)$/);
    if (!m) continue;
    out[m[1]] = String(m[2]).trim();
  }
  return out;
}

function parsePortRange(value, lo, hi) {
  if (value === undefined || value === null || String(value).trim() === '') return null;
  const n = Number(String(value).trim());
  if (!Number.isInteger(n) || n < lo || n > hi) return null;
  return n;
}

/** hamsterd.conf 的候选位置（供口令回退读取，减少两处口令不同步） */
function findDaemonConf(managerDir, explicit) {
  const cands = [];
  if (explicit) cands.push(explicit);
  if (process.env.HAMSTERD_CONF) cands.push(process.env.HAMSTERD_CONF);
  /* managerDir 是 "Hamster Manager"，守护进程在它的兄弟目录 Hamsterd/ 下 */
  cands.push(path.join(managerDir, '..', 'Hamsterd', 'hamsterd.conf'));
  cands.push(path.join(managerDir, '..', '..', 'Hamsterd', 'hamsterd.conf'));
  cands.push(path.join(managerDir, 'Hamsterd', 'hamsterd.conf'));
  for (const c of cands) {
    try { if (c && fs.existsSync(c)) return path.resolve(c); } catch (_) {}
  }
  return null;
}

/**
 * 读取主进程有效配置。
 * @param {string} managerDir "Hamster Manager" 目录（含 hamster_manager.conf 与 devices/）
 * 规则：hamd_codeword 为空时回退读 hamsterd.conf 的 codeword，避免"两处口令不一致"。
 */
function loadManagerConfig(managerDir, opts) {
  const o = opts || {};
  const cfg = {
    manager_dir: managerDir,
    conf_path: o.confPath || process.env.HAMSTER_MANAGER_CONF || path.join(managerDir, 'hamster_manager.conf'),
    conf_found: false,
    daemon_conf_path: '',
    hamd_port: DEFAULT_HAMD_PORT,
    ipc_port: DEFAULT_IPC_PORT,
    discovery_port: DISC_DEFAULT_PORT,
    heartbeat_time: 3,
    codeword: '',
    codeword_source: 'none',
    download_dir: '',
    log_level: 'info',
    command_timeout_ms: DEFAULT_TIMEOUT_MS,
    warnings: [],
  };

  let kv = {};
  try {
    if (fs.existsSync(cfg.conf_path)) {
      kv = parseConfText(fs.readFileSync(cfg.conf_path, 'utf8'));
      cfg.conf_found = true;
    } else {
      cfg.warnings.push('未找到 ' + cfg.conf_path + '，使用默认端口');
    }
  } catch (e) {
    cfg.warnings.push('读取 ' + cfg.conf_path + ' 失败: ' + e.message);
  }

  const p1 = parsePortRange(kv.hamd_port, 1, 65535);
  if (p1 !== null) cfg.hamd_port = p1;
  else if (kv.hamd_port !== undefined) cfg.warnings.push('hamd_port 非法(' + kv.hamd_port + ')，沿用 ' + cfg.hamd_port);

  const p2 = parsePortRange(kv.ipc_port, 1, 65535);
  if (p2 !== null) cfg.ipc_port = p2;
  else if (kv.ipc_port !== undefined) cfg.warnings.push('ipc_port 非法(' + kv.ipc_port + ')，沿用 ' + cfg.ipc_port);

  const hb = parsePortRange(kv.heartbeat_time, 1, 3600);
  if (hb !== null) cfg.heartbeat_time = hb;

  /* 发现端口：允许 hamd_discovery_port（与其它 hamd_* 键一致），也接受 discovery_port。
     0 是合法值，表示"本机不广播探测"，因此这里单独判定而不是走 parsePortRange(1..) */
  {
    const raw = (kv.hamd_discovery_port !== undefined) ? kv.hamd_discovery_port : kv.discovery_port;
    if (raw !== undefined && String(raw).trim() !== '') {
      const n = Number(String(raw).trim());
      if (Number.isInteger(n) && n >= 0 && n <= 65535) cfg.discovery_port = n;
      else cfg.warnings.push('hamd_discovery_port 非法(' + raw + ')，沿用 ' + cfg.discovery_port);
    }
  }

  const lv = String(kv.log_level || '').toLowerCase();
  if (LEVELS[lv] !== undefined) cfg.log_level = lv;

  if (kv.download_dir) cfg.download_dir = String(kv.download_dir);

  /* 守护进程配置：口令与 §8 开关都可能需要从那里继承 */
  const dconf = findDaemonConf(managerDir, o.daemonConfPath);
  cfg.daemon_conf_path = dconf || '';
  let dkv = {};
  if (dconf) {
    try { dkv = parseConfText(fs.readFileSync(dconf, 'utf8')); }
    catch (e) { cfg.warnings.push('读取 ' + dconf + ' 失败: ' + e.message); }
  }

  if (kv.hamd_codeword) {
    cfg.codeword = String(kv.hamd_codeword).trim();
    cfg.codeword_source = 'hamster_manager.conf';
  } else {
    if (dkv.codeword) {
      cfg.codeword = String(dkv.codeword).trim();
      cfg.codeword_source = dconf;
    }
    if (!cfg.codeword) {
      cfg.warnings.push('hamster_manager.conf 与 hamsterd.conf 都没读到口令，连接受保护命令会被拒');
    }
  }

  /* §8 传输加密：hamd_encrypt 优先，否则跟随守护进程的 encrypt_transport。
     两处都没写时按**开**处理 —— 守护进程 0.0.9 的默认也是开，客户端跟着开才不会
     "配置里没写就被降级成明文"。要明文必须显式写 off。 */
  cfg.encrypt = true;
  {
    const raw = (kv.hamd_encrypt !== undefined) ? kv.hamd_encrypt : dkv.encrypt_transport;
    if (raw !== undefined) {
      const s = String(raw).trim().toLowerCase();
      cfg.encrypt = (s === 'on' || s === 'true' || s === '1' || s === 'yes');
    }
  }
  return cfg;
}

/** 代理可执行文件（Electron 自己 spawn 它；找不到也不算致命） */
function resolveManagerExe(managerDir) {
  const names = process.platform === 'win32' ? ['hamster_manager.exe'] : ['hamster_manager'];
  for (const n of names) {
    const p = path.join(managerDir, n);
    try { if (fs.existsSync(p) && fs.statSync(p).isFile()) return p; } catch (_) {}
  }
  return null;
}

/* ==========================================================================
 * 路径与标识校验（主进程必须自己再校验一遍，不能把渲染层给的字符串直接拼路径）
 * ========================================================================== */
/** 设备 id 由主进程生成：dev_<毫秒时间戳>（13 位），渲染层无法构造任意 id */
function generateDeviceId(now) {
  const t = Number(now) || Date.now();
  let id = 'dev_' + t;
  while (!DEVICE_ID_RE.test(id)) id = 'dev_' + Date.now();   /* 极端时钟异常时兜底 */
  return id;
}

function isValidDeviceId(id) {
  return typeof id === 'string' && DEVICE_ID_RE.test(id);
}

function assertValidDeviceId(id) {
  if (!isValidDeviceId(id)) throw new HamsterError('invalid_device_id', String(id));
  return id;
}

/**
 * 宽松的"安全标识符"校验：给不参与本机路径拼接的上下文用（例如迁移编排里的 srcId/dstId）。
 * 存储层（devices.json / devices/<id>.db）仍然要求严格的 DEVICE_ID_RE 白名单。
 */
function assertSafeId(id, what) {
  const s = String(id === undefined || id === null ? '' : id);
  if (!s || s.length > 64) throw new HamsterError('invalid_id', (what || 'id') + '=' + s);
  if (!/^[A-Za-z0-9_.:\-]+$/.test(s) || s.indexOf('..') >= 0) {
    throw new HamsterError('invalid_id', (what || 'id') + '=' + s);
  }
  return s;
}

function normForCompare(p) {
  let s = path.resolve(String(p));
  if (process.platform === 'win32') s = s.toLowerCase();
  return s;
}

/** target 是否落在 baseDir 之内（含相等） */
function isWithinDir(baseDir, target) {
  const b = normForCompare(baseDir);
  const t = normForCompare(target);
  if (t === b) return true;
  const prefix = b.endsWith(path.sep) ? b : b + path.sep;
  return t.startsWith(prefix);
}

/**
 * 把若干片段拼到 baseDir 下并断言不越界。
 * 约束：path.join 会自动规范化 '..'，所以**不能**拿它当防线——拼完必须 path.resolve + 归属校验。
 */
function resolveInside(baseDir, ...parts) {
  const raw = path.resolve(baseDir, ...parts.map((x) => String(x)));
  if (!isWithinDir(baseDir, raw)) {
    throw new HamsterError('path_denied', raw + ' 不在 ' + path.resolve(baseDir) + ' 之内');
  }
  return raw;
}

/**
 * 严格校验"相对路径"（上传目标、迁移目标、mkdir 等）。
 * 拒绝：控制字符、绝对路径、盘符、UNC、'..'、ADS（':'）。
 */
function sanitizeRelPath(p) {
  const s = String(p === undefined || p === null ? '' : p).trim();
  if (!s) throw new HamsterError('missing_path', '路径为空');
  if (/[\u0000-\u001f\u007f]/.test(s)) throw new HamsterError('path_denied', '路径含控制字符');
  const n = s.replace(/\//g, '\\');
  if (/^\\\\/.test(n)) throw new HamsterError('path_denied', '不接受 UNC 路径: ' + s);
  if (/^[A-Za-z]:/.test(n)) throw new HamsterError('path_denied', '不接受盘符路径: ' + s);
  if (n.startsWith('\\')) throw new HamsterError('path_denied', '不接受绝对路径: ' + s);
  const parts = n.split('\\');
  for (const seg of parts) {
    if (seg === '..') throw new HamsterError('path_denied', '路径含 .. : ' + s);
  }
  if (n.indexOf(':') >= 0) throw new HamsterError('path_denied', '路径含 : (ADS): ' + s);
  const cleaned = parts.filter((x) => x !== '.' && x !== '');
  if (!cleaned.length) throw new HamsterError('missing_path', '路径为空: ' + s);
  return cleaned.join('\\');
}

/**
 * 宽松校验"路径参数"（download/list/delete 既可用相对路径也可用绝对路径，
 * 绝对路径的归属由守护进程裁决）。这里只挡明显危险/非法的形态。
 */
function assertSafePathArg(p) {
  const s = String(p === undefined || p === null ? '' : p).trim();
  if (!s) throw new HamsterError('missing_path', '路径为空');
  if (/[\u0000-\u001f\u007f]/.test(s)) throw new HamsterError('path_denied', '路径含控制字符');
  const n = s.replace(/\//g, '\\');
  if (/^\\\\/.test(n)) throw new HamsterError('path_denied', '不接受 UNC 路径: ' + s);
  const body = n.replace(/^[A-Za-z]:/, '');       /* 绝对路径的盘符前缀允许 */
  if (body.indexOf(':') >= 0) throw new HamsterError('path_denied', '路径含 : (ADS): ' + s);
  const parts = body.split('\\');
  if (parts.some((x) => x === '..')) throw new HamsterError('path_denied', '路径含 .. : ' + s);
  return s;
}

const WIN_RESERVED = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\.|$)/i;

/** 远端给出的文件名落到本地磁盘前必须净化（防目录穿越 / 非法字符 / Windows 设备名） */
function safeLocalFileName(name, fallback) {
  let n = String(name === undefined || name === null ? '' : name);
  const segs = n.split(/[\\/]/);              /* 只取最后一段：任何目录成分都不进本地文件名 */
  n = segs.length ? segs[segs.length - 1] : '';
  n = n.replace(/[\u0000-\u001f\u007f]/g, '');
  n = n.replace(/[:*?"<>|]/g, '_');
  n = n.replace(/[. ]+$/, '');
  if (!n || n === '.' || n === '..') n = '';
  if (n && WIN_RESERVED.test(n)) n = '_' + n;
  if (!n) n = fallback || 'download';
  return n.slice(0, 180);
}

/** 解析 "host:port" / "host" */
function parseAddr(addr, defPort) {
  const s = String(addr === undefined || addr === null ? '' : addr).trim();
  if (!s) throw new HamsterError('invalid_addr', '地址为空');
  if (/[\u0000-\u001f\u007f\s]/.test(s)) throw new HamsterError('invalid_addr', '地址含空白或控制字符');
  const i = s.lastIndexOf(':');
  if (i < 0) return { host: s, port: defPort || DEFAULT_HAMD_PORT };
  const host = s.slice(0, i);
  const port = parsePortRange(s.slice(i + 1), 1, 65535);
  if (!host || port === null) throw new HamsterError('invalid_addr', s);
  return { host, port };
}

/** 探测本机端口是否已有服务（用于"已有代理就直接用"） */
function probePort(port, opts) {
  const o = opts || {};
  return new Promise((resolve) => {
    let done = false;
    const sock = net.connect({ host: o.host || '127.0.0.1', port });
    const finish = (v) => {
      if (done) return;
      done = true;
      try { sock.destroy(); } catch (_) {}
      resolve(v);
    };
    sock.setTimeout(o.timeoutMs || 800, () => finish(false));
    sock.once('connect', () => finish(true));
    sock.once('error', () => finish(false));
  });
}

/* ==========================================================================
 * 二进制分帧（PROTOCOL §3，framing: raw）
 * ========================================================================== */
/**
 * 行分帧 + 负载分帧解析器。
 *
 * 规则：消息头里出现 payload_bytes(N>0) 时，紧接其后恰好 N 字节裸数据；
 *       必须精确读满 N 字节才能继续解析下一行。
 * 实现要点（修 P0-8）：
 *   - 全程 Buffer，绝不做 UTF-8/二进制字符串往返；
 *   - 用 indexOf(0x0a) 切消息头，按**字节**计数；
 *   - 负载走 sink 流式消费，不整份进内存；sink 用返回值/内部背压控制读取。
 */
class FrameParser {
  /**
   * @param {{onMessage:function, onError?:function, log?:object}} opts
   */
  constructor(opts) {
    const o = opts || {};
    this._onMessage = o.onMessage || function () {};
    this._onError = o.onError || function () {};
    this._log = o.log || null;
    this._parts = [];        /* 当前行的剩余片段（Buffer 视图） */
    this._len = 0;           /* 当前行已累积字节数 */
    this._payload = null;    /* {sink, bytes, got} */
    this._broken = false;
  }

  get inPayload() { return !!this._payload; }
  get pendingBytes() { return this._len; }

  /** 进入负载模式（必须紧跟 payload_bytes 的消息头之后调用） */
  expectPayload(bytes, sink) {
    const n = Number(bytes);
    if (!Number.isFinite(n) || n <= 0) throw new HamsterError('bad_framing', 'payload_bytes 非法: ' + bytes);
    if (this._payload) throw new HamsterError('bad_framing', '已经处于负载模式');
    this._payload = { sink, bytes: n, got: 0 };
  }

  /**
   * 喂入数据。负载模式下返回 true（表示还在负载中）。
   * @throws HamsterError 协议不可信时（调用方应断开连接）
   */
  push(buf) {
    if (this._broken) return false;
    let off = 0;
    while (off < buf.length) {
      if (this._payload) {
        const p = this._payload;
        const want = p.bytes - p.got;
        const take = Math.min(want, buf.length - off);
        p.sink.write(buf.subarray(off, off + take));
        p.got += take;
        off += take;
        if (p.got === p.bytes) {
          this._payload = null;
          p.sink.finish();
        }
        continue;
      }
      const nl = buf.indexOf(0x0a, off);
      if (nl === -1) {
        this._append(buf.subarray(off));
        off = buf.length;
        break;
      }
      this._append(buf.subarray(off, nl));
      off = nl + 1;
      this._flushLine();
    }
    return this.inPayload;
  }

  _append(part) {
    if (part.length === 0) return;
    this._len += part.length;
    if (this._len > OUT_MAX + 64 * 1024) {
      /* 单行超过响应上限：协议流已不可信，交给上层断开 */
      this._broken = true;
      throw new HamsterError('response_too_large', '单行超过 ' + OUT_MAX + ' 字节');
    }
    this._parts.push(part);
  }

  _flushLine() {
    const len = this._len;
    const parts = this._parts;
    this._parts = [];
    this._len = 0;
    if (len === 0) return;
    const line = parts.length === 1 ? parts[0] : Buffer.concat(parts, len);
    let text = line.toString('utf8').trim();
    if (!text) return;
    let msg;
    try {
      msg = JSON.parse(text);
    } catch (e) {
      throw new HamsterError('malformed_json', '无法解析服务端行: ' + text.slice(0, 160));
    }
    if (!msg || typeof msg !== 'object') throw new HamsterError('malformed_json', '服务端行不是对象');
    this._onMessage(msg);
  }
}

/**
 * 文件接收 sink（流式落盘 + 背压）。
 * 契约：
 *   - write(chunk) 同步返回；队列过长时调用 pause() 让上层暂停读取 socket；
 *   - finish() 在队列排空后 fsync+close，然后 onDone(null, bytes)；
 *   - abort(err) 关闭并删除半成品，然后 onDone(err, bytes)；
 *   - 内存占用上限 ≈ maxQueue × 分块大小（守护进程分块 64KiB）。
 */
class FileSink {
  constructor(filePath, opts) {
    const o = opts || {};
    this.path = filePath;
    this.bytes = 0;
    this.maxQueue = o.maxQueue || 16;
    this._fd = fs.openSync(filePath, 'w');
    this._queue = [];
    this._writing = false;
    this._paused = false;
    this._finishing = false;
    this._done = false;
    this._err = null;
    this._onDone = o.onDone || function () {};
    this._pause = o.pause || null;
    this._resume = o.resume || null;
  }

  write(chunk) {
    if (this._done || this._err) return;
    if (this._queue.length >= this.maxQueue && !this._paused) {
      this._paused = true;
      if (this._pause) { try { this._pause(); } catch (_) {} }
    }
    this._queue.push(chunk);
    this._pump();
  }

  finish() { this._finishing = true; this._pump(); }

  abort(err) {
    if (this._done) return;
    this._err = err || new HamsterError('aborted', '接收被中止');
    this._queue.length = 0;
    this._finish();
  }

  /** 硬失败：磁盘写不进去时不能丢字节，只能让上层断开连接 */
  _hardFail(err) {
    this._err = err;
    this._queue.length = 0;
    this._finish();
  }

  _pump() {
    if (this._done) return;
    if (this._err) { this._finish(); return; }
    if (this._writing) return;
    if (this._queue.length === 0) {
      if (this._finishing) this._finish();
      if (this._paused) {
        this._paused = false;
        if (this._resume) { try { this._resume(); } catch (_) {} }
      }
      return;
    }
    const buf = this._queue.shift();
    this._writing = true;
    fs.write(this._fd, buf, 0, buf.length, null, (e) => {
      this._writing = false;
      if (this._done) return;
      if (e) { this._hardFail(e); return; }
      this.bytes += buf.length;
      this._pump();
    });
  }

  _finish() {
    if (this._done) return;
    this._done = true;
    try {
      if (!this._err) fs.fsyncSync(this._fd);
    } catch (_) {}
    try { fs.closeSync(this._fd); } catch (_) {}
    if (this._err) {
      try { fs.unlinkSync(this.path); } catch (_) {}
    }
    try { this._onDone(this._err, this.bytes); } catch (_) {}
  }
}

/** 把本地文件流式灌进 socket（带背压），返回实际发送字节数 */
function pipeFileToSocket(filePath, socket, opts) {
  const o = opts || {};
  return new Promise((resolve, reject) => {
    let done = false;
    let sent = 0;
    const size = o.size || 0;
    const rs = fs.createReadStream(filePath, { highWaterMark: o.highWaterMark || 256 * 1024 });
    const onDrain = () => { try { rs.resume(); } catch (_) {} };
    const onClose = () => finish(new HamsterError('socket_closed', '上传过程中连接关闭'));
    function finish(err) {
      if (done) return;
      done = true;
      try { socket.removeListener('drain', onDrain); } catch (_) {}
      try { socket.removeListener('close', onClose); } catch (_) {}
      try { rs.destroy(); } catch (_) {}
      if (err) reject(err); else resolve(sent);
    }
    socket.once('close', onClose);
    rs.on('data', (chunk) => {
      sent += chunk.length;
      if (o.onProgress) { try { o.onProgress(sent, size); } catch (_) {} }
      if (!socket.write(chunk)) {
        rs.pause();
        socket.removeListener('drain', onDrain);
        socket.once('drain', onDrain);
      }
    });
    rs.on('end', () => finish(null));
    rs.on('error', (e) => finish(e));
  });
}

/* ==========================================================================
 * 协议连接（单条 TCP：分帧 + 按 id 配对 + 事件分流 + 超时）
 * ========================================================================== */
class HamsterConn {
  /**
   * @param {{host?:string,port?:number,logger?:object,label?:string,onEvent?:function,onClose?:function}} opts
   */
  constructor(opts) {
    const o = opts || {};
    this.host = o.host || '127.0.0.1';
    this.port = Number(o.port) || DEFAULT_HAMD_PORT;
    this.label = o.label || (this.host + ':' + this.port);
    this.log = o.logger || null;
    this.onEvent = o.onEvent || null;
    this.onClose = o.onClose || null;
    /* §8：encrypt=true 时先握手再走密文；secret 是 codeword 或 api_key */
    this.encrypt = !!o.encrypt;
    this.secret = o.secret ? String(o.secret) : '';
    this.deviceId = o.deviceId ? String(o.deviceId) : 'manager';
    this.hostname = o.hostname ? String(o.hostname) : '';
    this.timeouts = {
      command: Number(o.commandTimeoutMs) || DEFAULT_TIMEOUT_MS,
      transferIdle: TRANSFER_IDLE_MS,
      transferMax: TRANSFER_MAX_MS,
    };
    this._sock = null;
    this._parser = null;
    this._pending = new Map();
    this._seq = 0;
    this._closing = false;
    this._queue = Promise.resolve();
    this._bytesIn = 0;
    this._bytesOut = 0;
  }

  get connected() { return !!this._sock && !this._sock.destroyed && !this._closing; }
  get stats() { return { bytes_in: this._bytesIn, bytes_out: this._bytesOut, pending: this._pending.size }; }

  _log(lvl, msg) { if (this.log && this.log[lvl]) this.log[lvl]('[conn ' + this.label + '] ' + msg); }

  connect(timeoutMs) {
    if (this.connected) return Promise.resolve(this);
    if (this._sock) this.destroy('reconnect');
    if (this.encrypt) return this._connectEncrypted(timeoutMs);
    return new Promise((resolve, reject) => {
      const sock = new net.Socket();
      let settled = false;
      const to = setTimeout(() => {
        if (settled) return;
        settled = true;
        try { sock.destroy(); } catch (_) {}
        reject(new HamsterError('con_timeout', '连接 ' + this.label + ' 超时'));
      }, timeoutMs || 5000);

      sock.setNoDelay(true);
      sock.setKeepAlive(true, KEEPALIVE_MS);

      this._parser = new FrameParser({
        log: this.log,
        onMessage: (m) => this._onMessage(m),
        onError: (e) => this._log('warn', '分帧错误: ' + e.message),
      });

      sock.on('data', (buf) => {
        this._bytesIn += buf.length;
        try {
          this._parser.push(buf);
        } catch (e) {
          /* 分帧不可信：只能断开（例如单行超限 / JSON 损坏） */
          this._log('error', '协议流损坏，断开连接: ' + (e && e.message));
          this.destroy('framing');
        }
      });
      sock.on('error', (e) => {
        this._log('warn', 'socket 错误: ' + (e && e.message));
        if (!settled) { settled = true; clearTimeout(to); try { sock.destroy(); } catch (_) {} reject(new HamsterError('socket_error', e && e.message)); }
      });
      sock.on('close', () => {
        const was = this._sock;
        this._sock = null;
        this._failAll(new HamsterError('socket_closed', '连接 ' + this.label + ' 已关闭'));
        if (!settled) { settled = true; clearTimeout(to); reject(new HamsterError('socket_closed', '连接 ' + this.label + ' 被关闭')); }
        if (was && this.onClose) { try { this.onClose(); } catch (_) {} }
      });
      sock.connect(this.port, this.host, () => {
        if (settled) return;
        settled = true;
        clearTimeout(to);
        this._sock = sock;
        this._closing = false;
        this._log('debug', '已连接');
        resolve(this);
      });
    });
  }

  /**
   * §8 加密连接：握手成功后，AeadTransport 在语义上等价于一个 net.Socket
   * （write/pause/resume/destroy + 'data' 事件），所以 _sock 直接指向它，
   * 其余（FrameParser、payload_bytes、超时、事件分流）一行都不用改。
   */
  _connectEncrypted(timeoutMs) {
    const self = this;
    if (!this.secret) {
      return Promise.reject(new HamsterError('no_secret', '已开启传输加密，但没有可用口令（codeword / api_key）'));
    }
    return Aead.AeadTransport.connect({
      host: this.host,
      port: this.port,
      secret: this.secret,
      deviceId: this.deviceId,
      hostname: this.hostname || undefined,
      timeoutMs: timeoutMs || 5000,
      logger: this.log,
    }).then((t) => {
      self._parser = new FrameParser({
        log: self.log,
        onMessage: (m) => self._onMessage(m),
        onError: (e) => self._log('warn', '分帧错误: ' + e.message),
      });
      t.on('data', (buf) => {
        self._bytesIn += buf.length;
        try {
          self._parser.push(buf);
        } catch (e) {
          self._log('error', '协议流损坏，断开连接: ' + (e && e.message));
          self.destroy('framing');
        }
      });
      t.on('protocol_error', (e) => {
        self._log('error', '记录层错误，断开连接: ' + (e && e.code));
      });
      t.on('close', () => {
        const was = self._sock;
        self._sock = null;
        self._failAll(new HamsterError('socket_closed', '连接 ' + self.label + ' 已关闭'));
        if (was && self.onClose) { try { self.onClose(); } catch (_) {} }
      });
      self._sock = t;
      self._closing = false;
      self._log('debug', '已连接（§8 加密，server=' + ((t.peer && t.peer.version) || '?') + '）');
      return self;
    }, (e) => {
      const code = (e && e.code) === 'server_auth_failed' ? 'auth_failed' : ((e && e.code) || 'connect_failed');
      throw new HamsterError(code, e && e.message);
    });
  }

  destroy(reason) {
    this._closing = true;
    const s = this._sock;
    this._sock = null;
    this._failAll(new HamsterError('socket_closed', reason || 'destroyed'));
    if (s) { try { s.destroy(); } catch (_) {} }
    this._log('debug', '连接已释放' + (reason ? ' (' + reason + ')' : ''));
  }

  _failAll(err) {
    for (const entry of Array.from(this._pending.values())) this._fail(entry, err);
  }

  _armTimer(entry, idleMs) {
    const idle = idleMs || entry.idleMs || this.timeouts.command;
    entry.timer = setTimeout(() => {
      const now = Date.now();
      if (entry.maxMs && now - entry.started > entry.maxMs) {
        this._fail(entry, new HamsterError('timeout', '整体超时 ' + entry.action));
        return;
      }
      if (now - entry.last >= idle) {
        this._fail(entry, new HamsterError('timeout', '操作超时: ' + entry.action));
        return;
      }
      this._armTimer(entry, idle);
    }, idle);
  }

  _register(id, action, opts) {
    const o = opts || {};
    const entry = {
      id, action,
      idleMs: o.idleMs || this.timeouts.command,
      maxMs: o.maxMs || 0,
      started: Date.now(),
      last: Date.now(),
      timer: null,
      sink: null,
      header: null,
      resolve: null,
      reject: null,
      settled: false,
      onPayload: o.onPayload || null,
    };
    const p = new Promise((res, rej) => { entry.resolve = res; entry.reject = rej; });
    this._pending.set(id, entry);
    this._armTimer(entry);
    return { entry, promise: p };
  }

  _touch(entry) {
    entry.last = Date.now();
  }

  _settle(entry, value) {
    if (entry.settled) return;
    entry.settled = true;
    if (entry.timer) { clearTimeout(entry.timer); entry.timer = null; }
    if (entry.sinkTimer) { clearTimeout(entry.sinkTimer); entry.sinkTimer = null; }
    this._pending.delete(entry.id);
    entry.resolve(value);
  }

  _fail(entry, err) {
    if (entry.settled) return;
    entry.settled = true;
    if (entry.timer) { clearTimeout(entry.timer); entry.timer = null; }
    if (entry.sinkTimer) { clearTimeout(entry.sinkTimer); entry.sinkTimer = null; }
    this._pending.delete(entry.id);
    if (entry.sink) { try { entry.sink.abort(err); } catch (_) {} }
    entry.reject(err);
  }

  _onMessage(msg) {
    const type = msg.type;
    if (type === 'event') {
      if (this.onEvent) { try { this.onEvent(msg); } catch (_) {} }
      return;
    }
    if (type !== 'response') {
      this._log('warn', '未知消息类型: ' + String(type));
      return;
    }
    const id = msg.id === undefined || msg.id === null ? '' : String(msg.id);
    const entry = this._pending.get(id);
    if (!entry) {
      /* id 为空的是服务端自身错误（malformed_json / line_too_long）：本客户端不会触发，
         但也必须记账而不是静默丢弃（修 P2-17） */
      this._log('warn', '收到无法配对的响应: ' + JSON.stringify(msg).slice(0, 200));
      return;
    }
    if (msg.status === 'error') {
      this._fail(entry, errorFromData(msg.data));
      return;
    }
    const data = (msg.data && typeof msg.data === 'object') ? msg.data : {};
    const pb = Number(data.payload_bytes);
    if (Number.isFinite(pb) && pb > 0) {
      if (!entry.onPayload) {
        this._fail(entry, new HamsterError('bad_framing', '响应带 payload_bytes 但调用方未准备接收'));
        this.destroy('unexpected_payload');
        return;
      }
      let sink;
      try {
        /* onPayload(data, transport)：调用方建 sink，并在落盘完成后调用
           transport.settle(err, {bytes,path}) —— 只有这样请求才会 resolve，
           因此"字节收满"与"文件真正落盘"两件事都被保证。 */
        sink = entry.onPayload(data, this._transport(entry));
      } catch (e) {
        this._fail(entry, isHamsterError(e) ? e : new HamsterError('sink_failed', e && e.message));
        this.destroy('sink_failed');
        return;
      }
      entry.header = data;
      entry.sink = sink;
      try {
        this._parser.expectPayload(pb, this._wrapSink(entry, sink));
      } catch (e) {
        this._fail(entry, e);
        this.destroy('bad_framing');
      }
      /* 兜底：负载已收完但调用方忘了 settle（sink 卡住）时不能永久挂起 */
      entry.sinkTimer = setTimeout(() => {
        if (entry.settled) return;
        this._fail(entry, new HamsterError('sink_timeout', '负载已接收但落盘未完成'));
        this.destroy('sink_timeout');
      }, 60000);
      return;
    }
    this._settle(entry, { data, payload: null });
  }

  /** 传给 onPayload 的宿主钩子：背压 + 完成通知 */
  _transport(entry) {
    const self = this;
    return {
      pause: () => { if (self._sock) { try { self._sock.pause(); } catch (_) {} } },
      resume: () => { if (self._sock) { try { self._sock.resume(); } catch (_) {} } },
      /**
       * 负载落盘结束（成功/失败）后必须调用。
       * @param {Error|null} err
       * @param {{bytes?:number,path?:string}} [info]
       */
      settle: (err, info) => {
        if (entry.sinkTimer) { clearTimeout(entry.sinkTimer); entry.sinkTimer = null; }
        if (err) {
          self._fail(entry, isHamsterError(err) ? err : new HamsterError('write_failed', (err && err.message) || String(err)));
          self.destroy('sink failed');
          return;
        }
        const i = info || {};
        self._settle(entry, {
          data: entry.header || {},
          payload: { bytes: Number(i.bytes) || 0, path: i.path || '' },
        });
      },
    };
  }

  /**
   * 包一层：把负载进度写进 entry（用于重置空闲超时），
   * 但"完成"仍由调用方通过 transport.settle 通知（保证文件已落盘）。
   */
  _wrapSink(entry, sink) {
    const self = this;
    return {
      write(chunk) {
        self._touch(entry);
        sink.write(chunk);
      },
      finish() {
        if (entry.sinkTimer) { clearTimeout(entry.sinkTimer); entry.sinkTimer = null; }
        entry.sinkTimer = setTimeout(() => {
          if (entry.settled) return;
          self._fail(entry, new HamsterError('sink_timeout', '负载已接收但落盘未完成'));
          self.destroy('sink_timeout');
        }, 60000);
        sink.finish();
      },
      abort(err) { sink.abort(err); },
    };
  }

  _nextId() {
    this._seq += 1;
    return 'c' + this._seq + '-' + Date.now().toString(36);
  }

  _writeLine(line) {
    if (!this.connected) throw new HamsterError('not_connected', this.label);
    if (Buffer.byteLength(line, 'utf8') > LINE_MAX) throw new HamsterError('line_too_long', '请求行超过 ' + LINE_MAX);
    this._bytesOut += Buffer.byteLength(line, 'utf8');
    this._sock.write(line);
  }

  _enqueue(fn) {
    const run = this._queue.then(fn, fn);
    this._queue = run.then(() => {}, () => {});
    return run;
  }

  /**
   * 发一条请求并等响应。
   * @param {string} action
   * @param {object} [params]
   * @param {{timeoutMs?:number,idleMs?:number,maxMs?:number,onPayload?:function}} [opts]
   * @returns {Promise<{data:object,payload:null|{bytes:number,path:string}}>}
   */
  request(action, params, opts) {
    return this._enqueue(() => this._requestInner(action, params, opts));
  }

  async _requestInner(action, params, opts) {
    const o = opts || {};
    if (!this.connected) await this.connect(o.connectTimeoutMs);
    const id = this._nextId();
    const entryOpts = {
      idleMs: o.idleMs || o.timeoutMs || this.timeouts.command,
      maxMs: o.maxMs || 0,
      onPayload: o.onPayload || null,
    };
    const { entry, promise } = this._register(id, action, entryOpts);
    const body = { type: 'request', id, action };
    if (params !== undefined && params !== null) body.params = params;
    try {
      this._writeLine(JSON.stringify(body) + '\n');
    } catch (e) {
      this._fail(entry, isHamsterError(e) ? e : new HamsterError('write_failed', e && e.message));
    }
    return promise;
  }

  /**
   * 带负载的请求（上传）：先发头（含 payload_bytes），再流式写负载，最后等响应。
   * 串行化在连接队列里，保证负载字节不会被别的请求插进来。
   */
  sendWithPayload(action, params, o) {
    return this._enqueue(async () => {
      const opt = o || {};
      if (!this.connected) await this.connect(opt.connectTimeoutMs);
      const id = this._nextId();
      const entryOpts = {
        idleMs: opt.idleMs || this.timeouts.transferIdle,
        maxMs: opt.maxMs || this.timeouts.transferMax,
      };
      const { entry, promise } = this._register(id, action, entryOpts);
      const body = { type: 'request', id, action, params: params || {}, payload_bytes: opt.payloadBytes };
      try {
        this._writeLine(JSON.stringify(body) + '\n');
      } catch (e) {
        this._fail(entry, isHamsterError(e) ? e : new HamsterError('write_failed', e && e.message));
        return promise;
      }
      const writeP = Promise.resolve()
        .then(() => opt.writePayload(this._sock, () => this._touch(entry)))
        .then(() => null, (e) => e || new Error('payload write failed'));

      let result = null;
      let rerr = null;
      try {
        result = await promise;
      } catch (e) {
        rerr = e;
      }
      /* 响应已到也必须等负载写完（否则连接里会残留字节，后续请求错位） */
      const werr = await Promise.race([
        writeP,
        new Promise((res) => setTimeout(() => res(new HamsterError('timeout', '负载写出超时')), 30000)),
      ]);
      if (rerr) throw rerr;
      if (werr && !this._isSocketClosed(werr)) throw (isHamsterError(werr) ? werr : new HamsterError('write_failed', werr.message));
      return result;
    });
  }

  _isSocketClosed(e) {
    return !!e && (e.code === 'socket_closed' || e.code === 'EPIPE' || e.code === 'ECONNRESET');
  }
}

/* ==========================================================================
 * 设备客户端（一台 hamsterd = 命令连接 + 事件连接）
 * ========================================================================== */
class HamsterClient {
  /**
   * @param {{id:string,name?:string,host:string,port:number,codeword?:string,apiKey?:string,
   *          deviceId?:string,hostname?:string,downloadDir:string,logger?:object,
   *          onEvent?:function,onState?:function,commandTimeoutMs?:number}} opts
   */
  constructor(opts) {
    const o = opts || {};
    this.id = String(o.id || '');
    this.name = String(o.name || o.host || 'device');
    this.host = o.host || '127.0.0.1';
    this.port = Number(o.port) || DEFAULT_HAMD_PORT;
    this.codeword = o.codeword ? String(o.codeword) : '';
    this.apiKey = o.apiKey ? String(o.apiKey) : '';
    this.deviceId = o.deviceId || ('manager_' + (this.id || 'local'));
    this.hostname = o.hostname || os.hostname();
    this.downloadDir = o.downloadDir || os.tmpdir();
    this.log = o.logger || null;
    this.onEvent = o.onEvent || null;
    this.onState = o.onState || null;
    this.commandTimeoutMs = Number(o.commandTimeoutMs) || DEFAULT_TIMEOUT_MS;
    /* §8：与守护进程之间的传输加密。开启后认证在握手阶段完成，不再发 hello。 */
    this.encrypt = !!o.encrypt;
    this.info = null;
    this._conn = null;
    this._connecting = null;
    this._events = null;
  }

  get addr() { return this.host + ':' + this.port; }
  _log(lvl, msg) { if (this.log && this.log[lvl]) this.log[lvl]('[' + this.name + '] ' + msg); }

  _newConn() {
    return new HamsterConn({
      host: this.host, port: this.port, logger: this.log, label: this.name + '@' + this.addr,
      commandTimeoutMs: this.commandTimeoutMs,
      encrypt: this.encrypt,
      secret: this.codeword || this.apiKey || '',
      deviceId: this.deviceId,
      hostname: this.hostname,
      /* kind:'command' —— 这是"命令通道"，不是事件通道。
         守护进程会按 HD_IDLE_MS(240s) 关掉空闲连接，命令通道因此会周期性断开、
         下一条命令再自动重连。调用方**不得**把它当成"设备离线/事件通道断开"，
         否则 UI 每 4 分钟闪一次离线，且渲染层收到离线就去探测 → 又把通道连起来 → 自激。 */
      onClose: () => {
        this.info = null;
        if (this.onState) { try { this.onState({ connected: false, device: this.name, kind: 'command' }); } catch (_) {} }
      },
    });
  }

  /** 建连接并完成 hello（每次重连都要重新认证） */
  async connect() {
    if (this._conn && this._conn.connected && this.info) return this;
    if (this._connecting) return this._connecting;
    this._connecting = (async () => {
      let conn = this._conn;
      if (!conn || !conn.connected) {
        conn = this._newConn();
        this._conn = conn;
        await conn.connect(this.commandTimeoutMs);
      }
      const params = { device_id: this.deviceId, hostname: this.hostname };
      if (this.codeword) params.codeword = this.codeword;
      if (this.apiKey) params.api_key = this.apiKey;
      /* §8：加密连接在握手里已经完成身份校验，命令层不再发 hello（PROTOCOL §8.4） */
      const authAction = this.encrypt ? 'info' : 'hello';
      const res = await conn.request(authAction, this.encrypt ? null : params, { timeoutMs: this.commandTimeoutMs });
      this.info = res.data || {};
      this._log('info', '认证通过 server=' + this.info.server + ' version=' + this.info.version +
        ' monitor=' + this.info.monitor_path + ' clients=' + this.info.clients);
      if (this.onState) { try { this.onState({ connected: true, device: this.name, kind: 'command' }); } catch (_) {} }
      return this;
    })();
    try {
      return await this._connecting;
    } catch (e) {
      const c = this._conn;
      this._conn = null;
      this.info = null;
      if (c) c.destroy('auth failed');
      throw e;
    } finally {
      this._connecting = null;
    }
  }

  async _ensure() {
    if (this._conn && this._conn.connected && this.info) return this._conn;
    await this.connect();
    return this._conn;
  }

  /**
   * 发命令。未认证/断线会自动重连并重新 hello。
   * @returns {Promise<object>} 响应 data
   */
  async call(action, params, opts) {
    const conn = await this._ensure();
    const res = await conn.request(action, params, opts);
    return res.data || {};
  }

  async ping(timeoutMs) { return this.call('ping', {}, { timeoutMs: timeoutMs || this.commandTimeoutMs }); }
  async health(timeoutMs) { return this.call('health', {}, { timeoutMs: timeoutMs || this.commandTimeoutMs }); }
  async stats(timeoutMs) { return this.call('stats', {}, { timeoutMs: timeoutMs || this.commandTimeoutMs }); }
  async verify(params, timeoutMs) { return this.call('verify', params || {}, { timeoutMs: timeoutMs || 60000 }); }
  async rescan() { return this.call('rescan', {}, { timeoutMs: this.commandTimeoutMs }); }
  async sync() { return this.call('sync', {}, { timeoutMs: this.commandTimeoutMs }); }

  /** search：params 直接透传（q/type/size_min/size_max/limit/offset/sort），只做数值兜底 */
  async search(params, timeoutMs) {
    const p = Object.assign({}, params || {});
    if (p.limit !== undefined) {
      const n = Number(p.limit);
      p.limit = Number.isFinite(n) && n > 0 ? Math.min(Math.floor(n), 1000) : 200;
    }
    if (p.offset !== undefined) {
      const n = Number(p.offset);
      p.offset = Number.isFinite(n) && n > 0 ? Math.floor(n) : 0;
    }
    const data = await this.call('search', p, { timeoutMs: timeoutMs || 30000 });
    return {
      total: Number(data.total) || 0,
      limit: Number(data.limit) || 0,
      offset: Number(data.offset) || 0,
      files: Array.isArray(data.files) ? data.files : [],
    };
  }

  async list(remotePath, limit, offset, timeoutMs) {
    const params = {};
    if (remotePath) params.path = assertSafePathArg(remotePath);
    if (limit) params.limit = Math.min(Math.floor(Number(limit)) || 200, 1000);
    if (offset) params.offset = Math.max(0, Math.floor(Number(offset)) || 0);
    const data = await this.call('list', params, { timeoutMs: timeoutMs || 30000 });
    return {
      path: data.path || '',
      /* 归一化：守护进程返回的 dir 是 0/1，对外统一成布尔，避免调用方拿数字做 === true */
      entries: (Array.isArray(data.entries) ? data.entries : []).map((e) => ({
        name: e.name || '', path: e.path || '', dir: !!e.dir,
        size: Number(e.size) || 0, mtime: Number(e.mtime) || 0,
      })),
      total: Number(data.total) || 0,
      limit: Number(data.limit) || 0,
      offset: Number(data.offset) || 0,
    };
  }

  async mkdir(remotePath) {
    const data = await this.call('mkdir', { path: assertSafePathArg(remotePath) });
    return { ok: true, path: data.path || remotePath };
  }

  /** 删除：confirm 由**客户端**补上（渲染层不接触这个开关） */
  async remove(remotePath) {
    const data = await this.call('delete', { path: assertSafePathArg(remotePath), confirm: true });
    return { ok: true, path: data.path || remotePath };
  }

  async keyAdd(label) { return this.call('key:add', { label: String(label || '') }); }
  async keyList() { return this.call('key:list', {}); }
  async keyRevoke(id) { return this.call('key:revoke', { id }); }

  /**
   * 下载：**流式落盘**，只回传本地路径，绝不把整份文件读进内存。
   * @param {string} remotePath 相对监控根或监控根内绝对路径
   * @param {{destDir?:string,destFile?:string,fileName?:string,
   *          idleMs?:number,maxMs?:number,onProgress?:function}} [opts]
   * @returns {Promise<{ok:true,saved_path:string,name:string,size:number,hash:string,index_hash:string,header:object}>}
   */
  async download(remotePath, opts) {
    const o = opts || {};
    const p = assertSafePathArg(remotePath);
    const conn = await this._ensure();
    const state = { target: '' };
    const log = this.log;

    const res = await conn.request('download', { path: p }, {
      idleMs: o.idleMs || TRANSFER_IDLE_MS,
      maxMs: o.maxMs || TRANSFER_MAX_MS,
      onPayload: (header, transport) => {
        const name = safeLocalFileName(o.fileName || header.name, 'download');
        const dir = o.destDir ? path.resolve(o.destDir) : this.downloadDir;
        ensureDir(dir);
        const target = o.destFile ? path.resolve(o.destFile) : uniquePath(path.join(dir, name));
        ensureDir(path.dirname(target));
        state.target = target;
        const part = target + '.part-' + process.pid;
        if (log) log.debug('[' + this.name + '] 下载开始 ' + header.path + ' → ' + target +
          ' (' + header.payload_bytes + ' 字节, hash=' + (header.hash || '-') + ')');
        return new FileSink(part, {
          pause: transport.pause,
          resume: transport.resume,
          onDone: (err, bytes) => {
            if (err) {
              if (log) log.warn('[' + this.name + '] 下载失败，已删除半成品 ' + part + ': ' + err.message);
              transport.settle(err);
              return;
            }
            try {
              fs.renameSync(part, target);
            } catch (e) {
              if (log) log.error('[' + this.name + '] 重命名落盘文件失败: ' + e.message);
              transport.settle(e);
              return;
            }
            if (log) log.debug('[' + this.name + '] 下载完成 ' + target + ' (' + bytes + ' 字节)');
            transport.settle(null, { bytes, path: target });
          },
        });
      },
    });

    const data = res.data || {};
    const bytes = res.payload ? res.payload.bytes : 0;
    const declared = Number(data.payload_bytes);
    /* 严格校验：实收字节数必须等于 payload_bytes 与 size（修 P0-8） */
    if (!res.payload || !Number.isFinite(declared) || bytes !== declared) {
      throw new HamsterError('size_mismatch',
        '下载字节数不符: 收到 ' + bytes + ' / 声明 ' + (Number.isFinite(declared) ? declared : '无'));
    }
    if (data.size !== undefined && Number(data.size) !== bytes) {
      throw new HamsterError('size_mismatch', '下载字节数与 size 不符: ' + bytes + ' / ' + data.size);
    }
    return {
      ok: true,
      saved_path: (res.payload && res.payload.path) || state.target,
      name: path.basename((res.payload && res.payload.path) || state.target),
      size: bytes,
      hash: String(data.hash || ''),
      index_hash: String(data.index_hash || ''),
      header: data,
    };
  }

  /**
   * 上传：流式发送（不把文件读进内存），可选携带权威 hash 做目标端校验。
   * @param {{localPath:string,remotePath:string,hash?:string,overwrite?:boolean,mkdir?:boolean,
   *          idleMs?:number,maxMs?:number,onProgress?:function}} o
   */
  async upload(o) {
    const opt = o || {};
    const localPath = path.resolve(String(opt.localPath || ''));
    if (!fs.existsSync(localPath)) throw new HamsterError('file_not_found', localPath);
    const st = fs.statSync(localPath);
    if (!st.isFile()) throw new HamsterError('not_a_file', localPath);
    const size = st.size;
    const remotePath = sanitizeRelPath(opt.remotePath);
    const params = {
      path: remotePath,
      size,
      overwrite: !!opt.overwrite,
      mkdir: opt.mkdir !== false,
    };
    if (opt.hash) params.hash = String(opt.hash);

    const conn = await this._ensure();
    const res = await conn.sendWithPayload('upload', params, {
      payloadBytes: size,
      idleMs: opt.idleMs || TRANSFER_IDLE_MS,
      maxMs: opt.maxMs || TRANSFER_MAX_MS,
      writePayload: (sock, touch) => pipeFileToSocket(localPath, sock, {
        size,
        onProgress: (sent, total) => {
          touch();
          if (opt.onProgress) { try { opt.onProgress(sent, total); } catch (_) {} }
        },
      }),
    });
    const data = res.data || {};
    const gotHash = String(data.hash || '');
    if (opt.hash && gotHash && gotHash.toLowerCase() !== String(opt.hash).toLowerCase()) {
      /* 目标端已自行校验并删除半成品；这层是防御性的二次确认（PROTOCOL §5 第 4 步） */
      throw new HamsterError('hash_mismatch', '目标端回传哈希 ' + gotHash + ' ≠ 源端 ' + opt.hash);
    }
    return {
      ok: true,
      path: data.path || remotePath,
      name: data.name || path.basename(remotePath),
      size: Number(data.size) || size,
      hash: gotHash,
    };
  }

  /** 小数据上传：落临时文件后走同一条流式路径，避免两套实现 */
  async uploadBuffer(buffer, remotePath, opts) {
    const o = opts || {};
    const tmpDir = o.tmpDir || os.tmpdir();
    ensureDir(tmpDir);
    const tmp = path.join(tmpDir, 'up_' + process.pid + '_' + Date.now().toString(36) + '.part');
    fs.writeFileSync(tmp, buffer);
    try {
      return await this.upload(Object.assign({}, o, { localPath: tmp, remotePath }));
    } finally {
      try { fs.unlinkSync(tmp); } catch (_) {}
    }
  }

  /**
   * 同步数据库：流式落盘，按 payload_bytes 精确校验（修 P0-8 / P1-9）。
   * @param {{destFile?:string,destDir?:string}} [opts]
   */
  async syncDatabase(opts) {
    const o = opts || {};
    const conn = await this._ensure();
    const state = { target: '' };
    const res = await conn.request('sync-database', {}, {
      idleMs: o.idleMs || TRANSFER_IDLE_MS,
      maxMs: o.maxMs || TRANSFER_MAX_MS,
      onPayload: (header, transport) => {
        const dir = o.destDir ? path.resolve(o.destDir) : this.downloadDir;
        ensureDir(dir);
        const target = o.destFile ? path.resolve(o.destFile) : path.join(dir, safeLocalFileName(header.name, 'hamster.db'));
        ensureDir(path.dirname(target));
        state.target = target;
        const part = target + '.part-' + process.pid;
        return new FileSink(part, {
          pause: transport.pause,
          resume: transport.resume,
          onDone: (err, bytes) => {
            if (err) { this._log('warn', '数据库落盘失败: ' + err.message); transport.settle(err); return; }
            try { fs.renameSync(part, target); } catch (e) { this._log('error', '数据库改名失败: ' + e.message); transport.settle(e); return; }
            transport.settle(null, { bytes, path: target });
          },
        });
      },
    });
    const data = res.data || {};
    const bytes = res.payload ? res.payload.bytes : 0;
    const declared = Number(data.payload_bytes);
    if (!res.payload || bytes !== declared) {
      throw new HamsterError('size_mismatch', '数据库字节数不符: 收到 ' + bytes + ' / 声明 ' + declared);
    }
    return { ok: true, path: state.target, size: bytes, hash: String(data.hash || '') };
  }

  /* ---------------- 事件连接（独立 socket，避免被负载传输挤掉事件） ---------------- */

  /**
   * 建立事件通道：独立连接 + hello + TCP keepalive + 30s 空闲看门狗 + 自动重连。
   * 之所以必须是独立连接：守护进程在传输负载时会 trylock 跳过该连接上的事件，
   * 与命令共用一个 socket 一定会丢事件。
   */
  startEvents() {
    if (this._events) return this._events;
    const self = this;
    const ev = new EventClient({
      host: this.host, port: this.port, codeword: this.codeword, apiKey: this.apiKey,
      deviceId: this.deviceId + '_evt', hostname: this.hostname,
      encrypt: this.encrypt,
      logger: this.log, label: this.name + '@' + this.addr,
      onEvent: (msg) => { if (self.onEvent) { try { self.onEvent(msg, self); } catch (_) {} } },
      onState: (s) => { if (self.onState) { try { self.onState(Object.assign({ device: self.name, kind: 'event' }, s)); } catch (_) {} } },
    });
    this._events = ev;
    ev.start();
    return ev;
  }

  stopEvents() {
    if (this._events) { this._events.stop(); this._events = null; }
  }

  /** 事件通道最近一次收到数据的年龄（毫秒）；未连接返回 null */
  eventAgeMs() {
    if (!this._events) return null;
    return this._events.ageMs();
  }

  /**
   * 发现命中：立刻把事件通道的退避复位并马上重连一次。
   * PROTOCOL §7.3(7)：目标设备刚上线就该被立刻连上，而不是等退避涨到 5s。
   * @returns {boolean} 是否真的触发了重连（已连上或已停止时返回 false）
   */
  nudgeEvents() {
    if (!this._events) return false;
    return this._events.nudge();
  }

  /** 事件通道是否已连接（供主进程上报给渲染层，避免外部触碰私有字段） */
  get eventsConnected() {
    return !!(this._events && this._events.connected);
  }

  close(reason) {
    this.stopEvents();
    if (this._conn) { this._conn.destroy(reason || 'close'); this._conn = null; }
    this.info = null;
  }
}

/* ==========================================================================
 * 事件通道
 * ========================================================================== */
class EventClient {
  /**
   * @param {{host:string,port:number,codeword?:string,apiKey?:string,deviceId:string,hostname:string,
   *          logger?:object,label?:string,onEvent?:function,onState?:function,
   *          keepAliveMs?:number,idleMs?:number}} opts
   */
  constructor(opts) {
    const o = opts || {};
    this.host = o.host || '127.0.0.1';
    this.port = Number(o.port) || DEFAULT_HAMD_PORT;
    this.codeword = o.codeword || '';
    this.apiKey = o.apiKey || '';
    this.deviceId = o.deviceId || 'manager_evt';
    this.hostname = o.hostname || os.hostname();
    this.log = o.logger || null;
    this.label = o.label || (this.host + ':' + this.port);
    this.onEvent = o.onEvent || null;
    this.onState = o.onState || null;
    this.keepAliveMs = o.keepAliveMs || KEEPALIVE_MS;
    this.idleMs = o.idleMs || IDLE_HALF_OPEN_MS;
    this.encrypt = !!o.encrypt;
    this._conn = null;
    this._keepTimer = null;
    this._watchTimer = null;
    this._retryTimer = null;
    this._retryDelay = 500;
    this._lastData = 0;
    this._connected = false;
    this._stopped = true;
    this._helloId = 0;
    this._pingId = 0;
  }

  _log(lvl, msg) { if (this.log && this.log[lvl]) this.log[lvl]('[evt ' + this.label + '] ' + msg); }

  get connected() { return this._connected; }

  ageMs() {
    if (!this._lastData) return null;
    return Date.now() - this._lastData;
  }

  start() {
    if (!this._stopped) return;
    this._stopped = false;
    this._open();
    if (!this._watchTimer) {
      this._watchTimer = setInterval(() => this._watchdog(), 5000);
      if (this._watchTimer.unref) this._watchTimer.unref();
    }
  }

  stop() {
    this._stopped = true;
    if (this._retryTimer) { clearTimeout(this._retryTimer); this._retryTimer = null; }
    if (this._keepTimer) { clearInterval(this._keepTimer); this._keepTimer = null; }
    if (this._watchTimer) { clearInterval(this._watchTimer); this._watchTimer = null; }
    this._teardown();
  }

  _emitState(connected) {
    if (this._connected === connected) return;
    this._connected = connected;
    if (this.onState) { try { this.onState({ connected, device: this.label }); } catch (_) {} }
  }

  _teardown() {
    const c = this._conn;
    this._conn = null;
    if (this._keepTimer) { clearInterval(this._keepTimer); this._keepTimer = null; }
    if (c) c.destroy('event teardown');
    this._emitState(false);
  }

  _open() {
    if (this._stopped) return;
    this._teardown();
    const conn = new HamsterConn({
      host: this.host, port: this.port, logger: this.log, label: 'evt/' + this.label,
      encrypt: this.encrypt,
      secret: this.codeword || this.apiKey || '',
      deviceId: this.deviceId,
      hostname: this.hostname,
      onEvent: (msg) => {
        this._lastData = Date.now();
        if (this.onEvent) { try { this.onEvent(msg); } catch (_) {} }
      },
      onClose: () => {
        this._emitState(false);
        this._scheduleRetry('连接关闭');
      },
    });
    this._conn = conn;
    conn.connect(5000).then(() => {
      this._lastData = Date.now();
      this._retryDelay = 500;
      const params = { device_id: this.deviceId, hostname: this.hostname };
      if (this.codeword) params.codeword = this.codeword;
      if (this.apiKey) params.api_key = this.apiKey;
      this._helloId += 1;
      /* §8：加密连接的身份校验已在握手中完成 */
      return conn.request(this.encrypt ? 'info' : 'hello', this.encrypt ? null : params, { timeoutMs: 8000 });
    }).then((res) => {
      const d = (res && res.data) || {};
      this._log('info', '事件通道已认证（server=' + d.server + ' monitor=' + d.monitor_path + '）');
      this._emitState(true);
      if (this._keepTimer) clearInterval(this._keepTimer);
      this._keepTimer = setInterval(() => {
        if (!conn.connected) return;
        this._pingId += 1;
        conn.request('ping', {}, { timeoutMs: 8000 }).then(() => {
          this._lastData = Date.now();
        }).catch((e) => {
          this._log('warn', '保活 ping 失败: ' + (e && e.message));
          this._teardown();
          this._scheduleRetry('保活失败');
        });
      }, this.keepAliveMs);
      if (this._keepTimer.unref) this._keepTimer.unref();
    }).catch((e) => {
      this._emitState(false);
      this._log('warn', '事件通道建立失败: ' + (e && e.message));
      this._teardown();
      this._scheduleRetry('建立失败');
    });
  }

  _scheduleRetry(why) {
    if (this._stopped || this._retryTimer) return;
    const delay = this._retryDelay;
    /* 上限从 60s 收到 5s：守护进程重启后应在几秒内就被连上，而不是等一分钟 */
    this._retryDelay = Math.min(Math.round(this._retryDelay * 2), 5000);
    this._log('warn', why + '，' + delay + 'ms 后重连事件通道');
    this._retryTimer = setTimeout(() => {
      this._retryTimer = null;
      this._open();
    }, delay);
    if (this._retryTimer.unref) this._retryTimer.unref();
  }

  /**
   * 发现命中：退避立刻复位到 500ms，并立即重连一次（不等定时器）。
   * 这样"目标设备一上线就连上"，而不是等退避涨到 5s 才轮到它。
   * @returns {boolean} 是否真的触发了重连
   */
  nudge() {
    if (this._stopped) return false;
    if (this._connected && this._conn && this._conn.connected) return false;
    this._retryDelay = 500;
    if (this._retryTimer) { clearTimeout(this._retryTimer); this._retryTimer = null; }
    this._log('info', '发现命中，立即重连事件通道');
    this._open();
    return true;
  }

  /** 空闲看门狗：超过 idleMs 没有任何数据（含 pong）说明是半开连接，重连 */
  _watchdog() {
    if (this._stopped) return;
    if (!this._conn || !this._conn.connected) return;
    const age = this.ageMs();
    if (age !== null && age > this.idleMs) {
      this._log('warn', '事件通道 ' + Math.round(age / 1000) + 's 无数据，判定半开，重连');
      this._teardown();
      this._scheduleRetry('半开');
    }
  }
}

/* ==========================================================================
 * 事件去重（同一 seq / 同一 (event,path) 时间窗口内只推一次）
 * ========================================================================== */
class EventDeduper {
  /**
   * @param {{windowMs?:number,onGap?:function,onDuplicate?:function,maxKeys?:number}} opts
   */
  constructor(opts) {
    const o = opts || {};
    this.windowMs = o.windowMs || 2000;
    this.maxKeys = o.maxKeys || 1024;
    this.onGap = o.onGap || null;
    this.onDuplicate = o.onDuplicate || null;
    this._lastSeq = new Map();   /* device -> seq */
    this._keys = new Map();      /* key -> ts */
  }

  /**
   * @returns {boolean} true = 新事件（应推给渲染层）
   */
  accept(ev) {
    const e = ev || {};
    const device = String(e.device || e.device_id || '-');
    const seq = Number(e.seq);
    const event = String(e.event || '');
    const dataPath = (e.data && (e.data.path || e.data.name)) || '';
    const key = device + '|' + event + '|' + dataPath;
    const now = Date.now();

    /* 1) seq 单调去重（同一事件从"事件 socket"与"代理转发"两条路都会到） */
    if (Number.isFinite(seq) && seq > 0) {
      const last = this._lastSeq.get(device);
      if (last !== undefined) {
        if (seq <= last) {
          /* 守护进程重启会让 seq 回到 1：此时不能把它永久丢掉 */
          if (!(seq <= 3 && last > 3)) {
            if (this.onDuplicate) { try { this.onDuplicate(e, 'seq'); } catch (_) {} }
            return false;
          }
          this._lastSeq.set(device, 0);
        } else if (seq > last + 1 && this.onGap) {
          try { this.onGap({ device, expected: last + 1, got: seq }); } catch (_) {}
        }
      }
      this._lastSeq.set(device, seq);
    }

    /* 2) (event,path) 时间窗口去重 */
    if (dataPath) {
      const seen = this._keys.get(key);
      if (seen !== undefined && now - seen < this.windowMs) {
        if (this.onDuplicate) { try { this.onDuplicate(e, 'key'); } catch (_) {} }
        return false;
      }
      this._keys.set(key, now);
      if (this._keys.size > this.maxKeys) {
        for (const [k, ts] of this._keys) {
          if (now - ts > this.windowMs) this._keys.delete(k);
          if (this._keys.size <= this.maxKeys / 2) break;
        }
      }
    }
    return true;
  }

  reset(device) {
    if (device === undefined) { this._lastSeq.clear(); this._keys.clear(); }
    else { this._lastSeq.delete(String(device)); }
  }
}

/* ==========================================================================
 * 设备库（原子写 + 数组校验 + 坏文件保留 + id 白名单）
 * ========================================================================== */
class DeviceStore {
  /**
   * @param {{file:string,logger?:object,hostname?:string}} opts
   */
  constructor(opts) {
    const o = opts || {};
    this.file = o.file;
    this.log = o.logger || null;
    this.hostname = o.hostname || os.hostname();
    this.devices = [];
    this._loaded = false;
  }

  _log(lvl, msg) { if (this.log && this.log[lvl]) this.log[lvl]('[devices] ' + msg); }

  /** 读取设备库：旧版单对象格式折成数组；非数组/解析失败 → 保留坏文件并回到空列表 */
  load() {
    const r = readJsonArraySync(this.file);
    if (r.recovered) {
      this._log('error', '设备库损坏，已保留为 ' + r.recovered + '（原因: ' + (r.error && r.error.message) + '），本次以空列表启动');
    } else if (r.error) {
      this._log('error', '读取设备库失败: ' + (r.error && r.error.message));
    } else if (r.migrated) {
      this._log('warn', '检测到旧版"单个设备对象"格式，已按 1 台设备加载（下次写入时自动规范化为数组）');
    } else if (r.existed) {
      this._log('info', '已加载 ' + r.list.length + ' 台设备: ' + this.file);
    } else {
      this._log('info', '设备库不存在，按空列表启动: ' + this.file);
      this.devices = [];
      this._loaded = true;
      this.save();
      return this.devices;
    }
    this.devices = r.list.filter((d) => d && typeof d === 'object' && isValidDeviceId(d.id));
    const dropped = r.list.length - this.devices.length;
    if (dropped > 0) this._log('warn', '丢弃 ' + dropped + ' 条 id 非法的设备记录');
    this._loaded = true;
    return this.devices;
  }

  save() {
    writeJsonAtomicSync(this.file, this.devices);
  }

  /** 内部使用（含 token） */
  raw() { return this.devices.map((d) => Object.assign({}, d)); }

  /** 对外契约：**不含 token**（修 P0-2/低 4） */
  list() {
    return this.devices.map((d) => ({
      id: d.id, name: d.name, addr: d.addr, status: d.status || 'offline',
      note: d.note || '', last_sync: d.last_sync || '', created_at: d.created_at || '',
    }));
  }

  find(id) { return this.devices.find((d) => d.id === id) || null; }

  findByAddr(addr) { return this.devices.find((d) => d.addr === addr) || null; }

  /**
   * 新增：**id 由主进程生成**（渲染层传来的 id 一律忽略），地址必须合法。
   * @returns {object} 新设备（含 token，供建立连接用）
   */
  add(fields) {
    const f = fields || {};
    const name = String(f.name === undefined || f.name === null ? '' : f.name).trim();
    const addrRaw = String(f.addr === undefined || f.addr === null ? '' : f.addr).trim();
    if (!addrRaw) throw new HamsterError('missing_addr', '设备地址不能为空');
    const { host, port } = parseAddr(addrRaw, DEFAULT_HAMD_PORT);
    const addr = host + ':' + port;
    if (this.findByAddr(addr)) throw new HamsterError('device_exists', '该地址已存在: ' + addr);
    const dev = {
      id: generateDeviceId(),
      name: name || addr,
      addr,
      token: String(f.token === undefined || f.token === null ? '' : f.token),
      status: 'offline',
      note: String(f.note === undefined || f.note === null ? '' : f.note),
      last_sync: '',
      created_at: new Date().toISOString(),
    };
    this.devices.push(dev);
    this.save();
    this._log('info', '新增设备 ' + dev.id + ' (' + dev.name + ' @ ' + dev.addr + ')');
    return Object.assign({}, dev);
  }

  remove(id) {
    assertValidDeviceId(id);
    const i = this.devices.findIndex((d) => d.id === id);
    if (i < 0) return false;
    const [gone] = this.devices.splice(i, 1);
    this.save();
    this._log('info', '移除设备 ' + gone.id + ' (' + gone.name + ')');
    return true;
  }

  /** 允许改的字段白名单；返回改动后的设备副本 */
  update(id, fields) {
    assertValidDeviceId(id);
    const d = this.find(id);
    if (!d) return null;
    const f = fields || {};
    if (f.name !== undefined) d.name = String(f.name);
    if (f.note !== undefined) d.note = String(f.note);
    if (f.token !== undefined) d.token = String(f.token);
    if (f.addr !== undefined) {
      const { host, port } = parseAddr(String(f.addr).trim(), DEFAULT_HAMD_PORT);
      const addr = host + ':' + port;
      const other = this.findByAddr(addr);
      if (other && other.id !== id) throw new HamsterError('device_exists', '该地址已被 ' + other.name + ' 使用');
      d.addr = addr;
    }
    this.save();
    return Object.assign({}, d);
  }

  /** 批量写状态（避免并发探测时各自整体覆盖写盘） */
  applyStatusBatch(items) {
    let dirty = false;
    for (const it of items || []) {
      const d = this.find(it.id);
      if (!d) continue;
      if (it.status !== undefined && d.status !== it.status) { d.status = it.status; dirty = true; }
      if (it.last_sync !== undefined && d.last_sync !== it.last_sync) { d.last_sync = it.last_sync; dirty = true; }
    }
    if (dirty) this.save();
    return dirty;
  }
}

/* ==========================================================================
 * 迁移日志（同 devices.json：原子写）
 * ========================================================================== */
class MigrationLog {
  /**
   * @param {{file:string,logger?:object,limit?:number}} opts
   */
  constructor(opts) {
    const o = opts || {};
    this.file = o.file;
    this.log = o.logger || null;
    this.limit = o.limit || 500;
    this.entries = [];
    const r = readJsonArraySync(this.file);
    if (r.recovered && this.log) this.log.error('[migrations] 迁移日志损坏，已保留为 ' + r.recovered);
    this.entries = r.list.filter((e) => e && typeof e === 'object');
  }

  /** 最近的迁移在前 */
  list(limit) {
    const n = limit ? Math.max(1, Number(limit)) : 200;
    return this.entries.slice(-n).reverse().map((e) => Object.assign({}, e));
  }

  append(entry) {
    const e = Object.assign({}, entry);
    if (!e.id) e.id = 'mig_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 8);
    if (!e.time) e.time = new Date().toISOString();
    this.entries.push(e);
    if (this.entries.length > this.limit) this.entries = this.entries.slice(-this.limit);
    try {
      writeJsonAtomicSync(this.file, this.entries);
    } catch (err) {
      if (this.log) this.log.error('[migrations] 写迁移日志失败: ' + err.message);
    }
    return Object.assign({}, e);
  }
}

/* ==========================================================================
 * 文件迁移编排（PROTOCOL §5）
 * ========================================================================== */
class Migrator {
  /**
   * @param {{getClient:function, tmpDir:string, log:Migrations|object, logger?:object, concurrency?:number}} opts
   *        getClient(id) 必须返回已连接可用的 HamsterClient
   */
  constructor(opts) {
    const o = opts || {};
    this.getClient = o.getClient;
    this.tmpDir = o.tmpDir || os.tmpdir();
    this.log = o.log || null;
    this.logger = o.logger || null;
    this.concurrency = o.concurrency || 2;
    ensureDir(this.tmpDir);
  }

  _log(lvl, msg) { if (this.logger && this.logger[lvl]) this.logger[lvl]('[migrate] ' + msg); }

  /**
   * 执行一次迁移：严格按 PROTOCOL §5。
   *   1 源下载（流式落临时文件，权威 hash）
   *   2 校验实收字节数 == payload_bytes（不等即中止，不留任何东西）
   *   3 目标上传（带源端 hash，mkdir:true，overwrite 由调用方决定）
   *   4 校验目标端回传 hash == 源端 hash（不通过绝不删源）
   *   5 仅当第 4 步通过且 mode==='move' 才删除源文件
   *   6 无论成功失败都写迁移日志
   * @param {{srcId:string,dstId:string,srcPath:string,dstPath:string,mode?:string,overwrite?:boolean}} job
   * @returns {Promise<{ok:true,size:number,hash:string,saved:boolean,removed:boolean,log_id:string}|{error:string,detail?:string,log_id:string}>}
   */
  async run(job) {
    const j = job || {};
    const entry = {
      id: 'mig_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 8),
      time: new Date().toISOString(),
      src: String(j.srcId || ''),
      dst: String(j.dstId || ''),
      src_name: '',
      path: String(j.srcPath || ''),
      dst_path: String(j.dstPath || ''),
      size: 0,
      hash: '',
      mode: String(j.mode || 'copy'),
      overwrite: !!j.overwrite,
      removed: false,
      ok: false,
      error: '',
      detail: '',
    };
    let tmp = null;
    try {
      if (!entry.src || !entry.dst) throw new HamsterError('missing_device', 'srcId / dstId 必填');
      if (!entry.path) throw new HamsterError('missing_path', 'srcPath 必填');
      assertSafePathArg(entry.path);
      assertSafeId(entry.src, 'srcId');
      assertSafeId(entry.dst, 'dstId');
      /* 目标路径必须是受控相对路径；校验失败时 entry.dst_path 保留原值以便日志定位 */
      const safeDst = sanitizeRelPath(j.dstPath);
      entry.dst_path = safeDst;
      if (entry.mode !== 'copy' && entry.mode !== 'move') throw new HamsterError('bad_mode', "mode 只能是 copy 或 move");
      if (!this.getClient) throw new HamsterError('internal', 'getClient 未提供');

      const src = await this.getClient(entry.src);
      const dst = await this.getClient(entry.dst);

      tmp = path.join(this.tmpDir, 'mig_' + process.pid + '_' + Date.now().toString(36) + '_' +
        Math.random().toString(36).slice(2, 8) + '.part');

      /* 1) 下载到临时文件（流式） */
      const dl = await src.download(entry.path, { destFile: tmp });
      entry.src_name = dl.name;
      entry.size = dl.size;
      if (!dl.hash) throw new HamsterError('hash_missing', '源端未返回权威 hash，无法做端到端校验');
      entry.hash = dl.hash;

      /* 2) 字节数校验（download 内部已严格校验，这里再确认一次，失败绝不留残件） */
      if (!fs.existsSync(tmp) || fs.statSync(tmp).size !== dl.size) {
        throw new HamsterError('size_mismatch', '临时文件大小 ' +
          (fs.existsSync(tmp) ? fs.statSync(tmp).size : -1) + ' ≠ 收到 ' + dl.size);
      }

      /* 3) 上传到目标端：携带源端权威 hash，由目标端在写入过程中比对 */
      const up = await dst.upload({
        localPath: tmp,
        remotePath: entry.dst_path,
        hash: entry.hash,
        overwrite: entry.overwrite,
        mkdir: true,
      });

      /* 4) 目标端 hash 必须与源端一致（upload 内部已比对，这里保留显式判定以便审计） */
      if (String(up.hash || '').toLowerCase() !== String(entry.hash).toLowerCase()) {
        throw new HamsterError('hash_mismatch', '目标端 hash=' + up.hash + ' 源端 hash=' + entry.hash);
      }

      /* 5) 只有第 4 步通过后，move 才允许删源。
            Windows 上刚落盘的文件可能被杀软/索引器短暂占用（remove_failed），
            delete 是幂等操作，因此对 remove_failed 做一次 300ms 后的重试；
           重试仍失败就如实返回错误并保留源文件（绝不会误报成功）。 */
      let removed = false;
      if (entry.mode === 'move') {
        try {
          await src.remove(entry.path);
        } catch (e) {
          if (isHamsterError(e) && e.code === 'remove_failed') {
            this._log('warn', '删除源文件失败（' + e.code + '），300ms 后重试一次: ' + entry.path);
            await new Promise((r) => setTimeout(r, 300));
            await src.remove(entry.path);
          } else {
            throw e;
          }
        }
        removed = true;
      }
      entry.removed = removed;
      entry.ok = true;
      this._log('info', entry.mode + ' 成功 ' + location(entry) + ' size=' + entry.size + ' hash=' + entry.hash +
        (removed ? '（已删源）' : ''));
      return { ok: true, size: entry.size, hash: entry.hash, saved: true, removed, log_id: entry.id };
    } catch (e) {
      entry.error = isHamsterError(e) ? e.code : ((e && e.code) ? String(e.code) : 'error');
      entry.detail = isHamsterError(e) ? e.detail : String((e && e.message) || e);
      this._log('warn', entry.mode + ' 失败 ' + location(entry) + ': ' + entry.error + ' ' + entry.detail);
      return { error: entry.error, detail: entry.detail, log_id: entry.id };
    } finally {
      if (tmp) { try { fs.unlinkSync(tmp); } catch (_) {} }
      if (this.log && this.log.append) {
        try { this.log.append(entry); } catch (_) {}
      }
    }
  }

  /**
   * 批量迁移：并发受控，逐个返回结果，单个失败不影响其它。
   * @param {Array} jobs
   * @param {{concurrency?:number}} [opts]
   * @returns {Promise<Array>} 与 jobs 同序，失败项为 {error,detail,index}
   */
  async runMany(jobs, opts) {
    const list = Array.isArray(jobs) ? jobs : [];
    const limit = Math.max(1, Math.min(Number((opts && opts.concurrency) || this.concurrency) || 2, 8));
    const results = new Array(list.length);
    let next = 0;
    const worker = async () => {
      for (;;) {
        const i = next++;
        if (i >= list.length) return;
        try {
          const r = await this.run(list[i]);
          results[i] = Object.assign({ index: i }, r);
        } catch (e) {
          results[i] = Object.assign({ index: i }, toErrorResult(e));
        }
      }
    };
    await Promise.all(Array.from({ length: Math.min(limit, list.length) }, worker));
    return results;
  }
}

function location(entry) {
  return '[' + entry.src + ': ' + entry.path + ' → ' + entry.dst + ': ' + entry.dst_path + ']';
}

/* ==========================================================================
 * 局域网发现（PROTOCOL §7）：客户端广播探测，服务端只在对上暗号时单播应答
 *
 * 为什么不是"读设备的 peers"：旧做法只能看见**已经连上**的设备上报的同网设备，
 * 于是"从没连上过的设备"永远发现不了——而这正是发现功能存在的理由。
 * 现在反过来：本地广播探测，谁能对上暗号谁回话，回话里带着它自己的 TCP 端口。
 * ========================================================================== */
const DISC_DEFAULT_PORT = 9110;
const DISC_VERSION = 1;
const DISC_FRAME_MAX = 512;
const DISC_PROBE_PREFIX = 'hamster-disc-probe/v1\n';
const DISC_REPLY_PREFIX = 'hamster-disc-reply/v1\n';
const DISC_ID_RE = /^[0-9A-Za-z_-]{8,63}$/;
const DISC_NONCE_RE = /^[0-9a-fA-F]{32}$/;
const DISC_MAC_RE = /^[0-9a-fA-F]{64}$/;

/** 探测帧的 MAC；原文必须与服务端逐字节一致（PROTOCOL §7.1） */
function discProbeMac(codeword, id, nonceHex) {
  return crypto.createHmac('sha256', codeword)
    .update(DISC_PROBE_PREFIX + id + '\n' + nonceHex, 'utf8')
    .digest('hex');
}

/** 应答帧的 MAC：绑定探测方 id，因此捕获的应答无法重放给别的客户端 */
function discReplyMac(codeword, probeId, nonceHex, selfId, port) {
  return crypto.createHmac('sha256', codeword)
    .update(DISC_REPLY_PREFIX + probeId + '\n' + nonceHex + '\n' + selfId + '\n' + String(port), 'utf8')
    .digest('hex');
}

/** 定长十六进制串的常量时间比较（不要用 ===，时序会泄露前缀匹配长度） */
function discMacEquals(a, b) {
  const x = Buffer.from(String(a).toLowerCase(), 'utf8');
  const y = Buffer.from(String(b).toLowerCase(), 'utf8');
  if (x.length !== y.length) return false;
  try { return crypto.timingSafeEqual(x, y); } catch (_) { return false; }
}

function ipv4ToInt(ip) {
  const p = String(ip).split('.');
  if (p.length !== 4) return null;
  let n = 0;
  for (const s of p) {
    const v = Number(s);
    if (!Number.isInteger(v) || v < 0 || v > 255) return null;
    n = (n * 256) + v;
  }
  return n >>> 0;
}

function intToIpv4(n) {
  return [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff].join('.');
}

/**
 * 广播目标：有限广播 + 每个网卡的子网广播 + 回环。
 * 回环是必须的：同机部署（开发、测试、单机多实例）时广播包不保证被本机收回。
 */
function discBroadcastTargets() {
  const out = new Set(['255.255.255.255', '127.0.0.1']);
  let ifs = {};
  try { ifs = os.networkInterfaces() || {}; } catch (_) { ifs = {}; }
  for (const name of Object.keys(ifs)) {
    for (const a of ifs[name] || []) {
      const fam = a.family;
      if (fam !== 'IPv4' && fam !== 4) continue;
      if (a.internal || !a.address || !a.netmask) continue;
      const ip = ipv4ToInt(a.address);
      const mask = ipv4ToInt(a.netmask);
      if (ip === null || mask === null) continue;
      const b = ((ip | (~mask >>> 0)) >>> 0);
      if (b && b !== ip) out.add(intToIpv4(b));
    }
  }
  return Array.from(out);
}

/**
 * 局域网发现器：周期性广播探测，收集并校验应答。
 *
 * 用法：
 *   const d = new Discovery({ codeword, deviceId, port: 9110, logger });
 *   d.start();  ...  d.list();  ...  d.stop();
 */
class Discovery {
  /**
   * @param {object} opts
   * @param {string} opts.codeword  与服务端一致的连接口令；空则**不广播**
   * @param {string} opts.deviceId  本机标识（8–63 位 [0-9A-Za-z_-]），进探测帧的 MAC
   * @param {number} [opts.port=9110] 服务端的 UDP 发现端口（hamd_discovery_port）
   * @param {number} [opts.intervalMs=1000] 广播间隔
   * @param {number} [opts.ttlMs=3000] 多久没应答就从列表里移除
   * @param {object} [opts.logger]  createLogger() 的产物
   * @param {function} [opts.onFound] (peer, isNew) => void，每次收到有效应答调用
   * @param {string[]} [opts.targets] 覆盖广播目标（测试用）
   */
  constructor(opts) {
    const o = opts || {};
    this.codeword = String(o.codeword || '');
    this.deviceId = String(o.deviceId || '');
    this.port = Number(o.port) > 0 ? Number(o.port) : DISC_DEFAULT_PORT;
    this.intervalMs = Number(o.intervalMs) > 0 ? Number(o.intervalMs) : 1000;
    this.ttlMs = Number(o.ttlMs) > 0 ? Number(o.ttlMs) : 3000;
    this.logger = o.logger || null;
    this.onFound = typeof o.onFound === 'function' ? o.onFound : null;
    this._targets = Array.isArray(o.targets) && o.targets.length ? o.targets : null;

    this._sock = null;
    this._timer = null;
    this._peers = new Map();          /* 服务端 id → 条目 */
    this._nonces = [];                /* [{n, at}] 最近几轮发出的 nonce */
    this._running = false;
    this._rounds = 0;
    this._sent = 0;
    this._recv = 0;
    this._rejected = 0;
  }

  /** 配置是否足以广播（没有暗号就不该出声，否则只是在暴露本机存在） */
  get enabled() {
    return !!(this.codeword && DISC_ID_RE.test(this.deviceId));
  }

  get running() { return this._running; }

  start() {
    if (this._running) return true;
    if (!this.codeword) {
      this._warn('未配置 codeword，不广播探测（算不出 MAC，广播只会暴露本机存在）');
      return false;
    }
    if (!DISC_ID_RE.test(this.deviceId)) {
      this._warn('deviceId 不合法，不广播探测: ' + JSON.stringify(this.deviceId));
      return false;
    }

    const sock = dgram.createSocket('udp4');
    this._sock = sock;
    this._running = true;
    sock.on('error', (e) => this._warn('发现 socket 错误: ' + (e && e.message)));
    sock.on('message', (buf, rinfo) => {
      try { this._onMessage(buf, rinfo); } catch (e) { this._warn('处理应答异常: ' + (e && e.message)); }
    });
    sock.once('listening', () => {
      try { sock.setBroadcast(true); } catch (_) {}
      if (this._running) this.probe();
    });
    try {
      sock.bind(0);
    } catch (e) {
      this._warn('绑定发现 socket 失败: ' + (e && e.message));
      this._running = false;
      this._sock = null;
      try { sock.close(); } catch (_) {}
      return false;
    }

    this._timer = setInterval(() => this.probe(), this.intervalMs);
    if (this._timer.unref) this._timer.unref();
    this._info('开始广播探测：端口 ' + this.port + '，间隔 ' + this.intervalMs + 'ms');
    return true;
  }

  stop() {
    const was = this._running;
    this._running = false;
    if (this._timer) { clearInterval(this._timer); this._timer = null; }
    const s = this._sock;
    this._sock = null;
    if (s) { try { s.close(); } catch (_) {} }
    this._nonces.length = 0;
    this._peers.clear();
    if (was) this._info('已停止广播探测');
  }

  /** 立刻广播一轮；返回发出的目标数 */
  probe() {
    if (!this._running || !this._sock) return 0;

    const now = Date.now();
    const nonce = crypto.randomBytes(16).toString('hex');
    this._nonces.push({ n: nonce, at: now });

    /* 只保留最近 3 轮：应答可能在下一轮才到，更早的一定是脏数据 */
    const keepMs = this.intervalMs * 3 + 500;
    while (this._nonces.length && now - this._nonces[0].at > keepMs) this._nonces.shift();

    const frame = Buffer.from(JSON.stringify({
      t: 'hp', v: DISC_VERSION, id: this.deviceId, n: nonce,
      m: discProbeMac(this.codeword, this.deviceId, nonce),
    }), 'utf8');

    const targets = this._targets || discBroadcastTargets();
    for (const host of targets) {
      try {
        this._sent += 1;
        this._sock.send(frame, this.port, host, (err) => {
          if (err) this._debug('发送探测到 ' + host + ' 失败: ' + err.message);
        });
      } catch (e) {
        this._debug('发送探测到 ' + host + ' 异常: ' + (e && e.message));
      }
    }
    this._rounds += 1;
    return targets.length;
  }

  /** 当前发现的设备，最近应答的在前 */
  list() {
    const now = Date.now();
    const out = [];
    for (const [id, e] of this._peers) {
      if (now - e.last_ms > this.ttlMs) { this._peers.delete(id); continue; }
      out.push(this._public(e, now));
    }
    out.sort((a, b) => (a.age_ms - b.age_ms) || String(a.id).localeCompare(String(b.id)));
    return out;
  }

  /** 诊断计数（供日志/测试断言，不要拿去当业务状态） */
  get stats() {
    return {
      port: this.port, rounds: this._rounds, sent: this._sent,
      recv: this._recv, rejected: this._rejected, peers: this._peers.size,
    };
  }

  _public(e, now) {
    const t = now || Date.now();
    return {
      id: e.id, ip: e.ip, name: e.name, port: e.port, ver: e.ver,
      age_ms: Math.max(0, t - e.last_ms),
      addr: e.ip + ':' + e.port,
    };
  }

  _nonceKnown(n, now) {
    const ttl = this.ttlMs + this.intervalMs;
    for (const e of this._nonces) {
      if (e.n === n && (now - e.at) <= ttl) return true;
    }
    return false;
  }

  _onMessage(buf, rinfo) {
    const now = Date.now();

    if (!buf || buf.length === 0 || buf.length > DISC_FRAME_MAX) { this._rejected += 1; return; }

    let f = null;
    try { f = JSON.parse(buf.toString('utf8')); } catch (_) { this._rejected += 1; return; }
    if (!f || typeof f !== 'object' || Array.isArray(f)) { this._rejected += 1; return; }

    /* 任何一个字段不符都当"没收到"：不报错、不提示（PROTOCOL §7.3(4)） */
    if (f.t !== 'hr' || f.v !== DISC_VERSION) { this._rejected += 1; return; }
    if (typeof f.id !== 'string' || !DISC_ID_RE.test(f.id)) { this._rejected += 1; return; }
    if (f.id === this.deviceId) { this._rejected += 1; return; }        /* 同机自打自收 */
    if (typeof f.n !== 'string' || !DISC_NONCE_RE.test(f.n)) { this._rejected += 1; return; }
    if (typeof f.m !== 'string' || !DISC_MAC_RE.test(f.m)) { this._rejected += 1; return; }

    const port = Number(f.port);
    if (!Number.isInteger(port) || port <= 0 || port > 65535) { this._rejected += 1; return; }
    if (!this._nonceKnown(f.n, now)) { this._rejected += 1; return; }   /* 旧应答/不在窗口内 */

    if (!discMacEquals(discReplyMac(this.codeword, this.deviceId, f.n, f.id, port), f.m)) {
      this._rejected += 1;
      return;
    }

    const ip = (rinfo && rinfo.address) ? String(rinfo.address) : '';
    if (!ip || ip === '0.0.0.0') { this._rejected += 1; return; }

    const prev = this._peers.get(f.id);
    const entry = {
      id: f.id,
      ip,
      name: typeof f.name === 'string' ? f.name : '',
      port,
      ver: typeof f.ver === 'string' ? f.ver : '',
      first_ms: prev ? prev.first_ms : now,
      last_ms: now,
    };
    this._peers.set(f.id, entry);
    this._recv += 1;
    this._debug('发现设备 ' + (entry.name || f.id) + ' @ ' + ip + ':' + port);

    if (this.onFound) {
      try { this.onFound(this._public(entry, now), !prev); } catch (_) {}
    }
  }

  _log(level, msg) {
    if (this.logger && typeof this.logger[level] === 'function') this.logger[level]('[discover] ' + msg);
  }
  _info(msg) { this._log('info', msg); }
  _warn(msg) { this._log('warn', msg); }
  _debug(msg) { this._log('debug', msg); }
}

/**
 * @deprecated 0.0.8 起发现由客户端广播完成（见 Discovery）。
 * 保留此函数只为外部脚本兼容：服务端 `peers` 恒为空数组，因此这里恒返回 []。
 */
async function collectPeers(clients, opts) {
  const o = opts || {};
  const seen = new Map();
  await Promise.all((clients || []).map(async (c) => {
    try {
      const st = await c.stats(o.timeoutMs || 4000);
      const peers = Array.isArray(st.peers) ? st.peers : [];
      for (const p of peers) {
        if (!p || typeof p !== 'object') continue;
        const key = String(p.id || (p.ip + ':' + p.port));
        if (seen.has(key)) continue;
        seen.set(key, {
          id: String(p.id || key),
          ip: String(p.ip || ''),
          name: String(p.name || ''),
          port: Number(p.port) || 0,
          age_ms: Number(p.age_ms) || 0,
        });
      }
    } catch (e) {
      if (o.logger) o.logger.debug('[discover] 查询 ' + (c.name || c.id) + ' 失败: ' + (e && e.message));
    }
  }));
  return Array.from(seen.values());
}

/* ==========================================================================
 * 导出
 * ========================================================================== */
module.exports = {
  /* 常量 */
  LINE_MAX, OUT_MAX, DEFAULT_HAMD_PORT, DEFAULT_IPC_PORT, DEFAULT_TIMEOUT_MS,
  KEEPALIVE_MS, IDLE_HALF_OPEN_MS, DEVICE_ID_RE,

  /* 错误 */
  HamsterError, isHamsterError, toErrorResult, errorFromData,

  /* 日志 */
  createLogger, redact,

  /* 配置 */
  parseConfText, loadManagerConfig, findDaemonConf, resolveManagerExe,

  /* 文件 */
  ensureDir, writeFileAtomicSync, writeJsonAtomicSync, readJsonArraySync, uniquePath,

  /* 路径与地址 */
  generateDeviceId, isValidDeviceId, assertValidDeviceId, assertSafeId, isWithinDir, resolveInside,
  sanitizeRelPath, assertSafePathArg, safeLocalFileName, parseAddr, probePort,

  /* 分帧与传输 */
  FrameParser, FileSink, pipeFileToSocket,

  /* 协议 */
  HamsterConn, HamsterClient, EventClient,

  /* 存储与编排 */
  DeviceStore, MigrationLog, Migrator, EventDeduper, collectPeers,

  /* 局域网发现（PROTOCOL §7） */
  Discovery, discProbeMac, discReplyMac, discBroadcastTargets, DISC_DEFAULT_PORT,
};
