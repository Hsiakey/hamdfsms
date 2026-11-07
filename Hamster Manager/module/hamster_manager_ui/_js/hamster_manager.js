/* ==========================================================================
   Hamster Manager — Electron 渲染层（原生 JS，无框架）
   契约：PROTOCOL.md §6
     dev.list/listAll/add/remove/update/stats/search/download/syncDb
     file.list/mkdir/delete/upload   migrate.run/list
     event.onBroadcast/onConnected/onHeartbeat/onMessage
     window.*  config.get/set  app.getVersion/getPaths
   约束：不 require、不发网络请求，只经 window.hamster.*；不拼 HTML 字符串承载远端文本。
   ========================================================================== */
'use strict';

/* ======================= 基础工具 ======================= */

function $(id) { return document.getElementById(id); }

/** 建元素：所有远端文本一律走 textContent / dataset，避免注入。 */
function mk(tag, cls, text) {
  const el = document.createElement(tag);
  if (cls) el.className = cls;
  if (text !== undefined && text !== null) el.textContent = String(text);
  return el;
}

/** 取 window.hamster 下的方法（能力探测用） */
function api(path) {
  let cur = window.hamster;
  for (const k of String(path).split('.')) {
    if (cur === null || cur === undefined) return undefined;
    cur = cur[k];
  }
  return cur;
}
function hasApi(path) { return typeof api(path) === 'function'; }

/** 调用主进程 IPC 方法；缺接口时给出明确错误而不是 TypeError */
async function callApi(path, ...args) {
  const parts = String(path).split('.');
  const name = parts.pop();
  let parent = window.hamster;
  for (const k of parts) parent = (parent === null || parent === undefined) ? undefined : parent[k];
  if (!parent || typeof parent[name] !== 'function') {
    throw new Error('主进程未提供接口 window.hamster.' + path);
  }
  return await parent[name](...args);
}

/* 关于转义：本文件不再存在 esc() 这类“拼 HTML 字符串”的辅助函数——
   远端文本（文件名/路径/设备名/错误信息）一律经 textContent、dataset、属性赋值注入，
   “属性上下文转义不全导致 XSS”这一攻击面被结构性消除，而不是靠补转义掩盖。
   维护约定：若将来确有必须拼接 HTML 的场合，必须内联完成 & < > " ' ` 六个字符的转义，
   并只用于属性值（title/aria-label 等请优先用 el.title = value 之类的属性赋值）。 */

function fmtBytes(b) {
  const n0 = Number(b);
  if (!isFinite(n0) || n0 <= 0) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0; let n = n0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return n.toFixed(1) + ' ' + u[i];
}

/** 统一时间格式化：ISO 字符串 / 秒级或毫秒级数字 → 本地时间；非法值一律 "—" */
function fmtTime(v) {
  if (v === null || v === undefined || v === '') return '—';
  let d;
  if (typeof v === 'number') {
    if (!isFinite(v) || v <= 0) return '—';        /* 0 是主进程"无值"的占位，不能显示成 1970 */
    d = new Date(v < 1e12 ? v * 1000 : v);
  } else if (typeof v === 'string') d = new Date(v);
  else return '—';
  if (!d || isNaN(d.getTime())) return '—';
  const p = n => String(n).padStart(2, '0');
  return d.getFullYear() + '.' + p(d.getMonth() + 1) + '.' + p(d.getDate()) +
         ' ' + p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
}
/** 用于排序的时间值（毫秒）；无法解析返回 0 */
function toMs(v) {
  if (typeof v === 'number' && isFinite(v) && v > 0) return v < 1e12 ? v * 1000 : v;
  if (typeof v === 'string' && v) { const t = new Date(v).getTime(); return isFinite(t) ? t : 0; }
  return 0;
}
function fmtNow() { return fmtTime(Date.now()); }
function fmtDuration(ms) {
  const n = Number(ms);
  if (!isFinite(n) || n < 0) return '—';
  if (n < 1000) return n + ' ms';
  if (n < 60000) return (n / 1000).toFixed(1) + ' 秒';
  return Math.round(n / 60000) + ' 分';
}
/** 校验周期：协议里是"分钟"还是"秒"由服务端决定；此处按秒解释并给出可读值 */
function fmtInterval(sec) {
  const n = Number(sec);
  if (!isFinite(n)) return '—';
  if (n <= 0) return '关闭';
  if (n >= 86400) return Math.round(n / 86400) + ' 天';
  if (n >= 3600) return Math.round(n / 3600) + ' 小时';
  if (n >= 60) return Math.round(n / 60) + ' 分钟';
  return n + ' 秒';
}
function fmtNum(v) {
  const n = Number(v);
  return isFinite(n) ? n.toLocaleString() : '—';
}

/* 错误码 → 中文说明（协议 §4.1 + 主进程自造错误） */
const ERR_ZH = {
  unauthenticated: '未认证（口令/密钥无效）', invalid_credential: '口令错误',
  malformed_json: '请求格式错误', missing_action: '缺少 action', unknown_action: '设备不支持该命令',
  missing_path: '缺少路径', missing_id: '缺少 id', path_denied: '路径越权或非法',
  not_found: '未找到', file_not_found: '文件不存在', not_a_directory: '不是目录',
  is_directory: '目标是目录', exists: '目标已存在（未勾选“覆盖”）', confirm_required: '缺少确认参数',
  too_large: '超过设备允许的传输大小', hash_mismatch: '哈希校验不一致（已丢弃半成品）',
  payload_incomplete: '传输负载不完整', line_too_long: '消息行过长', response_too_large: '响应过大，请缩小关键词或降低条数',
  remove_failed: '删除失败', mkdir_failed: '创建目录失败', rename_failed: '重命名失败',
  open_failed: '打开文件失败', write_failed: '写入失败', dir_not_empty: '目录非空，无法删除',
  timeout: '超时', con_timeout: '连接超时', socket_error: '网络错误', no_header: '响应缺少头部',
  bad_header: '响应头部无法解析', device_not_found: '设备不存在', device_exists: '设备已存在',
  missing_params: '缺少参数', size_mismatch: '实收字节数与声明不符', sync_error: '同步失败',
  db_not_found: '设备上没有数据库', offline: '设备离线', IPC: '与本机代理未连接'
};

/** 统一把 IPC 返回值/异常转成可读错误文案（含原始错误码，便于排查） */
function errText(e) {
  if (e === null || e === undefined) return '未知错误';
  if (typeof e === 'string') return ERR_ZH[e] ? (e + '（' + ERR_ZH[e] + '）') : e;
  if (e instanceof Error) return e.message || String(e);
  const raw = e.error || e.code || '';
  const detail = e.detail || e.message || '';
  if (!raw && !detail) return '未返回错误信息（响应结构异常）';
  const zh = ERR_ZH[raw];
  let s = raw ? String(raw) : '';
  if (zh) s += (s ? '（' + zh + '）' : zh);
  if (detail && String(detail) !== String(raw)) s += ' · ' + detail;
  return s || String(detail);
}

/** 判断 IPC 返回是否是失败结果 */
function isErr(res) {
  if (res === null || res === undefined) return true;
  if (typeof res === 'object' && (res.error || res.code)) return true;
  return false;
}

/* ======================= 通用 UI 组件 ======================= */

/** 消息条：textContent 写入（远端错误文本不再当 HTML 解析）；句柄存元素上，清除旧定时器 */
function showMsg(el, text, type) {
  if (!el) return;
  if (el.__msgTimer) { clearTimeout(el.__msgTimer); el.__msgTimer = null; }
  el.textContent = '';
  const div = mk('div', 'msg ' + (type === 'warn' ? 'error' : (type || 'info')), text);
  el.appendChild(div);
  el.__msgTimer = setTimeout(() => { el.textContent = ''; el.__msgTimer = null; }, 5000);
}

/** 行内状态文字（不自动消失，覆盖式） */
function setStatus(el, text) {
  if (!el) return;
  if (el.__msgTimer) { clearTimeout(el.__msgTimer); el.__msgTimer = null; }
  el.textContent = '';
  el.appendChild(mk('div', 'msg info', text));
}

function clearStatus(el) { if (el) { if (el.__msgTimer) { clearTimeout(el.__msgTimer); el.__msgTimer = null; } el.textContent = ''; } }

/** 错误态 + 重试按钮：IPC 失败不再永久停在“加载中” */
function renderErrorBox(container, text, onRetry) {
  if (!container) return;
  container.textContent = '';
  const box = mk('div', 'error-box');
  box.appendChild(mk('span', null, text));
  if (typeof onRetry === 'function') {
    const btn = mk('button', 'btn-secondary', '重试');
    btn.addEventListener('click', onRetry);
    box.appendChild(btn);
  }
  container.appendChild(box);
}

/** 按钮忙碌态：保存原标签，恢复时还原 */
function setBusy(btn, busy, busyLabel) {
  if (!btn) return;
  if (busy) {
    if (btn.__idleLabel === undefined) btn.__idleLabel = btn.textContent;
    btn.disabled = true;
    if (busyLabel) btn.textContent = busyLabel;
  } else {
    btn.disabled = false;
    if (btn.__idleLabel !== undefined) { btn.textContent = btn.__idleLabel; btn.__idleLabel = undefined; }
  }
}
/** 防重入：必须在任何 await 之前同步置位；恢复一律走 try/finally + endBusy() */
function beginBusy(btn, label) {
  if (!btn) return true;
  if (btn.dataset.busy === '1') return false;
  btn.dataset.busy = '1';
  setBusy(btn, true, label);
  return true;
}
function endBusy(btn) {
  if (!btn) return;
  btn.dataset.busy = '';
  setBusy(btn, false);
}

/** 受控并发池（默认 3 路） */
async function pool(items, limit, worker) {
  const queue = items.slice();
  const n = Math.max(1, Math.min(limit || 3, queue.length || 1));
  const runners = [];
  for (let i = 0; i < n; i++) {
    runners.push((async () => {
      while (queue.length) {
        const item = queue.shift();
        try { await worker(item); }
        catch (e) { console.warn('[POOL] worker 异常:', e); }
      }
    })());
  }
  await Promise.allSettled(runners);
}

/** 复制文本：优先 Clipboard API，退回 execCommand */
async function copyText(text) {
  const s = String(text === null || text === undefined ? '' : text);
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(s);
      return true;
    }
  } catch (e) { /* 落到兜底 */ }
  try {
    const ta = document.createElement('textarea');
    ta.value = s;
    ta.setAttribute('readonly', 'readonly');
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(ta);
    return !!ok;
  } catch (e) { return false; }
}

/**
 * 打开文件所在目录。
 * PROTOCOL §6 未定义“打开目录”接口，因此按可用性探测多种命名；
 * 一个都没有时退化为“复制路径”，并明确告知用户。
 */
async function revealPath(p) {
  const candidates = ['revealPath', 'showItemInFolder', 'openPath',
                      'shell.showItemInFolder', 'shell.openPath', 'app.revealPath', 'app.showItemInFolder'];
  for (const c of candidates) {
    if (!hasApi(c)) continue;
    try { await callApi(c, p); return true; }
    catch (e) { console.warn('[REVEAL] ' + c + ' 失败:', e && e.message); }
  }
  return false;
}
async function openFolderFor(p, msgEl) {
  if (!p) { showMsg(msgEl, '主进程未返回保存路径，无法打开目录', 'error'); return; }
  if (await revealPath(p)) { showMsg(msgEl, '已打开：' + p, 'success'); return; }
  const ok = await copyText(p);
  showMsg(msgEl, ok ? ('主进程未提供“打开目录”接口，已复制路径：' + p)
                    : ('主进程未提供“打开目录”接口，路径：' + p), ok ? 'info' : 'error');
}

/* ======================= 全局状态 ======================= */

let devices = [];          /* dev.list 结果 */
let devMap = {};           /* id → device */
let dashCache = [];        /* 仪表盘聚合数据（dev.listAll 结构） */
let secCache = {};         /* deviceId → verify 数据（null 表示未知） */
let dashSeq = 0;           /* 仪表盘请求序号 */
let secSeq = 0;            /* 校验页请求序号 */
let listAllInflight = null;/* dev.listAll 并发去重 */

/** dev.listAll 并发去重：仪表盘与校验页同时刷新时只打一次 IPC */
function fetchListAll() {
  if (!listAllInflight) {
    listAllInflight = (async () => {
      try {
        const r = await callApi('dev.listAll');
        return Array.isArray(r) ? r : [];
      } finally { listAllInflight = null; }
    })();
  }
  return listAllInflight;
}

/** 重新读取设备表并刷新 devMap */
async function reloadDevices() {
  const r = await callApi('dev.list');
  devices = Array.isArray(r) ? r : [];
  devMap = {};
  devices.forEach(d => { if (d && d.id !== undefined) devMap[String(d.id)] = d; });
  return devices;
}

function deviceLabel(d) {
  if (!d) return '未知设备';
  return (d.name || d.id || '未知设备') + (d.addr ? '（' + d.addr + '）' : '');
}

/* ======================= 页面路由 ======================= */

const PAGES = {
  dashboard: { enter() { loadDashboard(); loadSecurity(); } },
  security: { enter() { loadSecurity({ force: true }); } },
  search: { enter() { initSearchPage(); } },
  control: { enter() { initControlCenter(); } },
  devices: { enter() { loadDevices(); } },
  eventlog: { enter() { renderHealth(); startHealthTicker(); }, leave() { stopHealthTicker(); } },
  migrate: { enter() { initMigratePage(); } },
  settings: { enter() { loadAppSettings(); } },
  about: { enter() { loadAbout(); } }
};

let currentPage = 'dashboard';

function gotoPage(name) {
  const li = document.querySelector('#sidebar li[data-page="' + String(name).replace(/"/g, '') + '"]');
  if (!li || !PAGES[name]) return;
  activatePage(li);
}

function activatePage(li) {
  const name = li.dataset.page;
  if (!PAGES[name]) return;
  const prev = PAGES[currentPage];
  if (prev && typeof prev.leave === 'function') { try { prev.leave(); } catch (e) { console.warn(e); } }

  document.querySelectorAll('#sidebar li').forEach(l => {
    const on = l === li;
    l.classList.toggle('active', on);
    if (on) l.setAttribute('aria-current', 'page'); else l.removeAttribute('aria-current');
  });
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  const page = $('page-' + name);
  if (page) page.classList.add('active');
  currentPage = name;

  try { PAGES[name].enter(); }
  catch (e) {
    console.error('[PAGE] ' + name + ' 进入失败:', e);
    showMsg($('page-' + name), '页面加载失败：' + errText(e), 'error');
  }
}

function initSidebar() {
  const sidebar = $('sidebar');
  if (!sidebar) return;
  sidebar.addEventListener('click', (e) => {
    const li = e.target.closest('li[data-page]');
    if (li) activatePage(li);
  });
  /* 键盘可达：Enter / Space 等同点击 */
  sidebar.addEventListener('keydown', (e) => {
    const li = e.target.closest('li[data-page]');
    if (!li) return;
    if (e.key === 'Enter' || e.key === ' ' || e.key === 'Spacebar') {
      e.preventDefault();
      activatePage(li);
    }
  });
}

/* ======================= 设备编辑弹窗 ======================= */

let modalBusy = false;
let lastFocused = null;

function openDeviceModal() {
  const modal = $('deviceModal');
  if (!modal) return;
  lastFocused = document.activeElement;
  modal.style.display = 'flex';
  clearStatus($('modalMsg'));
  setTimeout(() => { const el = $('devName'); if (el) el.focus(); }, 0);
}
function closeDeviceModal() {
  const modal = $('deviceModal');
  if (!modal || modal.style.display === 'none') return;
  modal.style.display = 'none';
  /* 焦点还原到打开弹窗的控件 */
  if (lastFocused && typeof lastFocused.focus === 'function' && document.contains(lastFocused)) lastFocused.focus();
  lastFocused = null;
}
function isDeviceModalOpen() {
  const modal = $('deviceModal');
  return !!modal && modal.style.display !== 'none';
}

function initModal() {
  const modal = $('deviceModal');
  if (!modal) return;
  modal.addEventListener('click', (e) => { if (e.target === modal) closeDeviceModal(); });
  const on = (id, fn) => { const el = $(id); if (el) el.addEventListener('click', fn); };
  on('modalClose', closeDeviceModal);
  on('modalCancel', closeDeviceModal);
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && isDeviceModalOpen() && !modalBusy) { e.preventDefault(); closeDeviceModal(); }
  });
  const save = $('modalSave');
  if (save) save.addEventListener('click', submitDeviceModal);
}

function fillDeviceModal(d) {
  $('modalTitle').textContent = d ? '编辑设备' : '添加设备';
  $('devEditId').value = d ? (d.id || '') : '';
  $('devName').value = d ? (d.name || '') : '';
  $('devAddr').value = d ? (d.addr || '') : '';
  $('devToken').value = '';           /* 主进程回传不含 token，留空表示不修改 */
  $('devToken').placeholder = d ? '留空表示不修改口令' : 'codeword';
  $('devNote').value = d ? (d.note || '') : '';
}

async function submitDeviceModal() {
  const btn = $('modalSave');
  if (modalBusy) return;
  const msgEl = $('modalMsg');
  const editId = ($('devEditId').value || '').trim();
  const name = ($('devName').value || '').trim();
  const addr = ($('devAddr').value || '').trim();
  const token = ($('devToken').value || '').trim();
  const note = ($('devNote').value || '').trim();

  if (!name || !addr) { showMsg(msgEl, '名称和地址不能为空', 'error'); return; }
  if (!/^[^\s:]+:\d{1,5}$/.test(addr)) {
    showMsg(msgEl, '地址格式应为 ip:port（例 127.0.0.1:9100）', 'error'); return;
  }
  if (Number(addr.split(':').pop()) < 1 || Number(addr.split(':').pop()) > 65535) {
    showMsg(msgEl, '端口必须在 1..65535 之间', 'error'); return;
  }

  modalBusy = true;                 /* 任何 await 之前的同步防重 */
  beginBusy(btn, '提交中…');
  setStatus(msgEl, editId ? '正在更新设备…' : '正在连接设备…');
  try {
    if (editId) {
      const fields = { name, addr, note };
      if (token) fields.token = token;
      const ok = await callApi('dev.update', editId, fields);
      if (ok === true) {
        const d = devMap[editId];
        if (d) { d.name = name; d.addr = addr; d.note = note; }
        await reloadDevices().catch(() => {});
        renderDevices();
        closeDeviceModal();
        showMsg($('deviceStatus'), '设备已更新：' + name, 'success');
      } else {
        showMsg(msgEl, '更新失败：' + (isErr(ok) ? errText(ok) : '主进程返回 false（设备可能已被删除）'), 'error');
      }
    } else {
      const res = await callApi('dev.add', { name, addr, token, note });   /* id 由主进程生成 */
      if (res === 'online' || res === 'offline') {
        await reloadDevices().catch(() => {});
        dashCache = []; secCache = {};
        searchTypeReady = false;      /* 设备集合变化 → 类型下拉需重新收集 */
        await loadDevices().catch(() => {});
        closeDeviceModal();           /* 成功即关弹窗，不再等 1.5s */
        if (res === 'online') showMsg($('deviceStatus'), '✅ 设备添加成功并已同步：' + name, 'success');
        else showMsg($('deviceStatus'), '设备已添加但当前离线：' + name + '（请确认地址与口令）', 'error');
      } else {
        showMsg(msgEl, '添加失败：' + errText(res), 'error');
      }
    }
  } catch (e) {
    showMsg(msgEl, '提交失败：' + errText(e), 'error');
  } finally {
    modalBusy = false;
    endBusy(btn);
  }
}

/* ======================= 数据总览 ======================= */

async function loadDashboard() {
  const seq = ++dashSeq;
  try {
    const all = await fetchListAll();
    if (seq !== dashSeq) return;          /* 已有更新的刷新请求，丢弃本次结果 */
    dashCache = Array.isArray(all) ? all : [];
    renderDashboard(dashCache);
  } catch (e) {
    if (seq !== dashSeq) return;
    console.warn('[DASH] 仪表盘刷新失败:', e);
    dashCache = [];
    renderDashboard(dashCache);
    renderErrorBox($('devDistBody'), '仪表盘加载失败：' + errText(e), () => loadDashboard());
  }
}

/** 纯渲染：从缓存绘制仪表盘，不发网络请求 */
function renderDashboard(devs) {
  try {
    const list = Array.isArray(devs) ? devs : [];
    const totalFiles = list.reduce((s, d) => s + (Number(d && d.total_files) || 0), 0);
    const totalSize  = list.reduce((s, d) => s + (Number(d && d.total_size) || 0), 0);

    safeSetText('stat-total_files', totalFiles.toLocaleString());
    safeSetText('stat-total_size', fmtBytes(totalSize));
    const totalTypes = list.reduce((s, d) => s + (Number(d && d.file_types_count) || 0), 0);
    safeSetText('stat-file_types_count', totalTypes.toLocaleString());
    safeSetText('stat-last_scan', fmtNow());   /* 汇总时间：本地时间，与各设备“更新时间”同格式 */

    /* 设备文件分布 */
    const devBody = $('devDistBody');
    if (devBody) {
      devBody.textContent = '';
      if (!list.length) {
        const row = mk('div', 'dev-dist-row');
        const cell = mk('div', 'dev-dist-td muted center', '暂无设备');
        cell.style.padding = '16px';
        row.appendChild(cell);
        devBody.appendChild(row);
      } else {
        list.forEach(d => {
          const dot = (d && d.status === 'online') ? 'online' : 'offline';
          const row = mk('div', 'dev-dist-row');
          const c1 = mk('div', 'dev-dist-td td-dot-cell');
          c1.appendChild(mk('span', 'td-dot ' + dot));
          row.appendChild(c1);
          row.appendChild(mk('div', 'dev-dist-td td-name', (d && d.name) || ''));
          row.appendChild(mk('div', 'dev-dist-td td-count', fmtNum(d && d.total_files)));
          row.appendChild(mk('div', 'dev-dist-td td-size', fmtBytes(d && d.total_size)));
          row.appendChild(mk('div', 'dev-dist-td td-time', fmtTime(d && d.last_sync)));
          devBody.appendChild(row);
        });
      }
    }

    /* 设备列表 */
    safeSetText('devCountLabel', list.length + ' 只');
    const devListEl = $('dashboardDevList');
    if (devListEl) {
      devListEl.textContent = '';
      if (!list.length) {
        devListEl.appendChild(mk('div', 'muted', '暂无设备'));
        devListEl.firstChild.style.fontSize = '13px';
        devListEl.firstChild.style.padding = '8px 0';
      } else {
        const wrap = mk('div', 'device-mini-list');
        list.forEach(d => {
          const item = mk('div', 'device-mini');
          const online = d && d.status === 'online';
          item.appendChild(mk('span', 'dm-dot ' + (online ? 'online' : 'offline')));
          item.appendChild(mk('span', 'dm-name', (d && d.name) || ''));
          item.appendChild(mk('span', 'dm-info',
            (online ? '在线' : '离线') + ' · 心跳 ' + heartbeatAgeText(d && d.id, d && d.name)));
          wrap.appendChild(item);
        });
        devListEl.appendChild(wrap);
      }
    }

    renderTypeDistribution(list);
  } catch (e) {
    console.warn('[DASH] 渲染仪表盘失败:', e);
  }
}

function safeSetText(id, text) {
  const el = $(id);
  if (el) el.textContent = text;
}

/** 文件类型分布：跨设备汇总 */
function renderTypeDistribution(allDevs) {
  const devBody = $('typeDistBody');
  if (!devBody) return;
  try {
    const devs = Array.isArray(allDevs) ? allDevs : [];
    const typeMap = {};
    devs.forEach(d => {
      if (!d || !Array.isArray(d.file_types) || !d.file_types.length) return;
      d.file_types.forEach(t => {
        if (!t) return;
        const ext = typeof t.ext === 'string' ? t.ext : '(无)';
        if (!typeMap[ext]) typeMap[ext] = { count: 0, size_bytes: 0, topCount: 0, topDev: '' };
        typeMap[ext].count += Number(t.count) || 0;
        typeMap[ext].size_bytes += Number(t.size_bytes) || 0;
        if ((Number(t.count) || 0) > typeMap[ext].topCount) {
          typeMap[ext].topCount = Number(t.count) || 0;
          typeMap[ext].topDev = d.name || '';
        }
      });
    });

    const types = Object.entries(typeMap).sort((a, b) => b[1].count - a[1].count);
    devBody.textContent = '';
    if (!types.length) {
      const row = mk('div', 'dev-dist-row');
      const cell = mk('div', 'dev-dist-td muted center', '暂无数据');
      cell.style.padding = '16px';
      row.appendChild(cell);
      devBody.appendChild(row);
      return;
    }
    types.forEach(([ext, info], idx) => {
      const row = mk('div', 'dev-dist-row');
      const c1 = mk('div', 'dev-dist-td', String(idx + 1));
      c1.style.width = '60px'; c1.style.textAlign = 'center'; c1.style.color = '#6b7280'; c1.style.fontSize = '12px';
      row.appendChild(c1);
      row.appendChild(mk('div', 'dev-dist-td td-name', '.' + ext));
      row.appendChild(mk('div', 'dev-dist-td td-count', fmtNum(info.count)));
      row.appendChild(mk('div', 'dev-dist-td td-size', fmtBytes(info.size_bytes)));
      row.appendChild(mk('div', 'dev-dist-td td-time', info.topDev || ''));
      devBody.appendChild(row);
    });
  } catch (e) {
    console.warn('[DASH] 文件类型分布渲染失败:', e);
  }
}

/* ======================= 文件校验 ======================= */

/** verify 响应 → 规范化对象；缺字段一律 null（显示“—”），绝不伪造 */
function readVerify(vd) {
  if (!vd || typeof vd !== 'object') return { known: false };
  if (vd.error) return { known: false };
  const num = v => (typeof v === 'number' && isFinite(v)) ? v : null;
  const info = {
    verified_files: num(vd.verified_files),
    verify_count:   num(vd.verify_count),
    scan_count:     num(vd.scan_count),
    scan_interval:  num(vd.scan_interval),
    corrupt_count:  num(vd.corrupt_count),
    missing_count:  num(vd.missing_count),
    last_duration_ms: num(vd.last_duration_ms),
    last_verify:    (typeof vd.last_verify === 'string' || typeof vd.last_verify === 'number') ? vd.last_verify : null,
    last_scan:      (typeof vd.last_scan === 'string' || typeof vd.last_scan === 'number') ? vd.last_scan : null
  };
  info.known = info.verified_files !== null || info.verify_count !== null || info.scan_count !== null ||
               info.corrupt_count !== null || info.missing_count !== null || !!info.last_verify || !!info.last_scan;
  return info;
}

async function loadSecurity(opts) {
  const seq = ++secSeq;
  const force = !!(opts && opts.force);
  try {
    if (force || !dashCache.length) {
      const all = await fetchListAll();
      if (seq !== secSeq) return;
      dashCache = Array.isArray(all) ? all : [];
    }
    if (!dashCache.length) { secCache = {}; renderSecurity(); return; }

    /* 批量取值（主进程有自己的超时），取完一次性重绘 */
    const ids = dashCache.map(d => String(d.id));
    const results = await Promise.allSettled(ids.map(id => callApi('dev.verify', id)));
    if (seq !== secSeq) return;      /* 期间出现新请求 → 丢弃本轮 */

    const byId = {};
    ids.forEach((id, i) => {
      const r = results[i];
      byId[id] = (r.status === 'fulfilled' && r.value && !r.value.error) ? r.value : null;
    });
    /* await 之后 dashCache 可能已被整轮替换 → 按 id 重新定位 */
    const fresh = {};
    dashCache.forEach(d => {
      const id = String(d.id);
      if (Object.prototype.hasOwnProperty.call(byId, id)) fresh[id] = byId[id];
    });
    secCache = fresh;
    renderSecurity();
  } catch (e) {
    if (seq !== secSeq) return;
    console.warn('[SEC] 加载失败:', e);
    renderErrorBox($('secDevBody'), '校验数据加载失败：' + errText(e), () => loadSecurity({ force: true }));
  }
}

function renderSecurity() {
  const body = $('secDevBody');
  if (!body) return;
  try {
    const devs = Array.isArray(dashCache) ? dashCache : [];
    let totVf = 0, totVc = 0, totSc = 0, totCc = 0, knownCount = 0;
    const unknown = [];

    body.textContent = '';
    if (!devs.length) {
      const empty = mk('div', 'muted center', '暂无设备数据');
      empty.style.padding = '24px'; empty.style.fontSize = '13px';
      body.appendChild(empty);
      setSecTotals(null);
      safeSetText('secDataNote', '');
      const card0 = document.querySelector('#page-security .stat-card.sc-purple');
      if (card0) card0.classList.toggle('sc-corrupted', false);
      return;
    }

    devs.forEach(d => {
      const id = String(d.id);
      const info = readVerify(secCache[id]);
      const row = mk('div', 'sec-dev-row');
      if (!info.known) row.classList.add('sec-dev-offline');
      row.appendChild(mk('span', 'sdev-name', d.name || id));
      row.appendChild(mk('span', 'sdev-files', info.known ? fmtNum(info.verified_files) : '—'));
      row.appendChild(mk('span', 'sdev-count', info.known ? fmtNum(info.verify_count) : '—'));
      row.appendChild(mk('span', 'sdev-scan', info.known ? fmtNum(info.scan_count) : '—'));
      row.appendChild(mk('span', 'sdev-interval', info.known ? fmtInterval(info.scan_interval) : '—'));
      row.appendChild(mk('span', 'sdev-damage', info.known ? fmtNum(info.corrupt_count) : '—'));
      row.appendChild(mk('span', 'sdev-missing', info.known ? fmtNum(info.missing_count) : '—'));
      const lv = mk('span', 'sdev-lastverify', info.known ? fmtTime(info.last_verify) : '—');
      if (info.known && info.last_duration_ms !== null) lv.title = '上次校验耗时 ' + fmtDuration(info.last_duration_ms);
      row.appendChild(lv);
      row.appendChild(mk('span', 'sdev-lastscan', info.known ? fmtTime(info.last_scan) : '—'));
      body.appendChild(row);

      if (info.known) {
        knownCount++;
        totVf += info.verified_files || 0;
        totVc += info.verify_count || 0;
        totSc += info.scan_count || 0;
        totCc += info.corrupt_count || 0;
      } else {
        unknown.push(d.name || id);
      }
    });

    setSecTotals(knownCount ? { vf: totVf, vc: totVc, sc: totSc, cc: totCc } : null);
    const note = $('secDataNote');
    if (note) {
      note.textContent = unknown.length
        ? ('⚠ ' + unknown.length + ' 台设备未返回校验数据（不计入汇总）：' + unknown.join('、'))
        : (knownCount ? ('已读取 ' + knownCount + ' 台设备的校验数据') : '');
    }
    /* 警戒带随真实结果增减，不再只加不减 */
    const card = document.querySelector('#page-security .stat-card.sc-purple');
    if (card) card.classList.toggle('sc-corrupted', totCc > 0);
  } catch (e) {
    console.warn('[SEC] 渲染失败:', e);
  }
}

function setSecTotals(t) {
  safeSetText('sec-verified_files', t ? t.vf.toLocaleString() : '—');
  safeSetText('sec-verify_count', t ? t.vc.toLocaleString() : '—');
  safeSetText('sec-periodic_scan', t ? t.sc.toLocaleString() : '—');
  safeSetText('sec-silent_corrupt', t ? t.cc.toLocaleString() : '—');
}

/** 事件驱动的单设备校验刷新：批量取值后只重绘一次 */
async function refreshDevicesSecurity(ids) {
  const list = (Array.isArray(ids) ? ids : []).map(String);
  if (!list.length) return;
  try {
    const results = await Promise.allSettled(list.map(id => callApi('dev.verify', id)));
    list.forEach((id, i) => {
      const d = dashCache.find(x => String(x.id) === id);   /* await 之后按 id 重新定位 */
      if (!d) return;
      const r = results[i];
      secCache[id] = (r.status === 'fulfilled' && r.value && !r.value.error) ? r.value : null;
    });
    renderSecurity();
  } catch (e) { console.warn('[SEC] 增量刷新失败:', e); }
}

/* ======================= 搜索 ======================= */

const SEARCH_WATCHDOG_MS = 45000;   /* 兜底上限：必须长于主进程自身的超时（连接 5s + 搜索 30s）；
                                       到时只是停止等待并把"未响应设备"列出来，已到达的结果不丢 */
const SEARCH_RENDER_CHUNK = 300;    /* 首屏渲染上限，其余按需加载 */
const SEARCH_LIMIT = 500;

let searchTimer = null;
let searchSeq = 0;
let searchAll = [];                 /* 当前全部结果 */
let searchRendered = 0;             /* 已渲染条数 */
let searchSel = new Set();          /* 选中键集合 */
let searchByKey = new Map();        /* 键 → 结果对象 */
let searchTarget = 'ALL';
let searchTypeReady = false;
let searchUnresponsive = [];
let searchTruncated = [];

function searchKey(it) { return String(it.device_id || '') + '\u0000' + String(it.file_path || ''); }

function initSearchControls() {
  const input = $('searchInput');
  if (input) input.addEventListener('input', () => { clearTimeout(searchTimer); searchTimer = setTimeout(doSearch, 300); });
  const btn = $('searchBtn');
  if (btn) btn.addEventListener('click', doSearch);
  const type = $('searchType');
  if (type) type.addEventListener('change', doSearch);
  ['searchSizeMin', 'searchSizeMax'].forEach(id => {
    const el = $(id);
    if (el) el.addEventListener('input', () => { clearTimeout(searchTimer); searchTimer = setTimeout(doSearch, 400); });
  });

  const results = $('searchResults');
  if (results) results.addEventListener('click', onSearchResultsClick);
  /* 设备单选：只注册一次（选择器内容会被反复重建，不能在里面绑） */
  const box = $('deviceSelector');
  if (box) box.addEventListener('change', (e) => {
    const input = e.target.closest('input[name="devTarget"]');
    if (!input) return;
    searchTarget = input.value;
    box.querySelectorAll('.dev-opt').forEach(l => l.classList.toggle('active', !!l.querySelector('input:checked')));
    searchSel.clear();           /* 换设备 → 旧选择作废 */
    doSearch();
  });

  const selAll = $('searchSelAll');
  if (selAll) selAll.addEventListener('change', () => {
    const rendered = renderedItems();
    if (selAll.checked) rendered.forEach(it => searchSel.add(searchKey(it)));
    else rendered.forEach(it => searchSel.delete(searchKey(it)));
    syncRenderedRows();
    updateSearchSelInfo();
  });
  const clearBtn = $('btnClearSel');
  if (clearBtn) clearBtn.addEventListener('click', () => {
    searchSel.clear(); syncRenderedRows(); updateSearchSelInfo();
  });
  const dl = $('btnBulkDownload');
  if (dl) dl.addEventListener('click', bulkDownloadSelected);
  const mig = $('btnBulkMigrate');
  if (mig) mig.addEventListener('click', bulkMigrateSelected);
}

function getTargetDevice() { return searchTarget || 'ALL'; }

function buildSearchParams() {
  const q = (($('searchInput') || {}).value || '').trim();
  const typeFilt = (($('searchType') || {}).value || '');
  const sizeMin = parseFloat((($('searchSizeMin') || {}).value) || '') || 0;
  const sizeMax = parseFloat((($('searchSizeMax') || {}).value) || '') || 0;
  const params = { limit: SEARCH_LIMIT, offset: 0 };
  if (q) params.q = q;
  if (typeFilt) params.type = typeFilt;
  if (sizeMin > 0) params.size_min = Math.round(sizeMin * 1024 * 1024);
  if (sizeMax > 0) params.size_max = Math.round(sizeMax * 1024 * 1024);
  return params;
}

/** 设备选择器（搜索页）：失败给出错误态 + 重试，不再永久停在“加载中” */
async function initSearchPage() {
  const box = $('searchResults');
  if (box && !box.children.length && !searchAll.length) {
    box.appendChild(mk('div', 'muted', '输入关键词开始搜索（留空则列出设备上的文件）'));
    box.firstChild.style.padding = '8px';
  }
  await initDeviceSelector();
  await populateTypeSelector();
}

async function initDeviceSelector() {
  const box = $('deviceSelector');
  if (!box) return;
  try {
    const list = await reloadDevices();
    box.textContent = '';
    const makeOpt = (value, labelText) => {
      const label = mk('label', 'dev-opt' + (value === searchTarget ? ' active' : ''));
      const input = document.createElement('input');
      input.type = 'radio';
      input.name = 'devTarget';
      input.value = value;
      if (value === searchTarget) input.checked = true;
      label.appendChild(input);
      label.appendChild(mk('span', null, labelText));
      return label;
    };
    box.appendChild(makeOpt('ALL', 'ALL（全部在线设备）'));
    list.forEach(d => {
      const id = String(d.id);
      const online = d.status === 'online';
      box.appendChild(makeOpt(id, (online ? '🟢 ' : '🔴 ') + (d.name || id)));
    });
    /* 目标设备已不存在 → 回落到 ALL */
    if (searchTarget !== 'ALL' && !devMap[searchTarget]) searchTarget = 'ALL';
  } catch (e) {
    renderErrorBox(box, '设备列表加载失败：' + errText(e), () => initDeviceSelector());
  }
}

async function populateTypeSelector() {
  const sel = $('searchType');
  if (!sel) return;
  if (searchTypeReady) return;          /* 已加载过，避免每次进页面都打 N 次 stats */
  try {
    const list = devices.length ? devices : await reloadDevices();
    const online = list.filter(d => d.status === 'online');
    const results = await Promise.allSettled(online.map(d => callApi('dev.stats', d.id)));
    const typeMap = {};
    results.forEach(r => {
      if (r.status !== 'fulfilled' || !r.value || r.value.error) return;
      let ft = r.value.file_types;
      if (!ft) return;
      if (typeof ft === 'string') { try { ft = JSON.parse(ft); } catch (e) { return; } }
      if (!Array.isArray(ft)) return;
      ft.forEach(t => { if (t && t.ext) typeMap[t.ext] = (typeMap[t.ext] || 0) + (Number(t.count) || 0); });
    });
    sel.textContent = '';
    sel.appendChild(new Option('全部类型', ''));
    Object.entries(typeMap)
      .sort((a, b) => b[1] - a[1])
      .forEach(([ext, count]) => sel.appendChild(new Option('.' + ext + ' (' + count + '个)', String(ext).toLowerCase())));
    searchTypeReady = true;
  } catch (e) {
    console.warn('[SEARCH] 类型下拉加载失败:', e);
    /* 下拉失败不影响搜索：保留“全部类型” */
  }
}

/** 搜索：序号守卫 + 明确列出未响应设备（不再静默丢结果） */
async function doSearch() {
  const seq = ++searchSeq;
  const container = $('searchResults');
  const statusEl = $('searchStatus');
  if (!container) return;
  container.textContent = '';
  container.appendChild(mk('div', 'muted', '⏳ 搜索中…'));
  if (statusEl) statusEl.textContent = '';

  const params = buildSearchParams();
  const target = getTargetDevice();
  const collected = new Map();     /* deviceId → {ok, res} —— 逐台到达即记录，超时也不丢已收数据 */
  let pendingIds = [];

  try {
    if (target === 'ALL') {
      let list;
      try { list = devices.length ? devices : await reloadDevices(); }
      catch (e) { list = await reloadDevices(); }        /* 再试一次，失败则抛出到外层错误态 */
      const online = list.filter(d => d.status === 'online');
      pendingIds = online.map(d => String(d.id));
      if (!online.length) {
        if (seq !== searchSeq) return;
        container.textContent = '';
        container.appendChild(mk('div', 'muted', '没有在线设备可搜索'));
        if (statusEl) statusEl.textContent = '⚠ 当前没有在线设备';
        return;
      }
      const tasks = online.map(d => {
        const id = String(d.id);
        return callApi('dev.search', id, params)
          .then(res => { collected.set(id, { ok: true, res }); })
          .catch(err => { collected.set(id, { ok: false, err }); });
      });
      await Promise.race([
        Promise.allSettled(tasks),
        new Promise(r => setTimeout(r, SEARCH_WATCHDOG_MS))
      ]);
    } else {
      const dev = devMap[target];
      if (!dev) {
        container.textContent = '';
        container.appendChild(mk('div', 'muted', '设备不存在，请刷新设备列表'));
        return;
      }
      if (dev.status !== 'online') {
        container.textContent = '';
        container.appendChild(mk('div', 'muted', '设备离线，暂无数据'));
        if (statusEl) statusEl.textContent = '⚠ ' + deviceLabel(dev) + ' 当前离线';
        return;
      }
      pendingIds = [String(dev.id)];
      try {
        const res = await callApi('dev.search', dev.id, params);
        collected.set(String(dev.id), { ok: true, res });
      } catch (err) {
        collected.set(String(dev.id), { ok: false, err });
      }
    }

    if (seq !== searchSeq) return;    /* 过期响应：绝不写入结果区 */

    /* 结果归并（兼容 files 数组形态与 §6 的 {files:[...]} 形态） */
    const files = [];
    const failed = [];
    const truncated = [];
    pendingIds.forEach(id => {
      const d = devMap[id] || { id, name: id };
      const got = collected.get(id);
      if (!got) { failed.push(d.name || id); return; }
      if (!got.ok) { failed.push((d.name || id) + '（' + errText(got.err) + '）'); return; }
      const res = got.res;
      const arr = Array.isArray(res) ? res : (res && Array.isArray(res.files) ? res.files : null);
      if (!arr) { failed.push((d.name || id) + '（响应结构异常）'); return; }
      if (res && typeof res.total === 'number' && res.total > arr.length) truncated.push((d.name || id) + ' ' + arr.length + '/' + res.total);
      arr.forEach(f => {
        if (!f) return;
        files.push({
          name: f.name || '',
          file_path: f.file_path || f.path || '',
          size: Number(f.size) || 0,
          mtime: f.mtime || f.modified || '',
          type: f.type || '',
          hash: f.hash || '',
          device: d.name || id,
          device_id: id
        });
      });
    });

    const kw = ((($('searchInput') || {}).value) || '').trim().toLowerCase();
    files.sort((a, b) => {
      const an = a.name.toLowerCase().indexOf(kw) >= 0 ? 0 : 1;
      const bn = b.name.toLowerCase().indexOf(kw) >= 0 ? 0 : 1;
      if (an !== bn) return an - bn;
      return (a.name || '').localeCompare(b.name || '');
    });

    searchAll = files;
    searchRendered = 0;
    searchUnresponsive = failed;
    searchTruncated = truncated;
    searchByKey = new Map();
    files.forEach(f => searchByKey.set(searchKey(f), f));
    /* 只保留仍然存在的选中项 */
    [...searchSel].forEach(k => { if (!searchByKey.has(k)) searchSel.delete(k); });

    if (!files.length) {
      container.textContent = '';
      container.appendChild(mk('div', 'muted center', '🔍 无结果，换个关键词试试？'));
      container.firstChild.style.padding = '8px';
      if (statusEl) {
        statusEl.textContent = '';
        statusEl.appendChild(mk('span', 'muted', failed.length ? ('未找到匹配文件；未响应：' + failed.join('、')) : '未找到匹配的文件'));
      }
      updateSearchSelInfo();
      return;
    }

    const totalSize = files.reduce((s, f) => s + f.size, 0);
    const uniqueDevs = [...new Set(files.map(f => f.device))];
    if (statusEl) {
      statusEl.textContent = '';
      statusEl.appendChild(mk('span', 'muted',
        '📦 ' + uniqueDevs.length + ' 台设备返回 ' + files.length + ' 个文件 · ' + fmtBytes(totalSize)));
      if (failed.length) {
        statusEl.appendChild(mk('div', 'msg error', '⚠ 未响应/失败设备（结果可能不完整）：' + failed.join('、')));
      }
      if (truncated.length) {
        statusEl.appendChild(mk('div', 'msg info', 'ℹ 受 limit=' + SEARCH_LIMIT + ' 限制被截断：' + truncated.join('、') + '（设备端 total 大于已取条数）'));
      }
    }

    container.textContent = '';
    container.appendChild(buildSearchHeader());
    const body = mk('div', 'search-body');
    body.id = 'searchBody';
    container.appendChild(body);
    renderSearchChunk();
    updateSearchSelInfo();
  } catch (e) {
    if (seq !== searchSeq) return;
    console.warn('[SEARCH] 搜索失败:', e);
    renderErrorBox(container, '搜索失败：' + errText(e), () => doSearch());
  }
}

function buildSearchHeader() {
  const hdr = mk('div', 'search-hdr');
  hdr.appendChild(mk('span', 'sc-sel', '选择'));
  hdr.appendChild(mk('span', 'sc-dev', '设备'));
  hdr.appendChild(mk('span', 'sc-name', '文件名'));
  hdr.appendChild(mk('span', 'sc-path', '路径'));
  hdr.appendChild(mk('span', 'sc-size', '大小'));
  hdr.appendChild(mk('span', 'sc-date', '修改时间'));
  hdr.appendChild(mk('span', 'sc-act', '操作'));
  return hdr;
}

function renderedItems() { return searchAll.slice(0, searchRendered); }

/** 分块渲染：首屏最多 SEARCH_RENDER_CHUNK 条，其余“加载更多” */
function renderSearchChunk() {
  const body = $('searchBody');
  if (!body) return;
  const oldMore = body.parentElement ? body.parentElement.querySelector('.load-more') : null;
  if (oldMore) oldMore.remove();
  const from = searchRendered;
  const to = Math.min(searchAll.length, from + SEARCH_RENDER_CHUNK);
  for (let i = from; i < to; i++) body.appendChild(buildSearchRow(searchAll[i]));
  searchRendered = to;
  if (searchRendered < searchAll.length) {
    const more = mk('button', 'load-more btn-secondary',
      '加载更多（已显示 ' + searchRendered + ' / ' + searchAll.length + '）');
    more.addEventListener('click', renderSearchChunk);
    body.parentElement.appendChild(more);
  }
  syncRenderedRows();
}

function buildSearchRow(f) {
  const row = mk('div', 'search-row');
  row.dataset.key = searchKey(f);

  const selCell = mk('span', 'sc-sel');
  const cb = document.createElement('input');
  cb.type = 'checkbox';
  cb.className = 'row-sel';
  cb.checked = searchSel.has(row.dataset.key);
  cb.setAttribute('aria-label', '选择 ' + (f.name || f.file_path || '文件'));
  selCell.appendChild(cb);
  row.appendChild(selCell);

  /* 所有远端文本走 textContent；需要提示的属性用属性赋值（不经过 HTML 解析） */
  const devCell = mk('span', 'sc-dev', f.device || '未知');
  devCell.title = f.device || '';
  row.appendChild(devCell);

  const nameCell = mk('span', 'sc-name', f.name || '');
  nameCell.title = f.name || '';
  row.appendChild(nameCell);

  const pathCell = mk('span', 'sc-path', f.file_path || '');
  pathCell.title = f.file_path || '';
  row.appendChild(pathCell);

  row.appendChild(mk('span', 'sc-size', fmtBytes(f.size)));
  row.appendChild(mk('span', 'sc-date', fmtTime(f.mtime)));

  const act = mk('span', 'sc-act');
  const dl = mk('button', 'dl-btn', '⬇');
  dl.dataset.act = 'download';
  dl.title = '下载到本机';
  dl.setAttribute('aria-label', '下载 ' + (f.name || ''));
  act.appendChild(dl);
  const mg = mk('button', 'dl-btn', '➡');
  mg.dataset.act = 'migrate';
  mg.title = '加入迁移任务列表';
  mg.setAttribute('aria-label', '迁移 ' + (f.name || ''));
  act.appendChild(mg);
  row.appendChild(act);
  return row;
}

/** 事件委托：结果区不再逐行 addEventListener */
function onSearchResultsClick(e) {
  const row = e.target.closest('.search-row');
  if (!row) return;
  const key = row.dataset.key;
  const item = searchByKey.get(key);
  if (!item) return;

  if (e.target.classList.contains('row-sel')) {
    if (e.target.checked) searchSel.add(key); else searchSel.delete(key);
    updateSearchSelInfo();
    return;
  }
  const btn = e.target.closest('.dl-btn');
  if (!btn) return;
  if (btn.dataset.act === 'download') downloadOne(btn, item);
  else if (btn.dataset.act === 'migrate') pushOneToMigrate(item);
}

function syncRenderedRows() {
  const body = $('searchBody');
  if (!body) return;
  body.querySelectorAll('.search-row').forEach(row => {
    const on = searchSel.has(row.dataset.key);
    const cb = row.querySelector('.row-sel');
    if (cb) cb.checked = on;
    row.classList.toggle('selected', on);
  });
  const selAll = $('searchSelAll');
  if (selAll) {
    const rendered = renderedItems();
    const selCount = rendered.filter(it => searchSel.has(searchKey(it))).length;
    selAll.checked = rendered.length > 0 && selCount === rendered.length;
    selAll.indeterminate = selCount > 0 && selCount < rendered.length;
  }
}

function updateSearchSelInfo() {
  const info = $('searchSelInfo');
  if (info) info.textContent = searchSel.size ? ('已选 ' + searchSel.size + ' 项') : '未选择';
  const has = searchSel.size > 0;
  ['btnBulkDownload', 'btnBulkMigrate', 'btnClearSel'].forEach(id => { const b = $(id); if (b) b.disabled = !has; });
}

function selectedSearchItems() {
  const out = [];
  searchSel.forEach(k => { const it = searchByKey.get(k); if (it) out.push(it); });
  return out;
}

/* ---- 单文件下载：主进程落盘，渲染层只显示路径 ---- */

async function downloadOne(btn, item) {
  if (!beginBusy(btn, '⏳')) return;      /* await 之前同步防重 */
  try {
    const res = await callApi('dev.download', item.device_id, item.file_path);
    if (isErr(res)) { pushBulkResult({ ok: false, name: item.name, err: errText(res) }); return; }
    pushBulkResult({
      ok: true, name: res.name || item.name,
      saved: res.saved_path || res.path || '', size: res.size, hash: res.hash
    });
  } catch (e) {
    pushBulkResult({ ok: false, name: item.name, err: errText(e) });
  } finally {
    endBusy(btn);
  }
}

async function bulkDownloadSelected() {
  const items = selectedSearchItems();
  if (!items.length) return;
  const btn = $('btnBulkDownload');
  if (!beginBusy(btn, '下载中…')) return;
  clearBulkResults();
  pushBulkResult({ ok: true, name: '', saved: '', note: '开始批量下载 ' + items.length + ' 个文件（并发 3）' });
  let ok = 0, bad = 0;
  try {
    await pool(items, 3, async (item) => {
      try {
        const res = await callApi('dev.download', item.device_id, item.file_path);
        if (isErr(res)) { bad++; pushBulkResult({ ok: false, name: item.name, err: errText(res) }); return; }
        ok++;
        pushBulkResult({ ok: true, name: res.name || item.name, saved: res.saved_path || res.path || '', size: res.size, hash: res.hash });
      } catch (e) {
        bad++;
        pushBulkResult({ ok: false, name: item.name, err: errText(e) });
      }
    });
    pushBulkResult({ ok: bad === 0, name: '', saved: '', note: '批量下载结束：成功 ' + ok + ' · 失败 ' + bad });
  } finally {
    endBusy(btn);
  }
}

function clearBulkResults() {
  const box = $('searchBulkResults');
  if (!box) return;
  box.textContent = '';
  box.hidden = true;
}

function pushBulkResult(r) {
  const box = $('searchBulkResults');
  if (!box) return;
  box.hidden = false;
  if (box.children.length > 200) box.removeChild(box.firstChild);
  const row = mk('div', 'bulk-item ' + (r.ok ? 'ok' : 'err'));
  row.appendChild(mk('span', 'bi-state', r.ok ? '✅' : '❌'));
  if (r.name) row.appendChild(mk('span', null, r.name));
  if (r.ok && r.saved) {
    row.appendChild(mk('span', 'bi-path', '已保存到 ' + r.saved));
    if (r.size !== undefined) row.appendChild(mk('span', 'muted', '(' + fmtBytes(r.size) + ')'));
    const open = mk('button', 'btn-secondary', '打开所在目录');
    open.style.fontSize = '11px';
    open.style.padding = '1px 8px';
    open.addEventListener('click', () => openFolderFor(r.saved, $('searchStatus')));
    row.appendChild(open);
    const cp = mk('button', 'btn-secondary', '复制路径');
    cp.style.fontSize = '11px';
    cp.style.padding = '1px 8px';
    cp.addEventListener('click', async () => { await copyText(r.saved); showMsg($('searchStatus'), '已复制路径', 'success'); });
    row.appendChild(cp);
  } else if (r.err) {
    row.appendChild(mk('span', 'bi-path', '失败：' + r.err));
  }
  if (r.note) row.appendChild(mk('span', 'bi-path', r.note));
  box.appendChild(row);
  box.scrollTop = box.scrollHeight;
}

function searchItemsToQueue(items) {
  return items.map(it => ({
    srcId: String(it.device_id),
    srcPath: it.file_path,
    name: it.name || it.file_path,
    rel: it.name || it.file_path,
    size: it.size,
    origin: 'search'
  }));
}

/** 搜索结果 → 迁移任务列表 */
async function bulkMigrateSelected() {
  const items = selectedSearchItems();
  if (!items.length) { showMsg($('searchStatus'), '请先选择要迁移的文件', 'error'); return; }
  await enqueueMigrateJobs(searchItemsToQueue(items), '来自搜索结果');
  gotoPage('migrate');
}

async function pushOneToMigrate(item) {
  await enqueueMigrateJobs(searchItemsToQueue([item]), '来自搜索结果');
  gotoPage('migrate');
}

/* ======================= 控制中心 ======================= */

/** 控制指令通道：PROTOCOL §6 未定义，按可用性探测（沿用历史 ctrl.send） */
async function sendCtrl(id, action) {
  const candidates = ['ctrl.send', 'dev.ctrl', 'dev.send', 'dev.command'];
  for (const c of candidates) {
    if (hasApi(c)) return await callApi(c, id, action);
  }
  throw new Error('主进程未提供控制指令接口（PROTOCOL §6 未定义 ctrl.*）');
}

const CTRL_ZH = { rescan_requested: '设备已开始重新扫描', sync_requested: '设备已开始同步索引' };

async function initControlCenter() {
  const sel = $('ctrlDevice');
  if (!sel) return;
  const prev = sel.value;
  try {
    const list = await reloadDevices();
    sel.textContent = '';
    if (!list.length) {
      sel.appendChild(new Option('（暂无设备）', ''));
      const st = $('ctrlDevState'); if (st) st.textContent = '暂无设备，请先在「设备管理」添加';
      return;
    }
    list.forEach(d => {
      const id = String(d.id);
      sel.appendChild(new Option((d.status === 'online' ? '🟢 ' : '🔴 ') + deviceLabel(d), id));
    });
    if (prev && devMap[prev]) sel.value = prev;
    updateCtrlDevState();
    sel.onchange = updateCtrlDevState;
  } catch (e) {
    sel.textContent = '';
    sel.appendChild(new Option('设备列表加载失败', ''));
    renderErrorBox($('ctrlMsg'), '设备列表加载失败：' + errText(e), () => initControlCenter());
  }
}

function updateCtrlDevState() {
  const sel = $('ctrlDevice');
  const st = $('ctrlDevState');
  if (!sel || !st) return;
  const d = devMap[sel.value];
  if (!d) { st.textContent = '—'; return; }
  st.textContent = (d.status === 'online' ? '在线' : '离线') + ' · 最后同步 ' + fmtTime(d.last_sync) +
    ' · 心跳 ' + heartbeatAgeText(d.id, d.name);
}

/** 控制指令：成功/失败配色与真实结果一致 */
async function runControlAction(action, btn) {
  const msgEl = $('controlMsg');
  const sel = $('ctrlDevice');
  const id = sel ? sel.value : '';
  if (!id || !devMap[id]) { showMsg(msgEl, '请先选择目标设备', 'error'); return; }
  if (!beginBusy(btn, '执行中…')) return;
  try {
    const res = await sendCtrl(id, action);
    if (isErr(res)) { showMsg(msgEl, '执行失败：' + errText(res), 'error'); return; }
    const txt = CTRL_ZH[res && res.status] || ('已发送：' + action + (res && res.status ? '（' + res.status + '）' : ''));
    showMsg(msgEl, txt + ' · ' + deviceLabel(devMap[id]), 'success');
  } catch (e) {
    showMsg(msgEl, '执行失败：' + errText(e), 'error');
  } finally {
    endBusy(btn);
  }
}

async function runSyncDb(btn) {
  const msgEl = $('controlMsg');
  const sel = $('ctrlDevice');
  const id = sel ? sel.value : '';
  if (!id || !devMap[id]) { showMsg(msgEl, '请先选择目标设备', 'error'); return; }
  if (!beginBusy(btn, '同步中…')) return;
  try {
    const res = await callApi('dev.syncDb', id);
    if (isErr(res)) { showMsg(msgEl, '同步数据库失败：' + errText(res), 'error'); return; }
    const p = res.path || '';
    showMsg(msgEl, '数据库已保存到 ' + (p || '（主进程未返回路径）') + (res.size ? '（' + fmtBytes(res.size) + '）' : ''), 'success');
    if (p) {
      const open = mk('button', 'btn-secondary', '打开所在目录');
      open.style.marginLeft = '8px';
      open.addEventListener('click', () => openFolderFor(p, msgEl));
      const box = msgEl.querySelector('.msg');
      if (box) box.appendChild(open);
    }
  } catch (e) {
    showMsg(msgEl, '同步数据库失败：' + errText(e), 'error');
  } finally {
    endBusy(btn);
  }
}

function initControlPage() {
  const r = $('ctrlRefresh'); if (r) r.addEventListener('click', () => initControlCenter());
  const a = $('btnRescan'); if (a) a.addEventListener('click', () => runControlAction('rescan', a));
  const b = $('btnSync'); if (b) b.addEventListener('click', () => runControlAction('sync', b));
  const c = $('btnSyncDb'); if (c) c.addEventListener('click', () => runSyncDb(c));
}

/* ======================= 设备管理 ======================= */

const devSel = new Set();

async function loadDevices() {
  const grid = $('deviceGrid');
  if (!grid) return;
  setStatus($('deviceStatus'), '⏳ 加载设备列表…');
  try {
    await reloadDevices();
    /* 清理已删除设备的勾选 */
    [...devSel].forEach(id => { if (!devMap[id]) devSel.delete(id); });
    clearStatus($('deviceStatus'));
    renderDevices();
  } catch (e) {
    console.warn('[DEV] 加载失败:', e);
    devices = []; devMap = {};
    renderErrorBox(grid, '设备列表加载失败：' + errText(e), () => loadDevices());
    const st = $('deviceStatus');
    if (st) { st.textContent = ''; st.appendChild(mk('div', 'msg error', '设备列表加载失败：' + errText(e))); }
  }
}

function renderDevices() {
  const grid = $('deviceGrid');
  if (!grid) return;
  grid.textContent = '';
  if (!devices.length) {
    grid.appendChild(mk('div', 'muted', '暂无设备，点击右上角「＋ 添加设备」'));
    updateDevSelInfo();
    return;
  }
  devices.forEach(d => grid.appendChild(buildDeviceCard(d)));
  updateDevSelInfo();
}

function buildDeviceCard(d) {
  const id = String(d.id);
  const online = d.status === 'online';
  const card = mk('div', 'device-card ' + (online ? 'online' : 'offline'));

  const selLabel = mk('label', 'card-sel');
  const cb = document.createElement('input');
  cb.type = 'checkbox';
  cb.className = 'dev-sel';
  cb.dataset.id = id;
  cb.checked = devSel.has(id);
  cb.setAttribute('aria-label', '选择设备 ' + (d.name || id));
  selLabel.appendChild(cb);
  selLabel.appendChild(mk('span', null, '选择'));
  card.appendChild(selLabel);

  const head = mk('div');
  head.appendChild(mk('span', 'name', d.name || id));
  head.appendChild(mk('span', 'status ' + (online ? 'online' : 'offline'), online ? '在线' : '离线'));
  card.appendChild(head);

  const info = mk('div', 'info', (d.addr || '') + (d.note ? ' · ' + d.note : ''));
  card.appendChild(info);

  const meta = mk('div', 'muted', '最后同步: ' + fmtTime(d.last_sync) + ' · 心跳 ' + heartbeatAgeText(id, d.name));
  meta.style.fontSize = '11px';
  meta.style.marginBottom = '8px';
  card.appendChild(meta);

  const actions = mk('div', 'actions');
  const mkBtn = (cls, text, title, fn) => {
    const b = mk('button', cls, text);
    b.title = title;
    b.dataset.id = id;
    b.addEventListener('click', fn);
    return b;
  };
  actions.appendChild(mkBtn('btn-refresh-dev', '刷新', '读取该设备 stats', () => refreshOneDevice(id, actions.querySelector('.btn-refresh-dev'))));
  actions.appendChild(mkBtn('btn-rescan-dev', '重扫', '触发该设备 rescan', () => runControlActionFor(id, 'rescan', actions.querySelector('.btn-rescan-dev'))));
  actions.appendChild(mkBtn('btn-sync-dev', '同步', '触发该设备 sync', () => runControlActionFor(id, 'sync', actions.querySelector('.btn-sync-dev'))));
  actions.appendChild(mkBtn('btn-edit', '编辑', '编辑设备信息', () => editDevice(id)));
  actions.appendChild(mkBtn('btn-del', '删除', '删除该设备', () => deleteDevice(id)));
  card.appendChild(actions);
  return card;
}

async function refreshOneDevice(id, btn) {
  if (!beginBusy(btn, '刷新中…')) return;
  try {
    const st = await callApi('dev.stats', id);
    const d = devMap[id];
    if (d) {
      if (st && !st.error && typeof st.total_files === 'number') { d.status = 'online'; d.last_sync = new Date().toISOString(); }
      else d.status = 'offline';
    }
    dashCache = []; secCache = {};
    renderDevices();
    showMsg($('deviceStatus'), isErr(st)
      ? ('刷新失败：' + errText(st))
      : ((d ? (d.name || id) : id) + '：' + (st && typeof st.total_files === 'number' ? (fmtNum(st.total_files) + ' 个文件 · ' + fmtBytes(st.total_size)) : '无统计信息')),
      isErr(st) ? 'error' : 'success');
  } catch (e) {
    showMsg($('deviceStatus'), '刷新失败：' + errText(e), 'error');
  } finally {
    endBusy(btn);
  }
}

async function runControlActionFor(id, action, btn) {
  if (!beginBusy(btn, '执行中…')) return;
  try {
    const res = await sendCtrl(id, action);
    if (isErr(res)) showMsg($('deviceStatus'), '执行失败：' + errText(res), 'error');
    else showMsg($('deviceStatus'), (CTRL_ZH[res && res.status] || '已发送 ' + action) + ' · ' + deviceLabel(devMap[id]), 'success');
  } catch (e) {
    showMsg($('deviceStatus'), '执行失败：' + errText(e), 'error');
  } finally {
    endBusy(btn);
  }
}

function editDevice(id) {
  const d = devMap[id];
  if (!d) { showMsg($('deviceStatus'), '设备不存在（可能已被删除）', 'error'); return; }
  fillDeviceModal(d);
  openDeviceModal();
}

async function deleteDevice(id) {
  if (!confirm('确定删除此设备？数据将无法恢复。')) return;
  try {
    const ok = await callApi('dev.remove', id);
    if (ok !== true) { showMsg($('deviceStatus'), '删除失败：主进程返回 ' + String(ok), 'error'); return; }
    devSel.delete(id);
    dashCache = []; secCache = {};
    searchTypeReady = false;
    await loadDevices();
    showMsg($('deviceStatus'), '设备已删除', 'success');
  } catch (e) {
    showMsg($('deviceStatus'), '删除失败：' + errText(e), 'error');
  }
}

function updateDevSelInfo() {
  const info = $('devSelInfo');
  const has = devSel.size > 0;
  if (info) info.textContent = has ? ('已选 ' + devSel.size + ' 台') : '未选择';
  ['btnBatchVerify', 'btnBatchRescan', 'btnBatchSyncDb', 'btnBatchRefresh'].forEach(id => { const b = $(id); if (b) b.disabled = !has; });
  const all = $('devSelAll');
  if (all) {
    all.checked = devices.length > 0 && devSel.size === devices.length;
    all.indeterminate = devSel.size > 0 && devSel.size < devices.length;
  }
}

/* ==========================================================================
 * 局域网发现面板（PROTOCOL §7）
 * 主进程每 1s 广播一次探测，只有对上暗号的服务端才回应；
 * 这里只负责把 discover.list() 的结果画出来，并让用户一键加入设备库。
 * ========================================================================== */
let discTimer = null;
let discLast = [];

function discOpen() {
  const panel = $('discPanel');
  if (!panel) return;
  panel.hidden = false;
  refreshDiscover();
  if (discTimer) clearInterval(discTimer);
  /* 发现结果是滚动的（3s 无应答即过期），面板开着就持续刷新 */
  discTimer = setInterval(refreshDiscover, 1500);
}

function discClose() {
  const panel = $('discPanel');
  if (panel) panel.hidden = true;
  if (discTimer) { clearInterval(discTimer); discTimer = null; }
}

function discKnown(addr) {
  const a = String(addr || '');
  return devices.some(d => String(d.addr || '').trim() === a);
}

function renderDiscover(list) {
  const box = $('discList');
  const info = $('discInfo');
  if (!box) return;
  box.textContent = '';
  discLast = Array.isArray(list) ? list : [];

  if (info) {
    info.textContent = discLast.length
      ? ('发现 ' + discLast.length + ' 台 · 点「加入」即可'
         + (discLast.some(p => discKnown(p.addr)) ? '（灰色已存在）' : ''))
      : '未发现设备';
  }

  if (!discLast.length) {
    const empty = mk('div', 'disc-empty',
      '没有服务端回应。可能原因：不同网段 / 服务端 discovery_port 与本机不一致 / 口令（codeword）不一致。'
      + '口令不一致时服务端会保持沉默，这是设计如此。');
    box.appendChild(empty);
    return;
  }

  for (const p of discLast) {
    const row = mk('div', 'disc-row');
    row.appendChild(mk('span', 'disc-name', p.name || p.id || '(未命名)'));
    row.appendChild(mk('span', 'disc-addr', p.addr || (p.ip + ':' + p.port)));
    if (p.ver) row.appendChild(mk('span', 'disc-badge', 'v' + p.ver));
    row.appendChild(mk('span', 'disc-age', (Number(p.age_ms) >= 0 ? fmtDuration(Number(p.age_ms)) + '前' : '')));

    const known = discKnown(p.addr);
    if (known) {
      row.appendChild(mk('span', 'disc-badge', '已在列表'));
    } else {
      const btn = mk('button', 'btn-primary btn-sm disc-add', '加入');
      btn.type = 'button';
      btn.addEventListener('click', () => {
        fillDeviceModal(null);
        $('devName').value = String(p.name || p.id || '');
        $('devAddr').value = String(p.addr || (p.ip + ':' + p.port));
        openDeviceModal();
        discClose();
      });
      row.appendChild(btn);
    }
    box.appendChild(row);
  }
}

async function refreshDiscover() {
  if (!hasApi('discover.list')) {
    const info = $('discInfo');
    if (info) info.textContent = '当前主进程不支持局域网发现';
    return;
  }
  try {
    const list = await callApi('discover.list');
    if (isErr(list)) { const info = $('discInfo'); if (info) info.textContent = '发现失败：' + errText(list); return; }
    renderDiscover(Array.isArray(list) ? list : []);
  } catch (e) {
    const info = $('discInfo');
    if (info) info.textContent = '发现失败：' + errText(e);
  }
}

function initDiscoverPanel() {
  const open = $('btnDiscover');
  if (open) open.addEventListener('click', () => {
    const panel = $('discPanel');
    if (panel && !panel.hidden) { discClose(); } else { discOpen(); }
  });
  const refresh = $('discRefresh');
  if (refresh) refresh.addEventListener('click', refreshDiscover);
  const close = $('discClose');
  if (close) close.addEventListener('click', discClose);
}

function initDevicePage() {
  const add = $('btnAddDevice');
  if (add) add.addEventListener('click', () => { fillDeviceModal(null); openDeviceModal(); });

  initDiscoverPanel();

  const grid = $('deviceGrid');
  if (grid) {
    grid.addEventListener('change', (e) => {
      const cb = e.target.closest('.dev-sel');
      if (!cb) return;
      if (cb.checked) devSel.add(cb.dataset.id); else devSel.delete(cb.dataset.id);
      updateDevSelInfo();
    });
  }
  const selAll = $('devSelAll');
  if (selAll) selAll.addEventListener('change', () => {
    if (selAll.checked) devices.forEach(d => devSel.add(String(d.id))); else devSel.clear();
    renderDevices();
  });
  const v = $('btnBatchVerify'); if (v) v.addEventListener('click', () => batchVerify(v));
  const rs = $('btnBatchRescan'); if (rs) rs.addEventListener('click', () => batchCtrl('rescan', rs, '重扫'));
  const sd = $('btnBatchSyncDb'); if (sd) sd.addEventListener('click', () => batchSyncDb(sd));
  const rf = $('btnBatchRefresh'); if (rf) rf.addEventListener('click', () => batchRefresh(rf));
}

/** 批量校验：dev.verify（带 run:true 请求设备立即校验一次） */
async function batchVerify(btn) {
  const ids = [...devSel];
  if (!ids.length) return;
  if (!beginBusy(btn, '校验中…')) return;
  try {
    const results = await Promise.allSettled(ids.map(id => callApi('dev.verify', id, { run: true })));
    let ok = 0, bad = 0;
    const byId = {};
    ids.forEach((id, i) => {
      const r = results[i];
      if (r.status === 'fulfilled' && r.value && !r.value.error) { byId[id] = r.value; ok++; }
      else { byId[id] = null; bad++; }
    });
    if (!dashCache.length) { try { dashCache = await fetchListAll(); } catch (e) { /* 保持为空 */ } }
    dashCache.forEach(d => { const id = String(d.id); if (Object.prototype.hasOwnProperty.call(byId, id)) secCache[id] = byId[id]; });
    renderSecurity();
    showMsg($('deviceStatus'), '批量校验完成：成功 ' + ok + ' · 失败 ' + bad + '（结果见「文件校验」页）', bad ? 'error' : 'success');
  } catch (e) {
    showMsg($('deviceStatus'), '批量校验失败：' + errText(e), 'error');
  } finally {
    endBusy(btn);
  }
}

async function batchCtrl(action, btn, label) {
  const ids = [...devSel];
  if (!ids.length) return;
  if (!beginBusy(btn, label + '中…')) return;
  try {
    const results = await Promise.allSettled(ids.map(id => sendCtrl(id, action)));
    let ok = 0; const bad = [];
    results.forEach((r, i) => {
      if (r.status === 'fulfilled' && !isErr(r.value)) ok++;
      else bad.push((devMap[ids[i]] ? (devMap[ids[i]].name || ids[i]) : ids[i]) + '（' + errText(r.status === 'fulfilled' ? r.value : r.reason) + '）');
    });
    showMsg($('deviceStatus'), '批量' + label + '：成功 ' + ok + (bad.length ? ' · 失败 ' + bad.join('、') : ''),
      bad.length ? 'error' : 'success');
  } catch (e) {
    showMsg($('deviceStatus'), '批量' + label + '失败：' + errText(e), 'error');
  } finally {
    endBusy(btn);
  }
}

async function batchSyncDb(btn) {
  const ids = [...devSel];
  if (!ids.length) return;
  if (!beginBusy(btn, '同步中…')) return;
  const lines = [];
  try {
    await pool(ids, 3, async (id) => {
      try {
        const res = await callApi('dev.syncDb', id);
        const nm = devMap[id] ? (devMap[id].name || id) : id;
        lines.push(isErr(res) ? ('❌ ' + nm + '：' + errText(res)) : ('✅ ' + nm + ' → ' + (res.path || '(未返回路径)')));
      } catch (e) { lines.push('❌ ' + id + '：' + errText(e)); }
    });
    const st = $('deviceStatus');
    if (st) {
      st.textContent = '';
      st.appendChild(mk('div', 'msg ' + (lines.some(l => l.startsWith('❌')) ? 'error' : 'success'), '批量同步数据库：\n' + lines.join('\n')));
    }
  } finally {
    endBusy(btn);
  }
}

async function batchRefresh(btn) {
  const ids = [...devSel];
  if (!ids.length) return;
  if (!beginBusy(btn, '刷新中…')) return;
  try {
    const results = await Promise.allSettled(ids.map(id => callApi('dev.stats', id)));
    let ok = 0, bad = 0;
    ids.forEach((id, i) => {
      const d = dashCache.find(x => String(x.id) === id) || devMap[id];
      const r = results[i];
      const st = r.status === 'fulfilled' ? r.value : null;
      if (st && !st.error && typeof st.total_files === 'number') { ok++; if (d) { d.status = 'online'; d.last_sync = new Date().toISOString(); } }
      else { bad++; if (d) d.status = 'offline'; }
    });
    renderDevices();
    showMsg($('deviceStatus'), '批量刷新状态：在线 ' + ok + ' · 离线 ' + bad, bad ? 'error' : 'success');
  } catch (e) {
    showMsg($('deviceStatus'), '批量刷新失败：' + errText(e), 'error');
  } finally {
    endBusy(btn);
  }
}

/* ======================= 文件迁移 ======================= */

const MIG_LIST_LIMIT = 500;
const MIG_EXPAND_MAX = 2000;
const MIG_CONCURRENCY = 3;

/* 目录浏览状态：
   nav = 实际发给 file.list 的路径（用设备返回的路径最保险）；
   rel = 从监控根算起的相对链（migrate.run 的 dstPath 必须是相对路径，主进程会拒绝盘符）；
   rel === null 表示相对链未知（仅在源目录手工输入绝对路径时出现）。
   列表行的 data-nav / data-rel 同时携带两者。 */
const migSrc = { nav: '', rel: '', canonical: '', entries: [] };
const migDst = { nav: '', rel: '', canonical: '', entries: [] };
let migQueue = [];        /* { key, srcId, srcPath, name, rel, size, origin } */
let migRunning = false;
let migStop = false;
let migJobRows = new Map();  /* key → row 元素 */

function joinRel(dir, rel) {
  const d = String(dir || '').replace(/[\\/]+$/, '');
  const r = String(rel || '').replace(/^[\\/]+/, '');
  if (!d) return r;
  if (!r) return d;
  return d + '/' + r;
}

function splitPath(p) {
  const s = String(p || '').replace(/\\/g, '/').replace(/\/+$/, '');
  return s ? s.split('/') : [];
}
/** 上级目录：保留原路径的分隔符风格（Windows 绝对路径不要被改写成 /） */
function parentPath(p) {
  const s = String(p || '').replace(/[\\/]+$/, '');
  if (!s) return '';
  const i = Math.max(s.lastIndexOf('/'), s.lastIndexOf('\\'));
  if (i < 0) return '';
  const head = s.slice(0, i);
  if (!head) return s.slice(0, 1);                  /* POSIX 根 "/" */
  if (/^[A-Za-z]:$/.test(head)) return head + '\\'; /* "C:" → "C:\\" */
  return head;
}
/** 判断是否是绝对路径（迁移目标的 dstPath 必须是相对路径） */
function isAbsolutePath(p) {
  const s = String(p || '');
  return /^[\\/]/.test(s) || /^[A-Za-z]:/.test(s);
}

async function initMigratePage() {
  await fillMigDeviceSelects();
  if (migQueue.length) renderMigQueue();
  loadMigrateHistory();
}

async function fillMigDeviceSelects() {
  const s = $('migSrcDev'); const t = $('migDstDev');
  if (!s || !t) return;
  try {
    const list = await reloadDevices();
    [s, t].forEach(sel => {
      const prev = sel.value;
      sel.textContent = '';
      if (!list.length) { sel.appendChild(new Option('（暂无设备）', '')); return; }
      list.forEach(d => sel.appendChild(new Option((d.status === 'online' ? '🟢 ' : '🔴 ') + deviceLabel(d), String(d.id))));
      if (prev && devMap[prev]) sel.value = prev;
    });
    if (!s.value && list.length) s.value = String(list[0].id);
    if (!t.value && list.length) t.value = String(list[Math.min(1, list.length - 1)].id);
    /* 每次进入页面都按当前目录重读一次，保持与设备现状一致 */
    if (s.value) await loadMigSrc(migSrc.nav);
    else renderErrorBox($('migSrcList'), '暂无设备，请先在「设备管理」添加', null);
    if (t.value) await loadMigDst(migDst.nav);
    else renderErrorBox($('migDstList'), '暂无设备，请先在「设备管理」添加', null);
  } catch (e) {
    renderErrorBox($('migSrcList'), '设备列表加载失败：' + errText(e), () => fillMigDeviceSelects());
    renderErrorBox($('migDstList'), '设备列表加载失败：' + errText(e), () => fillMigDeviceSelects());
  }
}

/* ---- 源目录 ---- */

/**
 * @param {string} navPath 请求给 file.list 的路径（空串=根）
 * @param {string|null} [relPath] 相对链；undefined 表示沿用当前值，null 表示未知
 */
async function loadMigSrc(navPath, relPath) {
  const srcId = $('migSrcDev') ? $('migSrcDev').value : '';
  const listEl = $('migSrcList');
  const stEl = $('migSrcStatus');
  if (!srcId) { renderErrorBox(listEl, '请先选择源设备', null); return; }
  setStatus(stEl, '⏳ 读取目录…');
  if (listEl) listEl.textContent = '';
  try {
    const res = await callApi('file.list', srcId, navPath || '', MIG_LIST_LIMIT, 0);
    if (isErr(res)) throw new Error(errText(res));
    migSrc.nav = navPath || '';
    if (relPath !== undefined) migSrc.rel = relPath;
    migSrc.canonical = res.path || navPath || '';
    migSrc.entries = Array.isArray(res.entries) ? res.entries : [];
    renderMigSrcList();
    renderMigCrumbs($('migSrcCrumb'), migSrc.rel, migSrc.canonical, (rel) => loadMigSrc(rel, rel));
    const inp = $('migSrcPath'); if (inp) inp.value = migSrc.nav;
    clearStatus(stEl);
    const total = Number(res.total);
    if (isFinite(total) && total > migSrc.entries.length) {
      setStatus(stEl, '⚠ 目录共 ' + total + ' 项，本次仅列出前 ' + migSrc.entries.length + ' 项');
    }
  } catch (e) {
    renderErrorBox(listEl, '读取源目录失败：' + errText(e), () => loadMigSrc(navPath));
    showMsg(stEl, '读取源目录失败：' + errText(e), 'error');
  }
}

function renderMigSrcList() {
  const listEl = $('migSrcList');
  if (!listEl) return;
  listEl.textContent = '';
  if (!migSrc.entries.length) {
    listEl.appendChild(mk('div', 'muted', '（空目录）'));
    listEl.firstChild.style.padding = '8px';
    return;
  }
  migSrc.entries.forEach(en => {
    const row = mk('div', 'file-row' + (en.dir ? ' is-dir' : ''));
    row.dataset.path = en.path || '';                          /* 绝对路径：迁移 job 的 srcPath */
    row.dataset.nav = en.path || '';                           /* 目录导航：用设备返回的路径 */
    row.dataset.rel = (migSrc.rel === null) ? '' : joinRel(migSrc.rel, en.name || '');
    row.dataset.dir = en.dir ? '1' : '0';
    row.dataset.name = en.name || '';

    const selCell = mk('span', 'fr-sel');
    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.className = 'fr-chk';
    cb.dataset.path = en.path || '';
    cb.dataset.dir = en.dir ? '1' : '0';
    cb.dataset.name = en.name || '';
    cb.checked = migSrcSelHas(cb.dataset.path);
    cb.setAttribute('aria-label', '勾选 ' + (en.name || ''));
    selCell.appendChild(cb);
    row.appendChild(selCell);

    row.appendChild(mk('span', 'fr-icon', en.dir ? '📁' : '📄'));
    const nm = mk('span', 'fr-name', en.name || '');
    nm.title = en.path || en.name || '';
    row.appendChild(nm);
    row.appendChild(mk('span', 'fr-size', en.dir ? '' : fmtBytes(en.size)));
    row.appendChild(mk('span', 'fr-time', fmtTime(en.mtime)));
    listEl.appendChild(row);
  });
}

/* 源勾选集合：key = 路径 */
let migSrcSel = new Map();
function migSrcSelHas(p) { return migSrcSel.has(String(p)); }
function updateMigSelInfo() {
  const el = $('migSelInfo');
  if (el) el.textContent = migSrcSel.size ? ('已勾选 ' + migSrcSel.size + ' 项') : '未选择';
}

function onMigSrcListClick(e) {
  const row = e.target.closest('.file-row');
  if (!row) return;
  const isDir = row.dataset.dir === '1';
  const path = row.dataset.path;
  const cb = row.querySelector('.fr-chk');

  if (e.target.classList.contains('fr-chk')) {
    toggleMigSrc(cb, path, isDir);
    return;
  }
  if (isDir) { loadMigSrc(row.dataset.nav, migSrc.rel === null ? null : row.dataset.rel); return; }
  if (cb) { cb.checked = !cb.checked; toggleMigSrc(cb, path, isDir); }
}

function toggleMigSrc(cb, path, isDir) {
  const key = String(path);
  if (cb.checked) {
    const entry = migSrc.entries.find(x => String(x.path) === key) || {};
    migSrcSel.set(key, {
      path: key,
      name: cb.dataset.name || entry.name || key,
      dir: isDir,
      size: entry.size
    });
  } else {
    migSrcSel.delete(key);
  }
  const row = cb.closest('.file-row');
  if (row) row.classList.toggle('selected', cb.checked);
  updateMigSelInfo();
}

/** 勾选项 → 任务（目录用 file.list 递归展开，带条数上限） */
async function expandSelectionToJobs() {
  const files = [];
  const skipped = [];
  for (const item of migSrcSel.values()) {
    if (files.length >= MIG_EXPAND_MAX) { skipped.push('其余选择未展开（已达上限 ' + MIG_EXPAND_MAX + ' 项）'); break; }
    if (!item.dir) {
      files.push({ srcId: $('migSrcDev').value, srcPath: item.path, name: item.name, rel: item.name, size: item.size, origin: 'browse' });
      continue;
    }
    const stack = [{ path: item.path, rel: item.name }];
    let truncatedDir = false;
    while (stack.length) {
      if (files.length >= MIG_EXPAND_MAX) { skipped.push(item.name + '（达到展开上限 ' + MIG_EXPAND_MAX + ' 项）'); break; }
      const cur = stack.pop();
      let res;
      try { res = await callApi('file.list', $('migSrcDev').value, cur.path, 1000, 0); }
      catch (e) { skipped.push(cur.rel + '（' + errText(e) + '）'); continue; }
      if (isErr(res)) { skipped.push(cur.rel + '（' + errText(res) + '）'); continue; }
      const entries = Array.isArray(res.entries) ? res.entries : [];
      if (isFinite(Number(res.total)) && Number(res.total) > entries.length) truncatedDir = true;
      for (const en of entries) {
        if (files.length >= MIG_EXPAND_MAX) { truncatedDir = true; break; }
        if (en.dir) stack.push({ path: en.path, rel: cur.rel + '/' + (en.name || '') });
        else files.push({
          srcId: $('migSrcDev').value, srcPath: en.path, name: en.name || '',
          rel: cur.rel + '/' + (en.name || ''), size: en.size, origin: 'browse'
        });
      }
    }
    if (truncatedDir) skipped.push(item.name + '（子目录条目过多，结果可能不完整）');
  }
  return { files, skipped };
}

function migJobKey(j) { return String(j.srcId) + '\u0000' + String(j.srcPath); }

async function enqueueMigrateJobs(jobs, origin) {
  let added = 0, dup = 0;
  jobs.forEach(j => {
    const key = migJobKey(j);
    if (migQueue.some(x => x.key === key)) { dup++; return; }
    migQueue.push({ key, srcId: String(j.srcId), srcPath: j.srcPath, name: j.name, rel: j.rel, size: j.size, origin: j.origin || origin });
    added++;
  });
  renderMigQueue();
  showMsg($('migMsg'), '已加入任务列表 ' + added + ' 项' + (dup ? '（跳过重复 ' + dup + ' 项）' : '') + '，来源：' + (origin || '当前选择'), added ? 'success' : 'info');
  return added;
}

async function addSelectionToQueue() {
  if (!migSrcSel.size) {
    showMsg($('migMsg'), '请先在左侧勾选要迁移的文件或目录', 'error');
    return 0;
  }
  const btn = $('migAdd');
  if (!beginBusy(btn, '整理中…')) return 0;
  try {
    const { files, skipped } = await expandSelectionToJobs();
    if (skipped.length) showMsg($('migMsg'), '部分目录未能展开：' + skipped.join('；'), 'error');
    return await enqueueMigrateJobs(files, '源目录勾选');
  } catch (e) {
    showMsg($('migMsg'), '展开选择失败：' + errText(e), 'error');
    return 0;
  } finally {
    endBusy(btn);
  }
}

function renderMigQueue() {
  const box = $('migProgress');
  if (!box) return;
  if (migRunning) return;    /* 迁移进行中不重建，避免清掉实时结果 */
  box.textContent = '';
  migJobRows = new Map();
  migQueue.forEach(j => {
    const row = mk('div', 'mig-job');
    row.dataset.state = 'pending';
    row.appendChild(mk('span', 'mj-state', '等待'));
    const nm = mk('span', 'mj-name', j.name || j.srcPath);
    nm.title = j.srcPath;
    row.appendChild(nm);
    row.appendChild(mk('span', 'mj-path', (j.origin === 'search' ? '[搜索] ' : '[目录] ') + j.srcPath + ' → ' + joinRel(migDst.rel || '', j.rel || j.name)));
    row.appendChild(mk('span', 'mj-note', ''));
    box.appendChild(row);
    migJobRows.set(j.key, row);
  });
  const info = $('migQueueInfo');
  if (info) info.textContent = '任务列表：' + migQueue.length + ' 项';
  const start = $('migStart');
  if (start) start.textContent = migQueue.length ? ('开始迁移（' + migQueue.length + ' 项）') : '开始迁移';
}

function setJobState(job, state, note) {
  const row = migJobRows.get(job.key);
  if (!row) return;
  row.dataset.state = state;
  const s = row.querySelector('.mj-state');
  if (s) s.textContent = { pending: '等待', running: '迁移中', ok: '成功', error: '失败', skip: '已跳过' }[state] || state;
  const n = row.querySelector('.mj-note');
  if (n) { n.textContent = note || ''; n.title = note || ''; }
}

function currentMigMode() {
  const el = document.querySelector('input[name="migMode"]:checked');
  return el && el.value === 'move' ? 'move' : 'copy';
}

async function runMigration() {
  if (migRunning) return;
  const startBtn = $('migStart');
  const cancelBtn = $('migCancel');

  if (!migQueue.length) {
    const added = await addSelectionToQueue();
    if (!added) return;
  }
  const dstId = $('migDstDev') ? $('migDstDev').value : '';
  if (!dstId) { showMsg($('migMsg'), '请先选择目标设备', 'error'); return; }

  migRunning = true;
  migStop = false;
  beginBusy(startBtn, '迁移中…');
  if (cancelBtn) cancelBtn.disabled = false;

  const mode = currentMigMode();
  const overwrite = !!($('migOverwrite') || {}).checked;
  const jobs = migQueue.slice();
  const dstDir = migDst.rel || '';
  /* migrate.run 的 dstPath 必须是相对监控根的路径（主进程 sanitizeRelPath 会拒绝盘符/绝对路径） */
  if (isAbsolutePath(dstDir)) {
    showMsg($('migMsg'), '目标目录必须是相对监控根的路径，当前是绝对路径：' + dstDir + '（请在“文件迁移 → 目标位置”里从根目录逐级进入）', 'error');
    return;
  }
  let ok = 0, fail = 0, skip = 0;

  try {
    showMsg($('migMsg'), '开始迁移 ' + jobs.length + ' 项（模式：' + (mode === 'move' ? '移动' : '复制') +
      (overwrite ? '，覆盖同名' : '，不覆盖') + '，并发 ' + MIG_CONCURRENCY + '）', 'info');
    await pool(jobs, MIG_CONCURRENCY, async (job) => {
      if (migStop) { skip++; setJobState(job, 'skip', '已跳过（用户停止）'); return; }
      setJobState(job, 'running', '迁移中…');
      const dstPath = joinRel(dstDir, job.rel || job.name);
      if (!dstPath || isAbsolutePath(dstPath)) {
        fail++;
        setJobState(job, 'error', '失败：目标路径非法（必须是相对监控根的路径）：' + dstPath);
        return;
      }
      try {
        const res = await callApi('migrate.run', {
          srcId: job.srcId, dstId, srcPath: job.srcPath, dstPath, mode, overwrite
        });
        if (isErr(res)) {
          fail++;
          let why = errText(res);
          if (res && res.error === 'exists') why += ' → 勾选“覆盖目标同名文件”后可重试';
          setJobState(job, 'error', '失败：' + why);
          return;
        }
        ok++;
        let note = '成功 · ' + fmtBytes(res.size);
        if (res.removed === true) note += ' · 源文件已删除';
        else if (mode === 'move') note += ' · ⚠ 源文件未删除（已保留）';
        else note += ' · 源文件保留';
        if (res.hash) note += ' · ' + String(res.hash).slice(0, 12) + '…';
        setJobState(job, 'ok', note);
      } catch (e) {
        fail++;
        setJobState(job, 'error', '失败：' + errText(e));
      }
    });
    showMsg($('migMsg'), '迁移结束：成功 ' + ok + ' · 失败 ' + fail + (skip ? ' · 跳过 ' + skip : ''),
      fail ? 'error' : 'success');
  } catch (e) {
    showMsg($('migMsg'), '迁移中断：' + errText(e), 'error');
  } finally {
    migRunning = false;
    endBusy(startBtn);
    if (cancelBtn) cancelBtn.disabled = true;
    renderMigQueue_labels();
    loadMigrateHistory();
  }
}

/** 迁移结束后只需更新状态文字（保留每行结果），不重建行 */
function renderMigQueue_labels() {
  const info = $('migQueueInfo');
  if (info) info.textContent = '任务列表：' + migQueue.length + ' 项（已完成一轮）';
}

async function loadMigrateHistory() {
  const box = $('migHistory');
  if (!box) return;
  box.textContent = '';
  box.appendChild(mk('div', 'muted', '⏳ 读取迁移历史…'));
  try {
    const list = await callApi('migrate.list');
    const arr = Array.isArray(list) ? list : (list && Array.isArray(list.items) ? list.items : []);
    box.textContent = '';
    if (!arr.length) { box.appendChild(mk('div', 'muted', '暂无迁移记录')); return; }
    arr.slice().sort((a, b) => toMs(b.time) - toMs(a.time)).slice(0, 500).forEach(h => {
      const row = mk('div', 'hist-row');
      row.appendChild(mk('span', 'h-time', fmtTime(h.time)));
      row.appendChild(mk('span', 'h-mode', h.mode === 'move' ? '移动' : '复制'));
      row.appendChild(mk('span', 'h-ok ' + (h.ok ? 'ok' : 'bad'), h.ok ? '成功' : '失败'));
      const p = mk('span', 'h-path',
        deviceName(h.src) + ':' + (h.path || '?') + ' → ' + deviceName(h.dst) + ':' + (h.dst_path || '/'));
      p.title = p.textContent;
      row.appendChild(p);
      row.appendChild(mk('span', 'h-size', fmtBytes(h.size)));
      if (!h.ok && h.error) {
        const e = mk('span', 'muted', errText({ error: h.error, detail: h.detail }));
        e.title = e.textContent;
        row.appendChild(e);
      }
      box.appendChild(row);
    });
  } catch (e) {
    renderErrorBox(box, '读取迁移历史失败：' + errText(e), () => loadMigrateHistory());
  }
}

/** 设备 id → 显示名（历史记录里存的是 id） */
function deviceName(id) {
  const s = String(id || '');
  if (!s) return '?';
  const d = devMap[s];
  return d ? (d.name || s) : s;
}

/* ---- 目标目录 ---- */

/**
 * @param {string} navPath 请求给 file.list 的路径（空串=根）
 * @param {string} [relPath] 相对链；undefined 表示沿用当前值
 */
async function loadMigDst(navPath, relPath) {
  const dstId = $('migDstDev') ? $('migDstDev').value : '';
  const listEl = $('migDstList');
  const stEl = $('migDstStatus');
  if (!dstId) { renderErrorBox(listEl, '请先选择目标设备', null); return; }
  setStatus(stEl, '⏳ 读取目录…');
  if (listEl) listEl.textContent = '';
  try {
    const res = await callApi('file.list', dstId, navPath || '', MIG_LIST_LIMIT, 0);
    if (isErr(res)) throw new Error(errText(res));
    migDst.nav = navPath || '';
    if (relPath !== undefined) migDst.rel = (relPath === null ? '' : relPath);
    migDst.canonical = res.path || navPath || '';
    migDst.entries = Array.isArray(res.entries) ? res.entries : [];
    renderMigDstList();
    renderMigCrumbs($('migDstCrumb'), migDst.rel, migDst.canonical, (rel) => loadMigDst(rel, rel));
    const code = $('migDstPath');
    if (code) {
      code.textContent = migDst.rel || '/';
      code.title = migDst.canonical || migDst.nav || '';
    }
    renderMigQueue();
    clearStatus(stEl);
  } catch (e) {
    renderErrorBox(listEl, '读取目标目录失败：' + errText(e), () => loadMigDst(navPath));
    showMsg(stEl, '读取目标目录失败：' + errText(e), 'error');
  }
}

function renderMigDstList() {
  const listEl = $('migDstList');
  if (!listEl) return;
  listEl.textContent = '';
  const dirs = migDst.entries.filter(en => en && en.dir);
  if (!dirs.length) {
    listEl.appendChild(mk('div', 'muted', '（无子目录，可直接作为落点）'));
    listEl.firstChild.style.padding = '8px';
    return;
  }
  dirs.forEach(en => {
    const row = mk('div', 'file-row is-dir');
    row.dataset.path = en.path || '';
    row.dataset.nav = en.path || '';                        /* 列表用设备返回的路径 */
    row.dataset.rel = joinRel(migDst.rel, en.name || '');    /* dstPath 用相对链 */
    row.appendChild(mk('span', 'fr-icon', '📁'));
    const nm = mk('span', 'fr-name', en.name || '');
    nm.title = en.path || '';
    row.appendChild(nm);
    row.appendChild(mk('span', 'fr-size', ''));
    row.appendChild(mk('span', 'fr-time', fmtTime(en.mtime)));
    listEl.appendChild(row);
  });
}

function onMigDstListClick(e) {
  const row = e.target.closest('.file-row');
  if (!row) return;
  loadMigDst(row.dataset.nav || row.dataset.path, row.dataset.rel);
}

/**
 * 面包屑：基于"相对链"构造（保证 dstPath 始终是相对路径）。
 * 手工输入了绝对路径时相对链未知（rel === null），此处退化为纯文本显示。
 */
function renderMigCrumbs(box, rel, canonical, onNav) {
  if (!box) return;
  box.textContent = '';
  const root = mk('button', 'crumb', '根目录');
  root.addEventListener('click', () => onNav(''));
  box.appendChild(root);
  if (rel === null || rel === undefined) {
    box.appendChild(mk('span', 'crumb-sep', '·'));
    box.appendChild(mk('span', 'muted', canonical || '（相对链未知，仅支持文件搜索/根目录内选择）'));
    return;
  }
  const parts = splitPath(rel);
  let acc = '';
  parts.forEach(part => {
    box.appendChild(mk('span', 'crumb-sep', '/'));
    acc = acc ? (acc + '/' + part) : part;
    const target = acc;
    const b = mk('button', 'crumb', part);
    b.addEventListener('click', () => onNav(target));
    box.appendChild(b);
  });
}

async function migMkdir() {
  const dstId = $('migDstDev') ? $('migDstDev').value : '';
  const nameEl = $('migNewDir');
  const name = ((nameEl && nameEl.value) || '').trim();
  const btn = $('migMkdir');
  if (!dstId) { showMsg($('migDstStatus'), '请先选择目标设备', 'error'); return; }
  if (!name) { showMsg($('migDstStatus'), '请输入新目录名', 'error'); return; }
  if (/[\\/:*?"<>|]/.test(name) || name === '.' || name === '..') {
    showMsg($('migDstStatus'), '目录名不能包含 \\ / : * ? " < > | 或为 . / ..', 'error'); return;
  }
  if (!beginBusy(btn, '创建中…')) return;
  try {
    const target = joinRel(migDst.rel || '', name);
    const res = await callApi('file.mkdir', dstId, target);
    if (isErr(res)) { showMsg($('migDstStatus'), '创建目录失败：' + errText(res), 'error'); return; }
    if (nameEl) nameEl.value = '';
    showMsg($('migDstStatus'), '已创建目录：' + (res.path || target), 'success');
    await loadMigDst(migDst.nav, migDst.rel);
  } catch (e) {
    showMsg($('migDstStatus'), '创建目录失败：' + errText(e), 'error');
  } finally {
    endBusy(btn);
  }
}

function initMigratePageControls() {
  const on = (id, ev, fn) => { const el = $(id); if (el) el.addEventListener(ev, fn); };
  on('migSrcDev', 'change', () => { migSrcSel.clear(); updateMigSelInfo(); loadMigSrc('', ''); });
  on('migSrcRefresh', 'click', () => loadMigSrc(migSrc.nav));
  on('migSrcUp', 'click', () => {
    if (migSrc.rel === null) loadMigSrc(parentPath(migSrc.nav), null);
    else loadMigSrc(parentPath(migSrc.rel), parentPath(migSrc.rel));
  });
  on('migSrcGo', 'click', () => {
    const v = (($('migSrcPath') || {}).value || '').trim();
    /* 手工输入：绝对路径无法确定相对链，标记为未知；空串=根 */
    loadMigSrc(v, v === '' ? '' : (isAbsolutePath(v) ? null : v));
  });
  on('migSrcList', 'click', onMigSrcListClick);
  on('migSelClear', 'click', () => { migSrcSel.clear(); renderMigSrcList(); updateMigSelInfo(); });
  on('migAdd', 'click', () => addSelectionToQueue());

  on('migDstDev', 'change', () => loadMigDst('', ''));
  on('migDstRefresh', 'click', () => loadMigDst(migDst.nav));
  on('migDstUp', 'click', () => loadMigDst(parentPath(migDst.rel), parentPath(migDst.rel)));
  on('migDstList', 'click', onMigDstListClick);
  on('migMkdir', 'click', migMkdir);

  on('migStart', 'click', runMigration);
  on('migCancel', 'click', () => {
    if (!migRunning) return;
    migStop = true;
    showMsg($('migMsg'), '已请求停止：进行中的任务会跑完，未开始的任务将跳过', 'info');
    const c = $('migCancel'); if (c) c.disabled = true;
  });
  on('migQueueClear', 'click', () => {
    if (migRunning) { showMsg($('migMsg'), '迁移进行中，无法清空任务列表', 'error'); return; }
    migQueue = [];
    renderMigQueue();
    showMsg($('migMsg'), '任务列表已清空', 'info');
  });
  on('migHistRefresh', 'click', loadMigrateHistory);
}

/* ======================= 事件通道（单次注册 + 集中分发） ======================= */

let eventConnected = null;
let eventConnectedDevice = '';

function initEventChannel() {
  const ev = window.hamster && window.hamster.event;
  if (!ev) { addLog('info', '主进程未暴露 window.hamster.event，事件日志不可用'); return; }
  if (typeof ev.onBroadcast === 'function') ev.onBroadcast(handleBroadcast);
  if (typeof ev.onConnected === 'function') ev.onConnected(handleConnected);
  if (typeof ev.onDeviceDisconnect === 'function') ev.onDeviceDisconnect(handleDeviceDisconnect);
  if (typeof ev.onHeartbeat === 'function') ev.onHeartbeat(handleHeartbeat);
  if (typeof ev.onMessage === 'function') ev.onMessage(handleMessage);
}

function updateEventChannelState(connected, device) {
  const el = $('eventChannelState');
  if (!el) return;
  if (connected === null || connected === undefined) {
    el.textContent = '事件通道：—';
    el.classList.remove('on', 'off');
    return;
  }
  el.textContent = device
    ? ('事件通道 · ' + device + '：' + (connected ? '已连接' : '已断开'))
    : ('事件通道：' + (connected ? '已连接' : '已断开'));
  el.classList.toggle('on', !!connected);
  el.classList.toggle('off', !connected);
}

function handleConnected(data) {
  const isObj = data && typeof data === 'object';
  const connected = isObj ? !!data.connected : !!data;
  const device = isObj ? String(data.device || '') : '';
  updateEventChannelState(connected, device);
  eventConnected = connected;
  eventConnectedDevice = device;
  if (device) {
    addLog(connected ? 'device_connected manager <- ' + device : 'device_disconnected manager -/-> ' + device,
      'conn|' + device + '|' + (connected ? 1 : 0));
    schedulePanelRefresh({ type: 'connection_status', device, status: connected ? 'online' : 'offline' });
  } else {
    addLog(connected ? 'IPC manager -> electron' : 'IPC manager -/-> electron (disconnected)', 'conn|ipc|' + (connected ? 1 : 0));
  }
}

function handleBroadcast(msg) {
  if (!msg) return;
  const t = String(msg.type || msg.event || '');
  const dev = msg.device || msg.device_name || '?';
  if (t.indexOf('file_') === 0) {
    const p = msg.file || msg.path || (msg.data && (msg.data.path || msg.data)) || '';
    const label = t === 'file_added' ? 'ADDED' : (t === 'file_removed' ? 'REMOVED' : 'MODIFIED');
    addLog(t + ' ' + dev + ' ' + label + ' ' + p, t + '|' + dev + '|' + p);   /* 按 (event, 设备, path) 去重 */
    schedulePanelRefresh(msg);
  } else if (t === 'connection_status') {
    addLog('connection_status ' + dev + ' ' + (msg.status || ''), 'conn|' + dev + '|' + (msg.status || ''));
    schedulePanelRefresh(msg);
  } else if (t.indexOf('verify_done') === 0) {
    const d = msg.data && typeof msg.data === 'object' ? msg.data : {};
    addLog('verify_done ' + dev + (d.total !== undefined ? (' total=' + d.total + ' ok=' + d.ok + ' corrupt=' + d.corrupt + ' missing=' + d.missing) : ''),
      'verify|' + dev + '|' + (msg.seq !== undefined ? msg.seq : ''));
    schedulePanelRefresh(msg);
  } else if (t === 'migrate_done') {
    const d = msg.data && typeof msg.data === 'object' ? msg.data : {};
    addLog('migrate_done ' + (d.ok ? ('成功 size=' + d.size) : ('失败 ' + (d.error || '?'))) +
      (d.log_id ? (' log=' + d.log_id) : ''), 'migrate|' + (d.log_id || ''));
    if (currentPage === 'migrate' && !migRunning) loadMigrateHistory();
  }
}

function handleDeviceDisconnect(msg) {
  const name = (msg && (msg.device_id || msg.device_name || msg.device)) || '?';
  addLog('device_disconnected ' + name, 'disconn|' + name + '|' + Date.now());
  schedulePanelRefresh(msg);
}

function handleMessage(msg) {
  if (!msg) return;
  const raw = (() => { try { return JSON.stringify(msg.data || msg); } catch (e) { return '[不可序列化]'; } })();
  const text = 'message ' + (msg.device || '-') + ' ' + (msg.event || msg.type || '-') + ' ' +
    (raw.length > 120 ? raw.substring(0, 120) + '...' : raw);
  addLog(text, 'msg|' + (msg.device || '-') + '|' + (msg.event || msg.type || '-'));
}

/* ---- 心跳 / 连接健康 ----
   主进程每 5s 推一次 event:heartbeat → {device, device_id, age_ms, connected}，
   其中 age_ms 是"距该设备上一次事件的时间"。因此：
     - connected=false          → 事件通道确实断开；
     - age_ms 很大但 connected   → 可能只是设备空闲，也可能是半开连接，如实标注"待确认"；
     - 连心跳消息本身都停了      → 主进程或 IPC 侧卡住（这才是能一眼看出的半开/僵死信号）。 */

const heartbeats = new Map();   /* 设备键 → { age_ms, at, connected, device } */
const HEARTBEAT_TICK_MS = 5000;      /* 主进程推送周期 */
const HEARTBEAT_LOST_MS = 15000;     /* 连续 3 个周期没收到心跳 → 判定心跳停止 */
const HB_ACTIVE_MS = 30000;          /* 30s 内有事件 → 活跃 */
const HB_IDLE_MS = 300000;           /* 5 分钟内有事件 → 空闲；超过则需人工确认 */
let lastHeartbeatAt = 0;
let healthTimer = null;

function hbKey(id, name) { return String(id || name || '?'); }

function noteHeartbeat(idOrName, ageMs, connected) {
  lastHeartbeatAt = Date.now();
  const key = (idOrName && devMap[String(idOrName)]) ? String(idOrName)
    : (resolveDeviceIdByName(idOrName) || String(idOrName || '?'));
  heartbeats.set(key, {
    age_ms: Number(ageMs) || 0, at: Date.now(),
    connected: connected === undefined ? true : !!connected,
    device: String(idOrName || key)
  });
  if (currentPage === 'eventlog') renderHealth();
}

function resolveDeviceIdByName(name) {
  if (!name) return '';
  if (devMap[name]) return name;
  const hit = devices.find(d => d && (d.name === name || String(d.id) === String(name)));
  return hit ? String(hit.id) : '';
}

/** 兼容新契约 {device,device_id,age_ms,connected} 与历史 {id:{...}} 形态 */
function handleHeartbeat(data) {
  if (!data || typeof data !== 'object') return;
  if (typeof data.age_ms === 'number' || typeof data.device === 'string' || typeof data.device_id === 'string') {
    noteHeartbeat(data.device_id || data.device, data.age_ms, data.connected);
    return;
  }
  Object.keys(data).forEach(k => {
    const v = data[k];
    noteHeartbeat((v && (v.name || v.id)) || k, (v && v.age_ms) || 0, v && v.connected);
  });
}

/** 供仪表盘/设备卡片使用的一行式心跳描述 */
function heartbeatAgeText(id, name) {
  const hb = heartbeats.get(hbKey(id, name));
  if (!hb) return '无心跳数据';
  if (!hb.connected) return '⚠ 事件通道断开';
  const age = hb.age_ms + (Date.now() - hb.at);
  if (age <= HB_ACTIVE_MS) return (age / 1000).toFixed(1) + ' 秒前';
  if (age <= HB_IDLE_MS) return formatAge(age) + '前（空闲）';
  return '⚠ ' + formatAge(age) + '无事件（待确认）';
}

function formatAge(ms) {
  if (ms < 60000) return (ms / 1000).toFixed(0) + ' 秒';
  if (ms < 3600000) return (ms / 60000).toFixed(1) + ' 分钟';
  return (ms / 3600000).toFixed(1) + ' 小时';
}

function startHealthTicker() {
  if (healthTimer) return;
  healthTimer = setInterval(() => { if (currentPage === 'eventlog') renderHealth(); }, 1000);
}
function stopHealthTicker() {
  if (healthTimer) { clearInterval(healthTimer); healthTimer = null; }
}

function renderHealth() {
  const box = $('connHealth');
  if (!box) return;
  const list = devices.length ? devices : (Array.isArray(dashCache) ? dashCache : []);
  box.textContent = '';

  const sinceTick = lastHeartbeatAt ? (Date.now() - lastHeartbeatAt) : Infinity;
  const tickerLost = sinceTick > HEARTBEAT_LOST_MS;
  box.appendChild(mk('div', 'ch-item ' + (tickerLost ? 'st-bad' : 'st-ok'),
    lastHeartbeatAt
      ? (tickerLost
        ? '⚠ 已 ' + formatAge(sinceTick) + ' 未收到主进程心跳消息（主进程可能卡住，或事件通道半开）'
        : '心跳消息正常（每 ' + (HEARTBEAT_TICK_MS / 1000) + ' 秒一次，最近 ' + formatAge(sinceTick) + '前）')
      : '尚未收到主进程心跳消息（等待 ' + (HEARTBEAT_TICK_MS / 1000) + ' 秒一次的首帧）'));

  if (!list.length) { box.appendChild(mk('div', 'muted', '暂无设备')); return; }
  list.forEach(d => {
    const id = String(d.id);
    const hb = heartbeats.get(hbKey(d.id, d.name));
    const row = mk('div', 'ch-item');
    let ageText = '—';
    let note = '尚未收到该设备的心跳（设备可能离线）';
    let state = 'st-off';
    if (hb) {
      const age = hb.age_ms + (Date.now() - hb.at);
      if (!hb.connected) { state = 'st-bad'; ageText = formatAge(age); note = '事件通道断开'; }
      else {
        ageText = formatAge(age);
        if (age <= HB_ACTIVE_MS) { state = 'st-ok'; note = '活跃（近期有事件）'; }
        else if (age <= HB_IDLE_MS) { state = 'st-warn'; note = '空闲（连接仍在线，长时间无新事件）'; }
        else { state = 'st-bad'; note = '长时间无事件：可能一直空闲，也可能是半开连接（事件通道仍报已连接）'; }
      }
    }
    row.classList.add(state);
    row.appendChild(mk('span', 'ch-dot'));
    row.appendChild(mk('span', 'ch-name', d.name || id));
    row.appendChild(mk('span', 'ch-age', hb ? ('心跳 ' + ageText + '前') : '心跳 —'));
    row.appendChild(mk('span', 'ch-note', note + '（设备状态：' + (d.status === 'online' ? '在线' : '离线') + '）'));
    box.appendChild(row);
  });
}

/* ---- 事件日志（按 (event,path) 1 秒窗口合并计数） ---- */

const MAX_LOG = 600;            /* 多设备时事件很密：600 条足够回看，DOM 也更轻 */
const LOG_DEDUPE_MS = 1000;
const logIndex = new Map();     /* key → { el, msgEl, timeEl, countEl, count, at } */

function nowStamp() {
  const d = new Date();
  const p = n => String(n).padStart(2, '0');
  return d.getFullYear() + p(d.getMonth() + 1) + p(d.getDate()) + ' ' +
    p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
}

/* ---- 事件日志滚动策略 ----
   多设备时事件是连续涌入的，若每条都强制滚到底，用户永远看不了历史。
   规则：原本就贴在底部 → 自动跟随；用户往上滚了 → 停止跟随并累计新条目提示。 */
let logAutoScroll = true;
let logPending = 0;
function logNearBottom(el) { return (el.scrollHeight - el.scrollTop - el.clientHeight) < 24; }
function logJumpBtn() { return $('logJump'); }
function scrollLogToEnd(container) {
  if (logAutoScroll) {
    container.scrollTop = container.scrollHeight;
    logPending = 0;
    return;
  }
  /* 内容还没超出可视高度时不需要"回到底部"，否则按钮会在根本没有可跳内容时出现 */
  if (container.scrollHeight <= container.clientHeight + 4) { logPending = 0; return; }
  logPending++;
  const b = logJumpBtn();
  if (b) { b.textContent = '\u2193 ' + logPending + ' 条新事件'; b.dataset.show = '1'; }
}

function addLog(text, dedupeKey) {
  console.log('[LOG] ' + text);
  const container = $('eventLogContainer');
  if (!container) return;
  const empty = container.querySelector('.event-log-empty');
  if (empty) empty.remove();

  const now = Date.now();
  if (dedupeKey) {
    const prev = logIndex.get(dedupeKey);
    if (prev && prev.el && prev.el.isConnected && (now - prev.at) <= LOG_DEDUPE_MS) {
      prev.count++;
      prev.at = now;
      prev.msgEl.textContent = text;
      prev.timeEl.textContent = nowStamp();
      prev.countEl.textContent = '×' + prev.count;
      prev.countEl.hidden = false;
      scrollLogToEnd(container);
      return;
    }
  }

  while (container.children.length >= MAX_LOG) container.removeChild(container.firstChild);
  const entry = mk('div', 'event-log-entry');
  const timeEl = mk('span', 'el-time', nowStamp());
  const msgEl = mk('span', 'el-msg', text);
  const countEl = mk('span', 'el-count', '×1');
  countEl.hidden = true;
  entry.appendChild(timeEl);
  entry.appendChild(msgEl);
  entry.appendChild(countEl);
  container.appendChild(entry);
  scrollLogToEnd(container);

  if (dedupeKey) {
    logIndex.set(dedupeKey, { el: entry, msgEl, timeEl, countEl, count: 1, at: now });
    if (logIndex.size > 500) {
      const cutoff = now - LOG_DEDUPE_MS * 10;
      [...logIndex.entries()].forEach(([k, v]) => { if (v.at < cutoff || !v.el.isConnected) logIndex.delete(k); });
    }
  }
}

function initEventLog() {
  const btn = $('clearEventLog');
  const container = $('eventLogContainer');
  if (btn && container) {
    btn.addEventListener('click', () => {
      container.textContent = '';
      container.appendChild(mk('div', 'event-log-empty', '等待事件...'));
      logIndex.clear();
      logAutoScroll = true;
      logPending = 0;
      const jb = logJumpBtn();
      if (jb) jb.dataset.show = '0';
    });
  }
  /* 往上滚就停止自动跟随；回到底部再恢复 */
  if (container) {
    container.addEventListener('scroll', () => {
      const near = logNearBottom(container);
      logAutoScroll = near;
      const b = logJumpBtn();
      if (b && near) { b.dataset.show = '0'; logPending = 0; }
    });
  }
  /* "回到底部"提示按钮：绝对定位浮在日志区右下角 */
  const page = $('page-eventlog');
  if (page && !$('logJump')) {
    const b = mk('button', 'log-jump');
    b.id = 'logJump';
    b.dataset.show = '0';
    b.title = '回到底部并继续自动跟随';
    b.textContent = '\u2193 新事件';
    b.addEventListener('click', () => {
      logAutoScroll = true;
      logPending = 0;
      if (container) container.scrollTop = container.scrollHeight;
      b.dataset.show = '0';
    });
    page.appendChild(b);
  }
  updateEventChannelState(!!eventConnected, eventConnectedDevice);
}

/* ======================= 面板刷新调度 ======================= */

let panelRefreshTimer = null;
let lastPanelRefresh = 0;
const pendingIncIds = new Set();
let pendingFull = false;

function resolveTargetDeviceId(msg) {
  if (!msg) return null;
  const raw = msg.device_id !== undefined ? String(msg.device_id) : '';
  if (raw && dashCache.some(d => String(d.id) === raw)) return raw;
  const nm = msg.device || msg.device_name;
  if (!nm) return null;
  const hits = dashCache.filter(d => {
    if (d.name === nm) return true;
    if (nm === 'LOCAL') {
      const h = String(d.addr || '').split(':')[0];
      return h === '127.0.0.1' || h === 'localhost';
    }
    return false;
  });
  return hits.length === 1 ? String(hits[0].id) : null;
}

function schedulePanelRefresh(msg, immediate) {
  const tid = resolveTargetDeviceId(msg);
  if (tid && dashCache.length) pendingIncIds.add(tid);
  else pendingFull = true;
  if (panelRefreshTimer) clearTimeout(panelRefreshTimer);
  if (immediate || Date.now() - lastPanelRefresh >= 5000) { runPanelRefresh(); return; }
  panelRefreshTimer = setTimeout(runPanelRefresh, 400);
}

function runPanelRefresh() {
  panelRefreshTimer = null;
  lastPanelRefresh = Date.now();
  const ids = [...pendingIncIds];
  const full = pendingFull || !ids.length;
  pendingIncIds.clear();
  pendingFull = false;
  if (full) {
    loadDashboard();
    loadSecurity();
    return;
  }
  refreshDevicesData(ids);
  refreshDevicesSecurity(ids);
}

/** 单设备 stats 批量取值 → 只重绘一次；await 之后按 id 重新定位对象 */
async function refreshDevicesData(ids) {
  const list = (Array.isArray(ids) ? ids : []).map(String);
  if (!list.length) return;
  try {
    const results = await Promise.allSettled(list.map(id => callApi('dev.stats', id)));
    list.forEach((id, i) => {
      const d = dashCache.find(x => String(x.id) === id);
      if (!d) return;                       /* 设备已被移除 → 忽略 */
      const r = results[i];
      const st = (r.status === 'fulfilled') ? r.value : null;
      if (st && !st.error && typeof st.total_files === 'number') {
        d.total_files = st.total_files;
        d.total_size = st.total_size || 0;
        d.file_types_count = st.file_type_count || 0;
        d.file_types = Array.isArray(st.file_types) ? st.file_types : [];
        d.status = 'online';
        d.last_sync = new Date().toISOString();
      } else {
        d.status = 'offline';
      }
    });
    renderDashboard(dashCache);
  } catch (e) {
    console.warn('[DASH] 增量刷新失败:', e);
  }
}

/* ======================= 设置 / 关于 / 标题栏 ======================= */

const SETTINGS_KEY = 'hamster_app_settings';
let appSettings = { dlDir: '' };

async function getDefaultDlDir() {
  try {
    if (hasApi('config.get')) {
      const c = await callApi('config.get');
      if (c && (c.downloads_dir || c.download_dir)) return c.downloads_dir || c.download_dir;
    }
  } catch (e) { console.warn('[CFG] config.get 失败:', e && e.message); }
  try {
    if (hasApi('app.getPaths')) {
      const p = await callApi('app.getPaths');
      if (p && (p.downloads || p.downloadDir)) return p.downloads || p.downloadDir;
    }
  } catch (e) { console.warn('[CFG] app.getPaths 失败:', e && e.message); }
  if (hasApi('getDownloadsDir')) {
    try { return await callApi('getDownloadsDir'); } catch (e) { /* 忽略 */ }
  }
  return '';
}

async function loadAppSettings() {
  try {
    const s = localStorage.getItem(SETTINGS_KEY);
    if (s) {
      const p = JSON.parse(s);
      if (p && typeof p === 'object' && typeof p.dlDir === 'string') appSettings.dlDir = p.dlDir;
    }
  } catch (e) { console.warn('[CFG] 读取本地设置失败:', e && e.message); }

  const el = $('cfgDlDir');
  if (el) {
    el.value = appSettings.dlDir || '';
    if (!el.value) { try { el.value = (await getDefaultDlDir()) || ''; } catch (e) { /* 忽略 */ } }
  }
  loadAppPaths();
}

/** 保存设置：对不存在的元素做防御，绝不因缺少字段抛错中断 */
function saveAppSettings() {
  const el = $('cfgDlDir');
  if (el) appSettings.dlDir = String(el.value || '').trim();
  try {
    localStorage.setItem(SETTINGS_KEY, JSON.stringify({ dlDir: appSettings.dlDir }));
    return true;
  } catch (e) {
    console.warn('[CFG] 写入本地设置失败:', e && e.message);
    return false;
  }
}

async function loadAppPaths() {
  const box = $('appPaths');
  if (!box) return;
  box.textContent = '';
  if (!hasApi('app.getPaths')) { box.appendChild(mk('div', null, '主进程未提供 app.getPaths')); return; }
  try {
    const p = await callApi('app.getPaths');
    if (!p || typeof p !== 'object') { box.appendChild(mk('div', null, '主进程未返回路径信息')); return; }
    Object.keys(p).forEach(k => {
      const v = p[k];
      if (v === null || v === undefined || typeof v === 'object') return;
      box.appendChild(mk('div', null, k + '：' + String(v)));
    });
  } catch (e) {
    renderErrorBox(box, '读取本地路径失败：' + errText(e), () => loadAppPaths());
  }
}

async function loadAbout() {
  const el = $('aboutVersion');
  if (!el) return;
  if (!hasApi('app.getVersion')) { el.textContent = '未知（主进程未提供 app.getVersion）'; return; }
  try { el.textContent = String(await callApi('app.getVersion')); }
  catch (e) { el.textContent = '未知（' + errText(e) + '）'; }
}

function initSettingsPage() {
  const btn = $('saveCfgBtn');
  if (btn) btn.addEventListener('click', async () => {
    if (!beginBusy(btn, '保存中…')) return;
    try {
      const ok = saveAppSettings();
      let mainOk = true, mainErr = '';
      if (hasApi('config.set')) {
        /* 主进程的配置键名是 download_dir（见 config:set 实现）；同时带上 dlDir 便于后续扩展 */
        try { await callApi('config.set', { download_dir: appSettings.dlDir, dlDir: appSettings.dlDir }); }
        catch (e) { mainOk = false; mainErr = errText(e); }
      }
      if (!ok) showMsg($('cfgMsg'), '写入本地设置失败（localStorage 不可用），仅当前会话有效', 'error');
      else if (!mainOk) showMsg($('cfgMsg'), '界面设置已保存，但主进程未接受该配置：' + mainErr, 'error');
      else showMsg($('cfgMsg'), '设置已保存：' + (appSettings.dlDir || '(空)'), 'success');
    } catch (e) {
      showMsg($('cfgMsg'), '保存失败：' + errText(e), 'error');
    } finally {
      endBusy(btn);
    }
  });
  const browse = $('btnBrowseDl');
  if (browse) browse.addEventListener('click', async () => {
    if (!beginBusy(browse, '选择中…')) return;
    try {
      if (!hasApi('pickFolder')) { showMsg($('cfgMsg'), '主进程未提供目录选择接口', 'error'); return; }
      const folder = await callApi('pickFolder');
      if (folder) { const el = $('cfgDlDir'); if (el) el.value = folder; }
    } catch (e) {
      showMsg($('cfgMsg'), '选择目录失败：' + errText(e), 'error');
    } finally {
      endBusy(browse);
    }
  });
}

function initTitlebar() {
  const win = (window.hamster && window.hamster.window) || {};
  const on = (id, fn) => { const el = $(id); if (el) el.addEventListener('click', fn); };
  on('tbMin', () => { if (typeof win.minimize === 'function') win.minimize(); });
  on('tbMax', () => { if (typeof win.maximize === 'function') win.maximize(); });
  on('tbClose', () => { if (typeof win.close === 'function') win.close(); });
  /* Segoe MDL2 码位：E922=最大化，E923=还原 */
  const setMax = m => { const el = $('tbMax'); if (el) el.textContent = m ? '\uE923' : '\uE922'; };
  if (typeof win.onMaximizeChange === 'function') { try { win.onMaximizeChange(setMax); } catch (e) { console.warn(e); } }
  if (typeof win.isMaximized === 'function') {
    try { Promise.resolve(win.isMaximized()).then(setMax).catch(() => {}); } catch (e) { /* 忽略 */ }
  }
}

/* ======================= 校验页按钮 ======================= */

function initSecurityPage() {
  const b = $('secRefresh');
  if (b) b.addEventListener('click', async () => {
    if (!beginBusy(b, '读取中…')) return;
    try { await loadSecurity({ force: true }); }
    finally { endBusy(b); }
  });
}

/* ======================= 启动 ======================= */

function boot() {
  initTitlebar();
  initSidebar();
  initModal();
  initControlPage();
  initDevicePage();
  initSearchControls();
  initMigratePageControls();
  initSecurityPage();
  initSettingsPage();
  initEventLog();
  initEventChannel();

  /* 首次数据加载：各自 try/catch，互不阻塞 */
  loadDashboard().catch(e => console.error('[BOOT] 仪表盘初始化失败:', e));
  loadSecurity().catch(e => console.error('[BOOT] 校验页初始化失败:', e));
  loadAppSettings().catch(e => console.error('[BOOT] 设置初始化失败:', e));
  loadAbout().catch(e => console.error('[BOOT] 关于页初始化失败:', e));
  initDeviceSelector().catch(e => console.error('[BOOT] 设备选择器初始化失败:', e));

  renderHealth();
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
else boot();
