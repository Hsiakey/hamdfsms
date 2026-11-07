/*
 * 界面离屏截图工具 —— 没有 GUI 自动化环境也能看到真实渲染结果
 *
 * 用法:
 *   electron tests/ui-shot.js                          # 全部页面 → build/ui-<page>.png
 *   electron tests/ui-shot.js <html> <outDir> [w] [h]
 *
 * 说明:
 *   · 用内置示例数据填充各区域（真实守护进程不在场时表格是空的，看不出行样式）
 *   · 逐页切换并截图，便于人工核对配色、间距、对齐与控件外观
 *   · 只读取界面文件，不修改项目里的任何东西
 */
const { app, BrowserWindow } = require('electron');
const path = require('path');
const fs = require('fs');

const root = path.join(__dirname, '..');
const htmlPath = process.argv[2] || path.join(root, 'Hamster Manager', 'module', 'hamster_manager_ui', '_html', 'hamster_manager.html');
const outDir = process.argv[3] || path.join(root, 'build', 'ui');
const W = parseInt(process.argv[4] || '1280', 10);
const H = parseInt(process.argv[5] || '840', 10);

app.commandLine.appendSwitch('disable-gpu');
app.disableHardwareAcceleration();

const PAGES = ['dashboard', 'security', 'search', 'control', 'devices', 'migrate', 'eventlog', 'settings', 'about'];

/* 示例数据：只用到界面既有的类名，不新增结构 */
const STUB = `
(function () {
  const q = (s) => document.querySelector(s);
  const mk = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
  const num = (id, v) => { const e = document.getElementById(id); if (e) e.textContent = v; };

  num('stat-total_files', '12,483'); num('stat-total_size', '4.7 GB');
  num('stat-file_types_count', '58'); num('stat-last_scan', '2026-10-17 20:14');
  num('sec-verified_files', '12,483'); num('sec-verify_count', '27');
  num('sec-periodic_scan', '6'); num('sec-silent_corrupt', '0');
  const av = document.getElementById('aboutVersion'); if (av) av.textContent = 'ver.0.0.8';

  // 设备文件分布
  const dist = q('#devDistBody');
  if (dist) {
    dist.innerHTML = '';
    [['LOCAL', '9,120', '3.4 GB', '2026-10-17 20:14', true], ['NAS-A', '3,363', '1.3 GB', '2026-10-17 19:52', false]].forEach(r => {
      const row = mk('div', 'dev-dist-row');
      const dot = mk('div', 'dev-dist-td td-dot-cell');
      dot.appendChild(mk('span', 'td-dot ' + (r[4] ? 'online' : 'offline')));
      row.appendChild(dot);
      row.appendChild(mk('div', 'dev-dist-td td-name', r[0]));
      row.appendChild(mk('div', 'dev-dist-td td-count', r[1]));
      row.appendChild(mk('div', 'dev-dist-td td-size', r[2]));
      row.appendChild(mk('div', 'dev-dist-td td-time', r[3]));
      dist.appendChild(row);
    });
  }
  // 文件类型分布
  const types = q('#typeDistBody');
  if (types) {
    types.innerHTML = '';
    [['1', 'md', '4,210', '812 MB', '2'], ['2', 'png', '3,308', '2.1 GB', '2'], ['3', 'zip', '640', '1.6 GB', '1']].forEach(r => {
      const row = mk('div', 'dev-dist-row');
      row.appendChild(mk('div', 'dev-dist-td', r[0]));
      row.appendChild(mk('div', 'dev-dist-td td-name', r[1]));
      row.appendChild(mk('div', 'dev-dist-td td-count', r[2]));
      row.appendChild(mk('div', 'dev-dist-td td-size', r[3]));
      row.appendChild(mk('div', 'dev-dist-td', r[4]));
      types.appendChild(row);
    });
  }
  // 设备列表
  const dl = q('#dashboardDevList');
  if (dl) {
    dl.innerHTML = '';
    const box = mk('div', 'device-mini-list');
    [['LOCAL', '9,120 文件', true], ['NAS-A', '3,363 文件', false]].forEach(r => {
      const it = mk('div', 'device-mini');
      it.appendChild(mk('span', 'dm-dot ' + (r[2] ? 'online' : 'offline')));
      it.appendChild(mk('span', 'dm-name', r[0]));
      it.appendChild(mk('span', 'dm-info', r[1]));
      box.appendChild(it);
    });
    dl.appendChild(box);
  }
  const dcl = document.getElementById('devCountLabel'); if (dcl) dcl.textContent = '2 只';

  // 搜索结果
  const res = q('#searchResults');
  if (res) {
    res.innerHTML = '';
    const body = mk('div', 'search-body');
    const hdr = mk('div', 'search-hdr');
    [['sc-sel', ''], ['sc-dev', '设备'], ['sc-name', '文件名'], ['sc-path', '路径'], ['sc-size', '大小'], ['sc-date', '修改时间'], ['sc-act', '操作']]
      .forEach(h => hdr.appendChild(mk('span', h[0], h[1])));
    body.appendChild(hdr);
    [['LOCAL', '季度报告.pdf', 'docs/2026/季度报告.pdf', '2.4 MB', '10-17 20:11', true],
     ['NAS-A', 'setup-0.0.8.zip', 'release/setup-0.0.8.zip', '88.1 MB', '10-16 09:02', false],
     ['LOCAL', 'hamsterd.log', 'logs/hamsterd.log', '1.1 MB', '10-17 20:14', false]].forEach(r => {
      const row = mk('div', 'search-row' + (r[5] ? ' selected' : ''));
      const c1 = mk('span', 'sc-sel'); const cb = mk('input'); cb.type = 'checkbox'; cb.className = 'row-sel'; cb.checked = r[5]; c1.appendChild(cb);
      row.appendChild(c1);
      row.appendChild(mk('span', 'sc-dev', r[0]));
      row.appendChild(mk('span', 'sc-name', r[1]));
      row.appendChild(mk('span', 'sc-path', r[2]));
      row.appendChild(mk('span', 'sc-size', r[3]));
      row.appendChild(mk('span', 'sc-date', r[4]));
      const act = mk('span', 'sc-act');
      act.appendChild(mk('button', 'dl-btn', '⇩'));
      act.appendChild(mk('button', 'dl-btn', '➜'));
      row.appendChild(act);
      body.appendChild(row);
    });
    const more = mk('button', 'load-more', '加载更多（还有 8,120 条）');
    body.appendChild(more);
    res.appendChild(body);
  }

  // 设备卡片
  const grid = q('#deviceGrid');
  if (grid) {
    grid.innerHTML = '';
    [['LOCAL', '127.0.0.1:9100', true, '12,483 文件 · 4.7 GB'],
     ['NAS-A', '192.168.1.20:9100', false, '离线 · 最近 20:11']].forEach(r => {
      const card = mk('div', 'device-card');
      const sel = mk('label', 'card-sel'); const cb = mk('input'); cb.type = 'checkbox'; cb.className = 'dev-sel'; sel.appendChild(cb); sel.appendChild(document.createTextNode('选择'));
      card.appendChild(sel);
      const nm = mk('div'); nm.appendChild(mk('span', 'name', r[0]));
      nm.appendChild(mk('span', 'status ' + (r[2] ? 'online' : 'offline'), r[2] ? '在线' : '离线'));
      card.appendChild(nm);
      card.appendChild(mk('div', 'info', r[1] + ' · ' + r[3]));
      const acts = mk('div', 'actions');
      [['btn-refresh-dev', '刷新'], ['btn-rescan-dev', '重扫'], ['btn-sync-dev', '同步库'], ['btn-del', '删除']].forEach(b => acts.appendChild(mk('button', b[0], b[1])));
      card.appendChild(acts);
      grid.appendChild(card);
    });
  }

  // 校验页表格行
  const secBody = q('#secDevBody');
  if (secBody) {
    secBody.innerHTML = '';
    [['LOCAL', '12,483', '27', '6', '4320', '0', '0', '2026-10-17 20:10', '2026-10-17 20:14', false],
     ['NAS-A', '3,363', '11', '2', '4320', '2', '1', '2026-10-16 09:00', '2026-10-16 09:05', true]].forEach(r => {
      const row = mk('div', 'sec-dev-row' + (r[9] ? ' sec-dev-offline' : ''));
      ['sdev-name', 'sdev-files', 'sdev-count', 'sdev-scan', 'sdev-interval', 'sdev-damage', 'sdev-missing', 'sdev-lastverify', 'sdev-lastscan']
        .forEach((c, i) => row.appendChild(mk('span', c, r[i])));
      secBody.appendChild(row);
    });
  }

  // 迁移：目录内容 + 任务 + 历史
  const fl = q('#migSrcList');
  if (fl) {
    fl.innerHTML = '';
    [['📁', 'docs', '', '', true], ['📁', 'release', '', '', true], ['📄', 'readme.md', '4.2 KB', '10-17 20:11', false], ['📄', 'setup-0.0.8.zip', '88.1 MB', '10-16 09:02', false]].forEach(r => {
      const row = mk('div', 'file-row' + (r[4] ? ' is-dir' : ''));
      const c = mk('span', 'fr-sel'); const cb = mk('input'); cb.type = 'checkbox'; cb.className = 'fr-chk'; c.appendChild(cb); row.appendChild(c);
      row.appendChild(mk('span', 'fr-icon', r[0]));
      row.appendChild(mk('span', 'fr-name', r[1]));
      row.appendChild(mk('span', 'fr-size', r[2]));
      row.appendChild(mk('span', 'fr-time', r[3]));
      fl.appendChild(row);
    });
  }
  const prog = q('#migProgress');
  if (prog) {
    prog.innerHTML = '';
    [['ok', 'readme.md', '/docs → /backup', '2.4 MB · 已删源'], ['running', 'setup-0.0.8.zip', '/release → /backup', '传输中 62%'],
     ['error', 'big.iso', '/iso → /backup', 'exists：目标已存在'], ['skip', 'draft.txt', '/docs → /backup', '源文件不存在']].forEach(r => {
      const j = mk('div', 'mig-job'); j.dataset.state = r[0];
      j.appendChild(mk('span', 'mj-state', { ok: '成功', running: '迁移中', error: '失败', skip: '已跳过' }[r[0]]));
      j.appendChild(mk('span', 'mj-name', r[1]));
      j.appendChild(mk('span', 'mj-path', r[2]));
      j.appendChild(mk('span', 'mj-note', r[3]));
      prog.appendChild(j);
    });
  }
  const hist = q('#migHistory');
  if (hist) {
    hist.innerHTML = '';
    [['2026-10-17 20:12', 'move', true, 'LOCAL:/docs/a.md → NAS-A:/backup', '2.4 MB'],
     ['2026-10-17 19:58', 'copy', false, 'NAS-A:/iso/big.iso → LOCAL:/iso', '4.1 GB']].forEach(r => {
      const row = mk('div', 'hist-row');
      row.appendChild(mk('span', 'h-time', r[0]));
      row.appendChild(mk('span', 'h-mode', r[1]));
      row.appendChild(mk('span', 'h-ok ' + (r[2] ? 'ok' : 'bad'), r[2] ? '成功' : '失败'));
      row.appendChild(mk('span', 'h-path', r[3]));
      row.appendChild(mk('span', 'h-size', r[4]));
      hist.appendChild(row);
    });
  }

  // 事件日志 + 连接健康
  const log = q('#eventLogContainer');
  if (log) {
    log.innerHTML = '';
    [['20:14:02', 'file_added docs/2026/季度报告.pdf', ''],
     ['20:14:07', 'file_changed logs/hamsterd.log', '×3'],
     ['20:14:11', 'file_removed tmp/draft.txt', '']].forEach(r => {
      const e = mk('div', 'event-log-entry');
      e.appendChild(mk('span', 'el-time', r[0]));
      e.appendChild(mk('span', 'el-msg', r[1]));
      const c = mk('span', 'el-count', r[2]); if (!r[2]) c.hidden = true; e.appendChild(c);
      log.appendChild(e);
    });
  }
  const ch = q('#connHealth');
  if (ch) {
    ch.innerHTML = '';
    [['LOCAL', '2 秒前', '活跃', 'st-ok'], ['NAS-A', '4 分 12 秒前', '长时间无事件，可能空闲或半开', 'st-warn']].forEach(r => {
      const it = mk('div', 'ch-item ' + r[3]);
      it.appendChild(mk('span', 'ch-dot'));
      it.appendChild(mk('span', 'ch-name', r[0]));
      it.appendChild(mk('span', 'ch-age', r[1]));
      it.appendChild(mk('span', 'ch-note', r[2]));
      ch.appendChild(it);
    });
  }

  // 消息条与批量结果
  const cm = q('#ctrlMsg'); if (cm) cm.appendChild(mk('div', 'msg success', '已向 LOCAL 发送 rescan，设备已接受'));
  const dm = q('#dashboardDevList');
  const bm = q('#searchBulkResults');
  if (bm) {
    bm.hidden = false; bm.innerHTML = '';
    [['ok', 'LOCAL', 'docs/a.md → D:\\Downloads\\a.md'], ['err', 'NAS-A', 'exists：目标已存在，勾选“覆盖”后重试']].forEach(r => {
      const it = mk('div', 'bulk-item ' + r[0]);
      it.appendChild(mk('span', 'bi-state', r[0] === 'ok' ? '✔ 成功' : '✖ 失败'));
      it.appendChild(mk('span', '', r[1] + '：'));
      it.appendChild(mk('span', 'bi-path', r[2]));
      bm.appendChild(it);
    });
  }
  const sm = q('#searchStatus'); if (sm) sm.appendChild(mk('div', 'msg error', '设备 NAS-A 未响应（timeout）：已到达的结果不受影响'));
  const em = q('#eventChannelState'); if (em) { em.className = 'ev-state on'; em.textContent = '事件通道：已连接'; }
  const note = q('#secDataNote'); if (note) note.textContent = '未响应设备：NAS-A（部分字段显示为 —）';

  // 局域网发现面板（PROTOCOL §7）：展开并塞两条样例，用于看排版
  const dp = document.getElementById('discPanel');
  if (dp) {
    dp.hidden = false;
    if (typeof renderDiscover === 'function') {
      renderDiscover([
        { id: '5f2c1a9b7d3e4f60', ip: '192.168.1.24', name: 'NAS-A', port: 9100, ver: '0.0.8', age_ms: 240, addr: '192.168.1.24:9100' },
        { id: '0a1b2c3d4e5f6071', ip: '192.168.1.57', name: 'workstation-02', port: 9100, ver: '0.0.8', age_ms: 1180, addr: '192.168.1.57:9100' },
        { id: '778899aabbccddee', ip: '192.168.1.99', name: 'lab-pi', port: 9200, ver: '0.0.8', age_ms: 2400, addr: '192.168.1.99:9200' },
      ]);
    }
  }
})();
`;

app.whenReady().then(async () => {
  const win = new BrowserWindow({
    width: W, height: H, show: false, backgroundColor: '#f0f0f0',
    webPreferences: { contextIsolation: true, nodeIntegration: false }
  });

  await win.loadFile(htmlPath);
  await new Promise(r => setTimeout(r, 1500));   // 等渲染层的初始化与（失败的）网络探测跑完

  fs.mkdirSync(outDir, { recursive: true });
  const shots = [];
  let stubbed = false;
  /* 单页模式：页面没有侧栏导航时只拍一张（用于字形表之类的独立页面） */
  const hasNav = await win.webContents.executeJavaScript("!!document.querySelector('#sidebar li[data-page]')", true);
  if (!hasNav) {
    const one = await win.webContents.capturePage();
    fs.writeFileSync(path.join(outDir, 'ui-single.png'), one.toPNG());
    console.log('shots  :\n  ui-single.png ' + JSON.stringify(one.getSize()) + '  (单页模式)');
    app.quit();
    return;
  }
  for (const p of PAGES) {
    const switched = await win.webContents.executeJavaScript(`
      (function(){
        const li = document.querySelector('#sidebar li[data-page="${p}"]');
        if (!li) return false;
        li.click();
        return true;
      })()`, true);
    if (!switched) continue;
    await new Promise(r => setTimeout(r, 400));
    // 必须先切页再注入：渲染层切页时会重建该页内容，先注入会被覆盖掉
    try { await win.webContents.executeJavaScript(STUB, true); stubbed = true; }
    catch (e) { console.error('[warn] 示例数据注入失败：', e.message); }
    /* 页面 enter() 里可能还有异步失败回调会再渲染一次（例如 dev.list 不可用时的错误框），
       把注入做两遍并等一帧，截图才是"填好数据的"稳定状态 */
    await new Promise(r => setTimeout(r, 200));
    try { await win.webContents.executeJavaScript(STUB, true); } catch (_) {}
    await new Promise(r => setTimeout(r, 200));
    /* 隐藏窗口不会自动提交新帧：不 invalidate 时 capturePage 可能拿到注入前的旧帧
       （表现为"DOM 里明明有内容，截图却是空的/旧的"）。这里强制要一帧再等两帧。 */
    win.webContents.invalidate();
    await win.webContents.executeJavaScript(
      'new Promise(r => requestAnimationFrame(() => requestAnimationFrame(() => r(true))))', true);
    /* 最后一次注入必须紧贴截图：页面 enter() 的异步失败回调可能在注入之后才渲染错误框 */
    try { await win.webContents.executeJavaScript(STUB, true); } catch (_) {}
    win.webContents.invalidate();
    await win.webContents.executeJavaScript('new Promise(r => requestAnimationFrame(() => requestAnimationFrame(() => r(true))))', true);
    await new Promise(r => setTimeout(r, 120));
    await new Promise(r => setTimeout(r, 150));
    // 顺带核对导航状态：同一时刻只应有一个导航项处于 active
    const navState = await win.webContents.executeJavaScript(`
      Array.prototype.map.call(document.querySelectorAll('#sidebar li'), li => ({
        page: li.dataset.page,
        active: li.classList.contains('active')
      })).filter(x => x.active).map(x => x.page)`, true);
    const img = await win.webContents.capturePage();
    const file = path.join(outDir, 'ui-' + p + '.png');
    fs.writeFileSync(file, img.toPNG());
    shots.push('ui-' + p + '.png ' + JSON.stringify(img.getSize()) + '  导航 active=[' + navState.join(',') + ']');
  }

  // 窄窗口：核对响应式规则
  win.setSize(900, 640);
  await new Promise(r => setTimeout(r, 400));
  const img2 = await win.webContents.capturePage();
  fs.writeFileSync(path.join(outDir, 'ui-900x640.png'), img2.toPNG());

  console.log('html   : ' + htmlPath);
  console.log('stubbed: ' + stubbed);
  console.log('shots  :');
  shots.forEach(s => console.log('  ' + s));
  console.log('  ui-900x640.png ' + JSON.stringify(img2.getSize()));
  app.quit();
}).catch(e => { console.error('FAILED: ' + (e && e.stack || e)); app.exit(1); });
