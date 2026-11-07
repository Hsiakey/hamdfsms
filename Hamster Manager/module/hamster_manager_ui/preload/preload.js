/*
 * preload — 唯一的渲染层桥（PROTOCOL §6 契约）
 *
 * 约束：
 *   - 只暴露具名方法，绝不暴露 ipcRenderer 本体（保持 contextIsolation 边界）；
 *   - 每个事件订阅返回"取消订阅函数"（旧版没有，重复注册会成倍增长）；
 *   - 返回值形状严格按 PROTOCOL §6：错误一律是 {error, detail?}，不再抛到渲染层。
 *
 * 两套 UI 目录共用这一份 preload（主进程固定加载它），IPC 契约因此无法分叉。
 */

'use strict';

const { contextBridge, ipcRenderer } = require('electron');

/** 订阅辅助：返回取消订阅函数 */
function subscribe(channel, cb, map) {
  const fn = (_, payload) => {
    try { cb(map ? map(payload) : payload); } catch (e) { console.error('[' + channel + '] 回调异常:', e); }
  };
  ipcRenderer.on(channel, fn);
  return () => ipcRenderer.removeListener(channel, fn);
}

contextBridge.exposeInMainWorld('hamster', {
  /* ================= 设备（§6.1） ================= */
  dev: {
    /** [{id,name,addr,status,note,last_sync,created_at}] —— 不含 token */
    list: () => ipcRenderer.invoke('dev:list'),
    /** 同上，但会并发探测每台设备并刷新 status/last_sync/stats */
    listAll: () => ipcRenderer.invoke('dev:list_all'),
    /** {name,addr,token,note} → "online" | "offline" | {error,detail}；id 由主进程生成 */
    add: (dev) => ipcRenderer.invoke('dev:add', dev),
    remove: (id) => ipcRenderer.invoke('dev:remove', id),
    update: (id, fields) => ipcRenderer.invoke('dev:update', id, fields),
    stats: (id) => ipcRenderer.invoke('dev:stats', id),
    /** (id, params) → {total,limit,offset,files:[{hash,name,path,type,size,modified}]} 或 {error} */
    search: (id, params) => ipcRenderer.invoke('dev:search', id, params),
    /** ([id...], params) → [{id,ok:true,data}|{id,ok:false,error,detail}]，单个失败不影响其它 */
    searchMany: (ids, params) => ipcRenderer.invoke('dev:search_many', ids, params),
    /** (id, path) → {ok:true,saved_path,name,size,hash} 或 {error}；主进程流式落盘，不回传 base64 */
    download: (id, remotePath) => ipcRenderer.invoke('dev:download', id, remotePath),
    /** → {ok:true,path,size} 或 {error} */
    syncDb: (id) => ipcRenderer.invoke('dev:sync_db', id),
    /** 手动同步（stats + 状态刷新） */
    sync: (id) => ipcRenderer.invoke('dev:sync', id),
    verify: (id, params) => ipcRenderer.invoke('dev:verify', id, params),
  },

  /* ================= 文件操作（§6.2） ================= */
  file: {
    /** (id, path, limit, offset) → {path,entries,total,limit,offset} 或 {error} */
    list: (id, p, limit, offset) => ipcRenderer.invoke('file:list', id, p, limit, offset),
    mkdir: (id, p) => ipcRenderer.invoke('file:mkdir', id, p),
    /** 主进程负责补 confirm:true */
    delete: (id, p) => ipcRenderer.invoke('file:delete', id, p),
    /**
     * (id, localPath, remotePath, opts) → {ok:true,path,size,hash} 或 {error}
     * opts: {hash?, overwrite?, mkdir?, base64?}
     */
    upload: (id, localPath, remotePath, opts) => ipcRenderer.invoke('file:upload', id, localPath, remotePath, opts),
  },

  /* ================= 迁移（§6.2） ================= */
  migrate: {
    /**
     * job: {srcId,dstId,srcPath,dstPath,mode:'copy'|'move',overwrite?}
     * → {ok:true,size,hash,saved,removed,log_id} 或 {error,detail}
     */
    run: (job) => ipcRenderer.invoke('migrate:run', job),
    /** [job...] → [{index,ok...}|{index,error,detail}]，并发受控，逐个返回 */
    runMany: (jobs) => ipcRenderer.invoke('migrate:run_many', jobs),
    /** [{id,time,src,dst,path,size,hash,mode,ok,error}]，最近的在前 */
    list: () => ipcRenderer.invoke('migrate:list'),
  },

  /* ================= 局域网发现（§6.1） ================= */
  discover: {
    /** [{id,ip,name,port,age_ms}] */
    list: () => ipcRenderer.invoke('discover:list'),
  },

  /* ================= 控制指令 ================= */
  ctrl: {
    /** action: 'rescan' | 'sync' */
    send: (id, action) => ipcRenderer.invoke('ctrl:send', id, action),
  },

  /* ================= 配置与系统 ================= */
  config: {
    get: () => ipcRenderer.invoke('config:get'),
    /** set({download_dir?, log_level?}) → true；download_dir 会被 config.get().downloads_dir 反映 */
    set: (c) => ipcRenderer.invoke('config:set', c),
  },
  app: {
    getVersion: () => ipcRenderer.invoke('app:version'),
    getPaths: () => ipcRenderer.invoke('app:paths'),
    /**
     * 在文件管理器里定位文件（"打开所在文件夹"）。
     * @returns {{ok:true,path:string}|{ok:false,error:'missing_path'|'not_found',detail?:string}}
     *          文件不存在时只回错误对象，不会抛异常。
     */
    reveal: (p) => ipcRenderer.invoke('app:reveal', p),
    /**
     * 复制文本到系统剪贴板（file:// 下 navigator.clipboard 不可靠）。
     * @returns {{ok:true,length:number}|{ok:false,error:'missing_text'}}
     */
    copyText: (text) => ipcRenderer.invoke('app:copy-text', text),
  },
  getDownloadsDir: () => ipcRenderer.invoke('app:downloads-dir'),
  pickFolder: () => ipcRenderer.invoke('dialog:pick-folder'),

  /* ================= 窗口 ================= */
  window: {
    minimize: () => ipcRenderer.send('window-minimize'),
    maximize: () => ipcRenderer.send('window-maximize'),
    close: () => ipcRenderer.send('window-close'),
    isMaximized: () => ipcRenderer.invoke('window-is-maximized'),
    onMaximizeChange: (cb) => subscribe('window-maximize-change', cb),
  },

  /* ================= 事件（§6.3） =================
     所有订阅都返回取消订阅函数：
       const off = window.hamster.event.onBroadcast(cb);  ... off();
  */
  event: {
    /** cb(event)：event = {event, data, seq, time, device, device_id} */
    onBroadcast: (cb) => subscribe('event:broadcast', cb),
    /** cb({connected:boolean, device:string}) */
    onConnected: (cb) => subscribe('event:connected', cb),
    /** cb({device, device_id, age_ms, connected})：最近一次心跳年龄，用于发现半开连接 */
    onHeartbeat: (cb) => subscribe('event:heartbeat', cb),
    /** 旧通道：设备断开（保留兼容） */
    onDeviceDisconnect: (cb) => subscribe('event:device_disconnect', cb),
    onMessage: (cb) => subscribe('event:message', cb),
  },
});
