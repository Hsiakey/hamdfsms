/*
 * WSL / Linux 版主进程入口 —— 与 Windows 版**共用同一份实现**，消除两份分叉。
 *
 * 做法：
 *   1) 先把 HAMSTER_UI_DIR 指向本目录，让共用的主进程加载本目录的 _html/_js/_css；
 *   2) 再 require Windows 版的主进程实现（协议、IPC、生命周期、迁移编排全在那里）；
 *   3) 平台差异全部下沉到实现内部的 process.platform 判断
 *      （代理可执行文件名 hamster_manager.exe / hamster_manager、app.getPath 等）。
 *
 * 注意：preload 只有一份（module/hamster_manager_ui/preload/preload.js），
 * 由共用实现固定加载，因此两平台的 IPC 契约不可能分叉。
 * 同时 devices/、hamster_manager.conf、userData 也随之统一到 "Hamster Manager" 一处，
 * 不再出现"两个平台各写一份 devices.json"的问题。
 */

'use strict';

const path = require('path');

process.env.HAMSTER_UI_DIR = path.join(__dirname, '..');

require(path.join(__dirname, '..', '..', 'hamster_manager_ui', 'main', 'index.js'));
