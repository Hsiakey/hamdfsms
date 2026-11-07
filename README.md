# 🐹 Hamster — 文件监控与跨设备文件管理 ver.0.0.8

> 纯 C 守护进程 + Electron 界面。轻量级文件索引、局域网发现、跨设备文件迁移。
>
> **0.0.8 是一次安全与协议重构**：认证真正生效、二进制传输改为显式分帧、
> 路径访问收敛到监控根目录白名单、修复了 Linux 下的自死锁与"边写边校验"的自激循环。
> 升级前请阅读「[升级须知](#升级须知007--008)」。

---

## 一、架构总览

```
┌──────────────────────────────────────────────┐
│  Electron 主进程 (module/hamster_manager_ui) │
│   · 探测 :9102；没有代理时自己 spawn 代理     │
│   · 协议客户端：hamster-client.js（纯 Node）  │
│   · 迁移编排 / 流式落盘 / 原子写设备表        │
└───────────────┬──────────────────────────────┘
                │ IPC :9102（JSON 行协议）
┌───────────────▼──────────────────────────────┐
│  hamster_manager.exe（C，Electron 网络层）     │
│   · 内部连接 :9100，做心跳与重连（退避）       │
│   · 事件/响应转发，I/O 不在锁内               │
│   · 也可作启动器：无参数时自己拉起 Electron    │
└───────────────┬──────────────────────────────┘
                │ TCP :9100（JSON 行 + 二进制分帧）
┌───────────────▼──────────────────────────────┐
│  hamsterd.exe（C 守护进程）                   │
│   · 目录监控（ReadDirectoryChangesW/inotify） │
│   · SQLite 索引 + 检索 + 完整性校验           │
│   · 认证、路径白名单、下载/上传/迁移原语       │
│   · UDP 发现应答（对上暗号才回应）            │
└──────────────────────────────────────────────┘
```

**注意父子关系**：默认由 `hamster_manager.exe` 拉起 Electron 并等待它退出；
但当用户直接 `npx electron .` 时，Electron 会探测 :9102，发现没有代理就自己
`spawn` 一个 `hamster_manager.exe --proxy-only` 并在退出时回收。
两条启动路径行为一致（0.0.7 时开发模式完全绕过代理，是个长期被忽视的坑）。

端口分配：

| 端口 | 协议 | 用途 |
|---|---|---|
| 9100 | TCP | hamsterd 唯一数据端口（事件 + 命令 + 文件传输） |
| 9102 | TCP | 本机 IPC：Electron ↔ hamster_manager |
| 9110 | UDP | 局域网发现：客户端广播探测，服务端对上暗号才回应（可关闭） |

---

## 二、目录结构

```
Hamster/
├─ Hamsterd/                    守护进程
│  ├─ hamsterd.c                配置、监控线程、重扫/校验、CLI、生命周期
│  ├─ hd_util.c/.h              平台适配、日志、路径安全、文件与哈希
│  ├─ hd_db.c/.h                SQLite 索引、检索、校验记录、API 密钥
│  ├─ hd_net.c/.h               协议实现（认证、命令、传输、事件广播）
│  ├─ hd_crypto.c/.h            SHA-256 / HMAC-SHA256 / 十六进制（发现协议与后续加密的底座）
│  ├─ hd_disc.c/.h              局域网发现：探测帧构造/校验、限速、重放窗口
│  ├─ jsonx.c/.h                严格 JSON 子集工具（替代 strstr 手抠）
│  ├─ xxhash.c/.h               xxHash3-128
│  ├─ hamsterd.conf             本机配置（含口令，已被 .gitignore 忽略）
│  └─ hamsterd.conf.example     配置模板（可入库）
├─ Hamster Manager/             Electron 网络层 / 启动器
│  ├─ hamster_manager.c
│  ├─ hamster_manager.conf(.example)
│  ├─ devices/devices.json      设备注册表（运行时数据，已被忽略）
│  └─ module/
│     ├─ shared/                协议客户端与共享渲染层（单一源码）
│     ├─ hamster_manager_ui/    Windows 界面（main/index.js + package.json）
│     ├─ hamster_manager_ui_wsl/ WSL 界面（与上面共用渲染层）
│     └─ electron/dist/         Electron 运行时（由 npm 安装，不入库）
├─ tests/
│  ├─ test_jsonx.c              JSON 与路径安全单元测试（87 项）
│  ├─ integration.ps1           守护进程协议端到端测试（56 项）
│  ├─ proxy.ps1                 C 代理端到端测试（11 项）
│  ├─ test_crypto.c             SHA-256/HMAC 官方向量（19 项）
│  ├─ test_disc.c               发现协议帧构造/校验（76 项）
│  ├─ discovery.js              发现协议端到端：静默丢弃/重放/限速（30 项）
│  ├─ aead-js.js                传输加密（§8）：KAT/记录层/握手（84 项）
│  ├─ test_sec.c                传输加密（§8）C 侧：跨语言向量（54 项）
│  ├─ sec-live.js               §8 端到端互通：C 守护进程 ⇄ JS 客户端（23 项）
│  └─ client-protocol.js        Node 协议客户端与迁移测试
├─ PROTOCOL.md                  ★ 协议与 IPC 契约（实现方必读）
├─ Makefile
└─ README.md
```

---

## 三、构建

### Windows（MinGW-w64）

```bash
mingw32-make                    # 编译全部（先做依赖探测）
mingw32-make test               # 单元测试
mingw32-make clean              # 删除编译产物
mingw32-make info               # 查看工具链与探测结果
```

依赖：MinGW-w64 + `sqlite3.h` / `libsqlite3.a`（放在 `<MinGW>/opt/include` 与 `<MinGW>/opt/lib`）。

若自动探测失败：

```bash
mingw32-make MINGW_HOME=C:/Users/you/bine/mingw64
# 或把 MINGW_HOME 写进 Makefile.local（该文件已被忽略）
```

`make` 失败时不会让你去猜：`[deps]` 行会直接说明是找不到 sqlite3 还是路径没探测到。

### Linux

```bash
make OS=linux                   # 需要 libsqlite3-dev
```

inotify 监控、pthread 互斥量、`getrandom` 均已实现；但**尚未在真实 Linux 上跑过**
（见「已知问题」），请当作实验性支持。

### 界面

```bash
cd "Hamster Manager/module/hamster_manager_ui"
npm ci                          # 按 package.json 固定版本安装 Electron
npm start                       # 开发模式（Electron 会自己拉起代理）
```

---

## 四、配置

### Hamsterd/hamsterd.conf

| 键 | 默认 | 说明 |
|---|---|---|
| `monitor_path` | 程序目录 | 监控根目录。**不存在则拒绝启动**（避免静默扫错地方） |
| `ipv4_addr` | `127.0.0.1` | 监听地址。改 `0.0.0.0` 会暴露到局域网 |
| `ipv4_addr_port` | `9100` | 端口 |
| `codeword` | 自动生成 | 连接口令。留空则用 CSPRNG 生成强口令并写回 |
| `require_auth` | `on` | 数据命令是否必须认证 |
| `allow_loopback_noauth` | `off` | 回环免认证（仅调试） |
| `encrypt_transport` | `off` | §8 传输加密；`on`=每条连接先握手、之后全程密文（迁移期，0.0.9 默认开） |
| `max_transfer_mb` | `8192` | 单次传输上限 |
| `max_clients` | `16` | 并发连接上限 |
| `rescan_date` | `0,0,30` | 定时全量重扫 `天,小时,分钟`；`0,0,0`=禁用 |
| `verify_interval` | `4320` | 完整性校验周期（分钟，0=禁用） |
| `prune_missing` | `off` | 校验时是否删除已消失文件的记录 |
| `discovery_port` | `9110` | UDP 发现端口（0=禁用） |
| `discovery_respond` | `on` | 是否回应探测（off=收得到但不回应） |
| `heartbeat_time` | `3` | 心跳间隔（秒） |
| `log_level` | `info` | `error`/`warn`/`info`/`debug` |
| `log_dir` | `logs` | 日志目录（自动排除在监控之外，防止事件自激） |
| `exclude_internal` | `on` | 排除自身日志与数据库 |

### Hamster Manager/hamster_manager.conf

| 键 | 说明 |
|---|---|
| `hamd_port` | hamsterd 端口 |
| `ipc_port` | 代理监听端口（Electron 连它） |
| `hamd_codeword` | 口令；**留空会自动去读 `../Hamsterd/hamsterd.conf`** |
| `hamd_discovery_port` | UDP 发现端口；必须与 hamsterd 的 `discovery_port` 一致（0=本机不广播） |
| `heartbeat_time` | 心跳间隔（秒） |

---

## 五、协议

完整契约见 **[PROTOCOL.md](PROTOCOL.md)**。要点：

* 控制消息：一行一个 JSON 对象（`request` / `response` / `event`）。
* **二进制负载显式分帧**：消息头带 `payload_bytes: N`，随后恰好 N 字节裸数据。
  接收方必须精确读满 N 字节并校验，不再靠"猜边界"——这是 0.0.7 下载损坏的根因。
* 下载头里的 `hash` 是服务端对**实际发送字节**计算的 xxHash3-128，
  因此"源端下载 → 目标端上传"可以做到端到端内容一致校验，客户端无需自己实现哈希。
* 除 `hello` / `ping` / `info` 外所有命令都要求认证；失败返回稳定错误码。
* 所有文件操作路径都必须落在 `monitor_path` 之内，越权返回 `path_denied`。
* **局域网发现（§7）**：客户端每 1s 广播一条探测帧，服务端用 `HMAC-SHA256(codeword, ·)`
  校验；对不上、重放、超速一律**静默丢弃**（一个字节都不回），因此网内扫描者无法枚举设备。
  服务端不再广播信标，也不再维护 peer 表。

命令行自测（不带口令应当被拒）：

```bash
echo '{"type":"request","id":"t1","action":"ping","params":{}}' | ncat 127.0.0.1 9100
echo '{"type":"request","id":"t2","action":"stats","params":{}}' | ncat 127.0.0.1 9100
# → {"status":"error","data":{"error":"unauthenticated"}}
```

---

## 六、数据模型

```sql
file_in(xxHash3_128, file_name, file_path PK, file_type, file_sizeBy, change_dateT, file_readme)
file_total(id=1, total_file_num, total_sizeByte, total_type_num, last_update)
file_verify(id=1, verified_files, verify_count, scan_count, scan_interval,
            corrupt_count, missing_count, last_verify, last_scan, last_duration_ms)
api_keys(key_id, api_key UNIQUE, label, created, enabled)
```

* `journal_mode=WAL`，发送数据库前会先做 `TRUNCATE` checkpoint（否则发出去的是缺数据的库）。
* `file_verify` 的 `corrupt_count` / `missing_count` / `scan_interval` 现在会真正写入，
  界面上的"损坏数/校验周期"不再是恒为 0 的假数据。

---

## 七、使用

### 守护进程

```bash
hamsterd start               # 后台启动
hamsterd --console-log       # 前台运行（日志同时打到控制台）
hamsterd stop                # 平滑停止
hamsterd restart             # 重启
hamsterd status              # 运行状态
hamsterd rotate-codeword     # 重新生成连接口令并写回配置
hamsterd reset database      # 重置索引库（需先停止）
hamsterd reset config        # 删除配置（下次启动重建）
```

调试期可临时覆盖：`--port=` `--bind=` `--monitor=` `--auth=on|off` `--level=debug`。

### 代理

```bash
hamster_manager.exe                          # 启动代理并拉起 Electron（双击行为）
hamster_manager.exe --proxy-only             # 只做代理（由 Electron spawn）
hamster_manager.exe --proxy-only --follow-stdin   # 父进程退出后自动退出
hamster_manager.exe --ipc-port=9202 --hamd-port=9200
```

### 测试

```bash
mingw32-make test                                        # 单元 87 + 密码学 19 + 发现 76 + AEAD 41 + 加密 54
pwsh -File tests/integration.ps1                         # 守护进程协议（56 项；用 pwsh 7，PS 5.1 会误判 UTF-8 中文）
pwsh -File tests/proxy.ps1                               # C 代理（11 项）
node tests/discovery.js                                  # 局域网发现端到端（30 项）
node tests/aead-js.js                                    # 传输加密 §8 的 JS 侧（84 项）
node tests/sec-live.js                                   # §8 端到端互通（23 项；会独占 hamsterd 单实例）
node tests/client-protocol.js                            # Node 客户端与迁移
electron tests/ui-shot.js                                # 离屏逐页截图（无 GUI 也能核对界面）
```

所有测试都在 `tests/tmp/` 下自建隔离环境（独立端口、独立监控目录），
跑完自动清理，不会碰你正在运行的 hamsterd。

---

## 八、0.0.8 变更

### 安全

* **认证真正生效**：0.0.7 的 `authenticated` 标志只用于广播，`search`/`download`/`stats`
  等命令**完全不需要口令**；现在除 `hello`/`ping`/`info` 外一律要求认证。
* **口令不可预测**：旧版"自动生成"的口令用的是未播种的 `rand()`，同一平台每次生成都一样；
  现在用 CSPRNG，且日志与界面不再回显口令明文。
* **路径白名单**：`download` 曾可读取任意绝对路径；现在所有文件操作都必须落在
  `monitor_path` 之内，`..`、盘符、UNC、ADS、控制字符一律拒绝。
* **默认只监听本机**：`ipv4_addr` 默认从 `0.0.0.0` 改为 `127.0.0.1`。
* **API 密钥**：`api_keys` 表原先从未被使用，现在支持 `key:add`/`key:list`/`key:revoke`，
  `hello` 可用 `api_key` 免口令认证，密钥只在创建时回显一次。
* 代理改用 `SO_EXCLUSIVEADDRUSE` + 单实例互斥，避免端口劫持。
* 认证失败会按退避重试**并重新读取配置**（旧版会永久停止重连，改好口令也必须重启）。

### 协议与数据完整性

* 二进制负载改为 `payload_bytes` 显式分帧（旧版把二进制当 UTF-8 字符串处理，
  首包必然损坏，且截断后仍报成功）。
* 下载头新增权威 `hash`；上传在写入过程中校验哈希，不一致则删除半成品。
* `sync-database` 发送前先 checkpoint（旧版发出的是缺数据的库：主库 108KB / WAL 4MB）。
* 新增 `upload` / `list` / `mkdir` / `delete` / `key:*` / `info`；`search` 支持分页与排序白名单。
* 常量时间的口令比较；错误响应有稳定错误码，客户端不再靠超时感知失败。

### 质量与稳定性

* **修复 Linux/WSL 自死锁**：`g_db_mutex` 在 POSIX 下不可重入却有 4 条嵌套加锁路径
  （Windows 的 `CreateMutex` 可重入掩盖了它）。
* **修复事件自激循环**：守护进程原本在监控自己的日志，实测 170,932 行日志里
  168,595 行是该循环产生的；现在日志/数据库自动排除，并支持日志轮转。
* 修复 `search` 拼接的栈越界写、配置文件重写的越界写、`FILE_NOTIFY_INFORMATION`
  遍历不受 `bytes` 约束、重叠 I/O 的 `lpBytesReturned` 悬垂、`CancelIo` 后立即 `free`。
* 退出流程真正收尾：停止所有线程 → join → checkpoint → 关闭数据库（旧版会带着
  运行中的校验线程关库）。
* 看门狗改为监测"监控线程心跳"，不再把"目录没变化"误判为卡死而反复触发全量校验。
* `rescan` 现在真的重扫目录（旧版只做完整性校验，索引长期偏离文件系统）。
* WSAStartup 提前到任何网络线程之前（旧版顺序错误导致 UDP 发现从未工作）。
* 手写 JSON 解析换成严格解析器；`snprintf` 返回值不再被当作已写入长度。
* 32 位 `long` 换成 64 位文件大小，>2GB 文件不再溢出。
* 崩溃点：`resp_ok` 的固定缓冲会截断大响应（search/stats），现改为分段发送。

### 功能

* **文件迁移**（原为 UI 占位、后端未实现）：客户端编排"源下载 → 校验 → 目标上传 →
  端到端哈希比对 → 可选删除源"，支持复制/移动、冲突保护、迁移日志。
* 批量操作：批量搜索、批量下载、批量迁移、批量校验。
* 局域网发现改为「客户端广播探测、服务端对上暗号才单播应答」（PROTOCOL §7）：
  网内扫描者看不到任何东西，只有持有同一 codeword 的客户端才收得到应答；
  服务端不再维护 peer 表（`stats.peers` 恒为 `[]`），设备页「扫描局域网」一键加入。
* 界面：整体改为 **Windows 10 (Fluent) 风格**——Segoe UI、窗口底 #f0f0f0、强调色 #0078d7、方角与 1px 描边、浅色标题栏与 #e81123 关闭键、Segoe MDL2 标题栏图标、Win10 细滚动条；XSS 修复（sc() 漏转义引号却用于属性上下文）、错误态与重试、
  搜索序号守卫、校验页不再伪造数据、可访问性与对比度整改、CSS 死代码清理。

### 工程

* Makefile 重写：修复含空格路径导致 `manager` 从来编译不了、`clean` 删不掉文件、
  `MINGW_HOME` 探测漏掉真实安装路径、recipe 混入中文导致引号错乱等问题。
* 新增 `.gitignore`：不再把 251MB Electron 运行时、11MB 日志、数据库、编译产物与
  明文口令纳入版本管理。
* 源码从单文件 1535 行拆成 5 个模块；新增三套测试（单元 87 / 协议 56 / 代理 11 项）。
* 版本号、README、配置模板与实际实现对齐。

---

## 九、升级须知（0.0.7 → 0.0.8）

1. **协议不兼容**：请同时更新 `hamsterd.exe`、`hamster_manager.exe` 与界面代码。
   旧客户端对新守护进程只能执行 `hello`/`ping`/`info`。
2. **口令更换**：旧口令用可预测的 `rand()` 生成且明文散落在多个文件里，
   建议执行 `hamsterd rotate-codeword` 轮换，并同步 `hamster_manager.conf`。
3. **默认监听地址收紧**：若你原来依赖 `0.0.0.0` 让其它机器连接，需要显式改回，
   并确认口令强度（此后口令是唯一防线）。
4. **`monitor_path` 必须存在**，否则守护进程拒绝启动。
5. 首次启动会做一次全量重扫（索引与旧版结构兼容，会补 `missing_count` 等新列）。

---

## 十、已知问题

* [ ] **Linux/macOS 未做真机验证**：inotify 监控、pthread 互斥量、`getrandom` 已实现，
      但只在 Windows 上验证过行为；`make OS=linux` 能编译不代表运行时无坑。
* [ ] **文件迁移是"下载再上传"**：跨设备时数据要经过管理机中转，大文件耗时较长；
      尚未实现直连（A→B）与断点续传。
* [ ] **界面无自动化测试**：渲染层只有语法检查与人工核对，没有 DOM 级测试。
* [ ] **`hamsterd.log` 历史文件**：仓库里仍有一份 0.0.7 时期因自激循环产生的 11MB 日志，
      保留仅供对照，可直接删除。
* [ ] 旧版源码（`Hamster/hamster.c`、`Hamster Server/`）与 `README.docx` 仍在旧版本目录中，
      当前副本已不再包含。

## 十一、TODO

### P1
- [ ] 迁移支持直连与断点续传（需要守护进程之间建立数据通道）
- [ ] 渲染层引入 DOM 级测试（jsdom 或 Playwright）
- [ ] Linux 真机验证与 CI

### P2
- [ ] 事件推送改为按需订阅（现在所有认证连接都收全部事件）
- [ ] 索引支持增量持久化校验结果，避免每次全量重算
- [ ] 界面支持多语言

### P3
- [ ] 迁移任务可暂停/恢复
- [ ] 打包发布（electron-builder + 版本号单一来源）

---

## 十二、版本历史

| 版本 | 日期 | 概述 |
|------|------|------|
| **ver.0.0.8** | 2026-10-17 | 安全与协议重构：认证生效、路径白名单、二进制分帧、端到端哈希校验；修复 Linux 自死锁、事件自激、栈越界、退出竞态；新增文件迁移/批量操作/API 密钥；
局域网发现重构为「客户端广播 + 服务端 HMAC 应答 + 静默丢弃」（§7）；界面改为 Windows 10 Fluent 风格；五套自动化测试（单元 87 / 密码学 19 / 发现 76+30 / 协议 56 / 代理 11 / 并发 4 / 客户端 155） |
| ver.0.0.7 | 2026-05-31 | 搜索过滤增强、下载按设备 ID 匹配、UPSERT 参数绑定重构 |
| ver.0.0.6 | 2026-05-23 | Linux/WSL 试验分支 |
| ver.0.0.5 | 2026-05-13 | 10 个 Critical Bug 修复，事件系统重写，下载修复 |
| ver.0.0.4 | 2026-05-12 | 事件系统首版，Electron UI 集成，设备管理 |
| ver.0.0.3 | 2026-05-11 | 统一 TCP 协议（:9100），废弃 HTTP |
| ver.0.0.2 | 2026-05-10 | 文件监控 + HTTP 服务分离，SQLite 集成 |
| ver.0.0.1 | 2026-05-09 | 初始原型，仅文件监控 |

---

*该文档最后更新于 2026-10-17 (ver.0.0.8)*
*维护者：空门蓝 (@Sorakado_Ai)*


---

## 许可证

[MIT](LICENSE) —— 可商用、可修改、可闭源分发，只需保留版权声明。

项目本身用到的第三方组件各自保留原许可证：

| 组件 | 许可证 | 说明 |
|---|---|---|
| Electron 28 | MIT | 界面运行时 |
| SQLite | Public Domain | 索引数据库 |
| xxHash | BSD-2-Clause | 文件内容哈希（`Hamsterd/xxhash.*`） |
| MinGW-w64 运行时 | GPL-2.0 WITH GCC Runtime Library Exception | 用 `-static` 链接；该例外允许静态链接而不使本项目受 GPL 约束 |
