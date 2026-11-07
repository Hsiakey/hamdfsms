# Hamster 协议规格 (ver.0.0.8)

本文件是 **hamsterd ↔ 客户端** 与 **Electron 主进程 ↔ 渲染进程** 的接口契约。
任何客户端实现（C 代理、Electron 主进程、测试脚本）都必须遵守本文件。

上一版（0.0.7）的问题：认证形同虚设、二进制负载靠"猜长度"、错误响应无法被识别。
0.0.8 的协议在以下三点上不兼容旧客户端，属**有意破坏性变更**。

---

## 1. 传输层

* 传输：TCP，默认端口 `9100`，默认只监听 `127.0.0.1`。
* 编码：UTF-8。控制消息一行一个 JSON 对象，以 `\n` 结尾。
* 单行上限 `HD_LINE_MAX = 256 KiB`；**二进制负载不计入行长度**（见 §3）。
* 服务端对所有 socket 设置收发超时（20s），空闲超过 240s 的连接被关闭。

> **两条连接，别混为一谈。** 客户端对每台设备维护两条 TCP：
> **命令通道**（一问一答）与**事件通道**（长连接，只收事件）。
> 服务端会把**空闲 240s 的命令通道**按设计关掉——客户端在下一条命令到达时自动重连即可，
> 这**不代表设备离线**。只有事件通道断开才意味着事件流中断。
> 把命令通道的关闭当成"设备离线/事件通道断开"上报，会得到每 4 分钟一次的假离线，
> 而且界面收到假离线就去刷新 → 立刻又发命令 → 命令通道马上重连 → 4 分钟后再来一次。

### 1.1 消息类型

| type | 方向 | 说明 |
|---|---|---|
| `request` | 客户端 → 服务端 | 命令请求 |
| `response` | 服务端 → 客户端 | 命令结果（`status` 为 `ok` 或 `error`） |
| `event` | 服务端 → 客户端 | 异步事件（文件变更、发现设备等） |

客户端**必须**按 `type` 分流：事件可能与响应交错到达同一条连接。
（服务端已尽量不给"触发事件的连接"回灌它自己的事件，但客户端不能依赖这一点。）

### 1.2 请求

```json
{"type":"request","id":"<string>","action":"<string>","params":{...}}
```

* `id`：客户端自选，服务端在响应里原样回显；用于并发请求配对。
* `params`：可选，缺省视为 `{}`。
* `payload_bytes`：可选，仅上传使用，见 §3。

### 1.3 响应

```json
{"type":"response","id":"<string>","status":"ok","data":{...}}
{"type":"response","id":"<string>","status":"error","data":{"error":"<code>","detail":"<可选>"}}
```

错误码是**稳定的机器可读标识**，客户端应据此决策，不要匹配中文描述。

### 1.4 事件

```json
{"type":"event","event":"<name>","data":{...},"seq":<递增整数>,"time":<unix 秒>}
```

| event | data |
|---|---|
| `file_added` / `file_changed` / `file_removed` | `{path, name, dir}` |
| `scan_done` | `{reason:"full_scan"}` |
| `verify_done` | `{total, ok, corrupt, missing, reason}` |
| `peer_found` | `{id, ip, name, port}` — **0.0.8 起服务端不再发出**，见 §7 |

`seq` 单调递增。客户端若发现 `seq` 跳号，说明中间有事件被丢弃
（例如自己正在传输负载，服务端会跳过给你的事件），应主动重查一次。

---

## 2. 认证

除 `hello` / `ping` / `info` 外，**任何命令都必须先通过认证**，否则返回
`{"status":"error","data":{"error":"unauthenticated"}}`。

### 2.1 hello

```json
{"type":"request","id":"h1","action":"hello","params":{
    "device_id":"<客户端标识>", "hostname":"<显示名>",
    "codeword":"<连接口令>", "api_key":"<可选，与 codeword 二选一>"
}}
```

* `codeword`：`hamsterd.conf` 的 `codeword`。常量时间比较。
* `api_key`：`key:add` 生成的密钥（`hk_` 前缀），存于 `api_keys` 表。
* 二者任一匹配即通过。

成功响应（同时作为服务能力发现）：

```json
{"status":"ok","data":{
  "server":"hamsterd","version":"0.0.8","auth_required":1,
  "monitor_path":"<服务端监控根目录绝对路径>",
  "heartbeat":3,"uptime_ms":123456,"clients":1,"peers":0,
  "features":["search","download","upload","list","mkdir","delete",
              "sync-database","verify","rescan","sync","keys","framing:raw"]
}}
```

失败：返回 `invalid_credential`，延迟 200ms×失败次数（上限 1s）后**关闭连接**。

`peers` 字段在 0.0.8 起恒为 `0`：局域网发现改为客户端主动广播、服务端被动应答（§7），
服务端不再维护 peer 表，也不会再发出 `peer_found` 事件。

### 2.2 ping / info（免认证）

* `ping` → `{"pong":true,"time":<unix>}`：探活，不泄露任何信息。
* `info` → 与 hello 成功响应相同的结构：用于"添加设备"时探测对端是否为 hamsterd。

---

## 3. 二进制负载分帧（framing: raw）

**规则：消息头里若出现 `payload_bytes`（正整数），则紧跟其后是恰好 N 字节裸数据，
接收方必须精确读满 N 字节后才能继续解析下一行。**

发送方（服务端 → 客户端）：

```json
{"type":"response","id":"d1","status":"ok","data":{
  "action":"download","name":"报表.xlsx","path":"<绝对路径>",
  "hash":"<本次实际发送字节的 xxHash3_128，权威值>",
  "index_hash":"<索引中的哈希，仅供对比提示>",
  "size":123456,"payload_bytes":123456,"framing":"raw"}}
<123456 字节裸数据>
```

* 接收方**必须**校验实收字节数 == `payload_bytes`；不等就是失败，不得当作成功。
* `hash` 由服务端在发送前对**实际要发送的字节**计算，是权威值。
  客户端若把它随上传回传给目标端（`upload.hash`），即可获得
  **源端字节 == 目标端落盘字节** 的端到端校验，无需自己实现 xxHash。
* `index_hash` 是索引里的历史哈希，只用于提示"文件在索引之后是否被改动过"。
* 同一规则适用于 `sync-database`：客户端落盘后可用 `hash` 校验。服务端发的是**一致快照**
  （不是活动库文件），快照在发送期间不会再被改写，因此头里的 hash 就是实际字节的权威值。

发送方（客户端 → 服务端）上传同规则：在 request 顶层加 `payload_bytes`。

---

## 4. 命令一览

所有路径参数：既可以是**受控根目录内的相对路径**，也可以是**绝对路径**；
绝对路径同样必须落在 `monitor_path` 之内。任何越权一律返回 `path_denied`。
相对路径中不允许出现 `..`、盘符、UNC、控制字符或 `:`（ADS）。

| action | params | data |
|---|---|---|
| `hello` | 见 §2 | 见 §2 |
| `ping` | – | `{pong,time}` |
| `info` | – | 见 §2 |
| `health` | – | `{status,time,version,uptime_ms,clients,auth_required,monitor_path}` |
| `stats` | – | `{total_files,total_size,file_type_count,last_update,file_types[],monitor_path,peers[],clients}` |
| `search` | `q`,`type`,`size_min`,`size_max`,`limit`(≤1000,默认200),`offset`,`sort` | `{total,limit,offset,files[{hash,name,path,type,size,modified}]}` |
| `verify` | `run`(bool; true=立即执行一次校验) | `{verified_files,verify_count,scan_count,scan_interval,corrupt_count,missing_count,last_duration_ms,last_verify,last_scan}` |
| `rescan` | – | `{status:"rescan_requested"}` |
| `sync` | – | `{status:"sync_requested"}` |
| `list` | `path`(默认根),`limit`,`offset` | `{path,entries[{name,path,dir,size,mtime}],total,limit,offset}` |
| `mkdir` | `path` | `{path}` |
| `delete` | `path`,`confirm`(必须为 true) | `{path}` |
| `download` | `path` | 见 §3 |
| `sync-database` | – | 见 §3（发送前先 WAL checkpoint，再用 SQLite backup 生成**一致快照**，实际发出的是快照） |
| `upload` | `path`,`size`,`hash`(可选),`overwrite`(默认 false),`mkdir`(默认 false) + 顶层 `payload_bytes` | `{path,name,size,hash}` |
| `key:add` | `label` | `{api_key,note}` |
| `key:list` | – | `{keys[{id,label,created,enabled,prefix}]}` |
| `key:revoke` | `id` | `{revoked:true}` |

`sort` 取值：`name` / `size` / `modified` / `type` / `path`，前缀 `-` 表示降序。
服务端只接受白名单列名，其余一律按 `path` 升序——**不会把客户端文本拼进 SQL**。

### 4.1 错误码

| code | 含义 |
|---|---|
| `unauthenticated` | 未认证就调用了受保护命令 |
| `invalid_credential` | hello 的口令/密钥错误（随后断开） |
| `malformed_json` | 行不是合法 JSON 对象 |
| `missing_action` / `unknown_action` / `missing_path` / `missing_id` | 参数问题 |
| `path_denied` | 路径越权或非法 |
| `not_found` / `file_not_found` / `not_a_directory` / `is_directory` | 目标状态不符 |
| `exists` | 已存在且未指定 overwrite |
| `confirm_required` | `delete` 未带 `confirm:true` |
| `too_large` | 超过 `max_transfer_mb` |
| `hash_mismatch` | 上传内容哈希与声明不符（不会留下半成品） |
| `payload_incomplete` | 负载长度不足（连接会被断开） |
| `line_too_long` | 单行超过 256KiB（该行被丢弃，连接仍可用） |
| `response_too_large` | 响应超过 1MiB，请降低 `limit` 或缩小关键词 |
| `remove_failed` / `mkdir_failed` / `rename_failed` / `open_failed` / `write_failed` | 文件系统错误 |
| `dir_not_empty` | 只能删除空目录 |
| `snapshot_failed` | sync-database 无法生成一致快照（库被其它进程锁住）；请重试或关闭占用该库的工具 |

---

## 5. 文件迁移（由客户端编排，协议侧无需新命令）

「迁移」= 源设备下载 + 目标设备上传 + 校验 + 可选删除源文件。
协议已经提供全部原语，客户端按以下顺序执行，**每一步都必须校验**：

```
1. 源: download {path}                     → 收到 payload_bytes 字节 + hash + index_hash
2. 校验 实收字节数 == payload_bytes        → 不符则中止（不留任何东西）
3. 目标: upload {path, size:实收字节数, hash:第 1 步的 hash, mkdir:true, overwrite:false}
   目标端在写入过程中计算哈希并比对；不一致会返回 hash_mismatch 且删除半成品
4. 目标: 校验响应里的 hash == 第 1 步的 hash
5. 仅当 4 通过 且 迁移模式为 move 时：源: delete {path, confirm:true}
6. 记录迁移日志（源/目标/路径/大小/哈希/结果）
```

要点：

* **必须先上传成功再删除源文件**；任何一步失败都要中止并保留源文件。
* `overwrite:false` 时若目标已存在，上传失败并返回 `exists` —— 迁移应把它当作
  "目标已有同名文件"，由用户决定覆盖或改名，不要静默覆盖。
* 迁移到**同一个设备的另一个目录**同样适用（下载后上传，路径不同）。
* 由于下载头里的 `hash` 是服务端对实际发送字节计算的权威值，
  客户端**无需实现 xxHash** 即可完成端到端内容校验；但字节数校验不能省。

---

## 6. Electron 主进程 ↔ 渲染进程（IPC 契约）

主进程通过 `preload.js` 暴露 `window.hamster`。IPC 通道名与返回值如下（渲染进程只依赖这些）。

### 6.1 设备

| 调用 | 返回 |
|---|---|
| `dev.list()` | `[{id,name,addr,status,note,last_sync,created_at}]`（**不含 token**） |
| `dev.listAll()` | 同上，但会并发探测每台设备并刷新 `status`/`last_sync`/`stats` |
| `dev.add({name,addr,token,note})` | `"online"` / `"offline"` / `{error,detail}`；id 由主进程生成 |
| `dev.remove(id)` | `true` / `false` |
| `dev.update(id, fields)` | `true` / `false`；改动 `addr`/`token` 后会重建连接 |
| `dev.stats(id)` | 设备 `stats` 的 data 对象，或 `{error}` |
| `dev.search(id, params)` | `{total,limit,offset,files:[...]}`，或 `{error}` |
| `dev.searchMany([id...], params)` | `[{id, ok, data|error}]`：批量搜索，单个设备失败不影响其它 |
| `dev.verify(id, {run})` | 设备 `verify` 的 data 对象；`run:true` 触发一次真实校验 |
| `ctrl.send(id, action)` | `{status}` 或 `{error}`；`action` 仅允许 `rescan` / `sync` |
| `dev.download(id, path)` | `{ok:true, saved_path, name, size, hash}` 或 `{error}`；**主进程直接落盘**，不再回传 base64 |
| `dev.syncDb(id)` | `{ok:true, path, size}` 或 `{error}` |
| `discover.list()` | `[{id,ip,name,port,ver,age_ms,addr}]`：本进程广播探测得到的服务端（§7.5）。`addr` 可直接喂给 `dev.add()` |

### 6.2 文件操作（新增：迁移与批量）

| 调用 | 返回 |
|---|---|
| `file.list(id, path, limit, offset)` | `{path,entries,total,limit,offset}` 或 `{error}` |
| `file.mkdir(id, path)` | `{ok:true,path}` 或 `{error}` |
| `file.delete(id, path)` | `{ok:true,path}` 或 `{error}`（主进程负责补 `confirm:true`） |
| `file.upload(id, localPath, remotePath, opts)` | `{ok:true,path,size,hash}` 或 `{error}` |
| `migrate.run(job)` | 见下 |
| `migrate.list()` | 迁移历史 `[{id,time,src,dst,path,size,hash,mode,ok,error}]` |

`migrate.run(job)` 的 `job`：

```js
{ srcId, dstId,               // 设备 id；srcId === dstId 表示同设备搬移
  srcPath,                    // 源绝对路径（来自 search / list）
  dstPath,                    // 目标相对路径（相对目标设备监控根）
  mode: 'copy' | 'move',      // move 会在校验通过后删除源文件
  overwrite: false }          // 默认 false，冲突时返回 {error:'exists'}
```

返回：`{ok:true, size, hash, saved:true|false, removed:false|true, log_id}` 或 `{error, detail}`。
实现要求：
* 全程必须校验字节数；下载与上传都要校验；
* `move` 模式下，**只有目标端校验通过后**才允许删源；
* 每步都要写迁移日志（成功与失败都写）；
* 大文件必须流式处理（下载落临时文件 → 上传），**不得把整个文件读进内存**。

### 6.3 事件与窗口

| 调用 | 说明 |
|---|---|
| `event.onBroadcast(cb)` | 收到 `file_added/file_changed/file_removed` 等事件；`cb(event)`，`event = {event, data, seq, time}` |
| `event.onConnected(cb)` | `cb({connected:boolean, device:string, kind:'event'})`：**只反映事件通道**（见下） |
| `event.onHeartbeat(cb)` | `cb({device, age_ms})`：设备最近一次心跳年龄，用于发现半开连接 |
| `event.onMessage(cb)` | 未归类的原始消息（调试用） |
| `window.minimize/maximize/close/isMaximized/onMaximizeChange` | 窗口控制 |
| `config.get()` / `config.set(c)` | 有效配置。键名固定为 `download_dir`、`log_level`、`ipc_port`、`hamd_port` 等；读取时下载目录以 `downloads_dir` 返回（渲染层据此预填） |
| `app.getVersion()` | 版本号（取自 `package.json`，单一来源） |
| `app.getPaths()` | `{downloads, userData, devices, logs}` |
| `app.reveal(path)` | 在系统文件管理器中定位文件：`{ok:true}` 或 `{ok:false,error}`（文件不存在返回 `not_found`，不抛异常） |
| `app.copyText(text)` | 写入系统剪贴板：`{ok:true}` 或 `{ok:false,error}`（`file://` 下 `navigator.clipboard` 不可靠，必须走主进程） |

---

## 7. 局域网发现（客户端发起，服务端静默应答）

### 7.0 为什么反过来

0.0.7 的做法是服务端每 3s 向 `255.255.255.255:9110` 广播一条明文信标（`{"type":"beacon",...}`），
客户端被动收集。这有三个问题：

1. **可枚举**：网内任何人不需要口令就能看到所有设备的 id / 名称 / 端口。
2. **不可用**：客户端只在"已连上某台设备"之后才能从 `stats.peers` 间接知道别的设备，
   因此**从没连上过的设备永远发现不了**——这恰好是发现功能存在的理由。
3. **端口占用**：服务端必须绑定 `0.0.0.0:9110` 才能收到别人的信标，于是同一台机器上的
   第二个实例就抢不到端口。新设计下**客户端用临时端口**，只有服务端需要这个固定端口
   （每个 IP 一个监听者，这是 UDP 的硬约束，只能用 `discovery_port` 区分）。

0.0.8 反转为：**客户端广播探测，服务端只有在对上暗号时才单播应答，对不上就一个字都不回。**
网内扫描者看到的只有自己发出的包；没有口令的人无法从"有没有回应"里得到任何信息以外的收益
（回应本身是加密绑定的，无法伪造、无法重放）。

> 发现只解决"网内有哪些 hamsterd、在哪"。它**不替代** §2 的 `hello` 认证，
> 也不解决 `hello` 目前明文传口令的问题（那属于后续的挑战应答改造，见 README 的待办清单）。

### 7.1 帧格式

传输：UDP，默认端口 `9110`（服务端 `discovery_port`，客户端 `hamd_discovery_port`）。
载荷：一行 UTF-8 JSON，**不超过 512 字节**，不带 `\n`（UDP 有边界，不需要分隔符）。

#### 探测帧（客户端 → 广播地址）

```json
{"t":"hp","v":1,"id":"<本机 device_id>","n":"<32 位十六进制 nonce>","m":"<64 位十六进制 MAC>"}
```

| 字段 | 说明 |
|---|---|
| `t` | 固定 `hp`（hamster probe） |
| `v` | 协议版本，当前 `1`。**不等于 1 一律静默丢弃** |
| `id` | 探测方 device_id，`[0-9a-zA-Z_-]`，长度 8–63 |
| `n` | 16 字节随机数的十六进制（`randomBytes(16)`），每轮重新生成 |
| `m` | 见下 |

`m` 的计算（UTF-8，`\n` 为分隔，**末尾无换行**）：

```
HMAC-SHA256(key = codeword, msg = "hamster-disc-probe/v1\n" + id + "\n" + n)
```

#### 应答帧（服务端 → 探测源地址，单播）

```json
{"t":"hr","v":1,"id":"<服务端 instance_id>","n":"<原样回显探测帧的 n>",
 "m":"<64 位十六进制 MAC>","name":"<服务端主机名>","port":9100,"ver":"0.0.8"}
```

```
HMAC-SHA256(key = codeword, msg = "hamster-disc-reply/v1\n" + <探测帧的 id> + "\n" + n + "\n" + <服务端 id> + "\n" + <port>)
```

* `n` **必须原样回显**，客户端据此把应答配回某一轮探测（避免旧应答污染新结果）。
* `port` 是服务端 **TCP** 监听端口，客户端用它建立连接。
* 应答里的服务端 IP **不作为字段出现**：客户端一律采用 `recvfrom` 的源地址，
  因为那是唯一无法被载荷内容伪造的值。
* 应答 MAC 里带上探测方 `id`，使捕获到的应答无法被重放给另一个客户端。

### 7.2 静默丢弃（silent drop）

服务端在下列任一情况下**不回任何字节**（不回错误包、不发 ICMP、不做任何可区分的响应）。
这是安全要求，不是性能优化：任何可区分的错误反馈都会把"暗号对不对"变成可离线穷举的信号。

唯一的例外是**本机日志**：MAC 校验失败时最多每 60s 写一条汇总告警（累计条数）。
日志只有本机管理员能读到，不构成对外 oracle，而这是排查"两边口令不一致"的唯一线索。

| 条件 | 处理 |
|---|---|
| `discovery_port <= 0`，或配置 `discovery_respond 0` | 线程不启动 / 不回应 |
| 服务端未配置 `codeword` | 启动时记为"发现已禁用"，永不回应（算不出 MAC 就无法认证） |
| 非 JSON、超长、字段缺失或类型不符 | 丢弃 |
| `t != "hp"` 或 `v != 1` | 丢弃 |
| `id` 不符合 §7.1 的字符集/长度 | 丢弃 |
| `n` 不是 32 位十六进制 | 丢弃 |
| `m` 不是 64 位十六进制，或与本地计算值不等（常量时间比较） | 丢弃 |
| 同一源 IP 在 120s 内已用过同一个 `n` | 丢弃（重放） |
| 同一源 IP 超出速率上限 | 丢弃 |

限速：**每源 IP 20 次/秒，突发 40 次**。表容量 64 个 IP，满时按最久未用淘汰；
被淘汰的 IP 重新从满桶开始（可接受：攻击者只能让**自己**被限速）。

重放窗口：服务端保留最近 **256** 组 `(源 IP, n)` 及时间戳，命中且年龄 < 120s 即丢弃。
窗口满时覆盖最旧一条。

### 7.3 客户端行为（规范）

1. 每 **1000ms** 广播一轮探测，每轮新 `n`；广播目标为 `255.255.255.255`、各网卡的子网广播地址，
   以及 `127.0.0.1`（同机部署时广播不保证被本机收回，回环探测是必需的）。
2. 应答收集窗口 = 本轮 + 上一轮（吸收抖动），按 `id` 去重；同一 `id` 取最新 `age_ms`。
3. 设备最后一次应答距今 ≤ **3 轮（3s）** 视为"在线可发现"；超时即从发现列表移除。
4. 收到应答必须校验 `t/v/n` 与 §7.1 的 MAC。**校验失败一律当没收到**（不报错、不提示）。
5. 发现自己 `id` 相同的应答时忽略（同机多实例自打自收）。
6. 未配置 `codeword` 时**不广播**（算不出 MAC，广播只会暴露本机存在）。
7. 发现命中时，对该地址的重连退避**立即复位到 500ms**：目标设备刚上线就应被立刻连上，
   而不是等退避涨到 5s 再重试。

### 7.4 配置项

| 文件 | 键 | 默认 | 说明 |
|---|---|---|---|
| `hamsterd.conf` | `discovery_port` | `9110` | `0` = 完全禁用发现 |
| `hamsterd.conf` | `discovery_respond` | `1` | `0` = 收得到但不回应 |
| `hamster_manager.conf` | `hamd_discovery_port` | `9110` | 必须与服务端一致 |

两侧 `codeword` / `hamd_codeword` **必须一致**；不一致时的表现是"列表里永远发现不到那台设备"，
而不是报错——这是设计意图（§7.2）。

### 7.5 与 §6.1 `discover.list()` 的关系

`discover.list()` 由 **Electron 主进程自己**广播探测后返回本地结果，不再向已连接设备取 `peers`：

```js
[{ id, ip, name, port, age_ms, addr }]   // addr = "ip:port"，可直接喂给 dev.add()
```

`age_ms` 是距最近一次应答的毫秒数，供 UI 排序与"刚出现"高亮使用。
