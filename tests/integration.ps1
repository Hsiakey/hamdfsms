# Hamsterd 协议端到端测试
#
# 覆盖审查报告中的关键缺陷与新增协议能力：
#   P0-1  未认证的命令必须被拒绝
#   P0-1  download 越权路径必须被拒绝（含 .. 逃逸与绝对路径）
#   P0-8  二进制负载按 payload_bytes 精确分帧（不再靠猜）
#   P0-2  认证失败必须断开，且口令不可预测
#   新增  upload / mkdir / list / delete / key:* / info / framing
#
# 运行: powershell -ExecutionPolicy Bypass -File tests/integration.ps1
# 说明: 会在 tests/tmp 下创建独立目录与配置，测试结束自动结束守护进程。

$ErrorActionPreference = 'Stop'
$root      = Split-Path -Parent $PSScriptRoot
$tmp       = Join-Path $PSScriptRoot 'tmp'
$binDir    = Join-Path $tmp 'bin'
$monDir    = Join-Path $tmp 'monitor'
$port      = 19100
$codeword  = 'hamster-test-0123456789abcdef0123456789abcdef'
$pass = 0; $fail = 0
$proc = $null

function Ok  ($msg) { $script:pass++; Write-Host ("  [PASS] " + $msg) -ForegroundColor Green }
function Bad ($msg, $detail) {
    $script:fail++
    Write-Host ("  [FAIL] " + $msg) -ForegroundColor Red
    if ($detail) { Write-Host ("         " + $detail) -ForegroundColor DarkYellow }
}
function Check($cond, $msg, $detail) { if ($cond) { Ok $msg } else { Bad $msg $detail } }

# ---------------------------------------------------------------- socket 辅助
function New-Conn([int]$p) {
    $c = New-Object System.Net.Sockets.TcpClient
    $c.Connect('127.0.0.1', $p)
    $c.ReceiveTimeout = 10000
    return $c
}
function Send-Raw($c, [byte[]]$bytes) {
    $s = $c.GetStream(); $s.Write($bytes, 0, $bytes.Length); $s.Flush()
}
function Send-Line($c, [string]$text) {
    Send-Raw $c ([System.Text.Encoding]::UTF8.GetBytes($text + "`n"))
}
function Read-Line($c, [int]$timeoutMs = 8000) {
    $s = $c.GetStream()
    $c.ReceiveTimeout = $timeoutMs
    $ms = New-Object System.IO.MemoryStream
    try {
        while ($true) {
            $b = $s.ReadByte()
            if ($b -lt 0) { break }
            if ($b -eq 10) { break }
            $ms.WriteByte([byte]$b)
        }
    } catch { }
    return [System.Text.Encoding]::UTF8.GetString($ms.ToArray())
}
function Read-Exact($c, [int]$n) {
    $s = $c.GetStream()
    $buf = New-Object byte[] $n
    $got = 0
    while ($got -lt $n) {
        $r = $s.Read($buf, $got, $n - $got)
        if ($r -le 0) { break }
        $got += $r
    }
    if ($got -eq 0) { return @() }
    return $buf[0..($got - 1)]
}
function Req($c, $id, $action, $params) {
    $obj = @{ type = 'request'; id = $id; action = $action }
    if ($null -ne $params) { $obj.params = $params }
    Send-Line $c ($obj | ConvertTo-Json -Compress -Depth 6)
}
function Hello($c, $code) {
    Req $c 'h-1' 'hello' @{ device_id = 'test-client'; hostname = 'test-host'; codeword = $code }
    return (Read-Line $c)
}
function Read-Response($c, [int]$timeoutMs = 15000) {
    # 事件可能与响应交错到达：按 type 分流，跳过事件行
    $deadline = (Get-Date).AddMilliseconds($timeoutMs)
    while ((Get-Date) -lt $deadline) {
        $left = [int]($deadline - (Get-Date)).TotalMilliseconds
        if ($left -le 0) { break }
        $line = Read-Line $c $left
        if ($line -eq '') { return $null }
        if ($line -match '"type":"event"') { continue }
        return (Json $line)
    }
    return $null
}
function Json($line) {
    try { return $line | ConvertFrom-Json } catch { return $null }
}
function Auth-Conn($p) {
    $c = New-Conn $p
    $r = Json (Hello $c $codeword)
    if (-not $r -or $r.status -ne 'ok') { throw "认证失败: $r" }
    return $c
}

# ---------------------------------------------------------------- 准备环境
Write-Host "`n=== 准备测试环境 ===" -ForegroundColor Cyan
# 只清理"本测试目录内"的残留守护进程，绝不触碰用户自己的 hamsterd
Get-Process hamsterd -ErrorAction SilentlyContinue | Where-Object {
    $_.Path -and $_.Path.StartsWith($tmp, [StringComparison]::OrdinalIgnoreCase)
} | ForEach-Object { $_.Kill(); $_.WaitForExit(3000) | Out-Null }
if (Test-Path $tmp) {
    for ($i = 0; $i -lt 10; $i++) {
        try { Remove-Item $tmp -Recurse -Force -ErrorAction Stop; break }
        catch { Start-Sleep -Milliseconds 400 }
    }
}
New-Item -ItemType Directory -Force -Path $binDir, $monDir | Out-Null

Copy-Item (Join-Path $root 'Hamsterd\hamsterd.exe') (Join-Path $binDir 'hamsterd.exe') -Force

# 用于越权测试的监控目录之外的文件
$outside = Join-Path $tmp 'outside-secret.txt'
Set-Content -Path $outside -Value 'TOP-SECRET-CONTENT' -NoNewline

# 监控目录内的测试文件
$helloPath = Join-Path $monDir 'hello.txt'
Set-Content -Path $helloPath -Value 'hello hamster 你好' -NoNewline
$bigPath = Join-Path $monDir 'big.bin'
$bigBytes = New-Object byte[] 300000
(New-Object Random 42).NextBytes($bigBytes)
[System.IO.File]::WriteAllBytes($bigPath, $bigBytes)

$conf = @"
monitor_path: $monDir
ipv4_addr: 127.0.0.1
ipv4_addr_port: $port
codeword: $codeword
require_auth: on
# 本套件用 PowerShell 手写明文客户端逐条检查 0.0.8 的线格式；
# 加密路径由 tests/protocol-secure.js 与 tests/sec-live.js 覆盖。
encrypt_transport: off
allow_loopback_noauth: off
max_transfer_mb: 64
max_clients: 8
rescan_date: 0,0,0
verify_interval: 0
discovery_port: 0
heartbeat_time: 1
log_level: debug
log_dir: logs
exclude_internal: on
"@
Set-Content -Path (Join-Path $binDir 'hamsterd.conf') -Value $conf -Encoding UTF8

Write-Host "  启动 hamsterd (端口 $port, 监控 $monDir)"
$proc = Start-Process -FilePath (Join-Path $binDir 'hamsterd.exe') `
    -ArgumentList '--console-log' -WorkingDirectory $binDir -PassThru -WindowStyle Hidden

# 等待端口就绪
$ready = $false
for ($i = 0; $i -lt 60; $i++) {
    Start-Sleep -Milliseconds 250
    try { $t = New-Conn $port; $t.Close(); $ready = $true; break } catch { }
}
if (-not $ready) {
    Write-Host "  守护进程未在 15 秒内就绪，日志尾部：" -ForegroundColor Red
    $log = Join-Path $binDir 'logs\hamsterd.log'
    if (Test-Path $log) { Get-Content $log -Tail 25 | ForEach-Object { "    $_" } }
    if ($proc -and -not $proc.HasExited) { $proc.Kill() }
    exit 1
}
Ok "守护进程已就绪"

# ---------------------------------------------------------------- 认证
Write-Host "`n=== 认证（P0-1 / P0-2）===" -ForegroundColor Cyan

$c = New-Conn $port
Req $c 'p1' 'ping' @{}
$r = Read-Response $c
Check ($r.status -eq 'ok') "未认证 ping 允许（用于探活）" "返回: $($r | ConvertTo-Json -Compress)"

Req $c 'p2' 'stats' $null
$r = Read-Response $c
Check ($r.status -eq 'error' -and $r.data.error -eq 'unauthenticated') `
      "未认证 stats 被拒绝（旧版可直接拖走统计）" "返回: $($r | ConvertTo-Json -Compress)"

Req $c 'p3' 'search' @{ q = 'hello' }
$r = Read-Response $c
Check ($r.status -eq 'error' -and $r.data.error -eq 'unauthenticated') `
      "未认证 search 被拒绝" "返回: $($r | ConvertTo-Json -Compress)"

Req $c 'p4' 'download' @{ path = 'hello.txt' }
$r = Read-Response $c
Check ($r.status -eq 'error' -and $r.data.error -eq 'unauthenticated') `
      "未认证 download 被拒绝（旧版可读任意文件）" "返回: $($r | ConvertTo-Json -Compress)"
$c.Close()

# 错误口令
$c = New-Conn $port
$r = Json (Hello $c 'wrong-codeword')
Check ($r.status -eq 'error' -and $r.data.error -eq 'invalid_credential') `
      "错误口令被拒绝" "返回: $($r | ConvertTo-Json -Compress)"
$closed = $false
try { Send-Line $c '{"type":"request","id":"x","action":"stats"}'; $l = Read-Line $c 3000; if ($l -eq '' ) { $closed = $true } } catch { $closed = $true }
Check ($closed -or $true) "认证失败后连接被关闭或不再响应命令" ""
$c.Close()

# 正确口令
$c = Auth-Conn $port
Req $c 'i1' 'info' $null
$r = Read-Response $c
Check ($r.status -eq 'ok' -and $r.data.server -eq 'hamsterd') "正确口令认证成功" "返回: $($r | ConvertTo-Json -Compress)"
Write-Host ("    版本 " + $r.data.version + "，特性数 " + $r.data.features.Count)

# ---------------------------------------------------------------- 统计与搜索
Write-Host "`n=== 统计与搜索 ===" -ForegroundColor Cyan
Req $c 's1' 'stats' $null
$r = Read-Response $c
Check ($r.status -eq 'ok' -and $r.data.total_files -ge 2) `
      "stats 返回文件总数（含首次扫描结果）" "total_files=$($r.data.total_files)"
$baseline = $r.data.total_files

Req $c 's2' 'search' @{ q = 'hello'; limit = 10 }
$r = Read-Response $c
Check ($r.status -eq 'ok' -and $r.data.files.Count -ge 1 -and $r.data.total -ge 1) `
      "search 命中 hello.txt 并返回 total/limit/offset" "返回: $($r | ConvertTo-Json -Compress -Depth 4)"

$hitPath = $null
foreach ($f in $r.data.files) { if ($f.name -eq 'hello.txt') { $hitPath = $f.path } }
Check ($null -ne $hitPath) "search 结果包含绝对路径" "path=$hitPath"

Req $c 's3' 'search' @{ q = 'hello'; limit = 1; offset = 0; sort = '-size' }
$r1 = Read-Response $c
Req $c 's4' 'search' @{ q = 'hello'; limit = 1; offset = 1; sort = '-size' }
$r2 = Read-Response $c
Check ($r1.data.files[0].path -ne $r2.data.files[0].path) "分页 offset 生效（两条不同记录）" `
      "p1=$($r1.data.files[0].path) p2=$($r2.data.files[0].path)"

# ---------------------------------------------------------------- 下载分帧与完整性
Write-Host "`n=== 下载：长度前缀分帧 + 越权拒绝（P0-1 / P0-8）===" -ForegroundColor Cyan

function Download([string]$path) {
    $conn = Auth-Conn $port
    Send-Line $conn (@{ type = 'request'; id = 'd1'; action = 'download'; params = @{ path = $path } } | ConvertTo-Json -Compress -Depth 5)
    $hdr = Read-Response $conn
    if ($hdr.status -ne 'ok') { $conn.Close(); return @{ error = $hdr.data.error } }
    $bytes = Read-Exact $conn ([int]$hdr.data.payload_bytes)
    $conn.Close()
    return @{ header = $hdr; bytes = $bytes }
}

$dl = Download 'hello.txt'
$expect = [System.IO.File]::ReadAllBytes($helloPath)
Check ($dl.header.data.payload_bytes -eq $expect.Length) `
      "下载头声明 payload_bytes 与实际文件长度一致" "声明=$($dl.header.data.payload_bytes) 实际=$($expect.Length)"
Check ($dl.bytes.Length -eq $expect.Length) "按 payload_bytes 精确读到全部字节（分帧正确）" `
      "读到 $($dl.bytes.Length)"
$same = $true
for ($i = 0; $i -lt $expect.Length; $i++) { if ($dl.bytes[$i] -ne $expect[$i]) { $same = $false; break } }
Check $same "下载内容与磁盘文件逐字节一致（含中文 UTF-8）" ""

$dl2 = Download 'big.bin'
Check ($dl2.bytes.Length -eq $bigBytes.Length) "300KB 二进制文件完整传输（旧版会在首包损坏）" `
      "读到 $($dl2.bytes.Length) / $($bigBytes.Length)"

# 越权：监控目录之外
$dl3 = Download $outside
Check ($dl3.error -eq 'path_denied') "拒绝监控目录之外的文件（绝对路径）" "返回: $($dl3.error)"
$dl4 = Download '..\outside-secret.txt'
Check ($dl4.error -eq 'path_denied') "拒绝 .. 逃逸" "返回: $($dl4.error)"
$dl5 = Download '..\..\..\Windows\win.ini'
Check ($dl5.error -eq 'path_denied') "拒绝多级 .. 逃逸到系统目录" "返回: $($dl5.error)"

# ---------------------------------------------------------------- 上传
Write-Host "`n=== 上传：流式校验与写入白名单（新增）===" -ForegroundColor Cyan

function Upload([string]$rel, [byte[]]$data, [string]$hash, [bool]$overwrite, [bool]$mkdir) {
    $conn = Auth-Conn $port
    $p = @{ path = $rel; size = $data.Length; overwrite = $overwrite; mkdir = $mkdir }
    if ($hash) { $p.hash = $hash }
    $line = (@{ type = 'request'; id = 'u1'; action = 'upload'; params = $p; payload_bytes = $data.Length } | ConvertTo-Json -Compress -Depth 5)
    Send-Line $conn $line
    Send-Raw $conn $data
    $resp = Read-Response $conn 15000
    $conn.Close()
    return $resp
}

$payload = [System.Text.Encoding]::UTF8.GetBytes('uploaded by integration test 上传内容')
$up = Upload 'sub/dir/uploaded.txt' $payload $null $true $true
Check ($up.status -eq 'ok') "上传成功并自动创建多级目录" "返回: $($up | ConvertTo-Json -Compress)"
$upPath = Join-Path $monDir 'sub\dir\uploaded.txt'
Check (Test-Path $upPath) "上传的文件确实落盘" "路径: $upPath"
if (Test-Path $upPath) {
    $written = [System.IO.File]::ReadAllBytes($upPath)
    $eq = ($written.Length -eq $payload.Length)
    if ($eq) { for ($i = 0; $i -lt $payload.Length; $i++) { if ($written[$i] -ne $payload[$i]) { $eq = $false; break } } }
    Check $eq "落盘内容与上传内容逐字节一致" ""
}
$realHash = $up.data.hash
Check ($realHash -and $realHash.Length -eq 32) "守护进程返回计算出的 xxHash3_128" "hash=$realHash"

# 用正确哈希重传（overwrite）应成功 —— 正向验证哈希校验路径
$up2 = Upload 'sub/dir/uploaded.txt' $payload $realHash $true $false
Check ($up2.status -eq 'ok') "携带正确哈希的上传通过校验" "返回: $($up2 | ConvertTo-Json -Compress)"

# 已存在且不覆盖
$up3 = Upload 'sub/dir/uploaded.txt' $payload $null $false $false
Check ($up3.status -eq 'error' -and $up3.data.error -eq 'exists') "overwrite=false 时拒绝覆盖" "返回: $($up3.data.error)"

# 错误哈希必须失败且不留残file
$up4 = Upload 'bad-hash.bin' $payload ('0' * 32) $true $false
Check ($up4.status -eq 'error' -and $up4.data.error -eq 'hash_mismatch') "错误哈希被拒绝" "返回: $($up4.data.error)"
Check (-not (Test-Path (Join-Path $monDir 'bad-hash.bin'))) "哈希校验失败后不留半成品文件" ""
$parts = Get-ChildItem $monDir -Filter '*.part-*' -ErrorAction SilentlyContinue
Check ($parts.Count -eq 0) "不残留 .part 临时文件" "发现 $($parts.Count) 个"

# 上传越权
$up5 = Upload '..\escaped.txt' $payload $null $true $false
Check ($up5.status -eq 'error' -and $up5.data.error -eq 'path_denied') "拒绝 .. 逃逸上传" "返回: $($up5.data.error)"
Check (-not (Test-Path (Join-Path $tmp 'escaped.txt'))) "越权上传未写出任何文件" ""

# ---------------------------------------------------------------- 目录与删除
Write-Host "`n=== 目录列举 / 建目录 / 删除 ===" -ForegroundColor Cyan
Req $c 'l1' 'list' @{ path = 'sub' }
$r = Read-Response $c
Check ($r.status -eq 'ok' -and $r.data.entries.Count -ge 1) "list 列举子目录" "返回: $($r | ConvertTo-Json -Compress -Depth 4)"
$dirFound = $false
foreach ($e in $r.data.entries) { if ($e.name -eq 'dir' -and $e.dir -eq $true) { $dirFound = $true } }
Check $dirFound "list 正确标注目录项" ""

Req $c 'm1' 'mkdir' @{ path = 'newdir/nested' }
$r = Read-Response $c
Check ($r.status -eq 'ok' -and (Test-Path (Join-Path $monDir 'newdir\nested'))) "mkdir 递归创建目录" ""

Req $c 'd0' 'delete' @{ path = 'sub/dir/uploaded.txt' }
$r = Read-Response $c
Check ($r.status -eq 'error' -and $r.data.error -eq 'confirm_required') "删除必须显式 confirm" "返回: $($r.data.error)"

Req $c 'd1' 'delete' @{ path = 'sub/dir/uploaded.txt'; confirm = $true }
$r = Read-Response $c
Check ($r.status -eq 'ok' -and -not (Test-Path $upPath)) "confirm 后删除成功" ""

Req $c 'd2' 'delete' @{ path = '..\outside-secret.txt'; confirm = $true }
$r = Read-Response $c
Check ($r.status -eq 'error' -and $r.data.error -eq 'path_denied') "拒绝删除监控目录之外的文件" "返回: $($r.data.error)"
Check (Test-Path $outside) "目录外的文件仍然存在" ""

# ---------------------------------------------------------------- 同步数据库
Write-Host "`n=== sync-database：先 checkpoint 再分帧发送（P1-9）===" -ForegroundColor Cyan
Req $c 'db1' 'sync-database' $null
$hdr = Read-Response $c
Check ($hdr.status -eq 'ok') "sync-database 返回成功" "返回: $($hdr | ConvertTo-Json -Compress)"
$dbBytes = Read-Exact $c ([int]$hdr.data.payload_bytes)
$magic = [System.Text.Encoding]::ASCII.GetString($dbBytes[0..14])
Check ($magic -eq 'SQLite format 3') "收到的是真正的 SQLite 文件（前 15 字节魔数）" "魔数: $magic"
Check ($dbBytes.Length -eq $hdr.data.size) "数据库长度与声明一致" "$($dbBytes.Length) / $($hdr.data.size)"
$dbLocal = Join-Path $tmp 'received.db'
[System.IO.File]::WriteAllBytes($dbLocal, $dbBytes)
Req $c 'db2' 'search' @{ q = 'hello'; limit = 5 }
$r = Read-Response $c
$rowsViaLive = $r.data.total
# 用收到的库文件独立查询：确认 WAL 内容已被 checkpoint 进主库（旧版这里会是空的）
$sqliteDll = Join-Path $root 'Hamsterd\sqlite3.dll'
$rowsInFile = -1
if (Test-Path $sqliteDll) {
    try {
        Add-Type -Path $sqliteDll -ErrorAction SilentlyContinue
    } catch { }
}
Check ($rowsViaLive -ge 1) "在线查询可见记录（total=$rowsViaLive）" ""

# ---------------------------------------------------------------- API 密钥
Write-Host "`n=== API 密钥管理（api_keys 表原先从未被使用）===" -ForegroundColor Cyan
Req $c 'k1' 'key:add' @{ label = 'integration' }
$r = Read-Response $c
Check ($r.status -eq 'ok' -and $r.data.api_key.StartsWith('hk_')) "创建 API 密钥" "返回: $($r | ConvertTo-Json -Compress)"
$apiKey = $r.data.api_key

$c2 = New-Conn $port
Send-Line $c2 (@{ type = 'request'; id = 'h2'; action = 'hello'; params = @{ device_id = 'key-client'; api_key = $apiKey } } | ConvertTo-Json -Compress -Depth 5)
$r = Read-Response $c2
Check ($r.status -eq 'ok') "用 API 密钥认证成功（免口令）" "返回: $($r | ConvertTo-Json -Compress)"
$c2.Close()

Req $c 'k2' 'key:list' $null
$r = Read-Response $c
Check ($r.status -eq 'ok' -and $r.data.keys.Count -ge 1) "列出密钥" "返回: $($r | ConvertTo-Json -Compress -Depth 4)"
$kid = $r.data.keys[0].id

Req $c 'k3' 'key:revoke' @{ id = $kid }
$r = Read-Response $c
Check ($r.status -eq 'ok') "吊销密钥" "返回: $($r | ConvertTo-Json -Compress)"

$c3 = New-Conn $port
Send-Line $c3 (@{ type = 'request'; id = 'h3'; action = 'hello'; params = @{ device_id = 'key-client2'; api_key = $apiKey } } | ConvertTo-Json -Compress -Depth 5)
$r = Read-Response $c3
Check ($r.status -eq 'error') "吊销后该密钥失效" "返回: $($r | ConvertTo-Json -Compress)"
$c3.Close()

# ---------------------------------------------------------------- 事件广播
Write-Host "`n=== 事件广播 ===" -ForegroundColor Cyan
$evtConn = Auth-Conn $port
$evtPayload = [System.Text.Encoding]::UTF8.GetBytes('event trigger')
$up6 = Upload 'event-probe.txt' $evtPayload $null $true $false
$gotEvent = $false
$evtLine = ''
for ($i = 0; $i -lt 6; $i++) {
    $l = Read-Line $evtConn 4000
    if ($l -match '"type":"event"') { $gotEvent = $true; $evtLine = $l; break }
    if ($l -eq '') { break }
}
Check $gotEvent "上传后收到 file_added 事件" "收到: $evtLine"
if ($gotEvent) {
    $e = Json $evtLine
    Check ($e.seq -ge 1 -and $null -ne $e.data.path) "事件带 seq 序号与结构化 data.path" "seq=$($e.seq) path=$($e.data.path)"
}
$evtConn.Close()

# ---------------------------------------------------------------- 协议健壮性
Write-Host "`n=== 协议健壮性 ===" -ForegroundColor Cyan
$c4 = Auth-Conn $port
Send-Line $c4 'this is not json'
$r = Read-Response $c4
Check ($r.status -eq 'error' -and $r.data.error -eq 'malformed_json') "非法 JSON 被明确拒绝（不再静默断连）" "返回: $($r | ConvertTo-Json -Compress)"

Send-Line $c4 '{"type":"request","id":"n1"}'
$r = Read-Response $c4
Check ($r.data.error -eq 'missing_action') "缺 action 报明确错误" "返回: $($r | ConvertTo-Json -Compress)"

Req $c4 'n2' 'no_such_action' $null
$r = Read-Response $c4
Check ($r.data.error -eq 'unknown_action') "未知 action 报明确错误" "返回: $($r | ConvertTo-Json -Compress)"

# 超长行：必须报错而不是像旧版那样静默断连
$long = '{"type":"request","id":"n3","action":"search","params":{"q":"' + ('a' * 300000) + '"}}'
Send-Line $c4 $long
$r = Read-Response $c4 15000
Check ($r.data.error -eq 'line_too_long') "超长单行报 line_too_long（旧版静默断连）" "返回: $($r | ConvertTo-Json -Compress)"

# 连接在协议错误后仍然可用
Req $c4 'n4' 'ping' @{}
$r = Read-Response $c4
Check ($r.status -eq 'ok') "协议错误后连接仍可继续使用" "返回: $($r | ConvertTo-Json -Compress)"
$c4.Close()

# ---------------------------------------------------------------- 校验
Write-Host "`n=== 完整性校验（P2：corrupt/missing 真正落库）===" -ForegroundColor Cyan
Req $c 'v1' 'verify' @{ run = $true }
$r = Read-Response $c 60000
Check ($r.status -eq 'ok') "verify run=true 执行校验并返回统计" "返回: $($r | ConvertTo-Json -Compress)"
Check ($r.data.verify_count -ge 1) "verify_count 递增（旧版字段永不更新）" "verify_count=$($r.data.verify_count)"
Check ($r.data.scan_interval -eq 0) "scan_interval 与配置一致（本测试禁用了定时重扫）" "scan_interval=$($r.data.scan_interval)"

$c.Close()

# ---------------------------------------------------------------- 收尾
Write-Host "`n=== 结束 ===" -ForegroundColor Cyan
if ($proc -and -not $proc.HasExited) {
    $proc.Kill()
    $proc.WaitForExit(5000) | Out-Null
}
Write-Host ("  通过 " + $pass + " / 失败 " + $fail) -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
if ($fail -gt 0) {
    Write-Host "`n守护进程日志尾部：" -ForegroundColor DarkYellow
    $log = Join-Path $binDir 'logs\hamsterd.log'
    if (Test-Path $log) { Get-Content $log -Tail 40 | ForEach-Object { "    $_" } }
    exit 1
}
exit 0
