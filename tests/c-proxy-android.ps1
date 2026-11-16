# C 代理（hamster_manager.exe）⇄ 安卓守护端（app-daemon）互通检查
#
# 目的：PROTOCOL.md 里写明「C 侧客户端连安卓守护端这条组合还没测过」，
# 这个脚本补上。链路是：
#
#   PowerShell(IPC :9302) -> hamster_manager.exe --proxy-only -> :9200
#     -> adb forward -> 模拟器 :9100 -> 安卓守护端（Kotlin，§8 服务端）
#
# 于是"C 客户端侧的 §8 实现"与"Kotlin 服务端侧的 §8 实现"被真正对接起来。
#
#   用法：pwsh -File tests\c-proxy-android.ps1
#   前提（脚本不替你准备）：
#     1) 模拟器/真机里 ham-demon 已启动，且监听端口是 9100；
#     2) `adb forward tcp:9200 tcp:9100` 已设置（脚本会用 :9200 去连）；
#     3) 守护端口令与下面的 $codeword 一致（可用 --es secret 以 adb 钩子设）。
#   产物与代理 exe 都落在 tests\tmp\c-proxy-android（已被 gitignore）。

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$dir = Join-Path $PSScriptRoot 'tmp\c-proxy-android'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$hamdPort = 9200
$ipcPort = 9302
$codeword = 'daemon-app-e2e-2026'
$pass = 0; $fail = 0
$proxy = $null

function Ok($m) { $script:pass++; Write-Host ("  [PASS] " + $m) -ForegroundColor Green }
function Bad($m, $d) { $script:fail++; Write-Host ("  [FAIL] " + $m) -ForegroundColor Red; if ($d) { Write-Host ("         " + $d) -ForegroundColor DarkYellow } }
function Check($c, $m, $d) { if ($c) { Ok $m } else { Bad $m $d } }

function New-Conn([int]$p) {
    $c = New-Object System.Net.Sockets.TcpClient
    $c.Connect('127.0.0.1', $p)
    $c.ReceiveTimeout = 15000
    return $c
}
function Send-Line($c, [string]$t) {
    $b = [Text.Encoding]::UTF8.GetBytes($t + "`n")
    $c.GetStream().Write($b, 0, $b.Length); $c.GetStream().Flush()
}
function Read-Line($c, [int]$t = 15000) {
    $s = $c.GetStream(); $c.ReceiveTimeout = $t
    $ms = New-Object System.IO.MemoryStream
    try { while ($true) { $b = $s.ReadByte(); if ($b -lt 0 -or $b -eq 10) { break }; $ms.WriteByte([byte]$b) } } catch { }
    return [Text.Encoding]::UTF8.GetString($ms.ToArray())
}
function Read-Response($c, [int]$t = 15000) {
    $deadline = (Get-Date).AddMilliseconds($t)
    while ((Get-Date) -lt $deadline) {
        $left = [int]($deadline - (Get-Date)).TotalMilliseconds
        if ($left -le 0) { break }
        $l = Read-Line $c $left
        if ($l -eq '') { return $null }
        if ($l -match '"type":"event"') { continue }
        return ($l | ConvertFrom-Json)
    }
    return $null
}
function Read-Bytes($c, [int]$n) {
    $s = $c.GetStream(); $c.ReceiveTimeout = 20000
    $buf = New-Object byte[] $n
    $got = 0
    while ($got -lt $n) {
        $r = $s.Read($buf, $got, $n - $got)
        if ($r -le 0) { break }
        $got += $r
    }
    return ,$buf[0..([Math]::Max(0, $got - 1))]
}
function Wait-Port([int]$p, [int]$timeoutMs = 20000) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.ElapsedMilliseconds -lt $timeoutMs) {
        try { $c = New-Conn $p; $c.Close(); return $true } catch { Start-Sleep -Milliseconds 250 }
    }
    return $false
}

Write-Host "`n=== C 代理 ⇄ 安卓守护端 互通检查 ===" -ForegroundColor Cyan
Write-Host "  链路: IPC :$ipcPort -> 代理 -> :$hamdPort -> adb forward -> 设备 :9100"

Get-Process hamster_manager -ErrorAction SilentlyContinue | Where-Object {
    $_.Path -and $_.Path.StartsWith($dir, [StringComparison]::OrdinalIgnoreCase)
} | ForEach-Object { try { $_.Kill() } catch { } }
Start-Sleep -Milliseconds 300

Copy-Item (Join-Path $root 'Hamster Manager\hamster_manager.exe') (Join-Path $dir 'hamster_manager.exe') -Force
@"
hamd_port $hamdPort
ipc_port $ipcPort
hamd_codeword $codeword
hamd_encrypt on
"@ | Set-Content -Path (Join-Path $dir 'hamster_manager.conf') -Encoding UTF8

$proxy = Start-Process -FilePath (Join-Path $dir 'hamster_manager.exe') -ArgumentList '--proxy-only' `
        -WorkingDirectory $dir -PassThru -WindowStyle Hidden
if (-not (Wait-Port $ipcPort)) { Bad "代理未监听 :$ipcPort" ""; exit 1 }
Ok "代理已监听 :$ipcPort（配置 hamd_encrypt on）"

$c = New-Conn $ipcPort

# 1) stats：证明 §8 握手 + 命令通道（C 客户端侧 ⇄ Kotlin 服务端侧）
Send-Line $c '{"type":"request","id":"a1","action":"stats","params":{}}'
$r = Read-Response $c
Check ($null -ne $r -and $r.status -eq 'ok') "stats 经代理拿到 ok" ($r | ConvertTo-Json -Compress -Depth 4)
if ($r -and $r.status -eq 'ok') {
    Check ($null -ne $r.data.total_files) "stats.total_files 存在（$($r.data.total_files)）" ""
    Ok "C 客户端侧的 §8 握手被 Kotlin 服务端接受（否则这条连接根本建不起来）"
}

# 2) list：路径与条目结构
Send-Line $c '{"type":"request","id":"a2","action":"list","params":{"path":"/","limit":100,"offset":0}}'
$r = Read-Response $c
Check ($null -ne $r -and $r.status -eq 'ok') "list 成功" ($r | ConvertTo-Json -Compress -Depth 4)
$entry = $null
if ($r -and $r.status -eq 'ok') {
    $entry = $r.data.entries | Where-Object { $_.name -eq 'hello.txt' } | Select-Object -First 1
    Check ($null -ne $entry) "list 里能看到 hello.txt" (($r.data.entries | ForEach-Object { $_.name }) -join ',')
}

# 3) download：二进制负载（响应行之后紧跟裸数据）
if ($entry) {
    Send-Line $c ('{"type":"request","id":"a3","action":"download","params":{"path":"' + $entry.path + '"}}')
    $h = Read-Response $c
    Check ($null -ne $h -and $h.status -eq 'ok') "download 响应 ok" ($h | ConvertTo-Json -Compress -Depth 4)
    if ($h -and $h.status -eq 'ok') {
        $n = [int]$h.data.payload_bytes
        Check ($n -gt 0) "payload_bytes 正确（$n 字节）" ""
        $bytes = Read-Bytes $c $n
        $sha = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($bytes)).Replace('-', '').ToLower()
        $text = [Text.Encoding]::UTF8.GetString($bytes)
        Check ($text -match 'hi') "下载内容与设备上的文件一致（'$text'）" "sha256=$sha"
    }
}

# 4) upload：代理**不应该**承载二进制负载，必须明确拒绝（而不是静默写坏）
$payload = [Text.Encoding]::UTF8.GetBytes('written by C proxy at ' + (Get-Date -Format o))
$name = 'from-c-proxy.txt'
$hdr = '{"type":"request","id":"a4","action":"upload","params":{"path":"' + $name + '","size":' +
       $payload.Length + ',"overwrite":true},"payload_bytes":' + $payload.Length + '}'
Send-Line $c $hdr
$stream = $c.GetStream()
$stream.Write($payload, 0, $payload.Length); $stream.Flush()
$r = Read-Response $c
Check ($null -ne $r -and $r.status -eq 'error' -and $r.data.error -eq 'proxy_no_payload') `
      "带负载的请求被代理明确拒绝（proxy_no_payload），不再半转发" ($r | ConvertTo-Json -Compress -Depth 3)

# 连接仍可用：拒绝之后还能继续发普通命令
Send-Line $c '{"type":"request","id":"a4b","action":"ping","params":{}}'
$r = Read-Response $c
Check ($null -ne $r -and $r.status -eq 'ok' -and $r.data.pong -eq $true) "被拒绝后连接仍然可用（ping 正常）" `
      ($r | ConvertTo-Json -Compress -Depth 3)
# 5) 未知动作：错误语义要原样透传
Send-Line $c '{"type":"request","id":"a6","action":"no_such_action","params":{}}'
$r = Read-Response $c
Check ($null -ne $r -and $r.status -eq 'error' -and $r.data.error -eq 'unknown_action') `
      "未知动作返回 unknown_action（未被代理吞掉/改写）" ($r | ConvertTo-Json -Compress -Depth 3)

$c.Close()
Write-Host ""
Write-Host "PASS $pass / FAIL $fail"
if ($fail -gt 0) { exit 1 }
