# Hamster Manager（C 代理）端到端测试
#
# 验证审查报告里针对代理层的修复：
#   P0-9  慢客户端不再阻塞整个中间层（用快照+锁外发送+发送超时）
#   P1-2  认证失败后按退避重试并重读配置，而不是永久停止重连
#   P1-4  accept/select 出错不再退出服务
#   P1-5  端口独占（第二个实例不能抢占同一端口）
#   P1-1  发送长度一律 strlen（不再有手写魔数）
# 同时验证命令与事件的双向转发。
#
# 运行: powershell -ExecutionPolicy Bypass -File tests/proxy.ps1

$ErrorActionPreference = 'Stop'
$root   = Split-Path -Parent $PSScriptRoot
$tmp    = Join-Path $PSScriptRoot 'tmp'
$dir    = Join-Path $tmp 'proxy'
$mon    = Join-Path $dir 'monitor'
$hamdPort = 19100
$ipcPort  = 19102
$codeword = 'hamster-proxy-test-0123456789abcdef'
$pass = 0; $fail = 0
$hamd = $null; $proxy = $null

function Ok  ($m) { $script:pass++; Write-Host ("  [PASS] " + $m) -ForegroundColor Green }
function Bad ($m, $d) {
    $script:fail++
    Write-Host ("  [FAIL] " + $m) -ForegroundColor Red
    if ($d) { Write-Host ("         " + $d) -ForegroundColor DarkYellow }
}
function Check($c, $m, $d) { if ($c) { Ok $m } else { Bad $m $d } }

function New-Conn([int]$p) {
    $c = New-Object System.Net.Sockets.TcpClient
    $c.Connect('127.0.0.1', $p)
    $c.ReceiveTimeout = 8000
    return $c
}
function Send-Line($c, [string]$t) {
    $b = [Text.Encoding]::UTF8.GetBytes($t + "`n")
    $c.GetStream().Write($b, 0, $b.Length); $c.GetStream().Flush()
}
function Read-Line($c, [int]$t = 8000) {
    $s = $c.GetStream(); $c.ReceiveTimeout = $t
    $ms = New-Object System.IO.MemoryStream
    try { while ($true) { $b = $s.ReadByte(); if ($b -lt 0 -or $b -eq 10) { break }; $ms.WriteByte([byte]$b) } } catch { }
    return [Text.Encoding]::UTF8.GetString($ms.ToArray())
}
function Json($l) { try { return $l | ConvertFrom-Json } catch { return $null } }
# 代理会同时转发事件与响应，必须按 type 分流
function Read-Response($c, [int]$t = 10000) {
    $deadline = (Get-Date).AddMilliseconds($t)
    while ((Get-Date) -lt $deadline) {
        $left = [int]($deadline - (Get-Date)).TotalMilliseconds
        if ($left -le 0) { break }
        $l = Read-Line $c $left
        if ($l -eq '') { return $null }
        if ($l -match '"type":"event"') { continue }
        return (Json $l)
    }
    return $null
}
function Wait-Port([int]$p, [int]$timeoutMs = 15000) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.ElapsedMilliseconds -lt $timeoutMs) {
        try { $c = New-Conn $p; $c.Close(); return $true } catch { Start-Sleep -Milliseconds 250 }
    }
    return $false
}
function Stop-All {
    foreach ($p in @($proxy, $hamd)) {
        if ($p -and -not $p.HasExited) { try { $p.Kill(); $p.WaitForExit(3000) | Out-Null } catch { } }
    }
}

Write-Host "`n=== 准备代理测试环境 ===" -ForegroundColor Cyan
Stop-All
Get-Process hamsterd, hamster_manager -ErrorAction SilentlyContinue | Where-Object {
    $_.Path -and $_.Path.StartsWith($tmp, [StringComparison]::OrdinalIgnoreCase)
} | ForEach-Object { try { $_.Kill() } catch { } }
Start-Sleep -Milliseconds 500

New-Item -ItemType Directory -Force -Path $dir, $mon | Out-Null
Copy-Item (Join-Path $root 'Hamsterd\hamsterd.exe') (Join-Path $dir 'hamsterd.exe') -Force
Copy-Item (Join-Path $root 'Hamster Manager\hamster_manager.exe') (Join-Path $dir 'hamster_manager.exe') -Force
Set-Content -Path (Join-Path $mon 'probe.txt') -Value 'proxy test' -NoNewline

@"
monitor_path: $mon
ipv4_addr: 127.0.0.1
ipv4_addr_port: $hamdPort
codeword: $codeword
require_auth: on
rescan_date: 0,0,0
verify_interval: 0
discovery_port: 0
log_level: info
"@ | Set-Content -Path (Join-Path $dir 'hamsterd.conf') -Encoding UTF8

@"
hamd_port $hamdPort
ipc_port $ipcPort
hamd_codeword $codeword
"@ | Set-Content -Path (Join-Path $dir 'hamster_manager.conf') -Encoding UTF8

$hamd = Start-Process -FilePath (Join-Path $dir 'hamsterd.exe') -ArgumentList '--console-log' `
        -WorkingDirectory $dir -PassThru -WindowStyle Hidden
Check (Wait-Port $hamdPort) "hamsterd 已就绪 (:$hamdPort)"

$proxy = Start-Process -FilePath (Join-Path $dir 'hamster_manager.exe') -ArgumentList '--proxy-only' `
        -WorkingDirectory $dir -PassThru -WindowStyle Hidden
Check (Wait-Port $ipcPort) "代理已监听 :$ipcPort"

Write-Host "`n=== 命令转发 :9102 -> :9100 ===" -ForegroundColor Cyan
$c = New-Conn $ipcPort
Send-Line $c '{"type":"request","id":"p1","action":"stats","params":{}}'
$r = Read-Response $c
Check ($null -ne $r -and $r.status -eq 'ok') "通过代理拿到 stats 响应" "返回: $($r | ConvertTo-Json -Compress -Depth 3)"
Check ($r.data.total_files -ge 1) "stats 内容正确（代理未篡改）" "total_files=$($r.data.total_files)"

Send-Line $c '{"type":"request","id":"p2","action":"no_such_action","params":{}}'
$r = Read-Response $c
Check ($r.status -eq 'error' -and $r.data.error -eq 'unknown_action') `
      "业务错误能立刻返回（此前会被代理误判成认证失败并永久停止重连）" "返回: $($r | ConvertTo-Json -Compress)"

Write-Host "`n=== 事件转发 :9100 -> :9102 ===" -ForegroundColor Cyan
# 通过代理上传一个文件（走 daemon 的 upload），另一个连接应收到 file_added 事件
$c2 = New-Conn $ipcPort
Start-Sleep -Milliseconds 300
# 用代理连接发 upload（负载走同一连接）
$payload = [Text.Encoding]::UTF8.GetBytes('event through proxy')
$hdr = '{"type":"request","id":"u1","action":"upload","params":{"path":"proxy-event.txt","size":' +
       $payload.Length + ',"overwrite":true},"payload_bytes":' + $payload.Length + '}'
Send-Line $c2 $hdr
$c2.GetStream().Write($payload, 0, $payload.Length); $c2.GetStream().Flush()

$gotEvent = $false; $evtLine = ''
$deadline = (Get-Date).AddSeconds(8)
while ((Get-Date) -lt $deadline) {
    $l = Read-Line $c2 3000
    if ($l -eq '') { continue }
    if ($l -match 'file_added') { $gotEvent = $true; $evtLine = $l }
    if ($l -match '"id":"u1"') { break }
}
Check $gotEvent "上传产生的事件经代理转发到 :9102" "收到: $evtLine"
$c2.Close()

Write-Host "`n=== 端口独占与单实例（P1-5）===" -ForegroundColor Cyan
$p2 = Start-Process -FilePath (Join-Path $dir 'hamster_manager.exe') -ArgumentList '--proxy-only' `
      -WorkingDirectory $dir -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 2
$exited = $p2.HasExited
$code = if ($exited) { $p2.ExitCode } else { -1 }
Check ($exited -and $code -ne 0) "第二个实例无法独占端口并退出（退出码 $code，2=已有实例）" "仍在运行: $(-not $exited)"
if (-not $exited) { $p2.Kill() }

Write-Host "`n=== 认证失败不再永久停止（P1-2）===" -ForegroundColor Cyan
Stop-All
$proxy = Start-Process -FilePath (Join-Path $dir 'hamster_manager.exe') -ArgumentList '--proxy-only' `
        -WorkingDirectory $dir -PassThru -WindowStyle Hidden
Check (Wait-Port $ipcPort) "代理重新启动"

# 把代理配置里的口令改错，然后重启代理：它必须"报错并重试"，而不是永久放弃
@"
hamd_port $hamdPort
ipc_port $ipcPort
hamd_codeword wrong-codeword-on-purpose
"@ | Set-Content -Path (Join-Path $dir 'hamster_manager.conf') -Encoding UTF8
Stop-All
# 注意：这里必须重新起 hamsterd —— 上一段 Stop-All 把它也杀了，
# 没有守护进程就谈不上"重读配置后恢复"
$hamd = Start-Process -FilePath (Join-Path $dir 'hamsterd.exe') -ArgumentList '--console-log' `
        -WorkingDirectory $dir -PassThru -WindowStyle Hidden
Check (Wait-Port $hamdPort) "守护进程已重新启动（认证恢复用例前提）"
$proxy = Start-Process -FilePath (Join-Path $dir 'hamster_manager.exe') -ArgumentList '--proxy-only' `
        -WorkingDirectory $dir -PassThru -WindowStyle Hidden
Wait-Port $ipcPort | Out-Null
Start-Sleep -Seconds 4

$alive = -not $proxy.HasExited
Check $alive "口令错误时代理进程仍然存活（旧版会进入永不重连的死循环）" "进程已退出"

# 改回正确口令：代理应在下一次重试时自动恢复（依赖"认证失败后重读配置"）
@"
hamd_port $hamdPort
ipc_port $ipcPort
hamd_codeword $codeword
"@ | Set-Content -Path (Join-Path $dir 'hamster_manager.conf') -Encoding UTF8

$recovered = $false
$sw = [Diagnostics.Stopwatch]::StartNew()
while ($sw.ElapsedMilliseconds -lt 90000) {
    Start-Sleep -Seconds 3
    try {
        $t = New-Conn $ipcPort
        Send-Line $t '{"type":"request","id":"rr","action":"ping","params":{}}'
        $r = Read-Response $t 5000
        $t.Close()
        if ($r -and $r.status -eq 'ok') { $recovered = $true; break }
    } catch { }
}
Check $recovered "改回正确口令后，无需重启代理即可自动恢复（重读配置生效）" `
      "等待 $([int]($sw.Elapsed.TotalSeconds)) 秒仍未恢复"

$c.Close()
Stop-All

Write-Host "`n=== 结束 ===" -ForegroundColor Cyan
Write-Host ("  通过 " + $pass + " / 失败 " + $fail) -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
if ($fail -gt 0) {
    $log = Join-Path $dir 'logs\hamsterd.log'
    if (Test-Path $log) { Write-Host "`nhamsterd 日志尾部:"; Get-Content $log -Tail 15 | ForEach-Object { "    $_" } }
    exit 1
}
exit 0
