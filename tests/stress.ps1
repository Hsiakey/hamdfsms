# Hamsterd 并发压力测试
#
# 目的：验证"长度前缀分帧 + 每连接写锁"在高并发下不会被破坏。
# 这正是 0.0.7 的核心缺陷（二进制当字符串处理、响应与事件交错），
# 因此必须用一个"逐行校验 JSON 合法性"的监听连接来抓流损坏。
#
# 运行: powershell -ExecutionPolicy Bypass -File tests/stress.ps1 [-Workers 8] [-Rounds 5]

param(
    [int]$Workers = 8,
    [int]$Rounds  = 5
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$tmp  = Join-Path $PSScriptRoot 'tmp'
$dir  = Join-Path $tmp 'stress'
$mon  = Join-Path $dir 'monitor'
$hamdPort = 19400
$cw = 'hamster-stress-0123456789abcdef0123'
$hamd = $null

$script:streams = @{}
function S($c) {
    if (-not $script:streams.ContainsKey($c)) {
        $script:streams[$c] = New-Object IO.BufferedStream ($c.GetStream()), 65536
    }
    return $script:streams[$c]
}
function New-Conn([int]$p) {
    $c = New-Object System.Net.Sockets.TcpClient
    $c.Connect('127.0.0.1', $p)
    $c.ReceiveTimeout = 20000
    return $c
}
function Send-Line($c, [string]$t) {
    $b = [Text.Encoding]::UTF8.GetBytes($t + "`n")
    $c.GetStream().Write($b, 0, $b.Length); $c.GetStream().Flush()
}
function Read-Line($c, [int]$t = 15000) {
    $s = $c.GetStream(); $c.ReceiveTimeout = $t
    $ms = New-Object IO.MemoryStream
    try { while ($true) { $b = $bs.ReadByte(); if ($b -lt 0 -or $b -eq 10) { break }; $ms.WriteByte([byte]$b) } } catch { }
    return [Text.Encoding]::UTF8.GetString($ms.ToArray())
}
function Read-Exact($c, [int]$n) {
    $s = $c.GetStream()
    $buf = New-Object byte[] $n
    $got = 0
    while ($got -lt $n) { $r = $s.Read($buf, $got, $n - $got); if ($r -le 0) { break }; $got += $r }
    return $got
}
function Auth($p, $id) {
    $c = New-Conn $p
    Send-Line $c (@{ type='request'; id='h'; action='hello'; params=@{ device_id=$id; codeword=$cw } } | ConvertTo-Json -Compress -Depth 5)
    $r = Read-Line $c
    if ($r -notmatch '"status":"ok"') { throw "认证失败: $r" }
    return $c
}

Write-Host "`n=== 准备并发测试环境 ===" -ForegroundColor Cyan
Get-Process hamsterd -ErrorAction SilentlyContinue | Where-Object {
    $_.Path -and $_.Path.StartsWith($tmp, [StringComparison]::OrdinalIgnoreCase)
} | ForEach-Object { try { $_.Kill() } catch { } }
Start-Sleep -Milliseconds 500
Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $mon | Out-Null
Copy-Item (Join-Path $root 'Hamsterd\hamsterd.exe') (Join-Path $dir 'hamsterd.exe') -Force

# 20 个不同大小的文件（含中文名与二进制内容）
$rnd = New-Object Random 7
1..20 | ForEach-Object {
    $size = 1024 * (10 + $rnd.Next(1, 400))
    $bytes = New-Object byte[] $size
    $rnd.NextBytes($bytes)
    $name = if ($_ % 5 -eq 0) { "文件_$_.bin" } else { "file_$_.bin" }
    [IO.File]::WriteAllBytes((Join-Path $mon $name), $bytes)
}
Set-Content (Join-Path $mon 'readme.txt') 'stress test' -NoNewline

@"
monitor_path: $mon
ipv4_addr: 127.0.0.1
ipv4_addr_port: $hamdPort
codeword: $cw
require_auth: on
# 压测用明文客户端直连（不测加密开销）；加密路径见 tests/protocol-secure.js。
encrypt_transport: off
rescan_date: 0,0,0
verify_interval: 0
discovery_port: 0
max_clients: 32
log_level: warn
log_dir: logs
"@ | Set-Content (Join-Path $dir 'hamsterd.conf') -Encoding UTF8

$hamd = Start-Process -FilePath (Join-Path $dir 'hamsterd.exe') -ArgumentList '--console-log' `
        -WorkingDirectory $dir -PassThru -WindowStyle Hidden
$ready = $false
for ($i = 0; $i -lt 60; $i++) {
    Start-Sleep -Milliseconds 250
    try { $t = New-Conn $hamdPort; $t.Close(); $ready = $true; break } catch { }
}
if (-not $ready) { if ($hamd -and -not $hamd.HasExited) { $hamd.Kill() }; throw "守护进程未就绪" }
Write-Host "  守护进程就绪，文件数 21，并发 $Workers × $Rounds 轮"

Write-Host "`n=== 并发执行 ===" -ForegroundColor Cyan
$files = Get-ChildItem $mon -File | ForEach-Object { $_.Name }
$sw = [Diagnostics.Stopwatch]::StartNew()

# 事件监听者：把每一行都当 JSON 解析，任何一行不合法就说明流被破坏
$listener = Start-ThreadJob -ScriptBlock {
    param($port, $cw, $seconds)
    $bad = 0; $events = 0; $responses = 0
    try {
        $c = New-Object Net.Sockets.TcpClient
        $c.Connect('127.0.0.1', $port); $c.ReceiveTimeout = 1500
        $bs = New-Object IO.BufferedStream ($c.GetStream()), 65536
        $b = [Text.Encoding]::UTF8.GetBytes((@{type='request';id='hl';action='hello';params=@{device_id='listener';codeword=$cw}} | ConvertTo-Json -Compress -Depth 5) + "`n")
        $c.GetStream().Write($b, 0, $b.Length); $c.GetStream().Flush()
        $deadline = (Get-Date).AddSeconds($seconds)
        while ((Get-Date) -lt $deadline) {
            $ms = New-Object IO.MemoryStream
            try { while ($true) { $x = $bs.ReadByte(); if ($x -lt 0 -or $x -eq 10) { break }; $ms.WriteByte([byte]$x) } } catch { continue }
            $line = [Text.Encoding]::UTF8.GetString($ms.ToArray())
            if ($line -eq '') { continue }
            try { $null = $line | ConvertFrom-Json } catch { $bad++ }
            if ($line -match '"type":"event"') { $events++ } else { $responses++ }
        }
        $c.Close()
    } catch { }
    return @{ bad = $bad; events = $events; responses = $responses }
} -ArgumentList $hamdPort, $cw, ([int]($Workers * $Rounds * 2 + 15))

$sw = [Diagnostics.Stopwatch]::StartNew()
$results = 1..$Workers | ForEach-Object -Parallel {
    $port = $using:hamdPort; $cw = $using:cw; $files = $using:files; $rounds = $using:Rounds
    $wid = $_
    $errs = @(); $ops = 0

    $script:streams = @{}
    function S($c) {
        if (-not $script:streams.ContainsKey($c)) {
            $script:streams[$c] = New-Object IO.BufferedStream ($c.GetStream()), 65536
        }
        return $script:streams[$c]
    }
    function L-Conn([int]$p) { $c = New-Object Net.Sockets.TcpClient; $c.Connect('127.0.0.1', $p); $c.ReceiveTimeout = 20000; return $c }
    function L-Send($c, [string]$t) { $b = [Text.Encoding]::UTF8.GetBytes($t + "`n"); $c.GetStream().Write($b,0,$b.Length); $c.GetStream().Flush() }
    function L-Line($c, [int]$t = 15000) {
        $c.ReceiveTimeout = $t; $ms = New-Object IO.MemoryStream
        try { while ($true) { $x = (S $c).ReadByte(); if ($x -lt 0 -or $x -eq 10) { break }; $ms.WriteByte([byte]$x) } } catch { }
        return [Text.Encoding]::UTF8.GetString($ms.ToArray())
    }
    function L-Exact($c, [int]$n) {
        $buf = New-Object byte[] $n; $got = 0
        while ($got -lt $n) { $r = (S $c).Read($buf, $got, $n - $got); if ($r -le 0) { break }; $got += $r }
        return $got
    }
    function L-Resp($c, [int]$t = 15000) {
        $deadline = (Get-Date).AddMilliseconds($t)
        while ((Get-Date) -lt $deadline) {
            $left = [int]($deadline - (Get-Date)).TotalMilliseconds
            if ($left -le 0) { return $null }
            $l = L-Line $c $left
            if ($l -eq '') { return $null }
            if ($l -match '"type":"event"') { continue }
            try { return ($l | ConvertFrom-Json) } catch { $script:errs += "响应不是合法 JSON: $l"; return $null }
        }
        return $null
    }

    try {
        $c = L-Conn $port
        L-Send $c (@{type='request';id='h';action='hello';params=@{device_id="w$wid";codeword=$cw}} | ConvertTo-Json -Compress -Depth 5)
        $h = L-Line $c
        if ($h -notmatch '"status":"ok"') { throw "认证失败: $h" }

        for ($r = 0; $r -lt $rounds; $r++) {
            # 1) 下载随机文件并严格校验字节数
            $f = $files[(Get-Random -Maximum $files.Count)]
            L-Send $c (@{type='request';id="d$r";action='download';params=@{path=$f}} | ConvertTo-Json -Compress -Depth 5)
            $hdr = L-Resp $c
            if (-not $hdr -or $hdr.status -ne 'ok') { $errs += "download 失败: $($hdr | ConvertTo-Json -Compress)"; break }
            $got = L-Exact $c ([int]$hdr.data.payload_bytes)
            if ($got -ne [int]$hdr.data.payload_bytes) {
                $errs += "下载字节数不符: 声明=$($hdr.data.payload_bytes) 实际=$got"
            }
            $ops++

            # 2) 搜索
            L-Send $c (@{type='request';id="s$r";action='search';params=@{q='file_';limit=5}} | ConvertTo-Json -Compress -Depth 5)
            $sr = L-Resp $c
            if (-not $sr -or $sr.status -ne 'ok') { $errs += "search 失败"; break }
            $ops++

            # 3) 上传一个小文件（同名覆盖，避免冲突）
            $payload = [Text.Encoding]::UTF8.GetBytes("worker $wid round $r " + ('x' * 200))
            $path = "up/w$wid-r$r.txt"
            $hdrLine = (@{type='request';id="u$r";action='upload';
                          params=@{path=$path;size=$payload.Length;overwrite=$true;mkdir=$true};
                          payload_bytes=$payload.Length} | ConvertTo-Json -Compress -Depth 5)
            L-Send $c $hdrLine
            $c.GetStream().Write($payload, 0, $payload.Length); $c.GetStream().Flush()
            $ur = L-Resp $c 20000
            if (-not $ur -or $ur.status -ne 'ok') { $errs += "upload 失败: $($ur | ConvertTo-Json -Compress)"; break }
            $ops++
        }
        $c.Close()
    } catch { $errs += "异常: $_" }

    return @{ worker = $wid; ops = $ops; errors = $errs }
} -ThrottleLimit $Workers

$listenerResult = Receive-Job -Job $listener -Wait
Remove-Job -Job $listener -Force

$sw.Stop()
$totalOps = ($results | Measure-Object -Property ops -Sum).Sum
$allErrors = @()
foreach ($r in $results) { foreach ($e in $r.errors) { $allErrors += "worker $($r.worker): $e" } }

Write-Host ("  墙钟时间 {0:N1}s（该值含监听任务存活时间，不是吞吐指标），完成操作 {1} 次" -f $sw.Elapsed.TotalSeconds, $totalOps)

Write-Host "`n=== 结果 ===" -ForegroundColor Cyan
$pass = 0; $fail = 0
function Check-Result($cond, $msg, $detail) {
    if ($cond) { $script:pass++; Write-Host "  [PASS] $msg" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $msg" -ForegroundColor Red; if ($detail) { Write-Host "         $detail" -ForegroundColor DarkYellow } }
}
Check-Result ($allErrors.Count -eq 0) "所有并发操作成功（无字节数不符/无解析失败）" (($allErrors | Select-Object -First 5) -join ' | ')
Check-Result ($listenerResult.bad -eq 0) "监听连接收到的每一行都是合法 JSON（流未被交错破坏）" "非法行数=$($listenerResult.bad)"
Check-Result ($listenerResult.events -gt 0) "并发期间确实收到了事件（$($listenerResult.events) 条）" "events=$($listenerResult.events)"
Check-Result ($totalOps -ge ($Workers * $Rounds * 3 * 0.95)) "操作总数达到预期" "实际 $totalOps，期望约 $($Workers * $Rounds * 3)"

if ($hamd -and -not $hamd.HasExited) { $hamd.Kill(); $hamd.WaitForExit(3000) | Out-Null }
Write-Host "`n  通过 $pass / 失败 $fail" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
if ($fail -gt 0) {
    $log = Join-Path $dir 'logs\hamsterd.log'
    if (Test-Path $log) { Write-Host "`nhamsterd 日志尾部:"; Get-Content $log -Tail 20 | ForEach-Object { "    $_" } }
    exit 1
}
exit 0
