#requires -Version 7.0
<#
.SYNOPSIS
    Hamster Android 手工打包流水线（完全不依赖 Gradle）。

.DESCRIPTION
    步骤：kotlinc -> d8 -> aapt2 compile/link -> (javac R.java) -> 组装 APK
          -> zipalign -p 4 -> apksigner (debug keystore)。
    所有工具都显式使用绝对路径；java/javac/keytool 强制走 -JavaHome 指定的 JDK
    （本机默认是 Android Studio 的 JBR 21，避免 PATH 上的 Java 8）。

.PARAMETER Module
    模块目录名（android/<Module>/AndroidManifest.xml）。

.PARAMETER Src
    逗号分隔的 Kotlin 源码目录（也接受单个 .kt 文件），相对路径以仓库根为基准。

.PARAMETER Classpath
    可选。逗号分隔的额外 classpath（jar 或 class 目录），同时参与 kotlinc 编译和 d8 dex。
    默认什么都不加，即只有 android.jar。

.PARAMETER Out
    输出 APK 路径，相对路径以仓库根为基准。

.PARAMETER Version
    versionName，例如 0.0.1。

.EXAMPLE
    pwsh -File android/tools/build-apk.ps1 -Module app-manager `
        -Src android/app-manager/src `
        -Out android/build/out/hamster-manager-debug.apk -Version 0.0.1
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('app-manager', 'app-daemon')]
    [string]$Module,

    [Parameter(Mandatory = $true)]
    [string]$Src,

    # 额外依赖（jar / class 目录），默认空，只用 android.jar。
    [string]$Classpath,

    [Parameter(Mandatory = $true)]
    [string]$Out,

    [string]$Version = '0.0.1',

    # 资源目录；默认 android/<Module>/res，不存在/为空时跳过 aapt2 compile。
    [string]$Res,

    [int]$MinSdk = 24,
    [int]$TargetSdk = 34,

    # 0 表示由 -Version 推算（major*10000 + minor*100 + patch）。
    [int]$VersionCode = 0,

    [string]$AndroidJar,
    [string]$BuildTools,
    [string]$JavaHome,
    # Kotlin 安装目录（含 lib\kotlin-compiler.jar）；也可用 -Kotlinc 直接给 kotlinc.bat 路径。
    [string]$KotlinHome,
    [string]$Kotlinc,
    [string]$Keystore,

    # 保留中间产物（classes / dex / 未签名 apk）便于排查。
    [switch]$KeepWork
)

$ErrorActionPreference = 'Stop'

$ScriptDir   = $PSScriptRoot
$AndroidRoot = Split-Path -Parent $ScriptDir
$RepoRoot    = Split-Path -Parent $AndroidRoot
$LogPrefix   = "[$Module]"

function Resolve-RepoPath {
    param([string]$Path)
    if ([System.IO.Path]::IsPathRooted($Path)) { return [System.IO.Path]::GetFullPath($Path) }
    return [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $Path))
}

function Invoke-Native {
    param(
        [string]$Title,
        [string]$Exe,
        [string[]]$Arguments,
        # 这些正则命中的输出行不打印（例如 d8 对 Kotlin 2.x metadata 的刷屏警告）。
        [string[]]$SuppressPattern
    )
    $preview = ($Arguments | ForEach-Object {
        if ($_ -match '\s') { '"' + $_ + '"' } else { $_ }
    }) -join ' '
    if ($preview.Length -gt 400) { $preview = $preview.Substring(0, 400) + ' ...' }
    Write-Host "$LogPrefix == $Title"
    Write-Host "$LogPrefix    $Exe $preview"

    $lines = & $Exe @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    foreach ($line in $lines) {
        $text = if ($line -is [System.Management.Automation.ErrorRecord]) { $line.ToString() } else { [string]$line }
        $skip = $false
        foreach ($p in $SuppressPattern) {
            if ($text -match $p) { $skip = $true; break }
        }
        if (-not $skip) { Write-Host $text }
    }
    if ($exitCode -ne 0) {
        throw "$Title 失败（exit code $exitCode）"
    }
}

function Find-FirstExistingPath {
    param([string[]]$Candidates)
    foreach ($c in $Candidates) {
        if ($c -and (Test-Path -LiteralPath $c)) { return (Resolve-Path -LiteralPath $c).Path }
    }
    return $null
}

function Test-HasKotlinRuntime {
    # 判断一个 jar/目录里是否自带 Kotlin 运行时（fat jar 现象，例如 protocol-core.jar）。
    param([string]$Path)
    if (Test-Path -LiteralPath $Path -PathType Container) {
        return (Test-Path -LiteralPath (Join-Path $Path 'kotlin\Unit.class'))
    }
    if ($Path -notmatch '\.jar$') { return $false }
    $z = [System.IO.Compression.ZipFile]::OpenRead($Path)
    try {
        return ($null -ne $z.GetEntry('kotlin/Unit.class'))
    } finally {
        $z.Dispose()
    }
}

function Get-AndroidSdkRoot {
    $candidates = @()
    if ($env:ANDROID_HOME)     { $candidates += $env:ANDROID_HOME }
    if ($env:ANDROID_SDK_ROOT) { $candidates += $env:ANDROID_SDK_ROOT }
    $candidates += (Join-Path $env:LOCALAPPDATA 'Android\Sdk')
    $candidates += 'C:\Users\Hsiak\AppData\Local\Android\Sdk'
    foreach ($c in $candidates) {
        if ($c -and (Test-Path -LiteralPath (Join-Path $c 'platform-tools\adb.exe'))) {
            return (Resolve-Path -LiteralPath $c).Path
        }
    }
    throw "找不到 Android SDK：请设置 ANDROID_HOME，或用 -AndroidJar / -BuildTools 显式指定。"
}

try {
    Write-Host "$LogPrefix ==============================================="
    Write-Host "$LogPrefix Hamster 手工 APK 流水线（Kotlin / d8 / aapt2 / apksigner）"
    Write-Host "$LogPrefix ==============================================="

    # ---------------------------------------------------------------- 工具发现
    $SdkRoot = if ($AndroidJar -and $BuildTools) { Split-Path -Parent (Split-Path -Parent $BuildTools) } else { Get-AndroidSdkRoot }

    if (-not $BuildTools) {
        $btRoot = Join-Path $SdkRoot 'build-tools'
        $BuildTools = Get-ChildItem -LiteralPath $btRoot -Directory |
            Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'aapt2.exe') } |
            Sort-Object { try { [version]($_.Name -replace '[^0-9.]', '') } catch { [version]'0.0.0' } } -Descending |
            Select-Object -First 1 -ExpandProperty FullName
    }
    if (-not $BuildTools -or -not (Test-Path -LiteralPath (Join-Path $BuildTools 'aapt2.exe'))) {
        throw "找不到 build-tools（需要 aapt2.exe）：$BuildTools"
    }

    if (-not $AndroidJar) {
        $p = Join-Path $SdkRoot "platforms\android-$TargetSdk\android.jar"
        if (Test-Path -LiteralPath $p) {
            $AndroidJar = $p
        } else {
            $plat = Get-ChildItem -LiteralPath (Join-Path $SdkRoot 'platforms') -Directory |
                Where-Object { $_.Name -match '^android-(\d+)$' } |
                Sort-Object { [int]($_.Name -replace '^android-', '') } -Descending |
                Select-Object -First 1
            if (-not $plat) { throw "找不到 platforms/android-*/android.jar" }
            $AndroidJar = Join-Path $plat.FullName 'android.jar'
            Write-Host "$LogPrefix ! 没有 android-$TargetSdk，退回 $($plat.Name) 编译"
        }
    }

    if (-not $JavaHome) {
        $JavaHome = Find-FirstExistingPath @(
            'C:\Program Files\Android\Android Studio\jbr',
            'C:\Program Files\Android\Android Studio\jre',
            $env:JAVA_HOME,
            (Join-Path $env:LOCALAPPDATA 'Programs\Android Studio\jbr')
        )
    }
    if (-not $JavaHome -or -not (Test-Path -LiteralPath (Join-Path $JavaHome 'bin\javac.exe'))) {
        throw "找不到 JDK（需要 bin\java.exe 与 bin\javac.exe）：$JavaHome"
    }
    $JavaExe   = Join-Path $JavaHome 'bin\java.exe'
    $JavacExe  = Join-Path $JavaHome 'bin\javac.exe'
    $JarExe    = Join-Path $JavaHome 'bin\jar.exe'
    $KeytoolExe = Join-Path $JavaHome 'bin\keytool.exe'
    foreach ($exe in @($JavaExe, $JavacExe, $JarExe, $KeytoolExe)) {
        if (-not (Test-Path -LiteralPath $exe)) { throw "JDK 缺少工具：$exe" }
    }

    # 统一 JAVA_HOME 指向 JBR，避免任何工具回落到 PATH 上的 Java 8。
    $env:JAVA_HOME = $JavaHome
    $env:PATH = (Join-Path $JavaHome 'bin') + ';' + $env:PATH

    if (-not $KotlinHome) {
        $KotlinHome = Find-FirstExistingPath @(
            'C:\Program Files\kotlinc',
            (Join-Path $env:USERPROFILE 'kotlinc'),
            $env:KOTLIN_HOME
        )
    }
    if (-not $KotlinHome -and $Kotlinc) {
        # 兼容 -Kotlinc <...\bin\kotlinc.bat>
        $KotlinHome = Split-Path -Parent (Split-Path -Parent $Kotlinc)
    }
    if (-not $KotlinHome) {
        throw "找不到 Kotlin 安装目录，请用 -KotlinHome 指定（含 lib\kotlin-compiler.jar）。"
    }

    # 关键：不经过 kotlinc.bat。cmd 会把分号分隔的 -classpath 拆成多个参数，
    # 导致额外依赖 jar 被当成源码；这里直接用 JBR java 调编译器主类。
    $CompilerJar = Join-Path $KotlinHome 'lib\kotlin-compiler.jar'
    $StdlibJar   = Join-Path $KotlinHome 'lib\kotlin-stdlib.jar'
    foreach ($jar in @($CompilerJar, $StdlibJar)) {
        if (-not (Test-Path -LiteralPath $jar)) { throw "Kotlin 目录缺少 $jar" }
    }

    $Aapt2     = Join-Path $BuildTools 'aapt2.exe'
    $Zipalign  = Join-Path $BuildTools 'zipalign.exe'
    $D8Jar     = Join-Path $BuildTools 'lib\d8.jar'
    if (-not (Test-Path -LiteralPath $D8Jar)) { $D8Jar = Join-Path $BuildTools 'd8.jar' }
    $ApkSignerJar = Join-Path $BuildTools 'lib\apksigner.jar'
    if (-not (Test-Path -LiteralPath $ApkSignerJar)) { $ApkSignerJar = Join-Path $BuildTools 'apksigner.jar' }
    foreach ($tool in @($Aapt2, $Zipalign, $D8Jar, $ApkSignerJar)) {
        if (-not (Test-Path -LiteralPath $tool)) { throw "缺少打包工具：$tool" }
    }

    # ---------------------------------------------------------------- 输入校验
    $ModuleDir = Join-Path $AndroidRoot $Module
    $Manifest  = Join-Path $ModuleDir 'AndroidManifest.xml'
    if (-not (Test-Path -LiteralPath $Manifest)) { throw "模块 manifest 不存在：$Manifest" }

    $SourceEntries = @()
    foreach ($item in ($Src -split ',')) {
        $trimmed = $item.Trim()
        if (-not $trimmed) { continue }
        $full = Resolve-RepoPath $trimmed
        if (Test-Path -LiteralPath $full -PathType Container) {
            $SourceEntries += $full
        } elseif (Test-Path -LiteralPath $full -PathType Leaf) {
            if ($full -notmatch '\.kt$') { throw "不是 .kt 文件：$full" }
            $SourceEntries += $full
        } else {
            throw "源码路径不存在：$full"
        }
    }
    if ($SourceEntries.Count -eq 0) { throw "-Src 没有给出有效的源码路径。" }

    $ExtraClasspath = @()
    foreach ($item in ($Classpath -split ',')) {
        $trimmed = $item.Trim()
        if (-not $trimmed) { continue }
        $full = Resolve-RepoPath $trimmed
        if (-not (Test-Path -LiteralPath $full)) { throw "额外 classpath 不存在：$full" }
        if ($full -match '\.kt$') { throw "额外 classpath 不接受源码文件：$full" }
        $ExtraClasspath += $full
    }
    $KotlincClasspath = (@($AndroidJar) + $ExtraClasspath) -join ';'

    if (-not $Res) {
        $defaultRes = Join-Path $ModuleDir 'res'
        if (Test-Path -LiteralPath $defaultRes) { $Res = $defaultRes }
    }
    $ResDir = if ($Res) { Resolve-RepoPath $Res } else { $null }
    if ($ResDir -and -not (Test-Path -LiteralPath $ResDir)) { throw "资源目录不存在：$ResDir" }

    $OutApk = Resolve-RepoPath $Out
    $OutDir = Split-Path -Parent $OutApk
    if (-not (Test-Path -LiteralPath $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }

    if ($VersionCode -le 0) {
        $nums = @()
        foreach ($seg in ($Version -split '[^0-9]+')) {
            if ($seg -ne '') { $nums += [int]$seg }
        }
        while ($nums.Count -lt 3) { $nums += 0 }
        $VersionCode = $nums[0] * 10000 + $nums[1] * 100 + $nums[2]
        if ($VersionCode -le 0) { $VersionCode = 1 }
    }

    if (-not $Keystore) { $Keystore = Join-Path $env:USERPROFILE '.android\debug.keystore' }
    $Keystore = Resolve-RepoPath $Keystore

    Write-Host "$LogPrefix SDK        : $SdkRoot"
    Write-Host "$LogPrefix build-tools: $BuildTools"
    Write-Host "$LogPrefix android.jar: $AndroidJar"
    Write-Host "$LogPrefix JDK        : $JavaHome"
    Write-Host "$LogPrefix Kotlin     : $KotlinHome"
    Write-Host "$LogPrefix version    : $Version ($VersionCode), minSdk=$MinSdk targetSdk=$TargetSdk"

    # ---------------------------------------------------------------- 工作目录
    $WorkDir = Join-Path $AndroidRoot "build\apk-work\$Module"
    if (Test-Path -LiteralPath $WorkDir) { Remove-Item -LiteralPath $WorkDir -Recurse -Force }
    $ClassesDir = Join-Path $WorkDir 'classes'
    $DexDir     = Join-Path $WorkDir 'dex'
    $GenDir     = Join-Path $WorkDir 'gen'
    $StageDir   = Join-Path $WorkDir 'stage'
    foreach ($d in @($WorkDir, $ClassesDir, $DexDir, $GenDir)) {
        New-Item -ItemType Directory -Path $d -Force | Out-Null
    }
    $UnsignedApk = Join-Path $WorkDir 'unsigned.apk'
    $PackagedApk = Join-Path $WorkDir 'packaged.apk'
    $AlignedApk  = Join-Path $WorkDir 'aligned.apk'

    # 1) Kotlin -> class
    $KtFiles = @()
    foreach ($entry in $SourceEntries) {
        if (Test-Path -LiteralPath $entry -PathType Container) {
            $KtFiles += (Get-ChildItem -LiteralPath $entry -Recurse -File -Filter '*.kt').FullName
        } else {
            $KtFiles += $entry
        }
    }
    $KtFiles = @($KtFiles | Select-Object -Unique)
    if ($KtFiles.Count -eq 0) { throw "源码路径里没有 .kt 文件：$($SourceEntries -join ', ')" }

    $KotlincArgs = @(
        "-Dkotlin.home=$KotlinHome",
        '-cp', $CompilerJar,
        'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler',
        '-no-reflect',
        '-classpath', $KotlincClasspath,
        '-jvm-target', '1.8',
        '-d', $ClassesDir
    ) + $KtFiles
    Invoke-Native 'kotlinc 编译 Kotlin 源码（JBR java 直调）' $JavaExe $KotlincArgs
    if (-not (Get-ChildItem -LiteralPath $ClassesDir -Recurse -File -Filter '*.class')) {
        throw "kotlinc 没有产出任何 .class"
    }

    # 2) aapt2 compile（无资源则跳过）+ link（有资源时生成 R.java）
    $ResFiles = @()
    if ($ResDir) { $ResFiles = @(Get-ChildItem -LiteralPath $ResDir -Recurse -File) }

    $LinkArgs = @(
        'link',
        '-o', $UnsignedApk,
        '-I', $AndroidJar,
        '--manifest', $Manifest,
        '--min-sdk-version', "$MinSdk",
        '--target-sdk-version', "$TargetSdk",
        '--version-code', "$VersionCode",
        '--version-name', $Version
    )
    if ($ResFiles.Count -gt 0) {
        $ResZip = Join-Path $WorkDir 'resources.zip'
        Invoke-Native 'aapt2 compile 资源' $Aapt2 @('compile', '--dir', $ResDir, '-o', $ResZip)
        $LinkArgs += $ResZip
        $LinkArgs += @('--java', $GenDir)
    } else {
        Write-Host "$LogPrefix == 模块没有资源，跳过 aapt2 compile（manifest 只用 @android: 资源）"
    }
    Invoke-Native 'aapt2 link（manifest + 资源 -> 未签名 APK）' $Aapt2 $LinkArgs
    if (-not (Test-Path -LiteralPath $UnsignedApk)) { throw "aapt2 link 没有产出 APK：$UnsignedApk" }

    # 3) 若有 R.java，用 javac 编译后并入 class 目录
    $RJavaFiles = @()
    if (Test-Path -LiteralPath $GenDir) {
        $RJavaFiles = @(Get-ChildItem -LiteralPath $GenDir -Recurse -File -Filter '*.java')
    }
    if ($RJavaFiles.Count -gt 0) {
        Invoke-Native 'javac 编译 R.java' $JavacExe (@(
            '-encoding', 'UTF-8',
            '-source', '8', '-target', '8',
            '-classpath', $AndroidJar,
            '-d', $ClassesDir
        ) + $RJavaFiles.FullName)
    } else {
        Write-Host "$LogPrefix == 没有生成 R.java，无需 javac"
    }

    # 4) d8：class + kotlin-stdlib.jar -> classes.dex
    #    d8 不接受目录输入，先把 class 目录打成 jar。
    $ClassesJar = Join-Path $WorkDir 'classes.jar'
    Invoke-Native '打包 class 为 jar（d8 输入）' $JarExe @('cf', $ClassesJar, '-C', $ClassesDir, '.')

    $DexInputs = @($ClassesJar)
    $extraHasKotlinRuntime = $false
    foreach ($extra in $ExtraClasspath) {
        if (Test-HasKotlinRuntime $extra) { $extraHasKotlinRuntime = $true }
        $DexInputs += $extra
    }
    if ($extraHasKotlinRuntime) {
        Write-Host "$LogPrefix == 额外 classpath 自带 Kotlin 运行时（fat jar），d8 不再重复加入 kotlin-stdlib"
    } else {
        $DexInputs += $StdlibJar
    }

    Invoke-Native 'd8 dex（含 kotlin-stdlib）' $JavaExe (@(
        '-cp', $D8Jar,
        'com.android.tools.r8.D8',
        '--min-api', "$MinSdk",
        '--lib', $AndroidJar,
        '--output', $DexDir
    ) + $DexInputs) -SuppressPattern @(
        'compatible kotlin versions',
        'parsing kotlin metadata',
        'Unexpected error while reading',
        'kotlinx-metadata-jvm'
    )
    $DexFile = Join-Path $DexDir 'classes.dex'
    if (-not (Test-Path -LiteralPath $DexFile)) { throw "d8 没有产出 classes.dex" }

    # 5) 组装 APK：解包 aapt2 产物，放入 classes.dex，再用 JDK jar 重新打包。
    #    用 -0 让所有条目 STORED（未压缩）：这样 resources.arsc 一定未压缩，
    #    zipalign -p 4 才能满足 targetSdk 30+ 的 "arsc 未压缩且 4 字节对齐" 要求。
    #    代价是 APK 体积比压缩版大一些（本模块仍是 MB 级）。
    Write-Host "$LogPrefix == 组装 APK（jar cfM0，全部 STORED，保证 resources.arsc 未压缩）"
    [System.IO.Compression.ZipFile]::ExtractToDirectory($UnsignedApk, $StageDir)
    Copy-Item -LiteralPath $DexFile -Destination (Join-Path $StageDir 'classes.dex') -Force
    if (Test-Path -LiteralPath $PackagedApk) { Remove-Item -LiteralPath $PackagedApk -Force }
    Invoke-Native 'jar 打包 APK（STORED）' $JarExe @('cfM0', $PackagedApk, '-C', $StageDir, '.')

    Invoke-Native 'zipalign -p 4' $Zipalign @('-p', '-f', '4', $PackagedApk, $AlignedApk)

    # 6) 签名（debug keystore，缺失则用 keytool 现场生成）
    if (-not (Test-Path -LiteralPath $Keystore)) {
        $ksDir = Split-Path -Parent $Keystore
        if (-not (Test-Path -LiteralPath $ksDir)) { New-Item -ItemType Directory -Path $ksDir -Force | Out-Null }
        Write-Host "$LogPrefix == debug.keystore 不存在，生成：$Keystore"
        Invoke-Native 'keytool 生成 debug.keystore' $KeytoolExe @(
            '-genkeypair',
            '-keystore', $Keystore,
            '-storetype', 'PKCS12',
            '-storepass', 'android',
            '-keypass', 'android',
            '-alias', 'androiddebugkey',
            '-keyalg', 'RSA',
            '-keysize', '2048',
            '-validity', '10000',
            '-dname', 'CN=Android Debug,O=Android,C=US'
        )
    }

    if (Test-Path -LiteralPath $OutApk) { Remove-Item -LiteralPath $OutApk -Force }
    Invoke-Native 'apksigner 签名（debug）' $JavaExe @(
        '-jar', $ApkSignerJar,
        'sign',
        '--ks', $Keystore,
        '--ks-key-alias', 'androiddebugkey',
        '--ks-pass', 'pass:android',
        '--key-pass', 'pass:android',
        '--min-sdk-version', "$MinSdk",
        '--v1-signing-enabled', 'true',
        '--v2-signing-enabled', 'true',
        '--out', $OutApk,
        $AlignedApk
    )
    if (-not (Test-Path -LiteralPath $OutApk)) { throw "apksigner 没有产出 APK：$OutApk" }

    Invoke-Native 'apksigner verify' $JavaExe @(
        '-jar', $ApkSignerJar, 'verify', '--verbose', '--print-certs', $OutApk
    )

    $apkInfo = Get-Item -LiteralPath $OutApk
    $sizeMb = [math]::Round($apkInfo.Length / 1MB, 2)
    $hash = (Get-FileHash -LiteralPath $OutApk -Algorithm SHA256).Hash

    # 摘要里的包名/启动 Activity 从产物本身读，避免脚本里的字符串和真实 manifest 漂移。
    $badging = & $Aapt2 dump badging $OutApk 2>$null
    $pkgName = ($badging | Select-String -Pattern "^package: name='([^']+)'" |
        ForEach-Object { $_.Matches[0].Groups[1].Value } | Select-Object -First 1)
    $launchAct = ($badging | Select-String -Pattern "^launchable-activity: name='([^']+)'" |
        ForEach-Object { $_.Matches[0].Groups[1].Value } | Select-Object -First 1)
    if (-not $pkgName) { $pkgName = '?' }
    if (-not $launchAct) { $launchAct = '(无启动 Activity)' }

    Write-Host ""
    Write-Host "$LogPrefix package   : $pkgName"
    Write-Host "$LogPrefix activity  : $launchAct"
    Write-Host "$LogPrefix version   : $Version ($VersionCode)"
    Write-Host "$LogPrefix sha256    : $hash"

    if (-not $KeepWork) { Remove-Item -LiteralPath $WorkDir -Recurse -Force -ErrorAction SilentlyContinue }

    Write-Host ("BUILD OK: {0} {1:N2} MB" -f $OutApk, $sizeMb)
    exit 0
}
catch {
    Write-Host ""
    Write-Host "$LogPrefix BUILD FAILED: $($_.Exception.Message)" -ForegroundColor Red
    if ($_.ScriptStackTrace) { Write-Host "$LogPrefix   at $($_.ScriptStackTrace)" -ForegroundColor DarkGray }
    exit 1
}
