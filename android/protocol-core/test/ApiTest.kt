/*
 * ApiTest.kt — HamsterApi ⇄ 真实 hamsterd 的联调测试（自包含：自己起、自己收）
 *
 * 覆盖：
 *   1. 用临时目录 + 自定义端口（默认 TCP 29170 / discovery 29171）起一个真 hamsterd，
 *      conf 显式写 encrypt_transport: on；
 *   2. 明文请求拿不到任何响应（证明确实开着 §8 加密）；
 *   3. 错误口令 → SecureException（auth/socket_closed 语义），且异常里不含口令；
 *   4. stats() 字段合理、listFiles("/") 不崩；
 *   5. 200 KiB 文件下载回来与源文件 SHA-256 一致（progress 收到最终值）；
 *   6. 160 KiB 文件上传（跨 64 KiB 记录）后服务端落盘 SHA-256 一致；
 *      再 listFiles 能看到；再用服务端绝对路径下载回来比对；
 *   7. 中文/带空格文件名上传、子目录上传（daemon 侧 mkdir）与列举；
 *   8. 服务端错误码透传（file_not_found / not_found / exists），且错误后连接仍可用；
 *   9. 连接不存在端口 / 不可达地址 → HamsterApiException 且有时间上界；
 *  10. close() 两次不抛；关闭后调用得到 closed。
 *
 * 结束时必须杀掉自己起的 hamsterd：本程序用 destroyForcibly 并校验端口释放；
 * 外层 PowerShell 再按 build/api/live/hamsterd.pid 用 Stop-Process 兜底。
 *
 * 用法（工作目录 android/protocol-core）：
 *   java -cp build\api\api-test.jar hamster.ApiTestKt [--port 29170] [--base build\api\live]
 */
package hamster

import java.io.File
import java.io.FileDescriptor
import java.io.FileOutputStream
import java.io.IOException
import java.io.PrintStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.security.MessageDigest
import java.util.concurrent.TimeUnit

private var passCount = 0
private var failCount = 0

private fun check(cond: Boolean, name: String, detail: String = ""): Boolean {
    if (cond) {
        passCount++
        println("  [PASS] $name")
    } else {
        failCount++
        println("  [FAIL] $name" + if (detail.isNotEmpty()) "  -> $detail" else "")
    }
    return cond
}

private fun sha256Hex(bytes: ByteArray): String {
    val d = MessageDigest.getInstance("SHA-256").digest(bytes)
    val hex = "0123456789abcdef"
    val sb = StringBuilder(d.size * 2)
    for (b in d) {
        val v = b.toInt() and 0xff
        sb.append(hex[v ushr 4]).append(hex[v and 15])
    }
    return sb.toString()
}

private fun sha256Hex(f: File): String = sha256Hex(f.readBytes())

private fun makePatternFile(f: File, size: Int, salt: Int) {
    f.parentFile?.mkdirs()
    val out = FileOutputStream(f)
    try {
        val buf = ByteArray(8192)
        var written = 0
        while (written < size) {
            val n = minOf(buf.size, size - written)
            for (i in 0 until n) {
                buf[i] = (((written + i) * 31) + salt and 0xff).toByte()
            }
            out.write(buf, 0, n)
            written += n
        }
    } finally {
        out.close()
    }
}

private fun rmrf(f: File) {
    if (f.exists()) f.deleteRecursively()
}

private fun portFree(port: Int): Boolean = try {
    ServerSocket(port).use { true }
} catch (_: IOException) {
    false
}

private fun waitTcp(port: Int, timeoutMs: Int): Boolean {
    val deadline = System.currentTimeMillis() + timeoutMs
    while (System.currentTimeMillis() < deadline) {
        try {
            Socket().use { s ->
                s.connect(InetSocketAddress("127.0.0.1", port), 300)
                return true
            }
        } catch (_: IOException) {
        }
        try {
            Thread.sleep(150)
        } catch (_: InterruptedException) {
            return false
        }
    }
    return false
}

/** 进程退出后内核回收监听套接字可能晚几毫秒；这里轮询到"连接被拒"为止。 */
private fun waitPortClosed(port: Int, timeoutMs: Int): Boolean {
    val deadline = System.currentTimeMillis() + timeoutMs
    while (System.currentTimeMillis() < deadline) {
        val refused = try {
            Socket().use { s -> s.connect(InetSocketAddress("127.0.0.1", port), 300) }
            false
        } catch (_: IOException) {
            true
        }
        if (refused) return true
        try {
            Thread.sleep(150)
        } catch (_: InterruptedException) {
            return false
        }
    }
    return false
}

/** 发一条明文 ping；返回收到的明文（null = 一个字节都没回）。 */
private fun plaintextPing(port: Int): String? {
    return try {
        Socket().use { s ->
            s.connect(InetSocketAddress("127.0.0.1", port), 1500)
            s.soTimeout = 1500
            val line = "{\"type\":\"request\",\"id\":\"plain-1\",\"action\":\"ping\"}\n"
            s.getOutputStream().write(line.toByteArray(Charsets.UTF_8))
            s.getOutputStream().flush()
            val buf = ByteArray(256)
            val n = try {
                s.getInputStream().read(buf)
            } catch (_: SocketTimeoutException) {
                -1
            }
            if (n > 0) String(buf, 0, n, Charsets.UTF_8) else null
        }
    } catch (_: IOException) {
        null
    }
}

/** Process.pid() 是 Java 9+；kotlinc 用 JRE 8 编译，这里反射取，运行期 JDK 21 可用。 */
private fun pidOf(p: Process): Long = try {
    val m = Process::class.java.getMethod("pid")
    (m.invoke(p) as Number).toLong()
} catch (_: Exception) {
    -1L
}

private fun freeTcpPort(): Int = ServerSocket(0).use { it.localPort }

private fun findRepoRoot(): File {
    var d: File? = File(System.getProperty("user.dir")).absoluteFile
    var guard = 0
    while (d != null && guard < 8) {
        if (File(d, "Hamsterd" + File.separator + "hamsterd.exe").isFile) return d
        d = d.parentFile
        guard++
    }
    throw IllegalStateException("找不到 Hamsterd/hamsterd.exe；请从 android/protocol-core 运行，或用 --exe 指定")
}

private fun logTail(f: File, lines: Int) {
    if (!f.isFile) return
    try {
        val all = f.readLines(Charsets.UTF_8)
        println("  daemon 日志尾部（$f）：")
        for (l in all.takeLast(lines)) println("    $l")
    } catch (_: Exception) {
    }
}

private fun stopDaemon(p: Process, port: Int) {
    val pid = pidOf(p)
    try {
        p.destroyForcibly()
    } catch (_: Exception) {
    }
    var exited = false
    try {
        exited = p.waitFor(6, TimeUnit.SECONDS)
    } catch (_: Exception) {
    }
    if (!exited && p.isAlive && pid > 0) {
        try {
            val k = ProcessBuilder("taskkill", "/PID", pid.toString(), "/T", "/F")
                .redirectErrorStream(true)
                .start()
            k.waitFor(6, TimeUnit.SECONDS)
        } catch (_: Exception) {
        }
    }
    check(!p.isAlive, "临时 hamsterd 已停止（pid=$pid）")
    check(waitPortClosed(port, 5000), "临时 daemon 的 TCP 端口 :$port 已释放")
}

fun main(args: Array<String>) {
    /* 强制 UTF-8 输出，避免 Windows 控制台代码页把中文结果变成乱码。 */
    System.setOut(PrintStream(FileOutputStream(FileDescriptor.out), true, "UTF-8"))
    System.setErr(PrintStream(FileOutputStream(FileDescriptor.err), true, "UTF-8"))

    var port = 29170
    var discoveryPort = 29171
    var secret = "test-api-codeword-0123456789abcdef"
    var basePath = "build${File.separator}api${File.separator}live"
    var exePath: String? = null

    var i = 0
    while (i < args.size) {
        when (args[i]) {
            "--port" -> {
                port = args.getOrNull(i + 1)?.toIntOrNull() ?: port
                i++
            }
            "--discovery-port" -> {
                discoveryPort = args.getOrNull(i + 1)?.toIntOrNull() ?: discoveryPort
                i++
            }
            "--secret" -> {
                secret = args.getOrNull(i + 1) ?: secret
                i++
            }
            "--base" -> {
                basePath = args.getOrNull(i + 1) ?: basePath
                i++
            }
            "--exe" -> {
                exePath = args.getOrNull(i + 1)
                i++
            }
            else -> println("  （忽略未知参数：${args[i]}）")
        }
        i++
    }

    val base = File(basePath).absoluteFile
    println("=== HamsterApi 联调测试（临时 hamsterd :$port，discovery :$discoveryPort）===")
    println("  base = $base")

    var daemon: Process? = null
    var api: HamsterApi? = null

    try {
        /* ---------------------------------------------------------- 准备 */
        val repo = if (exePath != null) findRepoRoot() else findRepoRoot()
        val exeSrc = if (exePath != null) File(exePath) else File(repo, "Hamsterd${File.separator}hamsterd.exe")
        val dllSrc = File(exeSrc.parentFile, "sqlite3.dll")
        check(exeSrc.isFile, "找到 hamsterd.exe", exeSrc.absolutePath)

        rmrf(base)
        val bin = File(base, "bin").apply { mkdirs() }
        val monitor = File(base, "monitor").apply { mkdirs() }
        val downloads = File(base, "downloads").apply { mkdirs() }
        val exe = File(bin, "hamsterd.exe")
        exeSrc.copyTo(exe, overwrite = true)
        if (dllSrc.isFile) dllSrc.copyTo(File(bin, "sqlite3.dll"), overwrite = true)

        val seed = File(monitor, "seed.bin")
        val seedSize = 200 * 1024
        makePatternFile(seed, seedSize, 7)
        val seedHash = sha256Hex(seed)

        val conf = buildString {
            appendLine("monitor_path: ${monitor.absolutePath}")
            appendLine("ipv4_addr: 127.0.0.1")
            appendLine("ipv4_addr_port: $port")
            appendLine("codeword: $secret")
            appendLine("require_auth: on")
            appendLine("allow_loopback_noauth: off")
            appendLine("encrypt_transport: on")
            appendLine("max_transfer_mb: 64")
            appendLine("max_clients: 8")
            appendLine("rescan_date: 0,0,0")
            appendLine("verify_interval: 0")
            appendLine("discovery_port: $discoveryPort")
            appendLine("discovery_respond: on")
            appendLine("heartbeat_time: 1")
            appendLine("log_level: info")
            appendLine("log_dir: logs")
            appendLine("exclude_internal: on")
        }
        File(bin, "hamsterd.conf").writeText(conf, Charsets.UTF_8)
        check(
            File(bin, "hamsterd.conf").readText(Charsets.UTF_8).contains("encrypt_transport: on"),
            "临时 conf 明确开启 encrypt_transport: on",
        )

        /* ---------------------------------------------------------- 起 daemon */
        check(portFree(port), "TCP 端口 $port 空闲（无其它 hamsterd 占用）")
        check(portFree(discoveryPort), "UDP/TCP 发现端口 $discoveryPort 未被占用")

        val consoleLog = File(base, "daemon-console.log")
        val pb = ProcessBuilder(exe.absolutePath, "--console-log")
        pb.directory(bin)
        pb.redirectErrorStream(true)
        pb.redirectOutput(ProcessBuilder.Redirect.to(consoleLog))
        daemon = pb.start()
        val dpid = pidOf(daemon)
        File(base, "hamsterd.pid").writeText(dpid.toString())
        println("  已启动临时 hamsterd，pid=$dpid，日志=$consoleLog")

        val ready = waitTcp(port, 30000)
        check(ready, "临时 hamsterd 已就绪（127.0.0.1:$port）")
        if (!ready) {
            logTail(consoleLog, 30)
            throw IllegalStateException("临时 hamsterd 未就绪（可能是单实例互斥锁被占用，或监控目录/配置不合法）")
        }

        /* ---------------------------------------------------------- 加密确实开着 */
        val plain = plaintextPing(port)
        check(plain == null, "明文 ping 收不到任何响应（加密连接已生效）", plain ?: "")
        if (plain != null) println("    收到明文响应：${plain.take(160)}")

        /* ---------------------------------------------------------- 错误口令 */
        val wrongSecret = "definitely-wrong-codeword-" + "z".repeat(8)
        var bad: Throwable? = null
        val t0 = System.nanoTime()
        try {
            HamsterApi.connect("127.0.0.1", port, wrongSecret, "dev_api_test_bad", "HamsterApi ApiTest", 4000).close()
        } catch (e: Throwable) {
            bad = e
        }
        val badMs = (System.nanoTime() - t0) / 1_000_000
        check(bad is SecureException, "错误口令抛 SecureException", bad?.javaClass?.simpleName ?: "无异常")
        val badCode = (bad as? SecureException)?.code ?: ""
        check(
            badCode.contains("auth") || badCode.contains("socket_closed"),
            "错误口令异常码含 auth/socket_closed 语义",
            badCode,
        )
        val badText = bad?.toString() ?: ""
        check(
            !badText.contains(wrongSecret) && !badText.contains(secret),
            "异常文本不泄漏口令",
            badText.take(120),
        )
        check(badMs < 6000, "错误口令在时间上界内失败", "${badMs}ms")
        println("    错误口令 → ${bad?.javaClass?.simpleName} code=$badCode, ${badMs}ms")

        /* ---------------------------------------------------------- 正常连接 */
        val a = HamsterApi.connect("127.0.0.1", port, secret, "dev_api_test", "HamsterApi ApiTest", 5000)
        api = a
        check(true, "加密握手成功（peer=${
            try {
                a.peerName
            } catch (e: Exception) {
                "?"
            }
        } ver=${
            try {
                a.peerVersion
            } catch (e: Exception) {
                "?"
            }
        }）")

        try {
            check(a.peerName.isNotEmpty(), "peerName 非空", a.peerName)
            check(
                Regex("""^\d+\.\d+\.\d+$""").matches(a.peerVersion),
                "peerVersion 是 x.y.z（握手 challenge 的 version）",
                a.peerVersion,
            )

            val info = a.protocolInfo()
            check(info.contains("\"server\":\"hamsterd\""), "protocolInfo 返回 hamsterd 的 info", info.take(120))
            check(info.contains("framing:aead"), "info.features 含 framing:aead（走的是 §8 加密）")
            check(info.contains("framing:raw"), "info.features 仍含 framing:raw（负载分帧未变）")
            check(info.contains("monitor_path"), "info 含 monitor_path")

            val st = a.stats()
            check(st.deviceName.isNotEmpty(), "stats.deviceName 非空", st.deviceName)
            check(st.version.isNotEmpty(), "stats.version 非空", st.version)
            check(st.fileCount >= 1, "stats.fileCount >= 1（seed.bin 已入索引）", st.fileCount.toString())
            check(st.totalBytes >= seedSize.toLong(), "stats.totalBytes >= seed.bin 大小", st.totalBytes.toString())
            check(st.uptimeSec >= 0, "stats.uptimeSec >= 0", st.uptimeSec.toString())

            val root = a.listFiles("/")
            check(root.isNotEmpty(), "listFiles(\"/\") 返回非空", root.size.toString())
            val seedEntry = root.firstOrNull { it.name == "seed.bin" }
            check(seedEntry != null, "listFiles 能看到 seed.bin")
            check(seedEntry != null && !seedEntry.dir, "seed.bin 的 dir=false")
            check(seedEntry != null && seedEntry.size == seedSize.toLong(), "seed.bin 的 size 正确", seedEntry?.size?.toString() ?: "")
            check(seedEntry != null && seedEntry.mtime > 0, "seed.bin 的 mtime > 0", seedEntry?.mtime?.toString() ?: "")
            check(seedEntry != null && seedEntry.path.isNotBlank(), "seed.bin 有服务端绝对路径", seedEntry?.path ?: "")

            /* ------------------------------------------------------ 下载 */
            val localDl = File(downloads, "seed-downloaded.bin")
            var dlCalls = 0
            var dlLastGot = -1L
            var dlLastTotal = -1L
            val got = a.download("seed.bin", localDl) { done, totalBytes ->
                dlCalls++
                dlLastGot = done
                dlLastTotal = totalBytes
            }
            check(got == seedSize.toLong(), "download 返回字节数 = 200 KiB", got.toString())
            check(localDl.isFile && localDl.length() == seedSize.toLong(), "本地文件大小 = 200 KiB", localDl.length().toString())
            val dlHash = if (localDl.isFile) sha256Hex(localDl) else "<missing>"
            check(dlHash == seedHash, "下载文件 SHA-256 与源文件一致", "got=$dlHash want=$seedHash")
            check(dlCalls > 0 && dlLastTotal == seedSize.toLong() && dlLastGot == seedSize.toLong(), "download progress 收到最终值", "calls=$dlCalls last=$dlLastGot/$dlLastTotal")
            println("  SHA-256(seed.bin 源)        = $seedHash")
            println("  SHA-256(下载落盘)           = $dlHash")

            /* 用服务端绝对路径再下载一次（验证路径归一化） */
            if (seedEntry != null) {
                val absDl = File(downloads, "seed-downloaded-abs.bin")
                val gotAbs = a.download(seedEntry.path, absDl)
                check(
                    gotAbs == seedSize.toLong() && sha256Hex(absDl) == seedHash,
                    "用服务端绝对路径下载，SHA-256 一致",
                    gotAbs.toString(),
                )
            }

            /* ------------------------------------------------------ 上传 */
            val upSrc = File(base, "upload-src.bin")
            val upSize = 160 * 1024
            makePatternFile(upSrc, upSize, 13)
            val upHash = sha256Hex(upSrc)
            var upCalls = 0
            var upLastGot = -1L
            var upLastTotal = -1L
            val remotePath = a.upload(upSrc, "/") { done, totalBytes ->
                upCalls++
                upLastGot = done
                upLastTotal = totalBytes
            }
            check(remotePath.contains("upload-src.bin"), "upload 返回远端路径", remotePath)
            val serverCopy = File(monitor, "upload-src.bin")
            check(serverCopy.isFile, "服务端落盘 upload-src.bin")
            check(serverCopy.isFile && serverCopy.length() == upSize.toLong(), "服务端文件大小 = 160 KiB", serverCopy.length().toString())
            val upServerHash = if (serverCopy.isFile) sha256Hex(serverCopy) else "<missing>"
            check(upServerHash == upHash, "上传落盘 SHA-256 与本地源文件一致", "got=$upServerHash want=$upHash")
            check(upCalls > 0 && upLastTotal == upSize.toLong() && upLastGot == upSize.toLong(), "upload progress 收到最终值", "calls=$upCalls last=$upLastGot/$upLastTotal")
            println("  SHA-256(上传源)             = $upHash")
            println("  SHA-256(服务端落盘)         = $upServerHash")

            val root2 = a.listFiles("/")
            val upEntry = root2.firstOrNull { it.name == "upload-src.bin" }
            check(upEntry != null, "再次 listFiles 能看到上传的文件")
            check(upEntry != null && upEntry.size == upSize.toLong() && !upEntry.dir, "上传文件条目 size/dir 正确", upEntry?.size?.toString() ?: "")

            if (upEntry != null) {
                val back = File(downloads, "upload-back.bin")
                val gotBack = a.download(upEntry.path, back)
                check(gotBack == upSize.toLong(), "回读上传文件字节数一致", gotBack.toString())
                check(sha256Hex(back) == upHash, "回读上传文件 SHA-256 与源一致", sha256Hex(back))
            }

            /* 中文 + 空格文件名：同时验证 JSON 转义与 UTF-8 */
            val cnSrc = File(base, "测试 文件.bin")
            val cnSize = 32 * 1024
            makePatternFile(cnSrc, cnSize, 29)
            val cnHash = sha256Hex(cnSrc)
            val cnRemote = a.upload(cnSrc, "/")
            val cnOnServer = File(monitor, "测试 文件.bin")
            check(cnOnServer.isFile && sha256Hex(cnOnServer) == cnHash, "中文/空格文件名上传后落盘一致", cnRemote)
            val cnList = a.listFiles("/")
            check(cnList.any { it.name == "测试 文件.bin" && it.size == cnSize.toLong() }, "listFiles 能正确返回中文/空格文件名")

            /* 子目录上传：daemon 侧 mkdir:true 自动建目录 */
            val subSrc = File(base, "sub-src.bin")
            makePatternFile(subSrc, 8 * 1024, 41)
            val subRemote = a.upload(subSrc, "/api-sub")
            check(File(monitor, "api-sub${File.separator}sub-src.bin").isFile, "上传到 /api-sub 时服务端自动建目录", subRemote)
            check(a.listFiles("/api-sub").any { it.name == "sub-src.bin" }, "listFiles(\"/api-sub\") 能看到子目录文件")

            /* ------------------------------------------------------ 错误路径 */
            var missingErr: Throwable? = null
            val missingLocal = File(downloads, "no-such-file.bin")
            try {
                a.download("no-such-file.bin", missingLocal)
            } catch (e: Throwable) {
                missingErr = e
            }
            check(
                missingErr is HamsterApiException && (missingErr as HamsterApiException).code == "file_not_found",
                "下载不存在的文件 → HamsterApiException(file_not_found)",
                (missingErr as? HamsterApiException)?.code ?: missingErr?.javaClass?.simpleName ?: "无异常",
            )
            check(!missingLocal.exists(), "下载失败不留半成品")

            var listErr: Throwable? = null
            try {
                a.listFiles("/definitely-not-a-directory")
            } catch (e: Throwable) {
                listErr = e
            }
            check(
                listErr is HamsterApiException && (listErr as HamsterApiException).code == "not_found",
                "列不存在的目录 → HamsterApiException(not_found)",
                (listErr as? HamsterApiException)?.code ?: listErr?.javaClass?.simpleName ?: "无异常",
            )

            var existsErr: Throwable? = null
            try {
                a.upload(upSrc, "/")
            } catch (e: Throwable) {
                existsErr = e
            }
            check(
                existsErr is HamsterApiException && (existsErr as HamsterApiException).code == "exists",
                "重复上传同名文件 → HamsterApiException(exists)",
                (existsErr as? HamsterApiException)?.code ?: existsErr?.javaClass?.simpleName ?: "无异常",
            )

            /* 服务端拒绝上传时会把负载排空（hd_net.c reject 路径），连接必须还能用 */
            check(a.listFiles("/").isNotEmpty(), "错误响应之后连接仍然可用（帧流未错位）")

            /* 空文件上传：协议 payload_bytes 必须为正，应给出明确错误 */
            val empty = File(base, "empty.bin")
            empty.writeBytes(ByteArray(0))
            var emptyErr: Throwable? = null
            try {
                a.upload(empty, "/")
            } catch (e: Throwable) {
                emptyErr = e
            }
            check(
                emptyErr is HamsterApiException && (emptyErr as HamsterApiException).code == "empty_file",
                "0 字节上传给出 empty_file（而不是静默失败）",
                (emptyErr as? HamsterApiException)?.code ?: emptyErr?.javaClass?.simpleName ?: "无异常",
            )
        } finally {
            a.close()
        }

        /* ---------------------------------------------------------- close 幂等 */
        var closeErr: Throwable? = null
        try {
            a.close()
            a.close()
        } catch (e: Throwable) {
            closeErr = e
        }
        check(closeErr == null, "close() 连续两次不抛异常（幂等）", closeErr?.toString() ?: "")

        var closedErr: Throwable? = null
        try {
            a.stats()
        } catch (e: Throwable) {
            closedErr = e
        }
        check(
            closedErr is HamsterApiException && (closedErr as HamsterApiException).code == "closed",
            "关闭后调用 → HamsterApiException(closed)",
            (closedErr as? HamsterApiException)?.code ?: closedErr?.javaClass?.simpleName ?: "无异常",
        )
        api = null

        /* ---------------------------------------------------------- 明文服务端映射 */
        val fake = ServerSocket(0)
        val fakePort = fake.localPort
        val fakeThread = Thread {
            try {
                fake.accept().use { s ->
                    s.soTimeout = 3000
                    val input = s.getInputStream()
                    var c = input.read()
                    while (c >= 0 && c != '\n'.code) c = input.read()
                    val body = "{\"type\":\"response\",\"id\":\"\",\"status\":\"error\"," +
                        "\"data\":{\"error\":\"missing_action\"}}\n"
                    s.getOutputStream().write(body.toByteArray(Charsets.UTF_8))
                    s.getOutputStream().flush()
                }
            } catch (_: Exception) {
            }
        }
        fakeThread.isDaemon = true
        fakeThread.start()
        var plainErr: Throwable? = null
        try {
            HamsterApi.connect("127.0.0.1", fakePort, secret, "dev_plain_test", "HamsterApi ApiTest", 3000).close()
        } catch (e: Throwable) {
            plainErr = e
        }
        fake.close()
        check(
            plainErr is SecureException && (plainErr as SecureException).code == "not_encrypted",
            "对面是明文服务端 → SecureException(not_encrypted)",
            (plainErr as? SecureException)?.code ?: plainErr?.javaClass?.simpleName ?: "无异常",
        )

        /* ---------------------------------------------------------- 连接失败 */
        val deadPort = freeTcpPort()
        var deadErr: Throwable? = null
        val tDead = System.nanoTime()
        try {
            HamsterApi.connect("127.0.0.1", deadPort, secret, "dev_api_test_dead", "HamsterApi ApiTest", 1500).close()
        } catch (e: Throwable) {
            deadErr = e
        }
        val deadMs = (System.nanoTime() - tDead) / 1_000_000
        val deadCode = (deadErr as? HamsterApiException)?.code ?: ""
        check(
            deadErr is HamsterApiException && (deadCode == "connect_failed" || deadCode == "timeout"),
            "连接不存在的端口 → HamsterApiException(connect_failed/timeout)",
            "$deadCode / ${deadErr?.javaClass?.simpleName ?: "无异常"}",
        )
        check(deadErr !is SocketTimeoutException, "SocketTimeoutException 没有裸奔到调用方")
        check(deadMs < 5000, "连接不存在端口有时间上界", "${deadMs}ms")
        println("    不存在端口 :$deadPort → ${deadErr?.javaClass?.simpleName} code=$deadCode, ${deadMs}ms")

        var badPortErr: Throwable? = null
        try {
            HamsterApi.connect("127.0.0.1", 0, secret, "dev_api_test_badport", "HamsterApi ApiTest", 500)
        } catch (e: Throwable) {
            badPortErr = e
        }
        check(
            badPortErr is HamsterApiException && (badPortErr as HamsterApiException).code == "bad_address",
            "端口 0 → HamsterApiException(bad_address)",
            (badPortErr as? HamsterApiException)?.code ?: badPortErr?.javaClass?.simpleName ?: "无异常",
        )

        /* 不可达地址：有路由时是 timeout，无路由时 Windows 立刻 unreachable；
           两种情况都必须在时间上界内以 HamsterApiException 返回。 */
        var holeErr: Throwable? = null
        val tHole = System.nanoTime()
        try {
            HamsterApi.connect("192.0.2.1", 9, secret, "dev_api_test_hole", "HamsterApi ApiTest", 1200).close()
        } catch (e: Throwable) {
            holeErr = e
        }
        val holeMs = (System.nanoTime() - tHole) / 1_000_000
        val holeCode = (holeErr as? HamsterApiException)?.code ?: ""
        check(
            holeErr is HamsterApiException && (holeCode == "timeout" || holeCode == "connect_failed"),
            "不可达地址 → HamsterApiException(timeout/connect_failed)",
            "$holeCode / ${holeErr?.javaClass?.simpleName ?: "无异常"}",
        )
        check(holeMs < 6000, "不可达地址在时间上界内失败（timeoutMs=1200）", "${holeMs}ms")
        println("    不可达地址 192.0.2.1:9 → ${holeErr?.javaClass?.simpleName} code=$holeCode, ${holeMs}ms")
    } catch (e: Throwable) {
        failCount++
        println("  [FAIL] 测试执行异常：${e.javaClass.simpleName}: ${e.message}")
        e.printStackTrace()
    } finally {
        try {
            api?.close()
        } catch (_: Exception) {
        }
        daemon?.let {
            try {
                stopDaemon(it, port)
            } catch (e: Exception) {
                failCount++
                println("  [FAIL] 停止临时 hamsterd 时异常：${e.message}")
            }
        }
    }

    println()
    println("PASS $passCount / FAIL $failCount")
    if (failCount != 0) {
        System.exit(1)
    }
}
