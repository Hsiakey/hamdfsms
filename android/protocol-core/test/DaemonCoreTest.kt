/*
 * DaemonCoreTest.kt — DaemonCore + DaemonServer 的端到端联调测试（零依赖，纯 fun main）
 *
 * 客户端一律用**现有的** HamsterApi（真 socket + §8 握手 + 记录层），
 * 服务端是本次交付的 DaemonServer/DaemonCore。不 mock 任何一层。
 *
 * 覆盖：
 *   1. 启动：isRunning、重复 start() 抛 IllegalStateException、clientCount；
 *   2. info/health/stats/protocolInfo 字段合理；
 *   3. list 的 limit/offset/total 分页、越界 limit 回落 200、子目录/中文/空格名；
 *   4. search 的 q/type/size_min/sort/limit/offset 与真实文件树；
 *   5. mkdir → listPage 可见；
 *   6. upload：overwrite=true 覆盖、overwrite=false → exists、mkdir 语义、
 *      中文名、SHA-256 一致；
 *   7. download：1 MiB、绝对路径（根内）、中文名、0 字节、错误码；
 *   8. delete：空目录成功、非空 → dir_not_empty、根目录被拒、不存在 → not_found；
 *   9. rescan/sync/verify（verify 真读文件）；
 *  10. 路径安全：../、盘符绝对路径、/etc/passwd、junction/软链接逃逸 → path_denied，
 *      且 root 外的文件**真的没被动过**；
 *  11. 认证：错口令 → SecureException；第 3 个候选口令能连上；服务端不崩；
 *  12. 并发：3 个客户端同时下载/上传，SHA-256 全对；
 *  13. 协议细节（原始加密通道）：keep-alive、malformed_json、missing_action、
 *      unknown_action、line_too_long 后连接仍可用、upload 的 missing_payload/bad_size/
 *      hash_mismatch、0 字节 download 的 payload_bytes=0；
 *  14. stop()：幂等、端口释放（连接被拒 + 可重新监听）、无残留 hamsterd-* 线程。
 *
 * 用法（工作目录 android/protocol-core）：
 *   java -jar build\daemon\daemon-test.jar
 * 退出码：0 = 全通过，1 = 有失败。
 */
package hamster

import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.file.Files
import java.security.MessageDigest
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.system.exitProcess

private var pass = 0
private var fail = 0
private var skipped = 0

private fun section(title: String) {
    println()
    println("== $title")
}

private fun check(cond: Boolean, name: String, detail: String = "") {
    if (cond) {
        pass++
        println("  [PASS] $name")
    } else {
        fail++
        println("  [FAIL] $name" + if (detail.isNotEmpty()) "  -> $detail" else "")
    }
}

private fun checkEq(actual: Any?, expected: Any?, name: String) =
    check(actual == expected, name, "期望=$expected 实际=$actual")

private fun note(msg: String) {
    skipped++
    println("  [SKIP] $msg")
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
    FileOutputStream(f).use { out ->
        val buf = ByteArray(8192)
        var written = 0
        while (written < size) {
            val n = minOf(buf.size, size - written)
            for (i in 0 until n) buf[i] = (((written + i) * 31) + salt and 0xff).toByte()
            out.write(buf, 0, n)
            written += n
        }
    }
}

private fun rmrf(f: File) {
    if (f.exists()) f.deleteRecursively()
}

private fun freePort(from: Int, to: Int): Int {
    for (p in from..to) {
        try {
            ServerSocket().use { ss ->
                ss.reuseAddress = false
                ss.bind(InetSocketAddress("127.0.0.1", p))
                return p
            }
        } catch (_: IOException) {
        }
    }
    return from
}

/** 端口上没有监听者：连接应当被拒绝。 */
private fun portRefused(port: Int, timeoutMs: Int = 3000): Boolean {
    val deadline = System.currentTimeMillis() + timeoutMs
    while (System.currentTimeMillis() < deadline) {
        try {
            Socket().use { s ->
                s.connect(InetSocketAddress("127.0.0.1", port), 300)
                return false
            }
        } catch (_: IOException) {
            return true
        }
    }
    return false
}

private fun createDirLink(link: File, target: File): Boolean {
    if (link.exists()) return true
    try {
        Files.createSymbolicLink(link.toPath(), target.toPath())
        return true
    } catch (_: Exception) {
        /* Windows 下普通用户建符号链接需要开发者模式/管理员：退回到目录联接（junction） */
    }
    return try {
        val pb = ProcessBuilder("cmd", "/c", "mklink", "/J", link.absolutePath, target.absolutePath)
        pb.redirectOutput(ProcessBuilder.Redirect.DISCARD)
        pb.redirectError(ProcessBuilder.Redirect.DISCARD)
        val p = pb.start()
        p.waitFor(10, TimeUnit.SECONDS) && link.exists()
    } catch (_: Exception) {
        false
    }
}

/** 期望某个操作抛 HamsterApiException 且 code 匹配。 */
private fun expectError(name: String, code: String, block: () -> Unit): Boolean = try {
    block()
    check(false, name, "期望错误 $code，实际成功")
    false
} catch (e: HamsterApiException) {
    check(e.code == code, name, "期望 $code，实际 ${e.code}：${e.message}")
    e.code == code
} catch (e: Exception) {
    check(false, name, "期望 HamsterApiException($code)，实际 ${e.javaClass.simpleName}：${e.message}")
    false
}

/* ==========================================================================
 * 原始加密通道（用来测 HamsterApi 覆盖不到的协议细节）
 * ========================================================================== */
private class RawConn(host: String, port: Int, secret: String, deviceId: String) {
    val ch: SecureChannel = SecureChannel.connect(host, port, secret, deviceId)
    val reader = FrameReader(ch.input)

    val readerPayloadBytes: Long get() = reader.payloadBytes

    fun send(line: String) {
        ch.output.write(line.toByteArray(Charsets.UTF_8))
        ch.output.write('\n'.code)
        ch.output.flush()
    }

    fun sendPayload(bytes: ByteArray) {
        ch.output.write(bytes)
        ch.output.flush()
    }

    fun readHeader(): String? = reader.readHeader()

    fun call(json: String): String {
        send(json)
        return readHeader() ?: throw IOException("连接被服务端关闭")
    }

    fun close() {
        try {
            ch.close()
        } catch (_: Exception) {
        }
    }
}

private fun rawError(header: String): String? {
    val data = Json.getRawObject(header, "data") ?: return null
    return Json.getString(data, "error")
}

private fun rawPing(raw: RawConn, id: String): Boolean =
    try {
        val h = raw.call("{\"type\":\"request\",\"id\":\"$id\",\"action\":\"ping\"}")
        Json.getString(h, "id") == id && Json.getString(h, "status") == "ok"
    } catch (_: Exception) {
        false
    }

/* ========================================================================== */

fun main() {
    try {
        runAll()
    } catch (t: Throwable) {
        fail++
        println()
        println("  [FAIL] 未捕获异常中止测试 -> ${t.javaClass.name}: ${t.message}")
        t.printStackTrace()
    }
    println()
    println("PASS $pass / FAIL $fail" + if (skipped > 0) " / SKIP $skipped" else "")
    exitProcess(if (fail == 0) 0 else 1)
}

private fun runAll() {
    val base = File("build/daemon/tmp")
    rmrf(base)
    val root = File(base, "root")
    val outside = File(base, "outside")
    val srcDir = File(base, "src")
    root.mkdirs()
    outside.mkdirs()
    srcDir.mkdirs()

    /* ---------------- 测试用文件树 ---------------- */
    File(root, "hello.txt").writeText("hello hamster\n")
    File(root, "中文 文件.txt").writeText("中文内容 with spaces\n")
    File(root, "zero.bin").writeBytes(ByteArray(0))
    makePatternFile(File(root, "big.bin"), 1024 * 1024, 2)
    File(root, "sub").mkdirs()
    makePatternFile(File(root, "sub/nested.bin"), 4096, 1)
    File(root, "sub/deep").mkdirs()
    File(root, "sub/deep/more.txt").writeText("deep\n")
    File(root, "empty-dir").mkdirs()
    File(root, "nonempty").mkdirs()
    File(root, "nonempty/inner.txt").writeText("inner\n")

    File(outside, "secret.txt").writeText("TOP SECRET — 不许被读到或改动\n")
    val outsideSha = sha256Hex(File(outside, "secret.txt"))

    val port = freePort(29200, 29220)
    /* 第 3 个候选才是对的：验证服务端"逐把试 proof_C"确实在逐把试 */
    val secrets = listOf("codeword-wrong-0", "api-key-wrong-1", "codeword-right-2")
    val core = DaemonCore(root, "jvm-hamsterd", "0.0.9")
    val server = DaemonServer(core, port, "127.0.0.1", secrets)

    println("Hamster DaemonCore 端到端测试")
    println("  根目录 = ${root.absolutePath}")
    println("  端口   = $port")

    section("启动")
    var coreBadRootThrew = false
    try {
        DaemonCore(File(base, "no-such-root"), "x", "0.0.9")
    } catch (_: IllegalArgumentException) {
        coreBadRootThrew = true
    }
    check(coreBadRootThrew, "DaemonCore 根目录不存在 → IllegalArgumentException")
    server.start()
    check(server.isRunning, "start() 后 isRunning=true")
    var secondStartThrew = false
    try {
        server.start()
    } catch (_: IllegalStateException) {
        secondStartThrew = true
    } catch (_: Exception) {
    }
    check(secondStartThrew, "第二次 start() 抛 IllegalStateException")
    checkEq(server.clientCount(), 0, "握手前 clientCount=0")

    var api: HamsterApi? = null
    try {
        api = HamsterApi.connect("127.0.0.1", port, secrets[2], "jvm-daemon-test")
    } catch (e: Exception) {
        check(false, "HamsterApi.connect（第 3 个候选口令）", "${e.javaClass.simpleName}：${e.message}")
        println()
        println("PASS $pass / FAIL $fail")
        exitProcess(1)
    }
    val a = api!!
    check(true, "HamsterApi.connect 用第 3 个候选口令成功（服务端逐把试 proof_C）")
    checkEq(server.clientCount(), 1, "握手成功后 clientCount=1")

    /* ---------------- info / health / stats ---------------- */
    section("协议信息")
    val pinfo = a.protocolInfo()
    check(
        pinfo.contains("\"monitor_path\"") && pinfo.contains("framing:aead"),
        "protocolInfo() 是 info 的 data 原文（含 monitor_path / framing:aead）",
        pinfo.take(180),
    )
    val info = a.info()
    checkEq(info.server, "jvm-hamsterd", "info.server = DaemonCore.serverName")
    checkEq(info.version, "0.0.9", "info.version")
    check(info.authRequired, "info.auth_required=1")
    check(
        info.monitorPath.equals(root.canonicalPath, ignoreCase = true),
        "info.monitor_path = 根目录真实路径",
        "期望=${root.canonicalPath} 实际=${info.monitorPath}",
    )
    checkEq(info.heartbeatSec, 3, "info.heartbeat=3")
    check(info.clients >= 1, "info.clients >= 1", "实际=${info.clients}")
    checkEq(info.peers, 0, "info.peers=0（§7：服务端不再维护 peer 表）")
    check(info.features.contains("framing:aead"), "info.features 含 framing:aead", info.features.toString())
    check(
        !info.features.contains("keys") && !info.features.contains("sync-database"),
        "features 不谎报 keys / sync-database",
        info.features.toString(),
    )
    val health = a.health()
    checkEq(health.status, "ok", "health.status")
    checkEq(health.version, "0.0.9", "health.version")
    check(health.clients >= 1, "health.clients >= 1")
    check(health.uptimeMs >= 0L, "health.uptime_ms >= 0")
    check(
        health.monitorPath.equals(root.canonicalPath, ignoreCase = true),
        "health.monitor_path",
        health.monitorPath,
    )
    val stats = a.stats()
    checkEq(stats.deviceName, "hamsterd", "stats.deviceName 来自 §8 握手的 server 名")
    checkEq(stats.version, "0.0.9", "stats.version")
    check(stats.fileCount >= 6, "stats.fileCount >= 6", "实际=${stats.fileCount}")
    check(stats.totalBytes >= 1024L * 1024L, "stats.totalBytes >= 1 MiB", "实际=${stats.totalBytes}")
    check(stats.uptimeSec >= 0L, "stats.uptimeSec >= 0")

    /* ---------------- list ---------------- */
    section("list 分页")
    val p0 = a.listPage("/", 0, 3)
    checkEq(p0.total, 7, "listPage total=7")
    checkEq(p0.entries.size, 3, "limit=3 返回 3 条")
    checkEq(p0.limit, 3, "limit 回显")
    checkEq(p0.offset, 0, "offset 回显")
    val p1 = a.listPage("/", 3, 3)
    checkEq(p1.entries.size, 3, "offset=3 返回 3 条")
    check(
        p0.entries.map { it.name }.toSet().intersect(p1.entries.map { it.name }.toSet()).isEmpty(),
        "两页不重叠",
        "${p0.entries.map { it.name }} vs ${p1.entries.map { it.name }}",
    )
    val p2 = a.listPage("/", 6, 3)
    checkEq(p2.entries.size, 1, "最后一页 1 条")
    val p3 = a.listPage("/", 100, 3)
    checkEq(p3.entries.size, 0, "越界 offset 返回空页")
    val pBig = a.listPage("/", 0, 5000)
    checkEq(pBig.limit, 200, "limit=5000 越界按 200（与 C 侧一致）")
    val pZero = a.listPage("/", 0, 0)
    checkEq(pZero.limit, 200, "limit=0 越界按 200（与 C 侧一致）")
    val pSub = a.listPage("sub")
    val nested = pSub.entries.firstOrNull { it.name == "nested.bin" }
    check(
        nested != null && !nested.dir && nested.size == 4096L,
        "listPage(\"sub\") 含 nested.bin（dir=0, size=4096）",
        pSub.entries.joinToString { "${it.name}/${it.dir}/${it.size}" },
    )
    check(pSub.entries.any { it.name == "deep" && it.dir }, "listPage(\"sub\") 含目录 deep")
    check(pSub.entries.any { it.name == "nested.bin" && it.mtime > 0L }, "list 的 mtime 是 epoch 秒（>0）")
    checkEq(pSub.entries.first { it.name == "nested.bin" }.path, File(root, "sub/nested.bin").canonicalPath, "list 的 path 是服务端绝对路径")
    expectError("list 一个文件（不是目录）→ not_a_directory", "not_a_directory") { a.listPage("sub/nested.bin") }
    expectError("list 不存在的目录 → not_found", "not_found") { a.listPage("nope-dir") }

    /* ---------------- search ---------------- */
    section("search（真实文件树）")
    val s1 = a.search("big")
    check(
        s1.total >= 1 && s1.files.any { it.name == "big.bin" && it.size == 1024L * 1024L },
        "search(\"big\") 命中 big.bin",
        "total=${s1.total}",
    )
    val bigHit = s1.files.firstOrNull { it.name == "big.bin" }
    check(bigHit != null && bigHit.hash.length == 32, "search 的 hash 是 32 位十六进制（xxHash3_128）", bigHit?.hash ?: "null")
    checkEq(a.search("nested", type = "bin").total, 1, "search(type=bin) 命中 1 条")
    checkEq(a.search("nested", type = "txt").total, 0, "search(type=txt) 不命中 nested.bin")
    checkEq(a.search("", type = "txt").total, 4, "search(type=txt) 共 4 条（hello/中文/more/inner）")
    val s5 = a.search("中文")
    check(s5.total >= 1 && s5.files.any { it.name == "中文 文件.txt" }, "search 命中中文文件名", "total=${s5.total}")
    checkEq(a.search("", sizeMin = 1024L * 1024L).total, 1, "search(size_min=1MiB) 只命中 big.bin")
    checkEq(a.search("", sizeMax = 4096L).total, 6, "search(size_max=4096) 命中 6 条（除 1 MiB 的 big.bin）")
    val sSort = a.search("", sort = "-size")
    check(
        sSort.files.isNotEmpty() && sSort.files.first().size == 1024L * 1024L,
        "search(sort=-size) 最大文件在前",
        sSort.files.map { it.size }.toString(),
    )
    checkEq(a.search("", sort = "bogus-column").total, 7, "非白名单 sort 回落 path 升序（不报错）")
    val sPage = a.search("", limit = 2, offset = 0)
    checkEq(sPage.files.size, 2, "search(limit=2) 返回 2 条")
    checkEq(sPage.total, 7, "search total=7")
    checkEq(sPage.limit, 2, "search limit 回显")
    val sPage2 = a.search("", limit = 2, offset = 2)
    check(
        sPage.files.map { it.path }.toSet().intersect(sPage2.files.map { it.path }.toSet()).isEmpty(),
        "search 分页不重叠",
    )
    checkEq(a.search("", limit = 5000).limit, 1000, "search limit>1000 夹到 1000")

    /* ---------------- mkdir ---------------- */
    section("mkdir")
    val made = a.mkdir("新建 目录/子目录")
    check(made.endsWith("子目录") && made.contains("新建 目录"), "mkdir 返回落地绝对路径", made)
    check(File(root, "新建 目录/子目录").isDirectory, "mkdir 真的建了目录")
    val made2 = a.mkdir("新建 目录/子目录")
    check(made2.isNotEmpty(), "mkdir 已存在目录幂等成功", made2)
    check(
        a.listPage("/", 0, 1000).entries.any { it.name == "新建 目录" && it.dir },
        "mkdir 后 listPage 可见",
    )
    check(
        a.listPage("新建 目录").entries.any { it.name == "子目录" && it.dir },
        "listPage(\"新建 目录\") 可见子目录",
    )

    /* ---------------- upload ---------------- */
    section("upload")
    val srcA = File(srcDir, "A").apply { mkdirs() }
    val srcB = File(srcDir, "B").apply { mkdirs() }
    val fA = File(srcA, "v2.bin").also { makePatternFile(it, 200 * 1024, 11) }
    val fB = File(srcB, "v2.bin").also { makePatternFile(it, 160 * 1024, 12) }
    val shaA = sha256Hex(fA)
    val shaB = sha256Hex(fB)
    val upPath = a.upload(fA, "/")
    check(File(upPath).isFile && File(upPath).name == "v2.bin", "upload 返回落盘绝对路径", upPath)
    checkEq(sha256Hex(File(upPath)), shaA, "upload 后服务端文件 SHA-256 一致")
    expectError("overwrite=false 目标已存在 → exists", "exists") { a.upload(fA, "/", overwrite = false) }
    checkEq(sha256Hex(File(upPath)), shaA, "exists 失败后目标文件未被改动")
    val upPath2 = a.upload(fB, "/", overwrite = true)
    checkEq(upPath2, upPath, "overwrite=true 覆盖同一路径")
    checkEq(sha256Hex(File(upPath)), shaB, "overwrite=true 后内容换成新文件（SHA-256 一致）")
    val deepUp = a.upload(fA, "新建 目录/子目录/再深一层", mkdir = true)
    check(File(deepUp).isFile, "mkdir=true 自动建父目录", deepUp)
    expectError("mkdir=false 父目录不存在 → open_failed", "open_failed") { a.upload(fA, "不存在/子目录", mkdir = false) }
    val fileNamedDeep = File(srcDir, "deep").also { it.writeText("x") }
    expectError("upload 目标是已存在目录 → is_directory", "is_directory") { a.upload(fileNamedDeep, "sub") }
    val cn = File(srcDir, "中文 上传.txt").also { it.writeText("中文上传内容\n") }
    val cnPath = a.upload(cn, "/")
    checkEq(sha256Hex(File(cnPath)), sha256Hex(cn), "中文+空格文件名 upload SHA-256 一致")

    /* ---------------- download ---------------- */
    section("download")
    val bigLocal = File(root, "big.bin")
    val dl1 = File(srcDir, "dl-big.bin")
    checkEq(a.download("big.bin", dl1), 1024L * 1024L, "download 1 MiB 字节数")
    checkEq(sha256Hex(dl1), sha256Hex(bigLocal), "download 1 MiB SHA-256 一致")
    val bigEntry = a.listPage("/", 0, 1000).entries.first { it.name == "big.bin" }
    val dl2 = File(srcDir, "dl-big-abs.bin")
    checkEq(a.download(bigEntry.path, dl2), 1024L * 1024L, "download 用根内绝对路径（字节数）")
    checkEq(sha256Hex(dl2), sha256Hex(bigLocal), "download 根内绝对路径 SHA-256 一致")
    val dl3 = File(srcDir, "dl-cn.txt")
    a.download("中文 文件.txt", dl3)
    checkEq(sha256Hex(dl3), sha256Hex(File(root, "中文 文件.txt")), "中文名 download SHA-256 一致")
    val dl4 = File(srcDir, "dl-zero.bin")
    checkEq(a.download("zero.bin", dl4), 0L, "0 字节文件 download 返回 0")
    check(dl4.isFile && dl4.length() == 0L, "0 字节文件落盘为空")
    val dlUp = File(srcDir, "dl-v2.bin")
    a.download("v2.bin", dlUp)
    checkEq(sha256Hex(dlUp), shaB, "upload→download 往返 SHA-256 一致（覆盖后的内容）")
    expectError("download 不存在的文件 → file_not_found", "file_not_found") {
        a.download("nope.bin", File(srcDir, "x.bin"))
    }
    expectError("download 目录 → is_directory", "is_directory") {
        a.download("sub", File(srcDir, "y.bin"))
    }

    /* ---------------- delete ---------------- */
    section("delete")
    a.delete("empty-dir")
    check(!File(root, "empty-dir").exists(), "delete 空目录成功")
    expectError("delete 非空目录 → dir_not_empty", "dir_not_empty") { a.delete("nonempty") }
    check(File(root, "nonempty/inner.txt").isFile, "dir_not_empty 后内容仍在")
    a.delete("hello.txt")
    check(!File(root, "hello.txt").exists(), "delete 文件成功")
    expectError("delete 不存在的路径 → not_found", "not_found") { a.delete("nope.txt") }
    var rootDeleteThrew = false
    try {
        a.delete("/")
    } catch (_: HamsterApiException) {
        rootDeleteThrew = true
    }
    check(rootDeleteThrew && root.isDirectory, "delete 根目录被拒（客户端 normalizeFile 先行拦截）")

    /* ---------------- verify / rescan / sync ---------------- */
    section("verify / rescan / sync")
    check(a.rescan(), "rescan() 返回 rescan_requested")
    check(a.sync(), "sync() 返回 sync_requested")
    val v0 = a.verify(false)
    checkEq(v0.corruptCount, 0, "verify(run=false).corrupt_count=0")
    checkEq(v0.scanInterval, 0, "verify.scan_interval=0（无配置，未编造）")
    val v1 = a.verify(true)
    check(v1.verifiedFiles >= 5, "verify(run=true) 真的读了文件", "verified=${v1.verifiedFiles}")
    checkEq(v1.corruptCount, 0, "verify(run=true).corrupt_count=0")
    checkEq(v1.missingCount, 0, "verify(run=true).missing_count=0（无索引，不谎报）")
    check(v1.verifyCount >= 1, "verify_count 递增", "verify_count=${v1.verifyCount}")
    check(
        Regex("^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}$").matches(v1.lastVerify),
        "last_verify 是 ISO 本地时间",
        v1.lastVerify,
    )
    check(v1.lastDurationMs >= 0L, "last_duration_ms 是真实耗时", "dur=${v1.lastDurationMs}")

    /* ---------------- 路径安全 ---------------- */
    section("路径安全（越权一律 path_denied，且 root 外文件不动）")
    expectError("download ../ 逃逸", "path_denied") {
        a.download("../outside/secret.txt", File(srcDir, "esc1.bin"))
    }
    expectError("download ..\\ 逃逸", "path_denied") {
        a.download("..\\outside\\secret.txt", File(srcDir, "esc2.bin"))
    }
    expectError("download sub/../../ 逃逸", "path_denied") {
        a.download("sub/../../outside/secret.txt", File(srcDir, "esc3.bin"))
    }
    expectError("download 盘符绝对路径（root 外）", "path_denied") {
        a.download("C:\\Windows\\win.ini", File(srcDir, "esc4.bin"))
    }
    expectError("download 相对路径含 ':'", "path_denied") {
        a.download("a:b.txt", File(srcDir, "esc5.bin"))
    }
    expectError("download 含控制字符的路径", "path_denied") {
        a.download("bad\u0001name.txt", File(srcDir, "esc6.bin"))
    }
    expectError("list ../outside", "path_denied") { a.listPage("../outside") }
    expectError("mkdir ../evil", "path_denied") { a.mkdir("../evil") }
    check(!File(base, "evil").exists(), "mkdir 逃逸没有真的建目录")
    expectError("upload 到 ../outside", "path_denied") { a.upload(fA, "../outside") }
    expectError("delete ../outside/secret.txt", "path_denied") { a.delete("../outside/secret.txt") }
    checkEq(sha256Hex(File(outside, "secret.txt")), outsideSha, "所有逃逸尝试后 root 外文件未被改动")
    check(!File(outside, "v2.bin").exists(), "逃逸上传没有在 root 外落盘")

    section("软链接 / junction 逃逸")
    val link = File(root, "link-out")
    if (!createDirLink(link, outside)) {
        note("无法创建符号链接/junction（需要权限），跳过该组用例")
    } else {
        val resolved = try {
            link.toPath().toRealPath()
        } catch (_: Exception) {
            link.toPath()
        }
        check(
            Files.isSymbolicLink(link.toPath()) ||
                !resolved.startsWith(root.toPath().toRealPath()),
            "前置：link-out 确实指向 root 外",
            resolved.toString(),
        )
        expectError("list link-out（指向 root 外）", "path_denied") { a.listPage("link-out") }
        expectError("download link-out/secret.txt", "path_denied") {
            a.download("link-out/secret.txt", File(srcDir, "esc7.bin"))
        }
        expectError("delete link-out/secret.txt", "path_denied") { a.delete("link-out/secret.txt") }
        checkEq(sha256Hex(File(outside, "secret.txt")), outsideSha, "junction 逃逸尝试后 root 外文件未被改动")
        val sSecret = a.search("secret")
        check(
            sSecret.files.none { it.path.lowercase().contains("outside") },
            "search 不会穿过 junction 报 root 外文件",
            sSecret.files.map { it.path }.toString(),
        )
        check(a.stats().fileCount >= 6, "stats 跳过 junction 子树后仍正常", "fileCount=${a.stats().fileCount}")
        link.delete()
        check(!link.exists(), "清理：只删掉链接本身")
    }

    /* ---------------- 认证 ---------------- */
    section("认证")
    var wrongKind = ""
    var wrongRejected = false
    try {
        HamsterApi.connect("127.0.0.1", port, "definitely-wrong", "auth-test").close()
    } catch (e: SecureException) {
        wrongRejected = true
        wrongKind = "SecureException(${e.code})"
    } catch (e: Exception) {
        wrongKind = "${e.javaClass.simpleName}：${e.message}"
    }
    check(wrongRejected, "错口令 → SecureException（服务端静默断开）", wrongKind)
    /* secrets 里的每一把都应当被接受：服务端对每把候选各算一次 proof_C（逐把试） */
    for (i in 0..2) {
        var ok = false
        var kind = ""
        try {
            HamsterApi.connect("127.0.0.1", port, secrets[i], "auth-cand-$i").close()
            ok = true
        } catch (e: Exception) {
            kind = "${e.javaClass.simpleName}：${e.message}"
        }
        check(ok, "候选口令 #${i + 1} 可连接（secrets 里的都是有效凭据）", kind)
    }
    var wrong2Rejected = false
    try {
        HamsterApi.connect("127.0.0.1", port, "another-wrong-secret", "auth-wrong2").close()
    } catch (_: SecureException) {
        wrong2Rejected = true
    } catch (_: Exception) {
    }
    check(wrong2Rejected, "候选列表之外的口令仍被拒")
    var api2: HamsterApi? = null
    try {
        api2 = HamsterApi.connect("127.0.0.1", port, secrets[2], "auth-test-good")
    } catch (_: Exception) {
    }
    check(api2 != null, "错口令尝试之后服务端仍可用（正确口令能连上）")
    if (api2 != null) {
        check(rawPingApi(api2), "重连后 ping/info 正常")
        api2.close()
    }

    /* ---------------- 并发 ---------------- */
    section("并发（3 个客户端同时下载/上传）")
    concurrencyTest(port, secrets[2], root, srcDir)

    /* ---------------- 原始通道协议细节 ---------------- */
    rawProtocolTests(port, secrets[2], root)

    /* ---------------- 停止 ---------------- */
    section("停止与端口释放")
    a.close()
    server.stop()
    check(!server.isRunning, "stop() 后 isRunning=false")
    server.stop()
    check(true, "stop() 幂等（第二次不抛异常）")
    check(portRefused(port), "stop() 后端口不再接受连接")

    var restarted: DaemonServer? = null
    var restartOk = false
    try {
        restarted = DaemonServer(core, port, "127.0.0.1", secrets)
        restarted.start()
        val a3 = HamsterApi.connect("127.0.0.1", port, secrets[2], "restart-test")
        try {
            restartOk = rawPingApi(a3)
        } finally {
            a3.close()
        }
    } catch (e: Exception) {
        restartOk = false
        println("  重启失败：${e.javaClass.simpleName}：${e.message}")
    } finally {
        try {
            restarted?.stop()
        } catch (_: Exception) {
        }
    }
    check(restartOk, "stop() 后同一端口可以重新监听并连通（端口确实释放了）")
    check(portRefused(port), "第二次 stop() 后端口再次释放")

    val leftover = Thread.getAllStackTraces().keys.filter { it.isAlive && it.name.startsWith("hamsterd-") }
    check(leftover.isEmpty(), "没有残留的 hamsterd-* 线程", leftover.map { it.name }.toString())
    val nonDaemon = Thread.getAllStackTraces().keys.filter {
        it.isAlive && !it.isDaemon && it !== Thread.currentThread() && it.name != "DestroyJavaVM"
    }
    check(nonDaemon.isEmpty(), "没有残留的非 daemon 线程阻塞 JVM 退出", nonDaemon.map { it.name }.toString())
}

private fun rawPingApi(api: HamsterApi): Boolean = try {
    api.protocolInfo().contains("\"monitor_path\"")
} catch (_: Exception) {
    false
}

/* ==========================================================================
 * 并发：3 条独立连接各自下载 1 MiB + 上传 256 KiB
 * ========================================================================== */
private fun concurrencyTest(port: Int, secret: String, root: File, srcDir: File) {
    val workers = 3
    val ready = CountDownLatch(workers)
    val go = CountDownLatch(1)
    val okCount = AtomicInteger(0)
    val errors = java.util.Collections.synchronizedList(ArrayList<String>())
    val bigSha = sha256Hex(File(root, "big.bin"))

    val threads = (0 until workers).map { i ->
        Thread({
            var api: HamsterApi? = null
            try {
                api = HamsterApi.connect("127.0.0.1", port, secret, "conc-$i")
                ready.countDown()
                go.await(15, TimeUnit.SECONDS)

                val local = File(srcDir, "conc-$i.bin").also { makePatternFile(it, 256 * 1024, 200 + i) }
                val localSha = sha256Hex(local)

                val dl = File(srcDir, "conc-dl-$i.bin")
                val n = api.download("big.bin", dl)
                if (n != 1024L * 1024L) throw IllegalStateException("worker $i 下载字节数=$n")
                if (sha256Hex(dl) != bigSha) throw IllegalStateException("worker $i 下载 SHA-256 不符")

                val remotePath = api.upload(local, "conc", overwrite = true, mkdir = true)
                val remoteFile = File(remotePath)
                if (!remoteFile.isFile) throw IllegalStateException("worker $i 上传落盘缺失：$remotePath")
                if (sha256Hex(remoteFile) != localSha) throw IllegalStateException("worker $i 上传 SHA-256 不符")

                okCount.incrementAndGet()
            } catch (e: Exception) {
                errors.add("worker $i：${e.javaClass.simpleName}：${e.message}")
            } finally {
                try {
                    api?.close()
                } catch (_: Exception) {
                }
            }
        }, "test-conc-$i")
    }
    threads.forEach { it.start() }
    ready.await(15, TimeUnit.SECONDS)
    go.countDown()
    threads.forEach { it.join(120_000) }

    check(okCount.get() == workers, "3 个并发客户端下载+上传全部成功", errors.toString())
    check(File(root, "conc").listFiles()?.size == workers, "3 个并发上传文件都在服务端")
    for (i in 0 until workers) {
        val remote = File(root, "conc/conc-$i.bin")
        check(remote.isFile && sha256Hex(remote) == sha256Hex(File(srcDir, "conc-$i.bin")), "并发上传 #$i SHA-256 一致")
    }
}

/* ==========================================================================
 * 原始加密通道上的协议细节
 * ========================================================================== */
private fun rawProtocolTests(port: Int, secret: String, root: File) {
    section("协议细节（原始加密通道）")
    val raw = try {
        RawConn("127.0.0.1", port, secret, "raw-test")
    } catch (e: Exception) {
        check(false, "建立原始加密通道", "${e.javaClass.simpleName}：${e.message}")
        return
    }
    try {
        val ping = raw.call("{\"type\":\"request\",\"id\":\"r1\",\"action\":\"ping\"}")
        checkEq(Json.getString(ping, "type"), "response", "ping 的 type=response")
        checkEq(Json.getString(ping, "status"), "ok", "ping 的 status=ok")
        val pingData = Json.getRawObject(ping, "data") ?: ""
        checkEq(Json.getBoolean(pingData, "pong"), true, "ping 返回 pong=true")
        check((Json.getLong(pingData, "time") ?: 0L) > 0L, "ping 返回 unix 秒")

        checkEq(Json.getString(raw.call("{\"type\":\"request\",\"id\":\"r2\",\"action\":\"info\"}"), "id"), "r2", "同一连接第二条请求（keep-alive）")

        checkEq(rawError(raw.call("this is not json")), "malformed_json", "非 JSON → malformed_json")
        check(rawPing(raw, "r3"), "malformed_json 之后连接仍可用")
        checkEq(rawError(raw.call("{\"type\":\"request\",\"id\":\"r4\"}")), "missing_action", "缺 action → missing_action")
        checkEq(rawError(raw.call("{\"type\":\"request\",\"id\":\"r5\",\"action\":\"nope\"}")), "unknown_action", "未知 action → unknown_action")
        checkEq(
            rawError(raw.call("{\"type\":\"request\",\"id\":\"r6\",\"action\":\"hello\",\"params\":{\"codeword\":\"x\"}}")),
            "unknown_action",
            "加密连接上的 hello → unknown_action（§8.4）",
        )
        checkEq(
            rawError(raw.call("{\"type\":\"request\",\"id\":\"r7\",\"action\":\"sync-database\"}")),
            "unknown_action",
            "sync-database 未实现 → unknown_action（不谎报成功）",
        )

        /* 单行 300 KiB：超过 256 KiB 上限，该行被丢弃但连接可用（与 C 一致） */
        val huge = "{\"type\":\"request\",\"id\":\"big\",\"action\":\"ping\",\"params\":{\"q\":\"" + "x".repeat(300 * 1024) + "\"}}"
        checkEq(rawError(raw.call(huge)), "line_too_long", "300 KiB 单行 → line_too_long")
        check(rawPing(raw, "r8"), "line_too_long 之后连接仍可用")

        /* upload 无 payload_bytes */
        checkEq(
            rawError(raw.call("{\"type\":\"request\",\"id\":\"r9\",\"action\":\"upload\",\"params\":{\"path\":\"mp.bin\"}}")),
            "missing_payload",
            "upload 无 payload_bytes → missing_payload",
        )
        check(rawPing(raw, "r10"), "missing_payload 之后连接仍可用")

        /* size != payload_bytes：服务端必须排空负载后继续 */
        raw.send("{\"type\":\"request\",\"id\":\"r11\",\"action\":\"upload\",\"params\":{\"path\":\"bad.bin\",\"size\":5},\"payload_bytes\":10}")
        raw.sendPayload(ByteArray(10) { 7 })
        checkEq(rawError(raw.readHeader() ?: ""), "bad_size", "size != payload_bytes → bad_size")
        check(!File(root, "bad.bin").exists(), "bad_size 没有落盘")
        check(rawPing(raw, "r12"), "bad_size 排空负载后连接仍可用")

        /* hash 不符：不留半成品 */
        raw.send(
            "{\"type\":\"request\",\"id\":\"r13\",\"action\":\"upload\",\"params\":{" +
                "\"path\":\"hm.bin\",\"size\":10,\"hash\":\"" + "0".repeat(32) + "\"},\"payload_bytes\":10}",
        )
        raw.sendPayload(ByteArray(10) { 1 })
        checkEq(rawError(raw.readHeader() ?: ""), "hash_mismatch", "声明 hash 不符 → hash_mismatch")
        check(!File(root, "hm.bin").exists(), "hash_mismatch 不留半成品")
        check(root.listFiles()?.none { it.name.contains(".part-") } == true, "没有残留 .part- 中转文件")
        check(rawPing(raw, "r14"), "hash_mismatch 之后连接仍可用")

        /* 正常 upload：响应字段与 C 一致 */
        raw.send("{\"type\":\"request\",\"id\":\"r15\",\"action\":\"upload\",\"params\":{\"path\":\"raw-ok.bin\",\"size\":10},\"payload_bytes\":10}")
        raw.sendPayload(ByteArray(10) { 2 })
        val okResp = raw.readHeader() ?: ""
        checkEq(Json.getString(okResp, "status"), "ok", "原始 upload 成功")
        val okData = Json.getRawObject(okResp, "data") ?: ""
        checkEq((Json.getString(okData, "hash") ?: "").length, 32, "upload 响应 hash 是 32 位十六进制")
        checkEq(Json.getLong(okData, "size"), 10L, "upload 响应 size=10")
        checkEq(Json.getString(okData, "name"), "raw-ok.bin", "upload 响应 name")
        checkEq(Json.getString(okData, "path"), File(root, "raw-ok.bin").canonicalPath, "upload 响应 path 是绝对路径")

        /* 0 字节 download：payload_bytes=0，没有负载帧 */
        val zero = raw.call("{\"type\":\"request\",\"id\":\"r16\",\"action\":\"download\",\"params\":{\"path\":\"zero.bin\"}}")
        val zeroData = Json.getRawObject(zero, "data") ?: ""
        checkEq(Json.getLong(zeroData, "payload_bytes"), 0L, "0 字节 download 的 data.payload_bytes=0")
        checkEq(Json.getLong(zeroData, "size"), 0L, "0 字节 download 的 size=0")
        checkEq(Json.getString(zeroData, "framing"), "raw", "download 头 framing=raw")
        checkEq(raw.readerPayloadBytes, 0L, "0 字节 download 没有负载帧")
        check(rawPing(raw, "r17"), "0 字节 download 之后连接仍可用")

        /* download 1 MiB：校验分帧声明的 payload_bytes 与实收字节 */
        raw.send("{\"type\":\"request\",\"id\":\"r18\",\"action\":\"download\",\"params\":{\"path\":\"big.bin\"}}")
        val dlHead = raw.readHeader() ?: ""
        val dlData = Json.getRawObject(dlHead, "data") ?: ""
        checkEq(Json.getLong(dlData, "payload_bytes"), 1024L * 1024L, "download 头 payload_bytes=1 MiB")
        checkEq(raw.readerPayloadBytes, 1024L * 1024L, "FrameReader 认出了 data.payload_bytes")
        var got = 0L
        raw.reader.readFully(raw.readerPayloadBytes) { _, _, len -> got += len }
        checkEq(got, 1024L * 1024L, "实收负载字节数 == payload_bytes")
        checkEq((Json.getString(dlData, "hash") ?: "").length, 32, "download 头 hash 是 32 位十六进制")
        check(rawPing(raw, "r19"), "1 MiB download 之后连接仍可用")

        /* §5 迁移链路的核心一步：download 头里的 hash 直接回传给 upload.hash */
        raw.send("{\"type\":\"request\",\"id\":\"r26\",\"action\":\"download\",\"params\":{\"path\":\"sub/nested.bin\"}}")
        val nh = raw.readHeader() ?: ""
        val nd = Json.getRawObject(nh, "data") ?: ""
        val nHash = Json.getString(nd, "hash") ?: ""
        val nSize = Json.getLong(nd, "payload_bytes") ?: 0L
        check(nHash.length == 32 && nSize == 4096L, "download 头给出 hash 与 payload_bytes", "hash=$nHash size=$nSize")
        val nBytes = ByteArray(nSize.toInt())
        var nOff = 0
        raw.reader.readFully(nSize) { b, o, l ->
            System.arraycopy(b, o, nBytes, nOff, l)
            nOff += l
        }
        raw.send(
            "{\"type\":\"request\",\"id\":\"r27\",\"action\":\"upload\",\"params\":{" +
                "\"path\":\"hash-roundtrip.bin\",\"size\":$nSize,\"hash\":\"$nHash\"},\"payload_bytes\":$nSize}",
        )
        raw.sendPayload(nBytes)
        val upResp = raw.readHeader() ?: ""
        checkEq(Json.getString(upResp, "status"), "ok", "用 download 的 hash 作为 upload.hash → 成功（§5 迁移链路）")
        val upData = Json.getRawObject(upResp, "data") ?: ""
        checkEq(Json.getString(upData, "hash"), nHash, "upload 返回的 hash 与 download 的 hash 相同")
        checkEq(
            sha256Hex(File(root, "hash-roundtrip.bin")),
            sha256Hex(File(root, "sub/nested.bin")),
            "hash 往返后落盘内容一致",
        )
        check(rawPing(raw, "r28"), "hash 往返之后连接仍可用")

        /* 服务端侧删根（客户端 normalizeFile 会先行拦截，这里绕过它） */
        val rootAbs = root.canonicalPath.replace("\\", "\\\\")
        val delRoot = raw.call("{\"type\":\"request\",\"id\":\"r20\",\"action\":\"delete\",\"params\":{\"path\":\"$rootAbs\",\"confirm\":true}}")
        checkEq(rawError(delRoot), "path_denied", "delete 监控根（绝对路径）→ path_denied")
        check(root.isDirectory, "根目录仍在")

        /* 绝对路径逃逸 */
        checkEq(
            rawError(raw.call("{\"type\":\"request\",\"id\":\"r21\",\"action\":\"download\",\"params\":{\"path\":\"/etc/passwd\"}}")),
            "path_denied",
            "download /etc/passwd → path_denied",
        )
        checkEq(
            rawError(raw.call("{\"type\":\"request\",\"id\":\"r22\",\"action\":\"delete\",\"params\":{\"path\":\"/etc/passwd\",\"confirm\":true}}")),
            "path_denied",
            "delete /etc/passwd → path_denied",
        )
        /* 非 upload 动作带负载：与 C 一致，先把响应发出去，然后关闭连接 */
        check(rawPing(raw, "r23"), "带负载前的连接正常")
        raw.send("{\"type\":\"request\",\"id\":\"r24\",\"action\":\"ping\",\"payload_bytes\":4}")
        raw.sendPayload(byteArrayOf(1, 2, 3, 4))
        val r24 = try {
            raw.readHeader()
        } catch (_: Exception) {
            null
        }
        check(r24 != null && Json.getString(r24, "id") == "r24", "带负载的 ping 仍回了响应", r24 ?: "null")
        var closedAfterPayload = false
        try {
            raw.send("{\"type\":\"request\",\"id\":\"r25\",\"action\":\"ping\"}")
            closedAfterPayload = raw.readHeader() == null
        } catch (_: Exception) {
            closedAfterPayload = true
        }
        check(closedAfterPayload, "非 upload 动作带 payload_bytes → 响应后关闭连接（与 C 一致）")
    } finally {
        raw.close()
    }
}
