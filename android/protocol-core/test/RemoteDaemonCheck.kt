/*
 * RemoteDaemonCheck.kt — 从桌面连一台**远程**守护端做端到端检查
 *
 * 用途：安卓守护端 App（hamster-daemon）跑在手机/模拟器里时，
 * 用 `adb forward tcp:9200 tcp:9100` 把宿主 9200 映射到设备 9100，
 * 然后跑本程序对它做真实的功能与安全验收。
 *
 *   java -cp daemon-remote.jar hamster.RemoteDaemonCheckKt 127.0.0.1 9200 <codeword>
 *
 * 与 DaemonCoreTest 的区别：那个用进程内 ServerSocket + 临时目录，验证业务层；
 * 这个只依赖 HamsterApi，验证"真的能从外部连上、能传、拒得掉"。
 * 因为它会**在远端写文件**（随机名，结束时删掉），只应对测试实例使用。
 */
package hamster

import java.io.File
import java.security.MessageDigest
import java.security.SecureRandom

private var ok = 0
private var bad = 0

private fun expect(cond: Boolean, name: String, detail: String = "") {
    if (cond) {
        ok++
        println("  ok   $name")
    } else {
        bad++
        println("  FAIL $name" + if (detail.isNotEmpty()) "  → $detail" else "")
    }
}

private fun sha256(file: File): String {
    val d = MessageDigest.getInstance("SHA-256")
    file.inputStream().use { input ->
        val buf = ByteArray(64 * 1024)
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            d.update(buf, 0, n)
        }
    }
    return d.digest().joinToString("") { String.format("%02x", it) }
}

fun main(args: Array<String>) {
    val host = args.getOrNull(0) ?: "127.0.0.1"
    val port = args.getOrNull(1)?.toIntOrNull() ?: 9200
    val secret = args.getOrNull(2) ?: "hamster-daemon-e2e"
    val deviceId = args.getOrNull(3) ?: "desktop-check"

    println("Hamster 远程守护端检查（客户端 ⇄ $host:$port，§8 加密）")

    /* 1) 错口令必须先被拒，且不能泄漏口令 */
    val t0 = System.currentTimeMillis()
    val wrong = try {
        HamsterApi.connect(host, port, "not-the-codeword-$port", deviceId, timeoutMs = 8000).also { it.close() }
        null
    } catch (e: Exception) {
        e
    }
    val ms = System.currentTimeMillis() - t0
    expect(wrong != null, "错口令被拒绝（${ms}ms）")
    if (wrong != null) {
        expect(
            wrong is SecureException || (wrong is HamsterApiException && wrong.code in
                setOf("socket_closed", "timeout", "connect_failed", "io_error", "not_encrypted")),
            "错口令抛的是传输/认证语义异常",
            wrong.javaClass.name + ": " + wrong.message,
        )
        expect(!wrong.message.orEmpty().contains(secret), "异常文本不含正确口令")
    }

    /* 2) 正确口令握手 */
    val api = try {
        HamsterApi.connect(host, port, secret, deviceId, timeoutMs = 10000)
    } catch (e: Exception) {
        println("  FAIL 正确口令也连不上：${e.javaClass.name}: ${e.message}")
        println()
        println("PASS $ok / FAIL ${bad + 1}")
        kotlin.system.exitProcess(1)
    }
    expect(true, "正确口令握手成功（server=${api.peerName} ver=${api.peerVersion}）")

    val work = File(System.getProperty("java.io.tmpdir"), "hamster-remote-" + System.nanoTime())
    work.mkdirs()
    val remoteNames = ArrayList<String>()

    try {
        /* 3) 只读接口 */
        val info = api.info()
        expect(info.version.isNotEmpty(), "info.version 非空", info.version)
        expect(info.server.isNotEmpty(), "info.server 非空", info.server)
        expect(info.monitorPath.isNotEmpty(), "info.monitor_path 非空", info.monitorPath)
        expect(info.features.isNotEmpty(), "info.features 非空", info.features.joinToString(","))

        val health = api.health()
        expect(health.status.isNotEmpty(), "health.status 非空", health.status)

        val stats = api.stats()
        expect(stats.fileCount >= 0, "stats.fileCount 合理", stats.fileCount.toString())

        val root = api.listPage("/", 0, 100)
        expect(root.total >= 0, "listPage 可用（total=${root.total}）")
        expect(root.limit in 1..1000, "listPage 回显 limit 合理", root.limit.toString())

        /* 4) 上传 → 下载回读（字节级一致） */
        val blob = File(work, "remote-check-${System.nanoTime()}.bin")
        val rnd = SecureRandom()
        val data = ByteArray(300_000).also { rnd.nextBytes(it) }
        blob.writeBytes(data)
        val want = sha256(blob)
        val remotePath = api.upload(blob, "/", overwrite = true)
        remoteNames.add(remotePath.substringAfterLast('/').substringAfterLast('\\'))
        expect(true, "上传成功（${data.size} 字节 → $remotePath）")

        val back = File(work, "back.bin")
        val n = api.download(remotePath, back)
        expect(n == data.size.toLong(), "下载字节数一致", "got=$n want=${data.size}")
        expect(sha256(back) == want, "下载内容 SHA-256 一致", sha256(back).take(16) + " vs " + want.take(16))

        /* 5) 搜索能命中刚上传的文件 */
        val needle = remotePath.substringAfterLast('/').substringAfterLast('\\')
        val hits = api.search(needle, limit = 50)
        expect(hits.files.isNotEmpty(), "search 命中刚上传的文件（total=${hits.total}）")
        if (hits.files.isNotEmpty()) {
            expect(
                hits.files.any { it.path.contains(needle) },
                "命中项的 path 含文件名",
                hits.files.first().path,
            )
        }

        /* 6) 目录：建 → 列表可见 → 删 → 列表消失 */
        val dirName = "remote-dir-${System.nanoTime()}"
        api.mkdir(dirName)
        val after = api.listPage("/", 0, 1000)
        val hasDir = after.entries.any { it.name == dirName }
        expect(hasDir, "新建目录出现在列表里（$dirName）")
        if (hasDir) {
            val target = after.entries.first { it.name == dirName }.path
            api.delete(target)
            val gone = api.listPage("/", 0, 1000).entries.none { it.name == dirName }
            expect(gone, "删除后目录从列表消失")
            remoteNames.remove(dirName)
        }

        /* 7) verify 只读模式不崩 */
        val vr = api.verify(false)
        expect(vr.verifyCount >= 0, "verify(false) 可用", "count=${vr.verifyCount}")
    } catch (e: Exception) {
        expect(false, "执行中抛异常", e.javaClass.name + ": " + e.message)
    } finally {
        /* 8) 清理远端测试文件（尽力而为，失败不算用例失败） */
        for (nm in remoteNames) {
            try {
                val entries = api.listPage("/", 0, 1000).entries
                entries.firstOrNull { it.name == nm }?.let { api.delete(it.path) }
            } catch (_: Exception) {
            }
        }
        try {
            api.close()
            api.close()
            expect(true, "close() 幂等不抛")
        } catch (e: Exception) {
            expect(false, "close() 幂等不抛", e.message.orEmpty())
        }
        work.deleteRecursively()
    }

    println()
    println("PASS $ok / FAIL $bad")
    if (bad > 0) kotlin.system.exitProcess(1)
}
