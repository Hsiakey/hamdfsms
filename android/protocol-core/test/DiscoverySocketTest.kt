/*
 * DiscoverySocketTest.kt — DiscoverySocket.kt 的集成自检（真 UDP，回环地址）
 *
 * 不依赖 JUnit：用本地 DatagramSocket 当假 hamsterd，按 PROTOCOL §7.1 的规则
 * （replyMac 原文、nonce 回显、name/port/ver 字段）构造合法/非法应答，
 * 覆盖 scan / probeOnce 的真实收发路径。
 *
 * 编译与运行命令见 android/protocol-core/README.md 或本任务报告：
 *   kotlinc src\hamster\*.kt test\DiscoverySocketTest.kt -include-runtime -d build\disc\disc-test.jar
 *   java -jar build\disc\disc-test.jar
 *
 * 退出码：0 = 全部通过，1 = 有失败。
 */
package hamster

import java.io.Closeable
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import kotlin.system.exitProcess

private const val SECRET = "hamster-e05258d0ff46edc9601c2b3d585d463d"
private const val CLIENT_TARGET = "127.0.0.1"

private var pass = 0
private var fail = 0

/* ==========================================================================
 * 断言 / 输出
 * ========================================================================== */

private fun section(title: String) {
    println()
    println("== $title")
}

private fun check(cond: Boolean, name: String, detail: String = "") {
    if (cond) {
        pass++
        println("  ok   $name")
    } else {
        fail++
        println("  FAIL $name" + if (detail.isNotEmpty()) "  → $detail" else "")
    }
}

private fun checkEq(actual: Any?, expected: Any?, name: String) {
    check(actual == expected, name, "期望=$expected 实际=$actual")
}

private fun elapsedMs(startNs: Long): Long = (System.nanoTime() - startNs) / 1_000_000L

/* ==========================================================================
 * 假服务端
 * ========================================================================== */

private enum class Mode {
    NORMAL,                  // 正常应答
    WRONG_SECRET,            // 用错误暗号算 reply MAC
    WRONG_NONCE,             // 回显一个不属于本次探测的 nonce（MAC 本身合法）
    TAMPER_MAC,              // MAC 被改一位
    SILENT,                  // 收到也不回
    DROP_FIRST,              // 吞掉第一发探测，只回第二发
    DUPLICATE,               // 每发探测回两次相同应答
    OVERSIZED_THEN_REPLY,    // 先回 >512 字节垃圾帧，再回合法应答
    OVERSIZED_ONLY,          // 只回 >512 字节垃圾帧
    FOREIGN_NONCE_THEN_REPLY,// 先回旧 nonce 的合法应答，再回本轮合法应答（乱序）
    TWO_DEVICES              // 同一 socket 冒充两台设备，用于验证去重+排序
}

private data class DeviceSpec(
    val id: String,
    val name: String,
    val port: Int,
    val version: String
)

private data class SeenProbe(
    val id: String,
    val nonce: String,
    val mac: String,
    val atMs: Long
)

private class FakeServer(
    private val secret: String,
    private val mode: Mode,
    private val devices: List<DeviceSpec> = listOf(
        DeviceSpec("srv-000000000001", "客厅 Hamster", 19003, "0.0.9")
    ),
) : Closeable {

    private val bindAddress: InetAddress = InetAddress.getByName(CLIENT_TARGET)
    private val socket = DatagramSocket(InetSocketAddress(bindAddress, 0))
    private val lock = Object()
    private val seen = ArrayList<SeenProbe>()

    @Volatile
    private var running = true

    private val worker = Thread({ loop() }, "fake-hamsterd-disc").apply {
        isDaemon = true
        start()
    }

    val localPort: Int get() = socket.localPort

    fun probes(): List<SeenProbe> = synchronized(lock) { seen.toList() }

    fun awaitProbes(n: Int, timeoutMs: Long = 2000): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        synchronized(lock) {
            while (seen.size < n) {
                val left = deadline - System.currentTimeMillis()
                if (left <= 0) return false
                try {
                    lock.wait(left)
                } catch (_: InterruptedException) {
                    return false
                }
            }
            return true
        }
    }

    override fun close() {
        running = false
        try {
            socket.close()
        } catch (_: Exception) {
        }
        worker.join(500)
    }

    // ------------------------------------------------------------------ 收包 + 应答

    private fun loop() {
        socket.soTimeout = 100
        val buf = ByteArray(2048)
        var probeIndex = 0
        while (running) {
            val packet = DatagramPacket(buf, buf.size)
            try {
                socket.receive(packet)
            } catch (_: SocketTimeoutException) {
                continue
            } catch (_: IOException) {
                break
            }

            val text = String(packet.data, packet.offset, packet.length, Charsets.UTF_8)
            if (Json.getString(text, "t") != "hp") continue
            val id = Json.getString(text, "id") ?: continue
            val nonce = Json.getString(text, "n") ?: continue
            val mac = Json.getString(text, "m") ?: continue

            probeIndex++
            synchronized(lock) {
                seen.add(SeenProbe(id, nonce, mac, System.currentTimeMillis()))
                lock.notifyAll()
            }

            if (mode == Mode.SILENT) continue
            if (mode == Mode.DROP_FIRST && probeIndex == 1) continue

            val dest = InetSocketAddress(packet.address, packet.port)

            fun send(bytes: ByteArray) {
                if (!running) return
                try {
                    socket.send(DatagramPacket(bytes, bytes.size, dest))
                } catch (_: IOException) {
                }
            }

            val primary = devices.first()
            when (mode) {
                Mode.SILENT -> Unit // 上面已 continue；这里只是让 when 穷尽

                Mode.NORMAL, Mode.DROP_FIRST -> send(replyFrame(secret, id, nonce, primary))

                Mode.WRONG_SECRET ->
                    send(replyFrame("not-the-codeword", id, nonce, primary))

                Mode.WRONG_NONCE ->
                    // MAC 针对 foreign nonce 合法，但客户端必须因为 nonce 不属于本轮而丢弃。
                    send(replyFrame(secret, id, differentNonce(nonce), primary))

                Mode.TAMPER_MAC -> {
                    val good = replyMac(secret, id, nonce, primary.id, primary.port)
                    val bad = (if (good[0] == '0') "1" else "0") + good.substring(1)
                    send(replyFrame(secret, id, nonce, primary, macOverride = bad))
                }

                Mode.DUPLICATE -> {
                    val frame = replyFrame(secret, id, nonce, primary)
                    send(frame)
                    send(frame)
                }

                Mode.OVERSIZED_THEN_REPLY -> {
                    send(oversizedFrame())
                    send(replyFrame(secret, id, nonce, primary))
                }

                Mode.OVERSIZED_ONLY -> send(oversizedFrame())

                Mode.FOREIGN_NONCE_THEN_REPLY -> {
                    send(replyFrame(secret, id, differentNonce(nonce), primary))
                    send(replyFrame(secret, id, nonce, primary))
                }

                Mode.TWO_DEVICES -> {
                    for (device in devices) {
                        send(replyFrame(secret, id, nonce, device))
                    }
                }
            }
        }
    }

    /** 按 §7.1 组应答帧；字段值与 MAC 原文严格对应。 */
    private fun replyFrame(
        key: String,
        probeId: String,
        nonce: String,
        device: DeviceSpec,
        macOverride: String? = null,
    ): ByteArray {
        val mac = macOverride ?: replyMac(key, probeId, nonce, device.id, device.port)
        val json = "{\"t\":\"hr\",\"v\":1,\"id\":\"${device.id}\",\"n\":\"$nonce\"," +
            "\"m\":\"$mac\",\"name\":\"${device.name}\",\"port\":${device.port}," +
            "\"ver\":\"${device.version}\"}"
        return json.toByteArray(Charsets.UTF_8)
    }

    private fun differentNonce(current: String): String {
        val allZero = "00000000000000000000000000000000"
        return if (current != allZero) allZero else "11111111111111111111111111111111"
    }

    private fun oversizedFrame(): ByteArray = ByteArray(DISC_FRAME_MAX + 200) { 'x'.code.toByte() }
}

/* ==========================================================================
 * 用例
 * ========================================================================== */

private fun testHappyPath() {
    section("正常应答：字段、源 IP、两轮探测的 nonce/myId")
    FakeServer(SECRET, Mode.NORMAL).use { server ->
        val t0 = System.nanoTime()
        val list = DiscoveryClient.scan(
            SECRET, timeoutMs = 800, port = server.localPort, target = CLIENT_TARGET
        )
        val ms = elapsedMs(t0)

        checkEq(list.size, 1, "scan 收到 1 台设备（耗时 ${ms}ms）")
        val d = list.firstOrNull()
        checkEq(d?.id, "srv-000000000001", "id 正确")
        checkEq(d?.ip, "127.0.0.1", "ip 取 recvfrom 源地址（载荷里没有 IP）")
        checkEq(d?.name, "客厅 Hamster", "name 正确（UTF-8）")
        checkEq(d?.port, 19003, "port 是服务端 TCP 端口")
        checkEq(d?.version, "0.0.9", "version 正确")

        check(server.awaitProbes(2), "假服务端收到两次探测")
        val probes = server.probes()
        checkEq(probes.size, 2, "恰好收到 2 次探测")
        if (probes.size == 2) {
            check(probes.all { it.id == probes[0].id }, "两次探测共用同一个 myId")
            check(isValidDiscoveryId(probes[0].id), "myId 能通过 isValidDiscoveryId：${probes[0].id}")
            check(probes[0].nonce != probes[1].nonce, "两次探测的 nonce 不同")
            check(probes.all { isHex(it.nonce, DISC_NONCE_HEX_LEN) }, "nonce 是 32 位十六进制")
            check(
                probes.all { constantTimeEquals(probeMac(SECRET, it.id, it.nonce), it.mac) },
                "两次探测的 MAC 均按 §7.1 原文计算"
            )
            val gap = probes[1].atMs - probes[0].atMs
            check(gap in 100..800, "两次探测间隔约 200ms（实测 ${gap}ms）")
        }
    }
}

private fun testWrongSecret() {
    section("错误暗号：应答 MAC 对不上 → 静默丢弃")
    FakeServer(SECRET, Mode.WRONG_SECRET).use { server ->
        val list = DiscoveryClient.scan(
            SECRET, timeoutMs = 500, port = server.localPort, target = CLIENT_TARGET
        )
        check(list.isEmpty(), "错误暗号的应答返回空列表")
        check(server.awaitProbes(1), "假服务端确实收到了探测（不是没发包）")
    }
}

private fun testWrongNonce() {
    section("nonce 不匹配（回显别的 nonce）：丢弃")
    FakeServer(SECRET, Mode.WRONG_NONCE).use { server ->
        val list = DiscoveryClient.scan(
            SECRET, timeoutMs = 500, port = server.localPort, target = CLIENT_TARGET
        )
        check(list.isEmpty(), "nonce 不属于本轮探测的应答被丢弃")
        check(server.awaitProbes(1), "假服务端确实收到了探测")
    }
}

private fun testTamperedMac() {
    section("MAC 篡改：丢弃")
    FakeServer(SECRET, Mode.TAMPER_MAC).use { server ->
        val list = DiscoveryClient.scan(
            SECRET, timeoutMs = 500, port = server.localPort, target = CLIENT_TARGET
        )
        check(list.isEmpty(), "MAC 被改一位的应答被丢弃")
    }
}

private fun testSilentTimeout() {
    section("服务端完全不响应：超时后返回空列表，耗时不爆炸")
    FakeServer(SECRET, Mode.SILENT).use { server ->
        val timeoutMs = 400
        val t0 = System.nanoTime()
        val list = DiscoveryClient.scan(
            SECRET, timeoutMs = timeoutMs, port = server.localPort, target = CLIENT_TARGET
        )
        val ms = elapsedMs(t0)
        check(list.isEmpty(), "无人应答时返回空列表")
        check(ms >= timeoutMs - 100, "确实等到了超时（实测 ${ms}ms）")
        check(ms < timeoutMs + 1500, "耗时不爆炸：${ms}ms < ${timeoutMs + 1500}ms")
        check(server.awaitProbes(2), "两轮探测都发出去了")
    }
}

private fun testDropFirstProbe() {
    section("丢第一帧：第二轮探测仍能发现")
    FakeServer(SECRET, Mode.DROP_FIRST).use { server ->
        val list = DiscoveryClient.scan(
            SECRET, timeoutMs = 700, port = server.localPort, target = CLIENT_TARGET
        )
        checkEq(list.size, 1, "第一发被丢后，第二发仍发现设备")
        checkEq(list.firstOrNull()?.id, "srv-000000000001", "发现的 id 正确")
        check(server.awaitProbes(2), "两轮探测都发出去了")
    }
}

private fun testDuplicateReplies() {
    section("同一设备重复应答：按 id 去重成 1 条")
    FakeServer(SECRET, Mode.DUPLICATE).use { server ->
        val list = DiscoveryClient.scan(
            SECRET, timeoutMs = 600, port = server.localPort, target = CLIENT_TARGET
        )
        checkEq(list.size, 1, "4 次合法应答（2 轮 × 2 次）去重为 1 条")
        checkEq(list.firstOrNull()?.id, "srv-000000000001", "保留的 id 正确")
    }
}

private fun testOversizedAndOutOfOrder() {
    section("超大帧 / 乱序旧 nonce：丢弃但不崩")
    FakeServer(SECRET, Mode.OVERSIZED_THEN_REPLY).use { server ->
        val list = DiscoveryClient.scan(
            SECRET, timeoutMs = 600, port = server.localPort, target = CLIENT_TARGET
        )
        checkEq(list.size, 1, "先收到 >512 字节垃圾帧，随后合法应答仍被接收")
    }
    FakeServer(SECRET, Mode.OVERSIZED_ONLY).use { server ->
        val list = DiscoveryClient.scan(
            SECRET, timeoutMs = 500, port = server.localPort, target = CLIENT_TARGET
        )
        check(list.isEmpty(), "只有超大帧时返回空列表（没崩）")
    }
    FakeServer(SECRET, Mode.FOREIGN_NONCE_THEN_REPLY).use { server ->
        val list = DiscoveryClient.scan(
            SECRET, timeoutMs = 600, port = server.localPort, target = CLIENT_TARGET
        )
        checkEq(list.size, 1, "乱序：旧 nonce 的合法应答被丢弃，本轮应答被接收")
    }
}

private fun testTwoDevicesSorted() {
    section("多设备：按 name 再按 ip 排序")
    val devices = listOf(
        DeviceSpec("srv-00000000000a", "zeta-device", 19010, "0.0.9"),
        DeviceSpec("srv-00000000000b", "alpha-device", 19011, "0.0.9")
    )
    FakeServer(SECRET, Mode.TWO_DEVICES, devices).use { server ->
        val list = DiscoveryClient.scan(
            SECRET, timeoutMs = 600, port = server.localPort, target = CLIENT_TARGET
        )
        checkEq(list.size, 2, "发现 2 台设备")
        checkEq(list.map { it.name }, listOf("alpha-device", "zeta-device"), "按 name 升序")
        checkEq(list.map { it.ip }, listOf("127.0.0.1", "127.0.0.1"), "ip 均为源地址")
        checkEq(
            list.map { it.id },
            listOf("srv-00000000000b", "srv-00000000000a"),
            "name 顺序与 id 对应"
        )
    }
}

private fun testProbeOnce() {
    section("probeOnce：单发便利函数")
    FakeServer(SECRET, Mode.NORMAL).use { server ->
        val t0 = System.nanoTime()
        val d = DiscoveryClient.probeOnce(
            SECRET, target = CLIENT_TARGET, port = server.localPort, timeoutMs = 1000
        )
        val ms = elapsedMs(t0)
        checkEq(d?.id, "srv-000000000001", "probeOnce 返回设备")
        check(ms < 700, "probeOnce 命中即返回，不空等整个窗口（${ms}ms < 700ms）")
        check(server.awaitProbes(1), "假服务端收到 1 次探测")
        checkEq(server.probes().size, 1, "probeOnce 只发 1 帧")
    }
    FakeServer(SECRET, Mode.SILENT).use { server ->
        val t0 = System.nanoTime()
        val d = DiscoveryClient.probeOnce(
            SECRET, target = CLIENT_TARGET, port = server.localPort, timeoutMs = 300
        )
        val ms = elapsedMs(t0)
        check(d == null, "无人应答时 probeOnce 返回 null")
        check(ms >= 200, "probeOnce 等满超时（${ms}ms）")
    }
    FakeServer(SECRET, Mode.NORMAL).use { server ->
        val d = probeOnce(
            SECRET, target = CLIENT_TARGET, port = server.localPort, timeoutMs = 500
        )
        checkEq(d?.id, "srv-000000000001", "顶层 probeOnce 入口等价可用")
    }
}

private fun testInvalidInputs() {
    section("非法输入：不抛异常，返回空/null")
    check(DiscoveryClient.scan("", 300).isEmpty(), "空暗号 → 空列表")
    check(DiscoveryClient.scan(SECRET, 0).isEmpty(), "timeout=0 → 空列表")
    check(DiscoveryClient.scan(SECRET, -5).isEmpty(), "timeout<0 → 空列表")
    check(DiscoveryClient.scan(SECRET, 300, 0).isEmpty(), "端口 0 → 空列表")
    check(DiscoveryClient.scan(SECRET, 300, 70000).isEmpty(), "端口越界 → 空列表")
    check(
        DiscoveryClient.scan(SECRET, 300, DISC_DEFAULT_PORT, "   ").isEmpty(),
        "空 target → 空列表"
    )
    check(DiscoveryClient.probeOnce("", target = CLIENT_TARGET) == null, "probeOnce 空暗号 → null")
    check(
        DiscoveryClient.probeOnce(SECRET, target = "   ", timeoutMs = 200) == null,
        "probeOnce 空 target → null"
    )
}

private fun testConcurrentScans() {
    section("并发：两次 scan 同时跑，互不影响且 nonce 不复用")
    val s1 = FakeServer(SECRET, Mode.NORMAL)
    val s2 = FakeServer(
        SECRET, Mode.NORMAL,
        listOf(DeviceSpec("srv-000000000002", "书房 Hamster", 19004, "0.0.9"))
    )
    try {
        val results = arrayOfNulls<List<DiscoveredDevice>>(2)
        val errors = arrayOfNulls<Throwable>(2)

        val t1 = Thread {
            try {
                results[0] = DiscoveryClient.scan(
                    SECRET, timeoutMs = 700, port = s1.localPort, target = CLIENT_TARGET
                )
            } catch (t: Throwable) {
                errors[0] = t
            }
        }
        val t2 = Thread {
            try {
                results[1] = DiscoveryClient.scan(
                    SECRET, timeoutMs = 700, port = s2.localPort, target = CLIENT_TARGET
                )
            } catch (t: Throwable) {
                errors[1] = t
            }
        }
        t1.start()
        t2.start()
        t1.join(3000)
        t2.join(3000)

        check(errors.all { it == null }, "并发 scan 都没有抛异常")
        checkEq(results[0]?.size, 1, "scan #1 发现 1 台")
        checkEq(results[1]?.size, 1, "scan #2 发现 1 台")
        checkEq(results[0]?.firstOrNull()?.id, "srv-000000000001", "scan #1 id 正确")
        checkEq(results[1]?.firstOrNull()?.id, "srv-000000000002", "scan #2 id 正确")

        check(s1.awaitProbes(2) && s2.awaitProbes(2), "两个假服务端各收到 2 次探测")
        val nonces1 = s1.probes().map { it.nonce }.toSet()
        val nonces2 = s2.probes().map { it.nonce }.toSet()
        check(
            nonces1.intersect(nonces2).isEmpty(),
            "并发两次 scan（共 4 发）的 nonce 互不相同"
        )
        check(nonces1.size == 2 && nonces2.size == 2, "每次 scan 内两发 nonce 不同")
    } finally {
        s1.close()
        s2.close()
    }
}

/* ==========================================================================
 * main
 * ========================================================================== */

fun main() {
    println("Hamster DiscoverySocket 自检（真 UDP / 回环）")
    testHappyPath()
    testWrongSecret()
    testWrongNonce()
    testTamperedMac()
    testSilentTimeout()
    testDropFirstProbe()
    testDuplicateReplies()
    testOversizedAndOutOfOrder()
    testTwoDevicesSorted()
    testProbeOnce()
    testInvalidInputs()
    testConcurrentScans()

    println()
    println("PASS $pass / FAIL $fail")
    exitProcess(if (fail == 0) 0 else 1)
}
