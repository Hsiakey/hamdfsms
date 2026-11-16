/*
 * DiscoveryResponderTest.kt — §7 服务端应答器的零依赖自检
 *
 * 客户端侧（DiscoverySocketTest）已经证明"能收、会丢"；这里证明服务端的另一半：
 * 该回的回了、该静的静了、限速与重放窗口真的生效。
 *
 * 全部走 127.0.0.1 上的真 UDP，不需要 hamsterd。
 */
package hamster

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress

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

private fun section(t: String) = println("\n== $t")

private fun waitUntil(timeoutMs: Long, cond: () -> Boolean): Boolean {
    val deadline = System.currentTimeMillis() + timeoutMs
    while (System.currentTimeMillis() < deadline) {
        if (cond()) return true
        Thread.sleep(10)
    }
    return cond()
}

private const val CODEWORD = "responder-test-codeword"
private const val SERVER_ID = "0123456789abcdef"

private fun responder(port: Int = 0, codeword: String = CODEWORD): DiscoveryResponder =
    DiscoveryResponder(
        port = port,
        codeword = codeword,
        serverId = SERVER_ID,
        serverName = "测试机 A",
        tcpPort = 9100,
        version = "0.0.9",
    )

/** 手工发一帧探测，返回是否收到应答（顺便返回应答字节数）。 */
private fun rawProbe(port: Int, frame: ByteArray, timeoutMs: Int = 600): Int {
    DatagramSocket(null).use { s ->
        s.soTimeout = timeoutMs
        val addr = InetAddress.getByName("127.0.0.1")
        s.send(DatagramPacket(frame, frame.size, addr, port))
        val buf = ByteArray(DISC_FRAME_MAX + 1)
        return try {
            s.receive(DatagramPacket(buf, buf.size))
            DISC_FRAME_MAX // 只关心"有没有回"
        } catch (_: Exception) {
            0
        }
    }
}

fun main() {
    println("Hamster §7 应答器自检（真 UDP 回环）")

    /* 1. 正常应答：客户端能发现，字段对 */
    section("正常应答")
    val r = responder()
    r.start()
    expect(waitUntil(2000) { r.boundPort > 0 }, "应答器已绑定端口")
    val port = r.boundPort
    val one = DiscoveryClient.probeOnce(CODEWORD, "127.0.0.1", port, timeoutMs = 1500)
    expect(one != null, "客户端 probeOnce 发现设备")
    if (one != null) {
        expect(one.name == "测试机 A", "name 正确（含中文）", one.name)
        expect(one.port == 9100, "回给客户端的是 TCP 端口", one.port.toString())
        expect(one.version == "0.0.9", "version 正确", one.version)
        expect(one.id == SERVER_ID, "id 正确", one.id)
    }
    expect(r.acceptedProbes >= 1, "acceptedProbes 计数", r.acceptedProbes.toString())
    expect(r.sentReplies >= 1, "sentReplies 计数", r.sentReplies.toString())

    /* 2. scan 也会发现（两轮探测，nonce 不同，不被重放窗口误杀） */
    section("完整 scan")
    val all = DiscoveryClient.scan(CODEWORD, timeoutMs = 1500, port = port, target = "127.0.0.1")
    expect(all.size == 1, "scan 去重后正好 1 台", all.size.toString())

    /* 3. 错口令：一帧都不回 */
    section("错口令静默")
    val beforeDropped = r.droppedFrames
    val wrong = DiscoveryClient.probeOnce("wrong-codeword-xxx", "127.0.0.1", port, timeoutMs = 600)
    expect(wrong == null, "错口令探测拿不到应答")
    expect(r.droppedFrames > beforeDropped, "错口令计入 droppedFrames")

    /* 4. 同一帧重复发（重放）：第二次被丢 */
    section("重放窗口")
    val nonce = "a".repeat(32)
    val frame = buildProbe(CODEWORD, "client-replay-01", nonce)
    val first = rawProbe(port, frame)
    val second = rawProbe(port, frame)
    expect(first != 0, "第一次同帧探测有应答")
    expect(second == 0, "窗口期内同帧重放无应答")

    /* 5. 限速：一口气灌 100 帧，应答数必须明显少于 100（突发上限 40） */
    section("限速")
    val r2 = responder()
    r2.start()
    waitUntil(2000) { r2.boundPort > 0 }
    val p2 = r2.boundPort
    var got = 0
    DatagramSocket(null).use { s ->
        s.soTimeout = 200
        val addr = InetAddress.getByName("127.0.0.1")
        // 不等应答，连续灌 100 帧：这才是"突发"的真实形态
        for (i in 0 until 100) {
            val n = String.format("%032x", 5000 + i)
            val f = buildProbe(CODEWORD, "client-ratelimit", n)
            s.send(DatagramPacket(f, f.size, addr, p2))
        }
        val buf = ByteArray(DISC_FRAME_MAX + 1)
        val deadline = System.currentTimeMillis() + 1500
        while (System.currentTimeMillis() < deadline) {
            try {
                s.receive(DatagramPacket(buf, buf.size))
                got++
            } catch (_: Exception) {
                // 超时：窗口结束
            }
        }
    }
    expect(got > 0, "突发下仍有应答（$got/100）")
    expect(got <= 45, "突发上限生效：100 帧最多回 40 上下（实际 $got）")
    r2.stop()

    /* 6. 停掉之后不再应答 */
    section("停止后静默")
    r.stop()
    expect(!r.isRunning, "isRunning=false")
    expect(r.boundPort == -1, "端口已释放")
    val after = DiscoveryClient.probeOnce(CODEWORD, "127.0.0.1", port, timeoutMs = 400)
    expect(after == null, "停止后探测拿不到应答")

    /* 7. 空口令：永远不回（等价关闭发现） */
    section("空口令")
    val r3 = responder(codeword = "")
    r3.start()
    Thread.sleep(150)
    expect(!r3.isRunning, "空口令不会启动监听")
    r3.stop()

    println()
    println("PASS $ok / FAIL $bad")
    if (bad > 0) kotlin.system.exitProcess(1)
}
