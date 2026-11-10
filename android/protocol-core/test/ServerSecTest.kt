/*
 * ServerSecTest.kt — §8 服务端握手 + §7 探测解析/应答 的零依赖自检
 *
 * 证明两件事：
 *   1) SecureServer.handshake 能与**现有客户端** SecureChannel.connect 回环互通
 *      （不是自己跟自己玩：客户端侧一行代码都没改）；
 *   2) 记录层方向（服务端发 s2c、收 c2s）没弄反，且 300 KiB 跨记录、错口令静默、
 *      篡改记录被拒、探测帧解析/应答往返都成立。
 *
 * 运行（产物放 build\srvsec\，不覆盖别人的 jar）：
 *   kotlinc src\hamster\Protocol.kt src\hamster\Discovery.kt src\hamster\Crypto.kt `
 *           src\hamster\Secure.kt test\ServerSecTest.kt -include-runtime -d build\srvsec\srvsec-test.jar
 *   java -jar build\srvsec\srvsec-test.jar
 * 退出码：0 = 全部通过，1 = 有失败。
 */
package hamster

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.MessageDigest
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

private var okCount = 0
private var badCount = 0

/* ==========================================================================
 * 断言与输出
 * ========================================================================== */

private fun section(title: String) {
    println()
    println("== $title")
}

private fun check(cond: Boolean, name: String, detail: String = "") {
    if (cond) {
        okCount++
        println("  ok   $name")
    } else {
        badCount++
        println("  FAIL $name" + if (detail.isNotEmpty()) "  → $detail" else "")
    }
}

private fun checkEq(actual: Any?, expected: Any?, name: String) {
    check(actual == expected, name, "期望=$expected 实际=$actual")
}

/** 每个用例独立兜底：一个用例抛异常不影响其余用例，但仍然记 FAIL。 */
private fun test(title: String, block: () -> Unit) {
    section(title)
    try {
        block()
    } catch (e: Throwable) {
        badCount++
        println("  FAIL $title 抛出 ${e.javaClass.simpleName}: ${e.message}")
    }
}

/* ==========================================================================
 * 小工具
 * ========================================================================== */

private fun writeLine(out: OutputStream, line: String) {
    out.write(line.toByteArray(Charsets.UTF_8))
    out.write('\n'.code)
    out.flush()
}

/** 从明文流读一行（EOF 且一个字节都没读到 → null）。 */
private fun readLineFrom(input: InputStream): String? {
    val buf = ByteArrayOutputStream(128)
    while (true) {
        val c = input.read()
        if (c < 0) return if (buf.size() == 0) null else String(buf.toByteArray(), Charsets.UTF_8)
        if (c == '\n'.code) return String(buf.toByteArray(), Charsets.UTF_8)
        if (c != '\r'.code) buf.write(c)
    }
}

private fun sha256Hex(b: ByteArray): String {
    val d = MessageDigest.getInstance("SHA-256").digest(b)
    val sb = StringBuilder(d.size * 2)
    for (x in d) sb.append(String.format("%02x", x))
    return sb.toString()
}

/* ==========================================================================
 * 回环服务端：一个线程 accept 一次并跑 SecureServer.handshake
 * ========================================================================== */

private class ServerRun {
    val socket: ServerSocket = ServerSocket()
    @Volatile var session: SecureServerSession? = null
    @Volatile var handshakeError: String? = null
    @Volatile var readError: String? = null
    val handshakeDone = CountDownLatch(1)
    var thread: Thread? = null

    val port: Int get() = socket.localPort

    /**
     * 起服务端线程。握手成功后（且会话非 null）执行 [afterHandshake]，
     * 便于在服务端线程里读记录、观察拒绝语义。
     */
    fun start(secrets: List<String>, afterHandshake: ((SecureServerSession) -> Unit)? = null) {
        socket.reuseAddress = true
        socket.bind(InetSocketAddress("127.0.0.1", 0))
        val t = Thread(Runnable {
            var sock: Socket? = null
            try {
                sock = socket.accept()
                sock.tcpNoDelay = true
                val s = SecureServer.handshake(sock.getInputStream(), sock.getOutputStream(), secrets)
                session = s
                if (s == null) {
                    // 与 C 侧一致：认证失败由调用方直接关闭连接（不回错误对象）
                    try { sock.close() } catch (_: Exception) {}
                } else {
                    afterHandshake?.invoke(s)
                }
            } catch (e: Exception) {
                handshakeError = e.javaClass.simpleName + ": " + (e.message ?: "")
                try { sock?.close() } catch (_: Exception) {}
            } finally {
                handshakeDone.countDown()
            }
        }, "srvsec-test-server")
        t.isDaemon = true
        t.start()
        thread = t
    }

    fun awaitSession(ms: Long): SecureServerSession? {
        handshakeDone.await(ms, TimeUnit.MILLISECONDS)
        return session
    }

    fun close() {
        try { socket.close() } catch (_: Exception) {}
        try { session?.close() } catch (_: Exception) {}
        try { thread?.join(1000) } catch (_: InterruptedException) { Thread.currentThread().interrupt() }
    }
}

/* ==========================================================================
 * 手写客户端（只在"篡改记录"用例里用：需要逐字节改密文，
 * SecureChannel 不暴露 socket，做不到）
 * ========================================================================== */

private class ManualConn(val keys: SecKeys, val out: OutputStream)

private fun manualHandshake(sock: Socket, secret: String, deviceId: String): ManualConn {
    val rawIn = sock.getInputStream()
    val rawOut = sock.getOutputStream()

    val nc = ByteArray(Sec.NONCE_LEN)
    java.util.Random(20261111L).nextBytes(nc)
    val ncHex = Sec.bytesToHex(nc)

    writeLine(rawOut, "{\"type\":\"auth\",\"step\":\"hello\",\"v\":2,\"device_id\":\"$deviceId\"," +
        "\"hostname\":\"manual-client\",\"nc\":\"$ncHex\"}")

    val challenge = readLineFrom(rawIn) ?: throw IllegalStateException("没有收到 challenge")
    if (Json.getString(challenge, "type") != "auth" || Json.getString(challenge, "step") != "challenge") {
        throw IllegalStateException("challenge 形状不对：$challenge")
    }
    val saltHex = Json.getString(challenge, "salt") ?: throw IllegalStateException("challenge 缺 salt")
    val nsHex = Json.getString(challenge, "ns") ?: throw IllegalStateException("challenge 缺 ns")

    val keys = Sec.deriveSession(secret.toByteArray(Charsets.UTF_8), saltHex, ncHex, nsHex, deviceId)
    writeLine(rawOut, "{\"type\":\"auth\",\"step\":\"proof\",\"mac\":\"" + Sec.bytesToHex(keys.proofC) + "\"}")

    val okLine = readLineFrom(rawIn) ?: throw IllegalStateException("没有收到 auth/ok")
    val macHex = Json.getString(okLine, "mac") ?: ""
    if (!Sec.isHex32(macHex)) throw IllegalStateException("auth/ok 的 mac 不是 64 hex：$macHex")
    if (!Sec.constantTimeEquals(Sec.hexToBytes(macHex), keys.proofS)) {
        throw IllegalStateException("服务端证明不成立")
    }
    return ManualConn(keys, rawOut)
}

/* ==========================================================================
 * 用例
 * ========================================================================== */

private fun testServerHandshakeLoopback() = test("§8.2 服务端握手 ⇄ 现有 SecureChannel 客户端（候选口令 3 个）") {
    val correct = "srv-secret-cccccccccccccccc"
    val srv = ServerRun()
    srv.start(listOf("wrong-secret-1", "wrong-secret-2", correct))
    var ch: SecureChannel? = null
    try {
        ch = SecureChannel.connect("127.0.0.1", srv.port, correct, "dev_kotlin_srv", "android-daemon", 5000)
        val s = srv.awaitSession(5000)
        check(s != null, "服务端握手成功（正确口令在第 3 个候选）", "session=null")
        if (s != null) {
            checkEq(s.deviceId, "dev_kotlin_srv", "deviceId 来自 hello")
            checkEq(s.hostname, "android-daemon", "hostname 来自 hello")
            checkEq(s.authLabel, "api_key:" + correct.take(8), "命中第 3 个候选 → api_key 分支")
            check(Sec.isHex16(s.clientNonceHex), "clientNonceHex 是 32 位 hex")
            check(Sec.isHex16(s.serverNonceHex), "serverNonceHex 是 32 位 hex")
            check(s.clientNonceHex != s.serverNonceHex, "两侧 nonce 不同")
        }
        checkEq(ch.peerName, "hamsterd", "客户端看到 challenge 里的 server=hamsterd")
        checkEq(ch.peerVersion, "0.0.9", "客户端看到 challenge 里的 version=0.0.9")
        checkEq(srv.handshakeError, null, "服务端没有抛异常")
    } finally {
        try { ch?.close() } catch (_: Exception) {}
        srv.close()
    }
}

private fun testCodewordLabel() = test("§8.2 第 0 个候选命中 → authLabel=codeword；无 hostname → unknown") {
    val secret = "codeword-first-bbbbbbbbbbbb"
    val srv = ServerRun()
    srv.start(listOf(secret, "an-api-key-111111111111"))
    var ch: SecureChannel? = null
    try {
        ch = SecureChannel.connect("127.0.0.1", srv.port, secret, "dev_label", null, 5000)
        val s = srv.awaitSession(5000)
        check(s != null, "服务端握手成功（第 1 个候选命中）")
        if (s != null) {
            checkEq(s.authLabel, "codeword", "第 0 个候选 → codeword")
            checkEq(s.hostname, "unknown", "hello 没带 hostname → unknown（同 C 侧）")
        }
    } finally {
        try { ch?.close() } catch (_: Exception) {}
        srv.close()
    }
}

private fun testBidirectional() = test("§8.3 双向密文（c2s / s2c 方向没弄反）") {
    val secret = "dir-secret-dddddddddddddd"
    val srv = ServerRun()
    srv.start(listOf(secret))
    var ch: SecureChannel? = null
    try {
        ch = SecureChannel.connect("127.0.0.1", srv.port, secret, "dev_dir", "dir-client", 5000)
        val s = srv.awaitSession(5000) ?: throw IllegalStateException("服务端握手失败")
        val c2s = "{\"type\":\"request\",\"id\":\"d1\",\"action\":\"ping\"}"
        writeLine(ch.output, c2s)
        checkEq(readLineFrom(s.input), c2s, "服务端在 c2s 记录层读到客户端明文")

        val s2c = "{\"type\":\"response\",\"id\":\"d1\",\"status\":\"ok\",\"pong\":true}"
        writeLine(s.output, s2c)
        checkEq(readLineFrom(ch.input), s2c, "客户端在 s2c 记录层读到服务端明文")
    } finally {
        try { ch?.close() } catch (_: Exception) {}
        srv.close()
    }
}

private fun testBigRecord() = test("§8.3 大记录：服务端发 300 KiB，客户端按字节收全") {
    val secret = "big-secret-eeeeeeeeeeeeeeee"
    val srv = ServerRun()
    srv.start(listOf(secret))
    var ch: SecureChannel? = null
    try {
        ch = SecureChannel.connect("127.0.0.1", srv.port, secret, "dev_big", "big-client", 5000)
        val s = srv.awaitSession(5000) ?: throw IllegalStateException("服务端握手失败")

        val payload = ByteArray(300 * 1024)
        java.util.Random(20261111L).nextBytes(payload)

        /*
         * 必须边写边读：300 KiB 远大于 socket 发送缓冲，主线程先写满再读会自己把自己
         * 堵死（写阻塞在 send，读永远不开始）。这里让服务端在另一个线程写，主线程读。
         */
        var writeError: String? = null
        val writer = Thread(Runnable {
            try {
                s.output.write(payload)
                s.output.flush()
            } catch (e: Exception) {
                writeError = e.javaClass.simpleName + ": " + (e.message ?: "")
            }
        }, "srvsec-test-big-writer")
        writer.isDaemon = true
        writer.start()

        val got = ByteArray(payload.size)
        var off = 0
        while (off < got.size) {
            val n = ch.input.read(got, off, got.size - off)
            if (n < 0) break
            off += n
        }
        val records = (payload.size + Sec.MAX_PLAIN - 1) / Sec.MAX_PLAIN
        checkEq(off, payload.size, "按字节收全（跨 $records 条记录）")
        writer.join(5000)
        checkEq(writeError, null, "服务端写入没有异常")
        val want = sha256Hex(payload)
        val have = sha256Hex(got)
        checkEq(have, want, "SHA-256 一致")
        println("       SHA-256 = $have")
    } finally {
        try { ch?.close() } catch (_: Exception) {}
        srv.close()
    }
}

private fun testWrongSecret() = test("§8.2 错口令：服务端 null，客户端只看到连接关闭") {
    val srv = ServerRun()
    srv.start(listOf("alpha-secret", "beta-secret"))
    var code: String? = null
    try {
        try {
            val bad = SecureChannel.connect("127.0.0.1", srv.port, "gamma-wrong", "dev_wrong", null, 3000)
            bad.close()
            check(false, "错误口令必须失败")
        } catch (e: SecureException) {
            code = e.code
        } catch (e: Exception) {
            code = e.javaClass.simpleName
        }
        check(srv.handshakeDone.await(5, TimeUnit.SECONDS), "服务端握手线程返回")
        check(srv.session == null, "handshake 返回 null（不构造会话）")
        checkEq(code, "socket_closed", "客户端看到的是连接被关（不是错误对象）")
        checkEq(srv.handshakeError, null, "服务端没有抛异常（静默返回 null）")
    } finally {
        srv.close()
    }
}

private fun testSilentFailureNoBytes() = test("§8.2 认证失败静默：只发 challenge，不再发任何字节") {
    val nc = "00112233445566778899aabbccddeeff"
    val hello = "{\"type\":\"auth\",\"step\":\"hello\",\"v\":2,\"device_id\":\"dev_x\",\"nc\":\"$nc\"}\n"
    val wrongProof = "{\"type\":\"auth\",\"step\":\"proof\",\"mac\":\"" + "00".repeat(32) + "\"}\n"

    val out = ByteArrayOutputStream()
    val sess = SecureServer.handshake(
        ByteArrayInputStream((hello + wrongProof).toByteArray(Charsets.UTF_8)),
        out,
        listOf("right-secret"),
    )
    check(sess == null, "错 proof → null")
    val text = String(out.toByteArray(), Charsets.UTF_8)
    val lines = text.trimEnd('\n').split('\n')
    checkEq(lines.size, 1, "只输出 1 行（challenge）")
    check(lines[0].startsWith("{\"type\":\"auth\",\"step\":\"challenge\""), "发出去的确实是 challenge")
    check(!text.contains("\"step\":\"ok\""), "没有 auth/ok")
    check(!text.contains("error"), "没有错误对象")

    // 顺便把 challenge 的字段钉一遍（客户端 SecureChannel 解析的就是这些）
    val chal = lines[0]
    checkEq(Json.getInt(chal, "v"), 2, "challenge v=2")
    checkEq(Json.getString(chal, "alg"), "chacha20poly1305", "challenge alg")
    checkEq(Json.getString(chal, "kdf"), "hkdf-sha256", "challenge kdf")
    checkEq(Json.getString(chal, "server"), "hamsterd", "challenge server")
    checkEq(Json.getString(chal, "version"), "0.0.9", "challenge version")
    check(Sec.isHex16(Json.getString(chal, "salt")), "challenge salt 是 32 位 hex")
    check(Sec.isHex16(Json.getString(chal, "ns")), "challenge ns 是 32 位 hex")
    check(chal.contains("\"features\":[\"framing:aead\""), "features 含 framing:aead")

    // 空候选列表：连 hello 都不读，直接 null
    check(SecureServer.handshake(ByteArrayInputStream(ByteArray(0)), ByteArrayOutputStream(), emptyList()) == null,
        "secrets 为空 → 直接 null")

    // 非法 hello（nc 不是 32 hex）：一个字节都不发
    val badOut = ByteArrayOutputStream()
    val badHello = "{\"type\":\"auth\",\"step\":\"hello\",\"v\":2,\"device_id\":\"dev_x\",\"nc\":\"zz\"}\n"
    check(SecureServer.handshake(ByteArrayInputStream(badHello.toByteArray()), badOut, listOf("s")) == null,
        "非法 hello → null")
    checkEq(badOut.size(), 0, "非法 hello 时一个字节都不发")
}

private fun testTamperedRecord() = test("§8.3 篡改记录：服务端读时拒绝（aead_failed）") {
    val secret = "tamper-secret-ffffffffffff"
    val srv = ServerRun()
    srv.start(listOf(secret)) { s ->
        try {
            s.input.read()
            srv.readError = "no_error"
        } catch (e: SecureException) {
            srv.readError = e.code
        } catch (e: Exception) {
            srv.readError = e.javaClass.simpleName
        }
    }
    var sock: Socket? = null
    try {
        sock = Socket()
        sock.tcpNoDelay = true
        sock.connect(InetSocketAddress("127.0.0.1", srv.port), 3000)
        val conn = manualHandshake(sock, secret, "dev_tamper")

        val sealer = RecordSealer(conn.keys.keyC2S, Sec.DIR_C2S)
        val rec = sealer.seal("tampered-payload\n".toByteArray(Charsets.UTF_8))
        val idx = Sec.HDR_LEN + 4                      // 落在密文里（不是头部/counter）
        rec[idx] = (rec[idx].toInt() xor 0x01).toByte()
        conn.out.write(rec)
        conn.out.flush()

        check(srv.handshakeDone.await(5, TimeUnit.SECONDS), "服务端读记录返回")
        checkEq(srv.readError, "aead_failed", "被篡改的记录被拒绝")
        check(srv.session != null, "握手本身仍成功（篡改发生在记录层）")
    } finally {
        try { sock?.close() } catch (_: Exception) {}
        srv.close()
    }
}

private fun testDiscoveryProbeReply() = test("§7 探测帧解析 + 服务端应答（buildReply → parseReply 往返）") {
    val cw = "hamster-e05258d0ff46edc9601c2b3d585d463d"
    val clientId = "fedcba9876543210"
    val selfId = "0123456789abcdef"
    val nonce = "00112233445566778899aabbccddeeff"
    val otherNonce = "ffeeddccbbaa99887766554433221100"

    val probe = buildProbe(cw, clientId, nonce)
    val req = parseProbe(cw, selfId, probe)
    check(req != null, "合法探测帧通过")
    checkEq(req?.clientId, clientId, "clientId 回显")
    checkEq(req?.nonceHex, nonce, "nonce 回显")

    check(parseProbe("wrong-codeword", selfId, probe) == null, "错口令 → null")
    check(parseProbe(cw, clientId, probe) == null, "id == myId（自己发的探测）→ null")

    val text = String(probe, Charsets.UTF_8)
    val mac = probeMac(cw, clientId, nonce)

    val badNonce = text.replace(nonce, otherNonce).toByteArray(Charsets.UTF_8)
    check(parseProbe(cw, selfId, badNonce) == null, "篡改 nonce → null")

    val badMac = text.replace(mac, mac.dropLast(1) + (if (mac.last() == '0') '1' else '0'))
        .toByteArray(Charsets.UTF_8)
    check(parseProbe(cw, selfId, badMac) == null, "篡改 MAC → null")

    val nulFrame = (text.dropLast(1) + "\u0000}").toByteArray(Charsets.UTF_8)
    check(parseProbe(cw, selfId, nulFrame) == null, "内嵌 NUL → null")

    check(parseProbe(cw, selfId, ByteArray(0)) == null, "空帧 → null")

    val tooLong = ByteArray(DISC_FRAME_MAX + 1)
    System.arraycopy(probe, 0, tooLong, 0, probe.size)
    for (i in probe.size until tooLong.size) tooLong[i] = ' '.code.toByte()
    check(parseProbe(cw, selfId, tooLong) == null, "超过 512 字节 → null")

    check(parseProbe(cw, selfId, text.replace("\"hp\"", "\"hr\"").toByteArray()) == null, "t != hp → null")
    check(parseProbe(cw, selfId, text.replace("\"v\":1", "\"v\":2").toByteArray()) == null, "v != 1 → null")
    check(parseProbe(cw, selfId, text.replace(clientId, "short").toByteArray()) == null, "id 非法 → null")
    check(parseProbe(cw, selfId, text.replace(clientId, "fedcba98 76543210").toByteArray()) == null,
        "id 含空格 → null")

    /* --- 服务端应答 --- */
    val name = "客厅 NAS \"主\""
    val reply = buildReply(cw, selfId, clientId, nonce, name, 9100, "0.0.9")
    check(reply.size <= DISC_FRAME_MAX, "应答帧 ≤ 512 字节")
    check(!String(reply, Charsets.UTF_8).contains("\n"), "应答帧无换行")
    check(String(reply, Charsets.UTF_8).startsWith("{\"t\":\"hr\",\"v\":1,"), "应答字段顺序与 C 侧一致")

    val peer = parseReply(cw, clientId, reply)
    check(peer != null, "buildReply 的帧能过现有 parseReply")
    checkEq(peer?.id, selfId, "id == 服务端 id")
    checkEq(peer?.name, name, "name 一致（含引号转义）")
    checkEq(peer?.port, 9100, "port 一致")
    checkEq(peer?.version, "0.0.9", "ver 一致")
    checkEq(peer?.nonceHex, nonce, "nonce 原样回显")

    check(parseReply("wrong-codeword", clientId, reply) == null, "应答换错口令 → null（MAC 绑定口令）")
    check(parseReply(cw, "0123456789abcdee", reply) == null, "捕获的应答重放给另一个客户端 → null")

    var threw = false
    try {
        buildReply(cw, selfId, clientId, nonce, "x".repeat(600), 9100, "0.0.9")
    } catch (_: IllegalArgumentException) {
        threw = true
    }
    check(threw, "超长应答帧 → IllegalArgumentException")

    threw = false
    try {
        buildReply(cw, selfId, clientId, nonce, "n", 0, "0.0.9")
    } catch (_: IllegalArgumentException) {
        threw = true
    }
    check(threw, "非法端口 → IllegalArgumentException")
}

/* ==========================================================================
 * main
 * ========================================================================== */

fun main(args: Array<String>) {
    println("Hamster §8 服务端握手 + §7 探测应答 自检（纯 JVM / Kotlin）")
    if (args.isNotEmpty()) println("（忽略命令行参数：${args.joinToString(" ")}）")

    testServerHandshakeLoopback()
    testCodewordLabel()
    testBidirectional()
    testBigRecord()
    testWrongSecret()
    testSilentFailureNoBytes()
    testTamperedRecord()
    testDiscoveryProbeReply()

    println()
    println("PASS $okCount / FAIL $badCount")
    if (badCount != 0) {
        System.exit(1)
    }
}
