/*
 * TestMain.kt — Hamster 协议核心库自检（不依赖 JUnit）
 *
 * 目标：把"最容易写错、写错又最致命"的地方钉死。
 *   · HMAC-SHA256 对齐 RFC 4231（与 tests/test_crypto.c 的向量同一批）；
 *   · 发现协议的 MAC 原文固定向量（C 服务端 / Node 客户端 / Python 三方交叉算过）；
 *   · 分帧：半行、跨多次读取、负载分块、payload_bytes 与实际不符必须报错；
 *   · parseAddr：IPv4、IPv6 方括号、裸 IPv6、各种非法输入；
 *   · 发现帧：正确暗号通过，错暗号 / 篡改 nonce / 篡改 MAC 一律返回 null。
 *
 * 运行（见 README.md）：
 *   java -jar build\protocol-core.jar
 * 退出码：0 = 全部通过，1 = 有失败。
 */
package hamster

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream

private var pass = 0
private var fail = 0

/* ==========================================================================
 * 发现协议固定向量
 *
 * 参数与服务端测试 tests/test_disc.c 完全一致：
 *   codeword = "hamster-e05258d0ff46edc9601c2b3d585d463d"
 *   probe id = "fedcba9876543210"，self id = "0123456789abcdef"
 *   nonce    = "00112233445566778899aabbccddeeff"
 *   port     = 9100
 *
 * 下面两个 MAC 由三份互相独立的实现算出并写死：
 *   1) 服务端 C 实现 Hamsterd/hd_crypto.c（hd_hmac_sha256）；
 *   2) Node.js crypto.createHmac('sha256', ...)；
 *   3) Python 3 hmac + hashlib。
 * 三者结果一致，因此这两个常数可以当作"线格式"的钉子：
 * 任何人改动 MAC 原文（少一个 '\n'、末尾多一个 '\n'、端口写成带前导零）都会立刻失败。
 * ========================================================================== */
private const val CW = "hamster-e05258d0ff46edc9601c2b3d585d463d"
private const val PEER = "fedcba9876543210"
private const val SELF = "0123456789abcdef"
private const val NONCE = "00112233445566778899aabbccddeeff"

private const val PROBE_MAC = "25185ea6aebf8e6fb01cdeb61467663caf9bf7b0011d8e30da166f051524c958"
private const val REPLY_MAC = "a0d9d9a5e1f1d7e8ab90dab130b65541bd070efb79b76927631cdf077b505b7a"

/* ==========================================================================
 * 断言与输出
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

private fun checkBytes(actual: ByteArray, expected: ByteArray, name: String) {
    if (actual.contentEquals(expected)) {
        pass++
        println("  ok   $name")
    } else {
        fail++
        println("  FAIL $name")
        println("         期望(hex)=${hexOf(expected)}")
        println("         实得(hex)=${hexOf(actual)}")
    }
}

private inline fun <reified T : Throwable> expectThrows(name: String, block: () -> Unit) {
    try {
        block()
        check(false, name, "没有抛出异常")
    } catch (e: Throwable) {
        check(e is T, name, "抛出的是 ${e.javaClass.simpleName}: ${e.message}")
    }
}

private fun hexOf(bytes: ByteArray): String {
    val digits = "0123456789abcdef"
    val sb = StringBuilder(bytes.size * 2)
    for (b in bytes) {
        val v = b.toInt() and 0xFF
        sb.append(digits[v ushr 4]).append(digits[v and 0x0F])
    }
    val shown = if (sb.length > 160) sb.substring(0, 160) + "…" else sb.toString()
    return shown
}

private fun bytes(s: String): ByteArray = s.toByteArray(Charsets.UTF_8)

private fun concat(vararg parts: ByteArray): ByteArray {
    var total = 0
    for (p in parts) total += p.size
    val out = ByteArray(total)
    var off = 0
    for (p in parts) {
        System.arraycopy(p, 0, out, off, p.size)
        off += p.size
    }
    return out
}

/* ==========================================================================
 * 可控的分块流：read() 一次只返回一个 chunk，用来模拟"数据分批到达"。
 * ========================================================================== */
private class ChunkedStream(private val chunks: List<ByteArray>) : InputStream() {
    private var chunk = 0
    private var off = 0

    override fun read(): Int {
        val one = ByteArray(1)
        return if (read(one, 0, 1) == 1) one[0].toInt() and 0xFF else -1
    }

    override fun read(b: ByteArray, dstOff: Int, len: Int): Int {
        if (len == 0) return 0
        while (chunk < chunks.size && off >= chunks[chunk].size) {
            chunk++
            off = 0
        }
        if (chunk >= chunks.size) return -1
        val c = chunks[chunk]
        val n = minOf(len, c.size - off)
        System.arraycopy(c, off, b, dstOff, n)
        off += n
        return n
    }
}

/* ==========================================================================
 * 1. HMAC-SHA256 标准向量
 * ========================================================================== */
private fun testHmac() {
    section("HMAC-SHA256（RFC 4231 / tests/test_crypto.c）")

    checkEq(
        hmacSha256Hex("Jefe", "what do ya want for nothing?"),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        "RFC 4231 Test Case 2（key=\"Jefe\"）"
    )
    checkEq(
        hmacSha256Hex(ByteArray(20) { 0x0B.toByte() }, bytes("Hi There")),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        "RFC 4231 Test Case 1（20 字节 0x0b）"
    )
    checkEq(
        hmacSha256Hex(ByteArray(20) { 0xAA.toByte() }, ByteArray(50) { 0xDD.toByte() }),
        "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
        "RFC 4231 Test Case 3（20×0xaa / 50×0xdd）"
    )
    checkEq(
        hmacSha256Hex(
            ByteArray(131) { 0xAA.toByte() },
            bytes("Test Using Larger Than Block-Size Key - Hash Key First")
        ),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
        "RFC 4231 Test Case 6（131 字节密钥，超过分块）"
    )
    checkEq(
        hmacSha256Hex("key", "The quick brown fox jumps over the lazy dog"),
        "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8",
        "HMAC(key, fox) 经典向量"
    )
}

/* ==========================================================================
 * 2. 发现协议固定向量与探测帧构造
 * ========================================================================== */
private fun testDiscoveryVectors() {
    section("发现协议固定向量（PROTOCOL §7.1）")

    checkEq(probeMac(CW, PEER, NONCE), PROBE_MAC, "probe MAC 固定向量（与 C/Node/Python 一致）")
    checkEq(replyMac(CW, PEER, NONCE, SELF, 9100), REPLY_MAC, "reply MAC 固定向量（与 C/Node/Python 一致）")

    val expectedProbe =
        "{\"t\":\"hp\",\"v\":1,\"id\":\"$PEER\",\"n\":\"$NONCE\",\"m\":\"$PROBE_MAC\"}"
    val probe = buildProbe(CW, PEER, NONCE)
    checkBytes(probe, bytes(expectedProbe), "buildProbe 输出与服务端 hd_disc_build_probe 逐字节一致")
    check(probe.size <= DISC_FRAME_MAX, "探测帧不超过 512 字节", "实际 ${probe.size}")

    expectThrows<IllegalArgumentException>("空 codeword → buildProbe 抛异常") {
        buildProbe("", PEER, NONCE)
    }
    expectThrows<IllegalArgumentException>("id 过短（<8）→ buildProbe 抛异常") {
        buildProbe(CW, "short", NONCE)
    }
    expectThrows<IllegalArgumentException>("id 含非法字符 → buildProbe 抛异常") {
        buildProbe(CW, "bad id!!", NONCE)
    }
    expectThrows<IllegalArgumentException>("nonce 不是 32 位十六进制 → buildProbe 抛异常") {
        buildProbe(CW, PEER, "0011")
    }
}

/* ==========================================================================
 * 3. 极简 JSON
 * ========================================================================== */
private fun testJson() {
    section("Json（顶层匹配、跳过转义）")

    checkEq(
        Json.getString("{\"a\":{\"m\":\"nested\"},\"m\":\"top\"}", "m"),
        "top",
        "嵌套对象里的同名 key 不会被取到"
    )
    checkEq(
        Json.getString("{\"x\":\"a\\\"m\\\":1\",\"m\":\"ok\"}", "m"),
        "ok",
        "字符串里的转义引号不会破坏 key 扫描"
    )
    checkEq(
        Json.getString("{\"m\":\"a\\\\b\"}", "m"),
        "a\\b",
        "反斜杠转义被正确解码"
    )
    checkEq(
        Json.getString("{\"m\":\"\\u4e2d\\u6587\"}", "m"),
        "中文",
        "\\uXXXX 转义被正确解码"
    )
    checkEq(
        Json.getString("{\"m\":\"\\ud83d\\ude00\"}", "m"),
        "\uD83D\uDE00",
        "UTF-16 代理对转义被正确解码"
    )
    checkEq(Json.getString("{\"aa\":\"x\",\"a\":\"y\"}", "a"), "y", "key 是完整匹配，不做前缀匹配")
    checkEq(Json.getLong("{\"n\":123}", "n"), 123L, "整数读取")
    checkEq(Json.getLong("{\"n\":-7}", "n"), -7L, "负整数读取")
    check(Json.getLong("{\"n\":1.5}", "n") == null, "小数不当作整数")
    check(Json.getLong("{\"n\":1e3}", "n") == null, "指数写法不当作整数")
    check(Json.getLong("{\"n\":\"5\"}", "n") == null, "字符串数字不当作整数")
    checkEq(Json.getBoolean("{\"b\":true}", "b"), true, "布尔读取")
    checkEq(Json.getString("{\"m\":\"unterminated}", "m"), null, "不完整 JSON → null")
    check(!Json.isObject("[1,2,3]"), "数组不是对象")
    check(!Json.isObject("not json"), "非 JSON 不是对象")
    check(
        !Json.hasKey("{\"a\":{\"payload_bytes\":5}}", "payload_bytes"),
        "嵌套的 payload_bytes 不算顶层字段"
    )
}

/* ==========================================================================
 * 4. 二进制分帧（PROTOCOL §3）
 * ========================================================================== */
private fun testFraming() {
    section("二进制分帧（PROTOCOL §3）")

    val header = "{\"type\":\"response\",\"id\":\"d1\",\"status\":\"ok\",\"payload_bytes\":5}"
    val payload = byteArrayOf(0x00, 0x01, 0x02, 0x7F, 0xFF.toByte())

    // 4.1 单字节到达（一次给半行、一行跨多次读取的极端情形）
    run {
        val line = concat(bytes(header), bytes("\n"))
        val chunks = ArrayList<ByteArray>()
        for (b in line) chunks.add(byteArrayOf(b))
        for (b in payload) chunks.add(byteArrayOf(b))
        val r = FrameReader(ChunkedStream(chunks))
        checkEq(r.readHeader(), header, "单字节到达也能读出一整行")
        checkEq(r.payloadBytes, 5L, "payload_bytes 被识别为 5")
        check(r.hasPayload, "声明负载后 hasPayload=true")
        checkBytes(r.readFully(5), payload, "负载含 0x00/0xff 也按字节精确读取")
        check(!r.hasPayload, "读满后 hasPayload=false")
        checkEq(r.readHeader(), null, "之后到达 EOF → readHeader 返回 null")
    }

    // 4.2 半行 + 半行，负载分块到达
    run {
        val cut = 20
        val chunks = listOf(
            bytes(header.substring(0, cut)),
            bytes(header.substring(cut) + "\nAB"),
            bytes("CDE")
        )
        val r = FrameReader(ChunkedStream(chunks))
        checkEq(r.readHeader(), header, "一行跨多次读取（先到半行）")
        var calls = 0
        val collected = ByteArrayOutputStream()
        val n = r.readPayload { b, o, len ->
            calls++
            collected.write(b, o, len)
        }
        checkEq(n, 5L, "readPayload 返回实际消费的字节数")
        checkBytes(collected.toByteArray(), bytes("ABCDE"), "负载分块到达也能拼成完整字节")
        check(calls >= 2, "负载确实是流式分块回调（回调次数 $calls ≥ 2）")
    }

    // 4.3 多条消息连续、CRLF、以及"负载之后紧跟下一条消息头"
    run {
        val stream = ByteArrayInputStream(
            concat(
                bytes("{\"a\":1}\r\n"),
                bytes("{\"b\":2,\"payload_bytes\":3}\n"),
                bytes("XYZ"),
                bytes("{\"c\":3}\n")
            )
        )
        val r = FrameReader(stream)
        checkEq(r.readHeader(), "{\"a\":1}", "CRLF 行尾被去掉")
        checkEq(r.payloadBytes, 0L, "未声明 payload_bytes 时为 0")
        check(!r.hasPayload, "无负载消息 hasPayload=false")
        checkEq(r.readHeader(), "{\"b\":2,\"payload_bytes\":3}", "连续读取第二条消息头")
        checkBytes(r.readFully(3), bytes("XYZ"), "第三条消息的负载精确读取")
        checkEq(r.readHeader(), "{\"c\":3}", "负载后紧跟的下一条消息头可正常解析")
        checkEq(r.readHeader(), null, "流结束")
    }

    // 4.4 payload_bytes 与实际不符：偏少（对端提前关闭）必须报错
    run {
        val h = "{\"type\":\"response\",\"payload_bytes\":10}"
        val r = FrameReader(
            ByteArrayInputStream(concat(bytes(h), bytes("\n"), bytes("abcde")))
        )
        r.readHeader()
        expectThrows<ProtocolException>("payload_bytes=10 但只收到 5 字节 → 报错，不得当成功") {
            r.readFully(10)
        }
    }

    // 4.5 payload_bytes 与实际不符：偏多（声明 5，实际多送了 5 字节）
    run {
        val h = "{\"payload_bytes\":5}"
        val r = FrameReader(
            ByteArrayInputStream(concat(bytes(h), bytes("\n"), bytes("HELLO"), bytes("WORLD{\"x\":1}\n")))
        )
        r.readHeader()
        checkBytes(r.readFully(5), bytes("HELLO"), "先读满声明的 5 字节")
        expectThrows<ProtocolException>("多送的裸字节会被当成下一条消息头 → 报错") {
            r.readHeader()
        }
    }

    // 4.6 其他非法消息头
    expectThrows<ProtocolException>("readFully 超过 payload_bytes 声明 → 抛异常") {
        val r = FrameReader(
            ByteArrayInputStream(
                concat(bytes("{\"payload_bytes\":10}"), bytes("\n"), ByteArray(10) { 1 })
            )
        )
        r.readHeader()
        r.readFully(11)
    }
    expectThrows<ProtocolException>("负载未读完就解析下一条消息头 → 抛异常") {
        val r = FrameReader(
            ByteArrayInputStream(
                concat(bytes("{\"payload_bytes\":10}"), bytes("\n"), ByteArray(10) { 1 })
            )
        )
        r.readHeader()
        r.readHeader()
    }
    expectThrows<ProtocolException>("payload_bytes 是字符串 → 抛异常") {
        FrameReader(ByteArrayInputStream(bytes("{\"payload_bytes\":\"5\"}\n"))).readHeader()
    }
    expectThrows<ProtocolException>("payload_bytes 是小数 → 抛异常") {
        FrameReader(ByteArrayInputStream(bytes("{\"payload_bytes\":1.5}\n"))).readHeader()
    }
    expectThrows<ProtocolException>("payload_bytes 为负数 → 抛异常") {
        FrameReader(ByteArrayInputStream(bytes("{\"payload_bytes\":-1}\n"))).readHeader()
    }
    expectThrows<ProtocolException>("消息头不是 JSON 对象 → 抛异常") {
        FrameReader(ByteArrayInputStream(bytes("hello\n"))).readHeader()
    }
    expectThrows<ProtocolException>("消息头不是合法 UTF-8 → 抛异常") {
        FrameReader(ByteArrayInputStream(byteArrayOf(0xFF.toByte(), 0x0A))).readHeader()
    }

    // 4.7 行尾没有 '\n' 就 EOF：按"半行也算一行"处理（与服务端 rd_read_line 一致）
    run {
        val r = FrameReader(ByteArrayInputStream(bytes("{\"a\":1}")))
        checkEq(r.readHeader(), "{\"a\":1}", "EOF 前的半行也能被读出")
        checkEq(r.readHeader(), null, "再次读取返回 null")
    }

    // 4.8 单行上限严格按字节：恰好 256 KiB 通过，多 1 字节失败
    run {
        val okLine = jsonLineOfSize(FrameReader.DEFAULT_MAX_LINE_BYTES)
        val okReader = FrameReader(
            ByteArrayInputStream(concat(okLine, bytes("\n"), bytes("{\"next\":1}\n")))
        )
        val okHeader = okReader.readHeader()
        checkEq(
            okHeader?.toByteArray(Charsets.UTF_8)?.size,
            FrameReader.DEFAULT_MAX_LINE_BYTES,
            "恰好 256 KiB（262144 字节）的行被接受"
        )
        checkEq(okReader.readHeader(), "{\"next\":1}", "上限边界之后仍能继续解析")
    }
    run {
        val overLine = jsonLineOfSize(FrameReader.DEFAULT_MAX_LINE_BYTES + 1)
        val r = FrameReader(
            ByteArrayInputStream(concat(overLine, bytes("\n"), bytes("{\"next\":1}\n")))
        )
        expectThrows<LineTooLongException>("超过 256 KiB 的行 → LineTooLongException") {
            r.readHeader()
        }
        checkEq(r.readHeader(), "{\"next\":1}", "超长行被整体丢弃，连接仍可继续使用")
    }

    // 4.9 上限按字节而不是字符：10 万个汉字 = 30 万字节，String.length 只有 10 万
    run {
        val chinese = "字".repeat(100_000)
        val line = bytes("{\"x\":\"" + chinese + "\"}")
        check(line.size > FrameReader.DEFAULT_MAX_LINE_BYTES, "（构造的汉字行确实超过 256 KiB 字节）")
        val r = FrameReader(ByteArrayInputStream(concat(line, bytes("\n"))))
        expectThrows<LineTooLongException>("按字节计数：汉字行超限被拒（不是按 String.length）") {
            r.readHeader()
        }
    }
}

/** 构造一个总字节数恰好为 [totalBytes] 的 JSON 对象行：{"x":"aaa..."}。 */
private fun jsonLineOfSize(totalBytes: Int): ByteArray {
    // 固定开销：{"x":" 共 6 字节，结尾 "} 共 2 字节
    val pad = totalBytes - 8
    require(pad >= 0) { "totalBytes 太小：$totalBytes" }
    return bytes("{\"x\":\"" + "a".repeat(pad) + "\"}")
}

/* ==========================================================================
 * 5. parseAddr
 * ========================================================================== */
private fun testParseAddr() {
    section("parseAddr（host:port / IPv6）")

    checkEq(parseAddr("127.0.0.1:9100", 9110), "127.0.0.1" to 9100, "IPv4 + 端口")
    checkEq(parseAddr("127.0.0.1", 9110), "127.0.0.1" to 9110, "IPv4 + 默认端口")
    checkEq(parseAddr("[::1]:9100", 9110), "::1" to 9100, "[::1]:9100 → 主机去掉方括号")
    checkEq(parseAddr("[::1]", 9110), "::1" to 9110, "[::1] 用默认端口")
    checkEq(parseAddr("::1", 9110), "::1" to 9110, "裸 IPv6 用默认端口")
    checkEq(parseAddr("fe80::1", 9100), "fe80::1" to 9100, "裸 IPv6（链路本地形式）")
    checkEq(
        parseAddr("[2001:db8::1]:65535", 9110),
        "2001:db8::1" to 65535,
        "IPv6 + 端口边界 65535"
    )
    checkEq(
        parseAddr("::ffff:192.168.1.1", 9100),
        "::ffff:192.168.1.1" to 9100,
        "内嵌 IPv4 的 IPv6 字面量"
    )
    checkEq(parseAddr("localhost:9100", 9110), "localhost" to 9100, "主机名 + 端口")
    checkEq(parseAddr(" 127.0.0.1:9100 ", 9110), "127.0.0.1" to 9100, "首尾空白被忽略")

    val bad = listOf(
        "" to "空串",
        "   " to "全空白",
        ":9100" to "缺少主机",
        "127.0.0.1:" to "缺少端口",
        "127.0.0.1:0" to "端口 0",
        "127.0.0.1:65536" to "端口越界",
        "127.0.0.1:abc" to "端口非数字",
        "127.0.0.1: 9100" to "端口前有空格",
        "999.1.1.1:9100" to "IPv4 段越界",
        "1.2.3:9100" to "IPv4 段数不足",
        "010.0.0.1:9100" to "IPv4 前导零",
        "[::1" to "缺少右方括号",
        "[]:9100" to "方括号内为空",
        "[::1]9100" to "方括号后缺少冒号",
        "[127.0.0.1]:9100" to "方括号内不是 IPv6",
        "::1::2" to "IPv6 出现多处 ::",
        "::g" to "IPv6 含非十六进制字符",
        "host name:9100" to "主机含空格"
    )
    for ((input, why) in bad) {
        expectThrows<IllegalArgumentException>("非法地址（$why）被拒：\"$input\"") {
            parseAddr(input, 9110)
        }
    }
    expectThrows<IllegalArgumentException>("默认端口越界 → 抛异常") {
        parseAddr("127.0.0.1", 0)
    }
}

/* ==========================================================================
 * 6. 发现帧校验
 * ========================================================================== */
private fun testDiscoveryFrames() {
    section("发现帧校验（正确通过 / 各类篡改一律 null）")

    check(isValidDiscoveryId("0123456789abcdef"), "16 位十六进制 id 合法")
    check(isValidDiscoveryId("abc-def_123"), "允许 '-' 与 '_'")
    check(!isValidDiscoveryId("short"), "过短（<8）被拒")
    check(!isValidDiscoveryId(""), "空 id 被拒")
    check(!isValidDiscoveryId("has space"), "空格被拒")
    check(!isValidDiscoveryId("a".repeat(64)), "超长（64）被拒")
    check(isHex(NONCE, 32), "32 位十六进制 nonce 合法")
    check(!isHex(NONCE, 31), "长度不符被拒")
    check(!isHex("zz112233445566778899aabbccddeeff", 32), "非十六进制字符被拒")

    check(constantTimeEquals("abc", "abc"), "常量时间比较：相等")
    check(!constantTimeEquals("abc", "abd"), "常量时间比较：不等")
    check(!constantTimeEquals("abc", "abcd"), "常量时间比较：长度不同")
    check(constantTimeEquals("", ""), "常量时间比较：两个空串")

    val frame = replyFrame(NONCE, SELF, "my-pc", 9100, "0.0.8", REPLY_MAC)

    run {
        val peer = parseReply(CW, PEER, frame)
        check(peer != null, "正确 codeword → 应答通过")
        if (peer != null) {
            checkEq(peer.id, SELF, "服务端 id 正确")
            checkEq(peer.port, 9100, "TCP 端口正确")
            checkEq(peer.name, "my-pc", "显示名正确")
            checkEq(peer.version, "0.0.8", "版本正确")
            checkEq(peer.nonceHex, NONCE, "nonce 原样回显")
        } else {
            check(false, "正确 codeword → 应答通过（peer 为 null，后续字段断言跳过）")
        }
    }

    check(parseReply("wrong-codeword", PEER, frame) == null, "错 codeword → null（静默丢弃）")
    check(parseReply("", PEER, frame) == null, "空 codeword → null")
    check(parseReply(CW, "", frame) == null, "myId 为空 → null（不抛异常）")
    check(parseReply(CW, "short", frame) == null, "myId 不合法 → null（不抛异常）")

    // 篡改 nonce：MAC 覆盖 n，必须失败
    val tamperedNonce = NONCE.substring(0, 31) + (if (NONCE[31] == 'f') "0" else "f")
    check(
        parseReply(CW, PEER, replyFrame(tamperedNonce, SELF, "my-pc", 9100, "0.0.8", REPLY_MAC)) == null,
        "篡改 nonce → MAC 不符，null"
    )

    // 篡改 MAC：翻转最后一位
    val badMac = REPLY_MAC.substring(0, 63) + (if (REPLY_MAC[63] == 'a') "b" else "a")
    check(
        parseReply(CW, PEER, replyFrame(NONCE, SELF, "my-pc", 9100, "0.0.8", badMac)) == null,
        "篡改 MAC → null"
    )
    check(
        parseReply(CW, PEER, replyFrame(NONCE, SELF, "my-pc", 9100, "0.0.8", REPLY_MAC.uppercase())) == null,
        "大写 MAC → null（与 C 侧 hd_ct_equal 区分大小写一致）"
    )

    // 换一个探测方 id：MAC 原文里带 probe_id，必须失败（防重放给别的客户端）
    check(parseReply(CW, "aaaaaaaaaaaaaaaa", frame) == null, "换一个探测方 id → MAC 不符，null")
    check(parseReply(CW, SELF, frame) == null, "服务端 id == 本机 id → null（自打自收）")

    // t / v 不符
    val tHp = String(frame, Charsets.UTF_8).replace("\"t\":\"hr\"", "\"t\":\"hp\"")
    check(parseReply(CW, PEER, bytes(tHp)) == null, "t=hp 冒充应答 → null")
    val v2 = String(frame, Charsets.UTF_8).replace("\"v\":1", "\"v\":2")
    check(parseReply(CW, PEER, bytes(v2)) == null, "v=2 → null")

    // 篡改端口：MAC 覆盖 port
    check(
        parseReply(CW, PEER, replyFrame(NONCE, SELF, "my-pc", 9200, "0.0.8", REPLY_MAC)) == null,
        "篡改端口 → MAC 不符，null"
    )
    check(
        parseReply(CW, PEER, replyFrame(NONCE, SELF, "my-pc", 0, "0.0.8", replyMac(CW, PEER, NONCE, SELF, 9100))) == null,
        "port=0 → null"
    )
    // 端口字段是字符串（类型不符）
    val portAsString = String(frame, Charsets.UTF_8).replace("\"port\":9100", "\"port\":\"9100\"")
    check(parseReply(CW, PEER, bytes(portAsString)) == null, "port 是字符串 → null")

    // 显示名里的引号/反斜杠：转义后仍能原样取回
    run {
        val weird = "a\"b\\c"
        val p = parseReply(CW, PEER, replyFrame(NONCE, SELF, weird, 9100, "0.0.8", REPLY_MAC))
        check(p != null && p.name == weird, "显示名含引号/反斜杠时转义往返一致", "实得=${p?.name}")
    }

    // 缺 name / ver 时按空串（协议允许"可选"）
    run {
        val minimal = "{\"t\":\"hr\",\"v\":1,\"id\":\"$SELF\",\"n\":\"$NONCE\",\"m\":\"$REPLY_MAC\",\"port\":9100}"
        val p = parseReply(CW, PEER, bytes(minimal))
        check(
            p != null && p.name == "" && p.version == "",
            "name/ver 缺失时按空串处理",
            "peer=${p?.name}"
        )
    }

    // 其它拒绝路径
    check(parseReply(CW, PEER, ByteArray(0)) == null, "空帧 → null")
    check(parseReply(CW, PEER, bytes("not json")) == null, "非 JSON → null")
    check(parseReply(CW, PEER, frame.copyOf(frame.size - 10)) == null, "截断的应答 → null")
    check(
        parseReply(CW, PEER, bytes("{\"t\":\"hr\",\"v\":1,\"id\":\"$SELF\",\"n\":\"$NONCE\",\"m\":\"$REPLY_MAC\",\"name\":\"a\u0000b\",\"port\":9100}")) == null,
        "帧内嵌 NUL → null"
    )
    check(
        parseReply(CW, PEER, replyFrame(NONCE, SELF, "x".repeat(600), 9100, "0.0.8", REPLY_MAC)) == null,
        "超过 512 字节 → null"
    )
    check(
        parseReply(CW, PEER, bytes("{\"t\":\"hr\",\"v\":1,\"id\":\"$SELF\",\"n\":\"$NONCE\",\"m\":\"$REPLY_MAC\"}")) == null,
        "缺 port 字段 → null"
    )

    // 任意截断都不允许抛异常（只返回 null）
    run {
        var threw = false
        for (cut in 0..frame.size) {
            try {
                parseReply(CW, PEER, frame.copyOf(cut))
            } catch (_: Throwable) {
                threw = true
                break
            }
        }
        check(!threw, "任意长度的截断帧都不会抛异常（只返回 null）")
    }
}

/* ==========================================================================
 * 测试数据构造
 * ========================================================================== */

private fun jsonEscape(s: String): String {
    val sb = StringBuilder()
    for (c in s) {
        when (c) {
            '"' -> sb.append("\\\"")
            '\\' -> sb.append("\\\\")
            '\n' -> sb.append("\\n")
            '\r' -> sb.append("\\r")
            '\t' -> sb.append("\\t")
            else -> if (c.code < 0x20) sb.append(String.format("\\u%04x", c.code)) else sb.append(c)
        }
    }
    return sb.toString()
}

/**
 * 手工构造一条应答帧——字段顺序与 hd_disc_build_reply 一致：
 * {"t":"hr","v":1,"id":"...","n":"...","m":"...","name":"...","port":9100,"ver":"..."}
 * MAC 由调用方传入，便于构造"字段被篡改、MAC 还是旧值"的负例。
 */
private fun replyFrame(
    nonceHex: String,
    selfId: String,
    name: String,
    port: Int,
    ver: String,
    mac: String
): ByteArray {
    val json = buildString {
        append("{\"t\":\"hr\",\"v\":1")
        append(",\"id\":\"").append(selfId)
        append("\",\"n\":\"").append(nonceHex)
        append("\",\"m\":\"").append(mac)
        append("\",\"name\":\"").append(jsonEscape(name))
        append("\",\"port\":").append(port)
        append(",\"ver\":\"").append(jsonEscape(ver))
        append("\"}")
    }
    return json.toByteArray(Charsets.UTF_8)
}

/* ==========================================================================
 * main
 * ========================================================================== */
fun main(args: Array<String>) {
    println("Hamster 协议核心库自检（纯 JVM / Kotlin）")
    println("契约：PROTOCOL.md ver.0.0.8（§1 传输层 / §3 分帧 / §7 局域网发现）")
    if (args.isNotEmpty()) println("（忽略命令行参数：${args.joinToString(" ")}）")

    testHmac()
    testDiscoveryVectors()
    testJson()
    testFraming()
    testParseAddr()
    testDiscoveryFrames()

    println()
    println("=== 结果: 通过 $pass, 失败 $fail ===")
    if (fail != 0) {
        System.exit(1)
    }
}
