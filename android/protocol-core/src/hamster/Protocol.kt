/*
 * Protocol.kt — Hamster 协议核心（纯 JVM，不依赖 Android API）
 *
 * 契约来源：PROTOCOL.md（ver.0.0.8）
 *   · §1 传输层：TCP、UTF-8、一行一个 JSON 对象，单行上限 256 KiB；
 *   · §3 二进制分帧（framing:raw）：消息头里的 payload_bytes（正整数）之后紧跟
 *     恰好 N 字节裸数据，接收方必须精确读满 N 字节才能继续解析下一行；
 *   · §7 局域网发现用到的 host:port 解析（含 IPv6 方括号写法）。
 *
 * 设计取舍：
 *   · 长度一律按**字节**计，绝不用 String.length 冒充字节数；
 *   · 负载流式消费（readFully(n, sink)），不把整个文件读进内存；
 *   · 协议数据不可信：消息头不是合法 UTF-8 / 不是 JSON 对象 / payload_bytes 不是
 *     整数，一律抛 ProtocolException，而不是猜一个"差不多"的结果；
 *   · 任何一行超过上限时，先把该行剩余字节吞掉再抛异常，使连接仍然可用
 *     （与服务端 hd_net.c 的 line_too_long 语义一致）。
 */
package hamster

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

/** 协议错误：流上出现了不符合 PROTOCOL.md 的内容。调用方通常应关闭连接。 */
open class ProtocolException(message: String) : IOException(message)

/**
 * 单行超过 256 KiB（PROTOCOL §1）。该行已被丢弃，但连接本身仍可继续使用。
 */
class LineTooLongException(message: String) : ProtocolException(message)

/**
 * 极简 JSON 读取：只需要从**一行顶层 JSON 对象**里按 key 取字符串/整数/布尔。
 *
 * 虽然是"极简"，但扫描是严格的：
 *   · 只在深度 1（顶层对象）匹配 key，嵌套对象/数组里的同名 key 不会被误取；
 *   · 字符串转义（\" \\ \/ \b \f \n \r \t \uXXXX，含代理对）按 JSON 规则解码；
 *   · 字符串里的括号、冒号、逗号不会被当成结构字符；
 *   · 不完整的对象、非法转义、尾随垃圾、整数写成小数/指数，一律当"没有这个值"。
 *
 * 这里不是通用 JSON 库：不保留嵌套结构、不区分 null 与缺失（getXxx 都返回 null）。
 */
object Json {

    /** 嵌套深度上限，纯粹用于挡住恶意构造的极深嵌套。 */
    const val MAX_DEPTH: Int = 64

    /** 整行是否是一个完整的 JSON 对象（允许首尾空白）。 */
    fun isObject(text: String): Boolean = try {
        Parser(text).parseTopObject()
        true
    } catch (_: BadJson) {
        false
    }

    /**
     * 顶层是否存在该 key（值可以是任意类型，包括对象/数组/null）。
     * JSON 本身非法时返回 false。
     */
    fun hasKey(text: String, key: String): Boolean = find(text, key) != null

    /** 取顶层字符串；缺失、类型不符或 JSON 非法时返回 null。 */
    fun getString(text: String, key: String): String? =
        (find(text, key) as? Node.Str)?.value

    /**
     * 取顶层整数；缺失、类型不符（含小数/指数写法）或 JSON 非法时返回 null。
     * 超出 Long 范围也返回 null。
     */
    fun getLong(text: String, key: String): Long? {
        val raw = (find(text, key) as? Node.Num)?.raw ?: return null
        if (raw.indexOf('.') >= 0 || raw.indexOf('e') >= 0 || raw.indexOf('E') >= 0) return null
        return raw.toLongOrNull()
    }

    /** 取顶层整数并检查 Int 范围；否则返回 null。 */
    fun getInt(text: String, key: String): Int? {
        val v = getLong(text, key) ?: return null
        if (v < Int.MIN_VALUE || v > Int.MAX_VALUE) return null
        return v.toInt()
    }

    /** 取顶层布尔；缺失、类型不符或 JSON 非法时返回 null。 */
    fun getBoolean(text: String, key: String): Boolean? =
        (find(text, key) as? Node.Bool)?.value

    /**
     * 取顶层对象的**原文**（例如响应里的 `data`）；不是对象或缺失时返回 null。
     * 用于读取 §3 中嵌在 `data` 里的 `payload_bytes`。
     */
    fun getRawObject(text: String, key: String): String? =
        (find(text, key) as? Node.Other)?.raw

    // ---------------------------------------------------------------- 内部实现

    private fun find(text: String, key: String): Node? = try {
        Parser(text).parseTopObject()[key]
    } catch (_: BadJson) {
        null
    }

    /** 解析后的顶层值。对象/数组标记为 Other（对象会保留原文，数组不保留）。 */
    private sealed class Node {
        class Str(val value: String) : Node()
        class Num(val raw: String) : Node()
        class Bool(val value: Boolean) : Node()
        object Null : Node()
        class Other(val raw: String?) : Node()
    }

    private class BadJson : Exception() {
        override fun fillInStackTrace(): Throwable = this
    }

    private class Parser(private val s: String) {
        private var i = 0

        fun parseTopObject(): Map<String, Node> {
            skipWs()
            expect('{')
            val out = LinkedHashMap<String, Node>()
            skipWs()
            if (peek() == '}') {
                i++
                skipWs()
                requireEnd()
                return out
            }
            while (true) {
                skipWs()
                if (peek() != '"') throw BadJson()
                val key = parseString()
                skipWs()
                expect(':')
                skipWs()
                val value = parseValue(1)
                if (!out.containsKey(key)) out[key] = value   // 重复 key：先到先得
                skipWs()
                when (next()) {
                    ',' -> Unit
                    '}' -> break
                    else -> throw BadJson()
                }
            }
            skipWs()
            requireEnd()
            return out
        }

        private fun parseValue(depth: Int): Node {
            if (depth > MAX_DEPTH) throw BadJson()
            val c = peek()
            return when {
                c == '"' -> Node.Str(parseString())
                c == '{' -> {
                    val start = i
                    parseComposite('{', '}', depth)
                    /* 保留原文：§3 的 payload_bytes 在响应里位于 data 对象内部，
                       不保留就无法在读消息头时拿到它（见 FrameReader.readHeader） */
                    Node.Other(s.substring(start, i))
                }
                c == '[' -> {
                    parseComposite('[', ']', depth)
                    Node.Other(null)
                }
                c == 't' -> {
                    expectLiteral("true")
                    Node.Bool(true)
                }
                c == 'f' -> {
                    expectLiteral("false")
                    Node.Bool(false)
                }
                c == 'n' -> {
                    expectLiteral("null")
                    Node.Null
                }
                c == '-' || isAsciiDigit(c) -> Node.Num(parseNumber())
                else -> throw BadJson()
            }
        }

        /** 跳过对象/数组：内容不保留，但括号配对与元素语法必须合法。 */
        private fun parseComposite(open: Char, close: Char, depth: Int) {
            expect(open)
            skipWs()
            if (peek() == close) {
                i++
                return
            }
            while (true) {
                skipWs()
                if (open == '{') {
                    if (peek() != '"') throw BadJson()
                    parseString()
                    skipWs()
                    expect(':')
                    skipWs()
                }
                parseValue(depth + 1)
                skipWs()
                when (next()) {
                    ',' -> Unit
                    close -> return
                    else -> throw BadJson()
                }
            }
        }

        private fun parseString(): String {
            expect('"')
            val sb = StringBuilder()
            while (true) {
                if (i >= s.length) throw BadJson()
                val c = s[i++]
                when {
                    c == '"' -> return sb.toString()
                    c == '\\' -> {
                        if (i >= s.length) throw BadJson()
                        when (s[i++]) {
                            '"' -> sb.append('"')
                            '\\' -> sb.append('\\')
                            '/' -> sb.append('/')
                            'b' -> sb.append('\b')
                            'f' -> sb.append('\u000C')
                            'n' -> sb.append('\n')
                            'r' -> sb.append('\r')
                            't' -> sb.append('\t')
                            'u' -> appendUnicodeEscape(sb)
                            else -> throw BadJson()
                        }
                    }
                    c.code < 0x20 -> throw BadJson()   // JSON 不允许裸控制字符
                    else -> sb.append(c)
                }
            }
        }

        private fun appendUnicodeEscape(sb: StringBuilder) {
            val hi = readHex4()
            if (hi in 0xD800..0xDBFF && i + 1 < s.length && s[i] == '\\' && s[i + 1] == 'u') {
                val save = i
                i += 2
                val lo = readHex4()
                if (lo in 0xDC00..0xDFFF) {
                    val cp = 0x10000 + ((hi - 0xD800) shl 10) + (lo - 0xDC00)
                    sb.appendCodePoint(cp)
                    return
                }
                i = save   // 低位不合法：回退，按单独的 \uXXXX 处理
            }
            sb.append(hi.toChar())
        }

        private fun readHex4(): Int {
            if (i + 4 > s.length) throw BadJson()
            var v = 0
            var k = 0
            while (k < 4) {
                val d = hexVal(s[i++])
                if (d < 0) throw BadJson()
                v = (v shl 4) or d
                k++
            }
            return v
        }

        private fun parseNumber(): String {
            val start = i
            if (i < s.length && s[i] == '-') i++
            if (i >= s.length) throw BadJson()
            when {
                s[i] == '0' -> i++
                s[i] in '1'..'9' -> while (i < s.length && isAsciiDigit(s[i])) i++
                else -> throw BadJson()
            }
            if (i < s.length && s[i] == '.') {
                i++
                if (i >= s.length || !isAsciiDigit(s[i])) throw BadJson()
                while (i < s.length && isAsciiDigit(s[i])) i++
            }
            if (i < s.length && (s[i] == 'e' || s[i] == 'E')) {
                i++
                if (i < s.length && (s[i] == '+' || s[i] == '-')) i++
                if (i >= s.length || !isAsciiDigit(s[i])) throw BadJson()
                while (i < s.length && isAsciiDigit(s[i])) i++
            }
            return s.substring(start, i)
        }

        private fun expectLiteral(lit: String) {
            if (i + lit.length > s.length) throw BadJson()
            var k = 0
            while (k < lit.length) {
                if (s[i + k] != lit[k]) throw BadJson()
                k++
            }
            i += lit.length
        }

        private fun skipWs() {
            while (i < s.length) {
                when (s[i]) {
                    ' ', '\t', '\r', '\n' -> i++
                    else -> return
                }
            }
        }

        private fun peek(): Char = if (i < s.length) s[i] else throw BadJson()

        private fun next(): Char = if (i < s.length) s[i++] else throw BadJson()

        private fun expect(c: Char) {
            if (next() != c) throw BadJson()
        }

        private fun requireEnd() {
            if (i != s.length) throw BadJson()
        }

        private fun isAsciiDigit(c: Char): Boolean = c in '0'..'9'

        private fun hexVal(c: Char): Int = when (c) {
            in '0'..'9' -> c - '0'
            in 'a'..'f' -> c - 'a' + 10
            in 'A'..'F' -> c - 'A' + 10
            else -> -1
        }
    }
}

/**
 * 按 PROTOCOL §3 分帧的读取器。
 *
 * 用法：
 * ```
 * val reader = FrameReader(socket.getInputStream())
 * while (true) {
 *     val header = reader.readHeader() ?: break
 *     // 先按 type 分流；如果是 download/sync-database 响应，就消费负载
 *     if (reader.hasPayload) {
 *         reader.readPayload { buf, off, len -> fileOut.write(buf, off, len) }
 *     }
 * }
 * ```
 *
 * 关键约束：
 *   · [readHeader] 声明了 payload_bytes(N > 0) 后，**必须**先把 N 字节读完
 *     （readFully / readPayload / skipPayload），否则下一次 readHeader 会抛异常；
 *   · 负载精确读满才算成功；对端提前关闭 → ProtocolException；
 *   · 单行上限按字节计（默认 256 KiB），二进制负载不计入行长度；
 *   · 内部缓冲区会在每次填满时被复用，[readFully] 的回调参数只在回调期间有效，
 *     需要长期保留请自行复制。
 */
class FrameReader(
    private val input: InputStream,
    val maxLineBytes: Int = DEFAULT_MAX_LINE_BYTES
) {

    companion object {
        /** PROTOCOL §1：单行 JSON 上限 256 KiB（按字节；二进制负载不计入）。 */
        const val DEFAULT_MAX_LINE_BYTES: Int = 256 * 1024

        private const val BUFFER_BYTES = 16 * 1024
        private const val DISCARD_LIMIT_FACTOR = 8

        /** '\n' / '\r' 的字节值（直接写字面量，保证是编译期常量）。 */
        private const val NEWLINE: Byte = 10
        private const val CARRIAGE_RETURN: Byte = 13
        private val EMPTY_BYTES = ByteArray(0)
    }

    init {
        require(maxLineBytes > 0) { "maxLineBytes 必须为正数：$maxLineBytes" }
    }

    private val buffer = ByteArray(BUFFER_BYTES)
    private var bufPos = 0
    private var bufLen = 0
    private var eof = false

    /** 最近一次 [readHeader] 返回的消息头原文（已去掉行尾的 CR/LF）；EOF 时为 null。 */
    var header: String? = null
        private set

    /** 最近一条消息头声明的 payload 字节数；未声明为 0。 */
    var payloadBytes: Long = 0L
        private set

    /** 当前这条消息还剩多少负载字节没读。 */
    var payloadRemaining: Long = 0L
        private set

    /** 当前消息是否还有未消费的负载。 */
    val hasPayload: Boolean
        get() = payloadRemaining > 0L

    /**
     * 读取下一条消息头（一行 JSON，去掉行尾 `\n` / `\r\n`）。
     *
     * @return 消息头原文；流正常结束（EOF）时返回 null。
     * @throws LineTooLongException 单行超过 [maxLineBytes]（该行已被丢弃，连接可用）。
     * @throws ProtocolException 消息头不是合法 UTF-8 / 不是 JSON 对象 /
     *         payload_bytes 不是正整数；或上一条消息的负载尚未读完。
     */
    fun readHeader(): String? {
        if (payloadRemaining > 0L) {
            throw ProtocolException(
                "上一条消息还有 $payloadRemaining 字节负载未读完，不能开始解析下一条消息头"
            )
        }
        header = null
        payloadBytes = 0L
        payloadRemaining = 0L
        val line = readLineBytes()
        if (line == null) {
            header = null
            payloadBytes = 0L
            payloadRemaining = 0L
            return null
        }
        val text = decodeUtf8Strict(line)
            ?: throw ProtocolException("消息头不是合法的 UTF-8 字节序列")
        if (!Json.isObject(text)) {
            throw ProtocolException("消息头不是合法的 JSON 对象：${preview(text)}")
        }
        val declared: Long = if (Json.hasKey(text, "payload_bytes")) {
            Json.getLong(text, "payload_bytes")
                ?: throw ProtocolException("payload_bytes 不是整数：${preview(text)}")
        } else {
            /* §3：服务端 → 客户端的响应把 payload_bytes 放在 data 对象里；
               请求（客户端 → 服务端的上传）才放顶层。两种位置都要认。 */
            val data = Json.getRawObject(text, "data")
            if (data != null) {
                if (Json.hasKey(data, "payload_bytes")) {
                    Json.getLong(data, "payload_bytes")
                        ?: throw ProtocolException("data.payload_bytes 不是整数：${preview(text)}")
                } else 0L
            } else 0L
        }
        if (declared < 0L) throw ProtocolException("payload_bytes 不能为负数：$declared")

        header = text
        payloadBytes = declared
        payloadRemaining = declared
        return text
    }

    /**
     * 精确读取 n 字节负载，边读边交给 [sink]（流式，不整块进内存）。
     *
     * @throws ProtocolException n 超过本消息声明的剩余负载，或对端提前关闭（实收 < 声明）。
     */
    fun readFully(n: Long, sink: (ByteArray, Int, Int) -> Unit) {
        if (n < 0L) throw IllegalArgumentException("要读取的字节数不能为负：$n")
        if (n > payloadRemaining) {
            throw ProtocolException(
                "要读取 $n 字节，但本消息 payload_bytes=$payloadBytes，" +
                    "当前只剩 $payloadRemaining 字节"
            )
        }
        var left = n
        while (left > 0L) {
            if (bufPos >= bufLen) {
                if (eof) {
                    throw ProtocolException(
                        "负载不完整：payload_bytes=$payloadBytes，" +
                            "实收 ${payloadBytes - payloadRemaining} 字节，还缺 $payloadRemaining 字节"
                    )
                }
                fill()
                continue
            }
            val take = minOf(left, (bufLen - bufPos).toLong()).toInt()
            sink(buffer, bufPos, take)
            bufPos += take
            left -= take
            payloadRemaining -= take
        }
    }

    /** 精确读取 n 字节负载并返回副本。 */
    fun readFully(n: Int): ByteArray {
        if (n < 0) throw IllegalArgumentException("要读取的字节数不能为负：$n")
        if (n.toLong() > payloadRemaining) {
            throw ProtocolException(
                "要读取 $n 字节，但本消息 payload_bytes=$payloadBytes，" +
                    "当前只剩 $payloadRemaining 字节"
            )
        }
        val out = ByteArray(n)
        var off = 0
        readFully(n.toLong()) { b, o, len ->
            System.arraycopy(b, o, out, off, len)
            off += len
        }
        return out
    }

    /** 把本消息剩余负载全部流式读完，返回读到的字节数。 */
    fun readPayload(sink: (ByteArray, Int, Int) -> Unit): Long {
        val n = payloadRemaining
        if (n > 0L) readFully(n, sink)
        return n
    }

    /** 丢弃本消息剩余负载（用于"这个响应我不需要"的场景），返回丢弃字节数。 */
    fun skipPayload(): Long {
        val n = payloadRemaining
        readFully(n) { _, _, _ -> }
        return n
    }

    // ---------------------------------------------------------------- 内部实现

    private fun fill() {
        if (eof) return
        val n = input.read(buffer)
        when {
            n > 0 -> {
                bufPos = 0
                bufLen = n
            }
            n < 0 -> {
                bufPos = 0
                bufLen = 0
                eof = true
            }
            else -> {
                // 极少数流会返回 0；退化为读一个字节，避免死循环。
                val one = input.read()
                if (one < 0) {
                    bufPos = 0
                    bufLen = 0
                    eof = true
                } else {
                    buffer[0] = one.toByte()
                    bufPos = 0
                    bufLen = 1
                }
            }
        }
    }

    /** 读一行（不含 `\n`，并去掉行尾单个 `\r`）；EOF 且一个字节都没有时返回 null。 */
    private fun readLineBytes(): ByteArray? {
        var out: ByteArrayOutputStream? = null
        var total = 0
        while (true) {
            if (bufPos >= bufLen) {
                if (eof) {
                    if (total == 0) return null
                    return stripCr(out!!.toByteArray())
                }
                fill()
                continue
            }
            val b = buffer[bufPos++]
            if (b == NEWLINE) {
                return stripCr(out?.toByteArray() ?: EMPTY_BYTES)
            }
            total++
            if (total > maxLineBytes) {
                // 与服务端一致：把这一行剩下的字节吞掉，连接仍然可用。
                discardRestOfLine()
                throw LineTooLongException(
                    "单行超过 $maxLineBytes 字节上限；该行已丢弃，连接可继续使用"
                )
            }
            if (out == null) out = ByteArrayOutputStream(256)
            out.write(b.toInt())
        }
    }

    private fun discardRestOfLine() {
        var discarded = 0L
        val limit = maxLineBytes.toLong() * DISCARD_LIMIT_FACTOR
        while (true) {
            if (bufPos >= bufLen) {
                if (eof) return
                fill()
                continue
            }
            val nl = indexOfNewline(bufPos)
            if (nl >= 0) {
                discarded += (nl - bufPos).toLong()
                bufPos = nl + 1        // 吃掉 '\n'
                return
            }
            discarded += (bufLen - bufPos).toLong()
            bufPos = bufLen
            if (discarded > limit) {
                throw ProtocolException("超长行待丢弃的字节数超过上限，协议流已不可信")
            }
        }
    }

    private fun indexOfNewline(from: Int): Int {
        var k = from
        while (k < bufLen) {
            if (buffer[k] == NEWLINE) return k
            k++
        }
        return -1
    }

    private fun stripCr(b: ByteArray): ByteArray =
        if (b.isNotEmpty() && b[b.size - 1] == CARRIAGE_RETURN) b.copyOf(b.size - 1) else b

    private fun preview(text: String): String {
        val head = if (text.length > 60) text.substring(0, 60) + "…" else text
        return head.replace("\r", "\\r").replace("\n", "\\n")
    }
}

/** 严格 UTF-8 解码（非法字节序列返回 null，不做替换字符）。 */
internal fun decodeUtf8Strict(bytes: ByteArray): String? = try {
    StandardCharsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(bytes))
        .toString()
} catch (_: CharacterCodingException) {
    null
}

/**
 * 解析 `host:port`，返回 (主机, 端口)。来源：PROTOCOL §1 / §7 的地址用法。
 *
 * 支持的写法：
 *   · `127.0.0.1:9100`      —— 普通 host:port
 *   · `localhost:9100`      —— 主机名
 *   · `[::1]:9100`          —— IPv6 带方括号 + 端口
 *   · `[::1]`               —— IPv6 带方括号、用默认端口
 *   · `::1`                 —— 裸 IPv6、用默认端口（裸 IPv6 不解析端口：
 *                              冒号全是地址的一部分，端口需要有方括号才能指定）
 *
 * 非法输入一律抛 IllegalArgumentException（而不是返回一个"猜"的结果）：
 * 空串、空主机、空端口、端口越界/非数字、IPv4 段数或数值不对、IPv6 语法不对、
 * 方括号用法不对、主机里含空白或控制字符等。
 *
 * 注意：这里**只做语法校验，不做 DNS 解析**（Android 客户端应在连接阶段解析）。
 */
fun parseAddr(s: String, defaultPort: Int): Pair<String, Int> {
    if (defaultPort < 1 || defaultPort > 65535) {
        throw IllegalArgumentException("默认端口越界（1–65535）：$defaultPort")
    }
    val text = s.trim()
    if (text.isEmpty()) throw IllegalArgumentException("地址为空")
    for (c in text) {
        if (c.code < 0x20 || c.code == 0x7F) {
            throw IllegalArgumentException("地址含控制字符：${escapeForMessage(s)}")
        }
    }

    // 1) IPv6 方括号写法：[host]:port 或 [host]
    if (text.startsWith("[")) {
        val close = text.indexOf(']')
        if (close < 0) throw IllegalArgumentException("IPv6 地址缺少右方括号：$text")
        val host = text.substring(1, close)
        if (host.isEmpty()) throw IllegalArgumentException("方括号内是空的：$text")
        if (!host.contains(':')) throw IllegalArgumentException("方括号内不是 IPv6 地址：$text")
        validateIpv6(host, text)
        val rest = text.substring(close + 1)
        if (rest.isEmpty()) return host to defaultPort
        if (!rest.startsWith(":")) {
            throw IllegalArgumentException("方括号后只能是「:端口」：$text")
        }
        return host to parsePort(rest.substring(1), text)
    }

    // 2) 没有方括号：按冒号数量判断是 host:port 还是裸 IPv6
    var colons = 0
    for (c in text) if (c == ':') colons++

    return when (colons) {
        0 -> {
            validateHost(text, text)
            text to defaultPort
        }
        1 -> {
            val idx = text.indexOf(':')
            val host = text.substring(0, idx)
            val portText = text.substring(idx + 1)
            if (host.isEmpty()) throw IllegalArgumentException("缺少主机部分：$text")
            validateHost(host, text)
            host to parsePort(portText, text)
        }
        else -> {
            // 冒号 >= 2：只能是裸 IPv6，整串都是地址，端口用默认值。
            validateIpv6(text, text)
            text to defaultPort
        }
    }
}

// -------------------------------------------------------------------- 地址校验

private fun parsePort(portText: String, original: String): Int {
    if (portText.isEmpty()) throw IllegalArgumentException("端口为空：$original")
    if (portText.length > 5) throw IllegalArgumentException("端口越界（1–65535）：$original")
    for (c in portText) {
        if (c !in '0'..'9') throw IllegalArgumentException("端口不是十进制数字：$original")
    }
    val p = portText.toInt()
    if (p < 1 || p > 65535) throw IllegalArgumentException("端口越界（1–65535）：$original")
    return p
}

/** 主机部分：IPv4 字面量或普通主机名（不做 DNS）。 */
private fun validateHost(host: String, original: String) {
    if (host.isEmpty()) throw IllegalArgumentException("主机名为空：$original")
    for (c in host) {
        val ok = c in '0'..'9' || c in 'a'..'z' || c in 'A'..'Z' ||
            c == '.' || c == '-' || c == '_'
        if (!ok) throw IllegalArgumentException("主机名含非法字符「$c」：$original")
    }
    if (host.length > 253) throw IllegalArgumentException("主机名过长：$original")

    // 看起来像 IPv4（只由数字和点组成）就按 IPv4 严格校验，避免 "999.1.1.1" 蒙混过关。
    var looksIpv4 = true
    for (c in host) {
        if (c != '.' && (c !in '0'..'9')) {
            looksIpv4 = false
            break
        }
    }
    if (looksIpv4) {
        validateIpv4(host, original)
        return
    }

    // 主机名：点分标签，每个 1–63 字符，不以 '-' 开头/结尾。
    for (label in host.split('.')) {
        if (label.isEmpty()) throw IllegalArgumentException("主机名有空标签：$original")
        if (label.length > 63) throw IllegalArgumentException("主机名标签过长：$original")
        if (label.startsWith('-') || label.endsWith('-')) {
            throw IllegalArgumentException("主机名标签不能以 '-' 开头或结尾：$original")
        }
    }
}

private fun validateIpv4(ip: String, original: String) {
    val parts = ip.split('.')
    if (parts.size != 4) throw IllegalArgumentException("IPv4 必须是 4 段：$original")
    for (part in parts) {
        if (part.isEmpty() || part.length > 3) {
            throw IllegalArgumentException("IPv4 段长度非法：$original")
        }
        if (part.length > 1 && part[0] == '0') {
            throw IllegalArgumentException("IPv4 段不允许前导零：$original")
        }
        var v = 0
        for (c in part) {
            if (c !in '0'..'9') throw IllegalArgumentException("IPv4 段不是数字：$original")
            v = v * 10 + (c - '0')
        }
        if (v > 255) throw IllegalArgumentException("IPv4 段越界（0–255）：$original")
    }
}

/**
 * IPv6 语法校验（支持 `::` 压缩与内嵌 IPv4 尾部）。
 * 不支持 zone id（`%eth0`）——发现协议只用 IPv4，这里拒绝是为了不猜语义。
 */
private fun validateIpv6(addr: String, original: String) {
    if (addr.isEmpty()) throw IllegalArgumentException("IPv6 地址为空：$original")
    if (addr.contains('%')) throw IllegalArgumentException("不支持 IPv6 zone id：$original")

    var text = addr
    // 内嵌 IPv4：最后一段含 '.' 时，把它折算成两组（如 ::ffff:192.168.1.1 → ::ffff:0:0）
    val lastColon = text.lastIndexOf(':')
    if (lastColon >= 0) {
        val tail = text.substring(lastColon + 1)
        if (tail.contains('.')) {
            validateIpv4(tail, original)
            text = text.substring(0, lastColon + 1) + "0:0"
        }
    }

    val firstDbl = text.indexOf("::")
    if (firstDbl >= 0 && text.indexOf("::", firstDbl + 2) >= 0) {
        throw IllegalArgumentException("IPv6 里出现多处「::」：$original")
    }

    if (firstDbl < 0) {
        val groups = text.split(':')
        if (groups.size != 8) throw IllegalArgumentException("IPv6 必须是 8 组：$original")
        for (g in groups) validateIpv6Group(g, original)
        return
    }

    val left = text.substring(0, firstDbl)
    val right = text.substring(firstDbl + 2)
    val leftGroups = if (left.isEmpty()) emptyList() else left.split(':')
    val rightGroups = if (right.isEmpty()) emptyList() else right.split(':')
    for (g in leftGroups) validateIpv6Group(g, original)
    for (g in rightGroups) validateIpv6Group(g, original)
    // 「::」至少要代表一组 0，所以两侧合计最多 7 组。
    if (leftGroups.size + rightGroups.size > 7) {
        throw IllegalArgumentException("IPv6 的「::」两侧组数过多：$original")
    }
}

private fun validateIpv6Group(group: String, original: String) {
    if (group.isEmpty()) throw IllegalArgumentException("IPv6 有空组：$original")
    if (group.length > 4) throw IllegalArgumentException("IPv6 组超过 4 位十六进制：$original")
    for (c in group) {
        if (hexValue(c) < 0) throw IllegalArgumentException("IPv6 组含非十六进制字符：$original")
    }
}

private fun hexValue(c: Char): Int = when (c) {
    in '0'..'9' -> c - '0'
    in 'a'..'f' -> c - 'a' + 10
    in 'A'..'F' -> c - 'A' + 10
    else -> -1
}

private fun escapeForMessage(s: String): String {
    val sb = StringBuilder()
    for (c in s) {
        if (c.code < 0x20 || c.code == 0x7F) {
            sb.append("\\u").append(String.format("%04x", c.code))
        } else {
            sb.append(c)
        }
    }
    return sb.toString()
}
