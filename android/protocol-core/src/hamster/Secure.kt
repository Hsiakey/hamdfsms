/*
 * Secure.kt — §8 传输加密（协议核心层）
 *
 * 三块，与 C / JS 三端逐字节一致：
 *   §8.2  密钥派生：master / proof_C / proof_S / key_c2s / key_s2c
 *   §8.3  记录层：len(4,BE)|counter(8,BE)|密文|tag(16)
 *   握手：hello → challenge → 验 proof_S → proof → ok，之后整条连接只剩密文
 *
 * 只依赖 java.io / java.net 与 javax.crypto.Mac，**不引用任何 Android API**：
 * Android 客户端把 Socket 换掉即可，其余逻辑（包括帧解析）都复用这里。
 *
 * 出错一律抛 SecureException（带机器码）。握手失败与记录层错误都不向对端
 * 解释原因（§8.2/§8.3 的安全要求），调用方也不应该"补一个更友好的错误"。
 */
package hamster

import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket

class SecureException(val code: String, message: String) : Exception("$code: $message")

/** §8.2 一次连接的密钥材料（十六进制字符串按**文本**参与 info/proof 拼接） */
class SecKeys(
    val master: ByteArray,
    val proofC: ByteArray,
    val proofS: ByteArray,
    val keyC2S: ByteArray,
    val keyS2C: ByteArray,
)

object Sec {
    const val AUTH_VERSION = 2
    const val SALT_LEN = 16
    const val NONCE_LEN = 16
    const val KEY_LEN = 32
    const val TAG_LEN = 16
    const val HDR_LEN = 12
    const val MAX_PLAIN = 65536
    const val REC_MAX = HDR_LEN + MAX_PLAIN + TAG_LEN
    const val AUTH_LINE_MAX = 1024
    const val DIR_C2S = 0x01
    const val DIR_S2C = 0x02

    private const val AUTH_INFO = "hamster-auth/v1"
    private const val REC_C2S_INFO = "hamster-rec-c2s/v2"
    private const val REC_S2C_INFO = "hamster-rec-s2c/v2"
    private const val PROOF_C_PREFIX = "hamster-client-proof/v2\n"
    private const val PROOF_S_PREFIX = "hamster-server-proof/v2\n"

    private val HEX32 = Regex("^[0-9a-fA-F]{32}$")
    private val HEX64 = Regex("^[0-9a-fA-F]{64}$")

    fun isHex16(s: String?): Boolean = s != null && HEX32.matches(s)
    fun isHex32(s: String?): Boolean = s != null && HEX64.matches(s)

    /**
     * §8.2 派生。salt/nc/ns 必须是 32 个 hex 字符 —— 拼进 info/proof 的是
     * **hex 文本**而不是原始字节，这里写错就会和另外两端对不上。
     */
    fun deriveSession(secret: ByteArray, saltHex: String, ncHex: String, nsHex: String, deviceId: String): SecKeys {
        if (secret.isEmpty()) throw SecureException("bad_key_material", "secret required")
        if (!isHex16(saltHex)) throw SecureException("bad_salt", "salt must be 32 hex chars")
        if (!isHex16(ncHex)) throw SecureException("bad_nonce", "nc must be 32 hex chars")
        if (!isHex16(nsHex)) throw SecureException("bad_nonce", "ns must be 32 hex chars")
        if (deviceId.isEmpty()) throw SecureException("bad_device_id", "device_id required")

        val salt = hexToBytes(saltHex)
        val master = Hkdf.sha256(salt, secret, AUTH_INFO.toByteArray(Charsets.UTF_8), KEY_LEN)

        val proofC = Hkdf.hmacSha256(master,
            (PROOF_C_PREFIX + ncHex + "\n" + nsHex + "\n" + deviceId).toByteArray(Charsets.UTF_8))
        val proofS = Hkdf.hmacSha256(master,
            (PROOF_S_PREFIX + ncHex + "\n" + nsHex).toByteArray(Charsets.UTF_8))

        val keyC2S = Hkdf.sha256(salt, master, (REC_C2S_INFO + ncHex + nsHex).toByteArray(Charsets.UTF_8), KEY_LEN)
        val keyS2C = Hkdf.sha256(salt, master, (REC_S2C_INFO + ncHex + nsHex).toByteArray(Charsets.UTF_8), KEY_LEN)

        return SecKeys(master, proofC, proofS, keyC2S, keyS2C)
    }

    /* ---------------- 十六进制 ---------------- */
    fun bytesToHex(b: ByteArray): String {
        val sb = StringBuilder(b.size * 2)
        val digits = "0123456789abcdef"
        for (v in b) {
            val x = v.toInt() and 0xff
            sb.append(digits[x ushr 4]).append(digits[x and 15])
        }
        return sb.toString()
    }

    fun hexToBytes(s: String): ByteArray {
        if (s.length % 2 != 0) throw SecureException("bad_hex", "odd hex length")
        val out = ByteArray(s.length / 2)
        for (i in out.indices) {
            val hi = Character.digit(s[i * 2], 16)
            val lo = Character.digit(s[i * 2 + 1], 16)
            if (hi < 0 || lo < 0) throw SecureException("bad_hex", "invalid hex char")
            out[i] = ((hi shl 4) or lo).toByte()
        }
        return out
    }

    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        return ChaCha20Poly1305.constantTimeEquals(a, 0, b, 0, a.size)
    }
}

/**
 * 记录层的 counter 一律大端（§8.3）：记录头、nonce 后半段、AAD 后半段都用它。
 * 注意区分：ChaCha20 内部对 key/nonce 的分字是**小端**（RFC 8439 §2.3），
 * 那是算法内部的字节序，与协议里的字段编码无关。
 */
private fun store64be(b: ByteArray, off: Int, v: Long) {
    var i = 0
    while (i < 8) { b[off + i] = ((v ushr (56 - 8 * i)) and 0xff).toByte(); i++ }
}

/* ==========================================================================
 * §8.3 记录层
 * ========================================================================== */
class RecordSealer(private val key: ByteArray, private val dir: Int) {
    private var counter: Long = 0

    init {
        if (key.size != Sec.KEY_LEN) throw SecureException("bad_key", "sealer key must be 32 bytes")
        if (dir != Sec.DIR_C2S && dir != Sec.DIR_S2C) throw SecureException("bad_direction", dir.toString())
    }

    /** 封一条记录（明文 1..65536 字节） */
    fun seal(plain: ByteArray, off: Int, len: Int): ByteArray {
        if (len <= 0 || len > Sec.MAX_PLAIN) throw SecureException("bad_record_len", "len=$len")

        val nonce = ByteArray(12)
        store64be(nonce, 4, counter)
        val aad = ByteArray(9)
        aad[0] = dir.toByte()
        store64be(aad, 1, counter)

        val chunk = if (off == 0 && len == plain.size) plain else plain.copyOfRange(off, off + len)
        val sealed = ChaCha20Poly1305.seal(key, nonce, aad, chunk)

        val rec = ByteArray(Sec.HDR_LEN + sealed.size)
        rec[0] = ((len ushr 24) and 0xff).toByte()
        rec[1] = ((len ushr 16) and 0xff).toByte()
        rec[2] = ((len ushr 8) and 0xff).toByte()
        rec[3] = (len and 0xff).toByte()
        store64be(rec, 4, counter)
        System.arraycopy(sealed, 0, rec, Sec.HDR_LEN, sealed.size)

        counter++
        return rec
    }

    fun seal(plain: ByteArray): ByteArray = seal(plain, 0, plain.size)
}

class RecordOpener(private val key: ByteArray, private val dir: Int) {
    private var expected: Long = 0

    init {
        if (key.size != Sec.KEY_LEN) throw SecureException("bad_key", "opener key must be 32 bytes")
        if (dir != Sec.DIR_C2S && dir != Sec.DIR_S2C) throw SecureException("bad_direction", dir.toString())
    }

    /** 从输入流读一条完整记录并解密；EOF 返回 null，任何错误抛 SecureException */
    fun readRecord(input: InputStream): ByteArray? {
        val hdr = ByteArray(Sec.HDR_LEN)
        if (!readFully(input, hdr, 0, hdr.size)) return null

        val len = ((hdr[0].toInt() and 0xff) shl 24) or ((hdr[1].toInt() and 0xff) shl 16) or
                  ((hdr[2].toInt() and 0xff) shl 8) or (hdr[3].toInt() and 0xff)
        if (len <= 0 || len > Sec.MAX_PLAIN) throw SecureException("bad_record_len", "len=$len")

        val ctr = readLongBe(hdr, 4)
        if (ctr != expected) throw SecureException("bad_counter", "got=$ctr want=$expected")

        val body = ByteArray(len + Sec.TAG_LEN)
        if (!readFully(input, body, 0, body.size)) throw SecureException("truncated_record", "record $ctr")

        val nonce = ByteArray(12)
        store64be(nonce, 4, ctr)
        val aad = ByteArray(9)
        aad[0] = dir.toByte()
        store64be(aad, 1, ctr)

        val plain = ChaCha20Poly1305.open(key, nonce, aad, body)
            ?: throw SecureException("aead_failed", "record $ctr failed authentication")
        expected++
        return plain
    }

    private fun readFully(input: InputStream, buf: ByteArray, off: Int, len: Int): Boolean {
        var got = 0
        while (got < len) {
            val n = input.read(buf, off + got, len - got)
            if (n < 0) {
                if (got == 0) return false
                throw SecureException("truncated_record", "wanted $len got $got")
            }
            got += n
        }
        return true
    }

    private fun readLongBe(b: ByteArray, off: Int): Long {
        var v = 0L
        for (i in 0 until 8) v = (v shl 8) or (b[off + i].toLong() and 0xff)
        return v
    }
}

/* ==========================================================================
 * 握手后的明文字节流
 * ========================================================================== */
class AeadInputStream(private val src: InputStream, private val opener: RecordOpener) : InputStream() {
    private var buf = ByteArray(0)
    private var pos = 0
    private var eof = false

    private fun fill(): Boolean {
        if (pos < buf.size) return true
        if (eof) return false
        val next = opener.readRecord(src)
        if (next == null) { eof = true; return false }
        buf = next
        pos = 0
        return true
    }

    override fun read(): Int {
        if (!fill()) return -1
        return buf[pos++].toInt() and 0xff
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        if (len == 0) return 0
        if (!fill()) return -1
        val n = minOf(len, buf.size - pos)
        System.arraycopy(buf, pos, b, off, n)
        pos += n
        return n
    }

    override fun available(): Int = buf.size - pos
}

class AeadOutputStream(private val dst: OutputStream, private val sealer: RecordSealer) : OutputStream() {
    override fun write(b: Int) = write(byteArrayOf(b.toByte()), 0, 1)

    override fun write(b: ByteArray, off: Int, len: Int) {
        var o = off
        var remaining = len
        while (remaining > 0) {
            val n = minOf(remaining, Sec.MAX_PLAIN)
            dst.write(sealer.seal(b, o, n))
            o += n
            remaining -= n
        }
    }

    override fun flush() { dst.flush() }
}

/* ==========================================================================
 * §8.2 客户端握手
 * ========================================================================== */
class SecureChannel private constructor(
    private val socket: Socket,
    private val keys: SecKeys,
    /** 记录层之上的明文输入（可直接喂给 FrameReader） */
    val input: InputStream,
    /** 记录层之上的明文输出 */
    val output: OutputStream,
    val serverVersion: String,
    val serverName: String,
) {
    val peerVersion: String get() = serverVersion
    val peerName: String get() = serverName

    fun close() {
        try { socket.close() } catch (_: Exception) {}
    }

    companion object {
        /**
         * 建立 §8 加密连接。成功返回后连接已就绪（认证已完成、双方已切记录层）。
         * 失败抛 SecureException；其中 server_auth_failed 表示"服务端证明不成立"，
         * socket_closed/auth_timeout 通常意味着口令不对（守护进程静默断开）。
         */
        fun connect(
            host: String,
            port: Int,
            secret: String,
            deviceId: String,
            hostname: String? = null,
            timeoutMs: Int = 5000,
            random: ((ByteArray) -> Unit)? = null,
        ): SecureChannel {
            if (secret.isEmpty()) throw SecureException("bad_key_material", "secret required")
            if (deviceId.isEmpty()) throw SecureException("bad_device_id", "device_id required")

            val sock = Socket()
            sock.tcpNoDelay = true
            sock.connect(InetSocketAddress(host, port), timeoutMs)
            sock.soTimeout = timeoutMs

            val rawIn = BufferedInputStream(sock.getInputStream())
            val rawOut = sock.getOutputStream()

            val nc = ByteArray(Sec.NONCE_LEN)
            if (random != null) random(nc) else java.security.SecureRandom().nextBytes(nc)
            val ncHex = Sec.bytesToHex(nc)

            try {
                /* 1) hello（明文） */
                sendLine(rawOut, buildHello(deviceId, hostname, ncHex))

                /* 2) challenge */
                val challenge = readLine(rawIn)
                if (challenge == null) throw SecureException("socket_closed", "challenge 前连接被关闭")
                if (Json.isObject(challenge) == false) throw SecureException("bad_auth_json", challenge.take(80))
                if (Json.getString(challenge, "type") != "auth" || Json.getString(challenge, "step") != "challenge") {
                    throw SecureException("bad_auth_step", challenge.take(80))
                }
                if (Json.getInt(challenge, "v") != Sec.AUTH_VERSION) throw SecureException("bad_auth_version", "v")
                if (Json.getString(challenge, "alg") != "chacha20poly1305") throw SecureException("bad_auth_alg", "alg")
                if (Json.getString(challenge, "kdf") != "hkdf-sha256") throw SecureException("bad_auth_kdf", "kdf")

                val saltHex = Json.getString(challenge, "salt") ?: throw SecureException("bad_salt", "missing")
                val nsHex = Json.getString(challenge, "ns") ?: throw SecureException("bad_nonce", "missing")
                if (!Sec.isHex16(saltHex)) throw SecureException("bad_salt", saltHex.take(40))
                if (!Sec.isHex16(nsHex)) throw SecureException("bad_nonce", nsHex.take(40))

                /* 3) 派生 + 证明 */
                val keys = Sec.deriveSession(secret.toByteArray(Charsets.UTF_8), saltHex, ncHex, nsHex, deviceId)
                sendLine(rawOut, "{\"type\":\"auth\",\"step\":\"proof\",\"mac\":\"" +
                    Sec.bytesToHex(keys.proofC) + "\"}")

                /* 4) ok：先验服务端，通过后才相信这条连接 */
                val okLine = readLine(rawIn)
                if (okLine == null) throw SecureException("socket_closed", "proof 后连接被关闭（口令不对？）")
                if (Json.getString(okLine, "type") != "auth" || Json.getString(okLine, "step") != "ok") {
                    throw SecureException("bad_auth_step", okLine.take(80))
                }
                val mac = Json.getString(okLine, "mac") ?: throw SecureException("bad_server_proof", "missing")
                if (!Sec.isHex32(mac)) throw SecureException("bad_server_proof", mac.take(40))
                if (!Sec.constantTimeEquals(Sec.hexToBytes(mac), keys.proofS)) {
                    throw SecureException("server_auth_failed", "服务端证明不成立")
                }

                /* 5) 切记录层 */
                val inStream = AeadInputStream(rawIn, RecordOpener(keys.keyS2C, Sec.DIR_S2C))
                val outStream = AeadOutputStream(rawOut, RecordSealer(keys.keyC2S, Sec.DIR_C2S))
                sock.soTimeout = 0   /* 握手后由调用方按需设置（长连接不能有读超时） */

                return SecureChannel(
                    sock, keys, inStream, outStream,
                    (Json.getString(challenge, "version") ?: "?"),
                    (Json.getString(challenge, "server") ?: "?"),
                )
            } catch (e: Exception) {
                try { sock.close() } catch (_: Exception) {}
                if (e is SecureException) throw e
                throw SecureException("socket_error", e.message ?: e.javaClass.simpleName)
            }
        }

        private fun buildHello(deviceId: String, hostname: String?, ncHex: String): String {
            val sb = StringBuilder()
            sb.append("{\"type\":\"auth\",\"step\":\"hello\",\"v\":").append(Sec.AUTH_VERSION)
            sb.append(",\"device_id\":\"").append(jsonEscape(deviceId)).append('"')
            if (!hostname.isNullOrEmpty()) sb.append(",\"hostname\":\"").append(jsonEscape(hostname)).append('"')
            sb.append(",\"nc\":\"").append(ncHex).append("\"}")
            return sb.toString()
        }

        private fun jsonEscape(s: String): String {
            val sb = StringBuilder(s.length + 8)
            for (c in s) {
                when (c) {
                    '"' -> sb.append("\\\"")
                    '\\' -> sb.append("\\\\")
                    '\n' -> sb.append("\\n")
                    '\r' -> sb.append("\\r")
                    '\t' -> sb.append("\\t")
                    else -> if (c < ' ') sb.append(String.format("\\u%04x", c.code)) else sb.append(c)
                }
            }
            return sb.toString()
        }

        private fun sendLine(out: OutputStream, line: String) {
            val bytes = line.toByteArray(Charsets.UTF_8)
            if (bytes.size > Sec.AUTH_LINE_MAX) throw SecureException("line_too_long", "auth line > 1KiB")
            out.write(bytes)
            out.write('\n'.code)
            out.flush()
        }

        /** 握手阶段读一行明文（≤1 KiB）；EOF 返回 null */
        private fun readLine(input: InputStream): String? {
            val buf = ByteArrayOutputStream(256)
            while (true) {
                val c = input.read()
                if (c < 0) return if (buf.size() == 0) null else {
                    throw SecureException("truncated_line", "握手行未结束")
                }
                if (c == '\n'.code) break
                if (buf.size() >= Sec.AUTH_LINE_MAX) throw SecureException("line_too_long", "auth line > 1KiB")
                if (c != '\r'.code) buf.write(c)
            }
            return String(buf.toByteArray(), Charsets.UTF_8)
        }
    }
}

/* ==========================================================================
 * §8.2 服务端握手（Android 守护端 / 任何要扮演 hamsterd 的对端）
 *
 * 与 Hamsterd/hd_net.c 的 sec_handshake 逐条对齐：
 *   1) 读 hello（明文）→ 2) 发 challenge（明文）→ 3) 读 proof（明文）
 *   → 4) 用候选口令逐个派生 master 试 proof_C（常量时间比较）
 *   → 5) 发 auth/ok（明文）→ 6) 双方切记录层。
 *
 * 与客户端握手（SecureChannel.connect）的差别只在"谁发 challenge"和方向常量：
 *   服务端**发 s2c**（RecordSealer + keyS2C + DIR_S2C）、**收 c2s**
 *   （RecordOpener + keyC2S + DIR_C2S），与 hd_sec_init(is_server=1) 一致。
 * 弄反了客户端会立刻 AEAD 验签失败 —— 这两个常量是本文件最不能"顺手改"的地方。
 *
 * 失败路径（口令不对 / 格式不符 / 超时 / 对端关闭）一律返回 null，且**不向对端
 * 发送任何错误对象**（§8.2：任何可区分的反馈都会把"口令对不对"变成可离线穷举的
 * 信号）。本文件也不记录口令或派生密钥；authLabel 只交给调用方写本机日志。
 * ========================================================================== */

/**
 * 一次已完成的 §8 服务端会话（input/output 已是记录层之上的明文流）。
 *
 * 与 [SecureChannel] 一样，本类只负责握手与记录层：命令与分帧（§3）由调用方在
 * [input] / [output] 之上自己做。记录层方向在握手时已固定（服务端发 s2c、收 c2s）。
 *
 * @param deviceId 对端 hello 里的 device_id（按 C 侧 dev[64] 截断到 63 个字符）
 * @param hostname 对端 hello 里的 hostname；缺失时与 C 侧一致记为 "unknown"
 * @param authLabel "codeword" 或 "api_key:<前 8 位>" —— 只用于本机日志
 * @param rawCloseables 握手用的原始流，[close] 时一并关闭（通常就是 socket 两端）
 */
class SecureServerSession(
    val input: InputStream,
    val output: OutputStream,
    val deviceId: String,
    val hostname: String,
    val clientNonceHex: String,
    val serverNonceHex: String,
    /** "codeword" 或 "api_key:<前 8 位>" —— 用于日志，别把口令写进去 */
    val authLabel: String,
    private val rawCloseables: List<java.io.Closeable> = emptyList(),
) {
    /**
     * 关闭底层连接（尽力而为）。§8.3：没有关闭帧，直接关 socket 即可。
     *
     * 手工构造（不经过 [SecureServer.handshake]）的会话没有原始流可关，
     * 此时本方法是空操作，调用方需自行关闭自己的 socket。
     */
    fun close() {
        var i = rawCloseables.size - 1
        while (i >= 0) {
            try { rawCloseables[i].close() } catch (_: Exception) {}
            i--
        }
    }
}

object SecureServer {
    /** challenge 里 advertised 的 server 名（与 hd_net.c 一致） */
    const val SERVER_NAME: String = "hamsterd"

    /** challenge 里 advertised 的版本（§8.5：0.0.9 起默认加密） */
    const val SERVER_VERSION: String = "0.0.9"

    /** C 侧 dev[64] / host[128]（含结尾 NUL），截断上限分别是 63 / 127。 */
    private const val DEVICE_ID_MAX = 63
    private const val HOSTNAME_MAX = 127

    /**
     * 与 hd_net.c 的 challenge **完全相同**的 features 列表。
     * 本层不做能力协商（§8.5 明确不降级），所以这里不做成参数。
     */
    private const val FEATURES_JSON =
        "[\"framing:aead\",\"search\",\"download\",\"upload\",\"list\",\"mkdir\"," +
        "\"delete\",\"sync-database\",\"verify\",\"rescan\",\"sync\",\"keys\"]"

    /**
     * 服务端侧 §8 握手：读 hello（明文）→ 发 challenge → 读 proof（明文）→ 常数时间校验
     * → 发 auth/ok → 切记录层。
     *
     * 认证失败返回 null（并且**不**向对端发任何错误对象、不泄漏"是口令错还是格式错"），
     * 由调用方关闭连接。超时/对端关闭同样返回 null。
     *
     * challenge 的字段与顺序、features 列表都照抄 `sec_handshake`，这样现有客户端
     * （`SecureChannel.connect` / JS / C 代理）不需要任何改动就能连上来。
     *
     * 超时实现：本方法只拿到流、拿不到 socket，因此用一个守护线程在 [timeoutMs] 到期时
     * 关闭 `rawIn`/`rawOut`（socket 的流被关闭即等于关连接），阻塞中的读会抛异常 →
     * 返回 null。`timeoutMs <= 0` 表示不设超时（与 `Socket.soTimeout = 0` 语义一致）。
     *
     * @param secrets 候选口令：**第 0 个是 codeword，其余是 api_key 候选**（与 C 侧
     *   "先试 codeword、再逐把试 api_keys" 的顺序一致）。按顺序逐个派生 master 试
     *   proof_C，第一个命中即用；列表为空直接返回 null（连 hello 都不读）。
     * @param random 仅用于测试注入（填充 salt/ns）；为 null 时用 `SecureRandom`
     */
    fun handshake(
        rawIn: InputStream,
        rawOut: OutputStream,
        secrets: List<String>,
        timeoutMs: Int = 8000,
        random: ((ByteArray) -> Unit)? = null,
    ): SecureServerSession? {
        if (secrets.isEmpty()) return null

        /*
         * 客户端可能把第一条记录紧跟在 proof 之后发过来（同一个 TCP 段）。
         * 这里统一套一层 BufferedInputStream，并让记录层继续用同一个对象读，
         * 缓冲里剩下的密文字节就不会丢 —— 丢一个字节 counter 就永远对不上
         * （对应 C 侧把 rd 剩余字节搬进 cbuf 的那段）。
         */
        val input = if (rawIn is BufferedInputStream) rawIn else BufferedInputStream(rawIn)
        val deadline = HandshakeDeadline(timeoutMs, listOf<java.io.Closeable>(rawOut, input))
        var session: SecureServerSession? = null
        try {
            session = runHandshake(input, rawOut, secrets, random)
        } catch (_: Exception) {
            session = null
        } finally {
            deadline.finish()
        }
        if (deadline.expired) {
            if (session != null) session.close()
            return null
        }
        return session
    }

    /** 真正的握手流程；任何不符都直接返回 null（不解释原因）。 */
    private fun runHandshake(
        input: InputStream,
        rawOut: OutputStream,
        secrets: List<String>,
        random: ((ByteArray) -> Unit)?,
    ): SecureServerSession? {
        /* ---- 1) hello（明文）：字段与校验顺序同 sec_handshake ---- */
        val hello = readLine(input) ?: return null
        if (!Json.isObject(hello)) return null
        if (Json.getString(hello, "type") != "auth") return null
        if (Json.getString(hello, "step") != "hello") return null
        if (Json.getInt(hello, "v") != Sec.AUTH_VERSION) return null
        val ncHex = Json.getString(hello, "nc") ?: return null
        if (!Sec.isHex16(ncHex)) return null
        val deviceId = clamp(Json.getString(hello, "device_id") ?: "", DEVICE_ID_MAX)
        if (deviceId.isEmpty()) return null
        val host = clamp(Json.getString(hello, "hostname") ?: "", HOSTNAME_MAX)
        val hostname = if (host.isEmpty()) "unknown" else host

        /* ---- 2) challenge（明文）：salt/ns 每次连接都新生成 ---- */
        val salt = ByteArray(Sec.SALT_LEN)
        val ns = ByteArray(Sec.NONCE_LEN)
        fillRandom(salt, random)
        fillRandom(ns, random)
        val saltHex = Sec.bytesToHex(salt)
        val nsHex = Sec.bytesToHex(ns)
        sendLine(rawOut, buildChallenge(saltHex, nsHex))

        /* ---- 3) proof（明文） ---- */
        val proof = readLine(input) ?: return null
        if (!Json.isObject(proof)) return null
        if (Json.getString(proof, "type") != "auth") return null
        if (Json.getString(proof, "step") != "proof") return null
        val macHex = Json.getString(proof, "mac") ?: return null
        if (!Sec.isHex32(macHex)) return null
        val got = Sec.hexToBytes(macHex)

        /* ---- 4) 逐把候选口令派生 master 试 proof_C（常量时间比较，命中即停） ---- */
        var keys: SecKeys? = null
        var hit = -1
        for ((index, secret) in secrets.withIndex()) {
            if (secret.isEmpty()) continue          // 空口令算不出 master，跳过
            val candidate = try {
                Sec.deriveSession(secret.toByteArray(Charsets.UTF_8), saltHex, ncHex, nsHex, deviceId)
            } catch (_: SecureException) {
                null
            }
            if (candidate != null && Sec.constantTimeEquals(candidate.proofC, got)) {
                keys = candidate
                hit = index
                break
            }
        }
        val k = keys ?: return null                 /* 静默失败：一个字节都不发（§8.2） */

        /* ---- 5) ok 必须是明文：这条发完，双方才同时切到记录层（顺序同 C 侧） ---- */
        sendLine(rawOut, "{\"type\":\"auth\",\"step\":\"ok\",\"mac\":\"" + Sec.bytesToHex(k.proofS) + "\"}")

        /* ---- 6) 切记录层：服务端发 s2c、收 c2s（同 hd_sec_init(is_server=1)） ---- */
        val inStream = AeadInputStream(input, RecordOpener(k.keyC2S, Sec.DIR_C2S))
        val outStream = AeadOutputStream(rawOut, RecordSealer(k.keyS2C, Sec.DIR_S2C))
        return SecureServerSession(
            inStream, outStream, deviceId, hostname, ncHex, nsHex, authLabelFor(hit, secrets[hit]),
            listOf<java.io.Closeable>(rawOut, input),
        )
    }

    /**
     * 只给本机日志用的标签（**不是**口令本身）。
     * 第 0 个候选是 codeword；其余是 api_key。太短的口令（< 8）不截前缀，
     * 否则会把整把密钥写进日志。
     */
    private fun authLabelFor(index: Int, secret: String): String =
        if (index == 0) "codeword"
        else if (secret.length >= 8) "api_key:" + secret.take(8)
        else "api_key:key#" + (index + 1)

    /** challenge 行：字段顺序与 `sec_handshake` 的 snprintf 逐字节一致。 */
    private fun buildChallenge(saltHex: String, nsHex: String): String = buildString {
        append("{\"type\":\"auth\",\"step\":\"challenge\",\"v\":").append(Sec.AUTH_VERSION)
        append(",\"salt\":\"").append(saltHex)
        append("\",\"ns\":\"").append(nsHex)
        append("\",\"alg\":\"chacha20poly1305\",\"kdf\":\"hkdf-sha256\"")
        append(",\"server\":\"").append(SERVER_NAME)
        append("\",\"version\":\"").append(SERVER_VERSION)
        append("\",\"features\":").append(FEATURES_JSON).append('}')
    }

    private fun fillRandom(dst: ByteArray, random: ((ByteArray) -> Unit)?) {
        if (random != null) {
            random(dst)
        } else {
            java.security.SecureRandom().nextBytes(dst)
        }
    }

    /** C 侧固定缓冲区的截断语义（dev[64] / host[128]）：超长部分丢弃。 */
    private fun clamp(s: String, max: Int): String = if (s.length <= max) s else s.substring(0, max)

    private fun sendLine(out: OutputStream, line: String) {
        val bytes = line.toByteArray(Charsets.UTF_8)
        if (bytes.size > Sec.AUTH_LINE_MAX) throw SecureException("line_too_long", "auth line > 1KiB")
        out.write(bytes)
        out.write('\n'.code)
        out.flush()
    }

    /** 握手阶段读一行明文（≤ 1 KiB）；EOF / 超长 / 非 UTF-8 都返回 null。 */
    private fun readLine(input: InputStream): String? {
        val buf = ByteArrayOutputStream(256)
        while (true) {
            val c = input.read()
            if (c < 0) return null
            if (c == '\n'.code) break
            if (buf.size() >= Sec.AUTH_LINE_MAX) return null
            if (c != '\r'.code) buf.write(c)
        }
        return decodeUtf8Strict(buf.toByteArray())
    }

    /**
     * 握手超时看门狗：到期时关闭原始流，让阻塞中的读抛异常。
     *
     * 之所以要单开线程：本方法只拿到 InputStream/OutputStream，拿不到 Socket，
     * 无法设置 SO_TIMEOUT。关闭 socket 的流等价于关闭 socket，是唯一可移植的打断手段。
     */
    private class HandshakeDeadline(
        private val timeoutMs: Int,
        private val closeables: List<java.io.Closeable>,
    ) {
        private val lock = Any()
        private var finished = false
        private var expiredFlag = false

        private val worker: Thread? = if (timeoutMs <= 0) null else Thread(
            Runnable { runWorker() },
            "hamster-sec-handshake-deadline",
        ).apply {
            isDaemon = true
            start()
        }

        val expired: Boolean get() = synchronized(lock) { expiredFlag }

        private fun runWorker() {
            try {
                Thread.sleep(timeoutMs.toLong())
            } catch (_: InterruptedException) {
                return
            }
            synchronized(lock) {
                if (finished) return
                expiredFlag = true
            }
            for (c in closeables) {
                try { c.close() } catch (_: Exception) {}
            }
        }

        fun finish() {
            synchronized(lock) { finished = true }
            worker?.interrupt()
            try {
                worker?.join(100)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
            }
        }
    }
}
