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
