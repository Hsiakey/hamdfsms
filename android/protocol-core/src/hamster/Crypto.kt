/*
 * Crypto.kt — ChaCha20-Poly1305（RFC 8439）与 HKDF-SHA256（RFC 5869）
 *
 * 为什么要自带实现，而不是直接用 JCE：
 *   1. ChaCha20-Poly1305 直到 JDK 11 才进入 JCE；本仓库的自检环境是 JDK 8，
 *      而 Android 端真正可用又要看设备（Conscrypt 老版本也没有）。
 *   2. 协议核心（protocol-core）的约束是"纯 JVM + 无 Android 依赖"，自带实现
 *      让同一份代码在 JDK 8、JDK 17、Android 上行为完全一致 —— 传输加密最怕的
 *      就是"某个平台上算法悄悄不一样"。
 *   HKDF 只用 HMAC-SHA256，JCE 到处都有，所以直接复用 javax.crypto.Mac。
 *
 * 与 C（Hamsterd/hd_aead.c）、JS（hamster-aead.js）必须逐字节一致：
 * 对齐锚点是 RFC 8439 的官方向量与 RFC 5869 附录 A，再加 PROTOCOL §8.2 的
 * 五组固定值；任何一端写错，自检立刻红。
 *
 * 设计约束：
 *   · 认证失败时不返回任何明文（先验 tag 再解密）；
 *   · 允许空明文、空 AAD；
 *   · 只实现 12 字节 nonce 的标准版本，nonce 复用会毁掉安全性（调用方负责）。
 */
package hamster

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object ChaCha20Poly1305 {
    const val KEY_LEN = 32
    const val NONCE_LEN = 12
    const val TAG_LEN = 16

    private const val SIGMA0 = 0x61707865  /* "expa" */
    private const val SIGMA1 = 0x3320646e  /* "nd 3" */
    private const val SIGMA2 = 0x79622d32  /* "2-by" */
    private const val SIGMA3 = 0x6b206574  /* "te k" */

    private fun rotl(v: Int, n: Int): Int = (v shl n) or (v ushr (32 - n))

    private fun doubleRound(s: IntArray) {
        /* 列轮 */
        qr(s, 0, 4, 8, 12); qr(s, 1, 5, 9, 13); qr(s, 2, 6, 10, 14); qr(s, 3, 7, 11, 15)
        /* 对角轮 */
        qr(s, 0, 5, 10, 15); qr(s, 1, 6, 11, 12); qr(s, 2, 7, 8, 13); qr(s, 3, 4, 9, 14)
    }

    private fun qr(s: IntArray, a: Int, b: Int, c: Int, d: Int) {
        s[a] += s[b]; s[d] = rotl(s[d] xor s[a], 16)
        s[c] += s[d]; s[b] = rotl(s[b] xor s[c], 12)
        s[a] += s[b]; s[d] = rotl(s[d] xor s[a], 8)
        s[c] += s[d]; s[b] = rotl(s[b] xor s[c], 7)
    }

    /** RFC 8439 §2.3：生成 64 字节密钥流块（counter 是 32 位块计数器） */
    fun block(key: ByteArray, counter: Int, nonce: ByteArray, out: ByteArray) {
        require(key.size == KEY_LEN) { "key must be $KEY_LEN bytes" }
        require(nonce.size == NONCE_LEN) { "nonce must be $NONCE_LEN bytes" }
        require(out.size >= 64) { "block output needs 64 bytes" }

        val st = IntArray(16)
        st[0] = SIGMA0; st[1] = SIGMA1; st[2] = SIGMA2; st[3] = SIGMA3
        var i = 0
        while (i < 8) { st[4 + i] = load32le(key, i * 4); i++ }
        st[12] = counter
        i = 0
        while (i < 3) { st[13 + i] = load32le(nonce, i * 4); i++ }

        val x = st.copyOf()
        i = 0
        while (i < 10) { doubleRound(x); i++ }
        i = 0
        while (i < 16) { store32le(out, i * 4, x[i] + st[i]); i++ }
    }

    /** 用 counter 起始值异或整段明文/密文（就地写进 out） */
    private fun streamXor(key: ByteArray, counter: Int, nonce: ByteArray,
                          input: ByteArray, off: Int, len: Int, out: ByteArray, outOff: Int) {
        val ks = ByteArray(64)
        var ctr = counter
        var done = 0
        while (done < len) {
            block(key, ctr, nonce, ks)
            val take = minOf(64, len - done)
            var i = 0
            while (i < take) {
                out[outOff + done + i] = (input[off + done + i].toInt() xor ks[i].toInt()).toByte()
                i++
            }
            done += take
            ctr++
        }
    }

    /** RFC 8439 §2.5.1：钳位后的 r 与 26 位分肢乘法（一次性，够用且不易出错） */
    fun poly1305(key: ByteArray, msg: ByteArray, msgOff: Int, msgLen: Int): ByteArray {
        require(key.size >= 32) { "poly1305 key must be 32 bytes" }

        val r0 = load32le(key, 0) and 0x3ffffff
        val r1 = (load32le(key, 3) ushr 2) and 0x3ffff03
        val r2 = (load32le(key, 6) ushr 4) and 0x3ffc0ff
        val r3 = (load32le(key, 9) ushr 6) and 0x3f03fff
        val r4 = (load32le(key, 12) ushr 8) and 0x00fffff
        val s1 = r1 * 5
        val s2 = r2 * 5
        val s3 = r3 * 5
        val s4 = r4 * 5

        var h0 = 0; var h1 = 0; var h2 = 0; var h3 = 0; var h4 = 0
        var off = msgOff
        var bytes = msgLen

        fun absorb(p: Int, hibit: Int) {
            h0 += load32le(msg, p) and 0x3ffffff
            h1 += (load32le(msg, p + 3) ushr 2) and 0x3ffffff
            h2 += (load32le(msg, p + 6) ushr 4) and 0x3ffffff
            h3 += (load32le(msg, p + 9) ushr 6) and 0x3ffffff
            h4 += (load32le(msg, p + 12) ushr 8) or hibit
        }

        while (bytes >= 16) {
            absorb(off, 1 shl 24)

            val d0 = h0.toLong() * r0 + h1.toLong() * s4 + h2.toLong() * s3 + h3.toLong() * s2 + h4.toLong() * s1
            val d1 = h0.toLong() * r1 + h1.toLong() * r0 + h2.toLong() * s4 + h3.toLong() * s3 + h4.toLong() * s2
            val d2 = h0.toLong() * r2 + h1.toLong() * r1 + h2.toLong() * r0 + h3.toLong() * s4 + h4.toLong() * s3
            val d3 = h0.toLong() * r3 + h1.toLong() * r2 + h2.toLong() * r1 + h3.toLong() * r0 + h4.toLong() * s4
            val d4 = h0.toLong() * r4 + h1.toLong() * r3 + h2.toLong() * r2 + h3.toLong() * r1 + h4.toLong() * r0

            var c = (d0 ushr 26).toInt(); h0 = (d0 and 0x3ffffffL).toInt()
            var e = d1 + c; c = (e ushr 26).toInt(); h1 = (e and 0x3ffffffL).toInt()
            e = d2 + c; c = (e ushr 26).toInt(); h2 = (e and 0x3ffffffL).toInt()
            e = d3 + c; c = (e ushr 26).toInt(); h3 = (e and 0x3ffffffL).toInt()
            e = d4 + c; c = (e ushr 26).toInt(); h4 = (e and 0x3ffffffL).toInt()
            h0 += c * 5
            c = h0 ushr 26; h0 = h0 and 0x3ffffff
            h1 += c

            off += 16
            bytes -= 16
        }

        if (bytes > 0) {
            /* 尾巴：补 0x01 再补零（就是 2^(8*len)），并且不再加 2^128 位 */
            val tail = ByteArray(16)
            System.arraycopy(msg, off, tail, 0, bytes)
            tail[bytes] = 1
            return poly1305Finish(key, h0, h1, h2, h3, h4, tail)
        }
        return poly1305Finish(key, h0, h1, h2, h3, h4, null)
    }

    private fun poly1305Finish(key: ByteArray, h0in: Int, h1in: Int, h2in: Int, h3in: Int,
                               h4in: Int, tail: ByteArray?): ByteArray {
        var h0 = h0in; var h1 = h1in; var h2 = h2in; var h3 = h3in; var h4 = h4in

        if (tail != null) {
            val r0 = load32le(key, 0) and 0x3ffffff
            val r1 = (load32le(key, 3) ushr 2) and 0x3ffff03
            val r2 = (load32le(key, 6) ushr 4) and 0x3ffc0ff
            val r3 = (load32le(key, 9) ushr 6) and 0x3f03fff
            val r4 = (load32le(key, 12) ushr 8) and 0x00fffff
            val s1 = r1 * 5; val s2 = r2 * 5; val s3 = r3 * 5; val s4 = r4 * 5

            h0 += load32le(tail, 0) and 0x3ffffff
            h1 += (load32le(tail, 3) ushr 2) and 0x3ffffff
            h2 += (load32le(tail, 6) ushr 4) and 0x3ffffff
            h3 += (load32le(tail, 9) ushr 6) and 0x3ffffff
            h4 += (load32le(tail, 12) ushr 8)   /* 没有 2^128 位 */

            val d0 = h0.toLong() * r0 + h1.toLong() * s4 + h2.toLong() * s3 + h3.toLong() * s2 + h4.toLong() * s1
            val d1 = h0.toLong() * r1 + h1.toLong() * r0 + h2.toLong() * s4 + h3.toLong() * s3 + h4.toLong() * s2
            val d2 = h0.toLong() * r2 + h1.toLong() * r1 + h2.toLong() * r0 + h3.toLong() * s4 + h4.toLong() * s3
            val d3 = h0.toLong() * r3 + h1.toLong() * r2 + h2.toLong() * r1 + h3.toLong() * r0 + h4.toLong() * s4
            val d4 = h0.toLong() * r4 + h1.toLong() * r3 + h2.toLong() * r2 + h3.toLong() * r1 + h4.toLong() * r0

            var c = (d0 ushr 26).toInt(); h0 = (d0 and 0x3ffffffL).toInt()
            var e = d1 + c; c = (e ushr 26).toInt(); h1 = (e and 0x3ffffffL).toInt()
            e = d2 + c; c = (e ushr 26).toInt(); h2 = (e and 0x3ffffffL).toInt()
            e = d3 + c; c = (e ushr 26).toInt(); h3 = (e and 0x3ffffffL).toInt()
            e = d4 + c; c = (e ushr 26).toInt(); h4 = (e and 0x3ffffffL).toInt()
            h0 += c * 5
            c = h0 ushr 26; h0 = h0 and 0x3ffffff
            h1 += c
        }

        /* 完整进位 */
        var c = h1 ushr 26; h1 = h1 and 0x3ffffff; h2 += c
        c = h2 ushr 26; h2 = h2 and 0x3ffffff; h3 += c
        c = h3 ushr 26; h3 = h3 and 0x3ffffff; h4 += c
        c = h4 ushr 26; h4 = h4 and 0x3ffffff; h0 += c * 5
        c = h0 ushr 26; h0 = h0 and 0x3ffffff; h1 += c

        /* 常数时间选择 h 还是 h-p */
        var g0 = h0 + 5; c = g0 ushr 26; g0 = g0 and 0x3ffffff
        var g1 = h1 + c; c = g1 ushr 26; g1 = g1 and 0x3ffffff
        var g2 = h2 + c; c = g2 ushr 26; g2 = g2 and 0x3ffffff
        var g3 = h3 + c; c = g3 ushr 26; g3 = g3 and 0x3ffffff
        var g4 = h4 + c - (1 shl 26)

        val mask = (g4 ushr 31) - 1
        g0 = g0 and mask; g1 = g1 and mask; g2 = g2 and mask; g3 = g3 and mask; g4 = g4 and mask
        val nm = mask.inv()
        h0 = (h0 and nm) or g0
        h1 = (h1 and nm) or g1
        h2 = (h2 and nm) or g2
        h3 = (h3 and nm) or g3
        h4 = (h4 and nm) or g4

        /* 重新打包成 4 个 32 位字 */
        val w0 = (h0 or (h1 shl 26))
        val w1 = ((h1 ushr 6) or (h2 shl 20))
        val w2 = ((h2 ushr 12) or (h3 shl 14))
        val w3 = ((h3 ushr 18) or (h4 shl 8))

        /* tag = (h + s) mod 2^128，小端 */
        val out = ByteArray(16)
        var f = (w0.toLong() and 0xffffffffL) + (load32le(key, 16).toLong() and 0xffffffffL)
        store32le(out, 0, f.toInt())
        f = (w1.toLong() and 0xffffffffL) + (load32le(key, 20).toLong() and 0xffffffffL) + (f ushr 32)
        store32le(out, 4, f.toInt())
        f = (w2.toLong() and 0xffffffffL) + (load32le(key, 24).toLong() and 0xffffffffL) + (f ushr 32)
        store32le(out, 8, f.toInt())
        f = (w3.toLong() and 0xffffffffL) + (load32le(key, 28).toLong() and 0xffffffffL) + (f ushr 32)
        store32le(out, 12, f.toInt())
        return out
    }

    fun poly1305(key: ByteArray, msg: ByteArray): ByteArray = poly1305(key, msg, 0, msg.size)

    /** RFC 8439 §2.8：tag = Poly1305(ChaCha20 块 0 的前 32 字节, AAD||pad||密文||pad||长度) */
    private fun aeadTag(key: ByteArray, nonce: ByteArray, aad: ByteArray,
                        cipher: ByteArray, cipherOff: Int, cipherLen: Int): ByteArray {
        val block0 = ByteArray(64)
        block(key, 0, nonce, block0)
        val otk = block0.copyOf(32)

        val aadPad = (16 - (aad.size and 15)) and 15
        val ctPad = (16 - (cipherLen and 15)) and 15
        val total = aad.size + aadPad + cipherLen + ctPad + 16
        val buf = ByteArray(total)
        var p = 0
        System.arraycopy(aad, 0, buf, p, aad.size); p += aad.size + aadPad
        System.arraycopy(cipher, cipherOff, buf, p, cipherLen); p += cipherLen + ctPad
        store64le(buf, p, aad.size.toLong())
        store64le(buf, p + 8, cipherLen.toLong())

        return poly1305(otk, buf)
    }

    /** 加密：返回 密文||tag */
    fun seal(key: ByteArray, nonce: ByteArray, aad: ByteArray, plain: ByteArray): ByteArray {
        require(key.size == KEY_LEN && nonce.size == NONCE_LEN)
        val ct = ByteArray(plain.size)
        streamXor(key, 1, nonce, plain, 0, plain.size, ct, 0)
        val tag = aeadTag(key, nonce, aad, ct, 0, ct.size)
        return ct + tag
    }

    /** 解密：tag 不对返回 null（且不暴露任何明文） */
    fun open(key: ByteArray, nonce: ByteArray, aad: ByteArray, sealed: ByteArray): ByteArray? {
        require(key.size == KEY_LEN && nonce.size == NONCE_LEN)
        if (sealed.size < TAG_LEN) return null
        val clen = sealed.size - TAG_LEN
        val tag = aeadTag(key, nonce, aad, sealed, 0, clen)
        if (!constantTimeEquals(tag, 0, sealed, clen, TAG_LEN)) return null
        val out = ByteArray(clen)
        streamXor(key, 1, nonce, sealed, 0, clen, out, 0)
        return out
    }

    fun constantTimeEquals(a: ByteArray, aOff: Int, b: ByteArray, bOff: Int, len: Int): Boolean {
        if (a.size < aOff + len || b.size < bOff + len) return false
        var diff = 0
        var i = 0
        while (i < len) { diff = diff or (a[aOff + i].toInt() xor b[bOff + i].toInt()); i++ }
        return diff == 0
    }

    /* ---------------- 小端读写（只处理 32/64 位） ---------------- */
    internal fun load32le(b: ByteArray, off: Int): Int =
        (b[off].toInt() and 0xff) or
        ((b[off + 1].toInt() and 0xff) shl 8) or
        ((b[off + 2].toInt() and 0xff) shl 16) or
        ((b[off + 3].toInt() and 0xff) shl 24)

    internal fun store32le(b: ByteArray, off: Int, v: Int) {
        b[off] = (v and 0xff).toByte()
        b[off + 1] = ((v ushr 8) and 0xff).toByte()
        b[off + 2] = ((v ushr 16) and 0xff).toByte()
        b[off + 3] = ((v ushr 24) and 0xff).toByte()
    }

    internal fun store64le(b: ByteArray, off: Int, v: Long) {
        var i = 0
        while (i < 8) { b[off + i] = ((v ushr (8 * i)) and 0xff).toByte(); i++ }
    }
}

object Hkdf {
    /**
     * RFC 5869 HKDF-SHA256。
     * salt 为空时按 RFC 用 32 字节全零（与 HMAC 用全零密钥等价）。
     */
    fun sha256(salt: ByteArray, ikm: ByteArray, info: ByteArray, len: Int): ByteArray {
        require(len in 1..(255 * 32)) { "hkdf length out of range" }
        val mac = Mac.getInstance("HmacSHA256")

        val effSalt = if (salt.isEmpty()) ByteArray(32) else salt
        mac.init(SecretKeySpec(effSalt, "HmacSHA256"))
        val prk = mac.doFinal(ikm)

        val out = ByteArray(len)
        var t = ByteArray(0)
        var pos = 0
        var counter = 1
        while (pos < len) {
            mac.init(SecretKeySpec(prk, "HmacSHA256"))
            mac.update(t)
            mac.update(info)
            mac.update(counter.toByte())
            t = mac.doFinal()
            val n = minOf(t.size, len - pos)
            System.arraycopy(t, 0, out, pos, n)
            pos += n
            counter++
        }
        return out
    }

    fun hmacSha256(key: ByteArray, msg: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(msg)
    }
}
