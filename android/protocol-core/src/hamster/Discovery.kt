/*
 * Discovery.kt — 局域网发现（PROTOCOL.md §7）
 *
 * 规则（0.0.8）：客户端主动广播探测，服务端只有在对上暗号时才单播应答；
 * 校验失败一律"当没收到"——不抛异常、不提示（与服务端 hd_disc.c 的静默丢弃一致）。
 *
 * 帧格式（UDP 一行 UTF-8 JSON，≤512 字节，不带换行）：
 *   探测  {"t":"hp","v":1,"id":"<client>","n":"<32hex>","m":"<64hex>"}
 *   应答  {"t":"hr","v":1,"id":"<self>","n":"<回显>","m":"<64hex>","name":"...","port":9100,"ver":"0.0.8"}
 *
 * MAC 原文（UTF-8，'\n' 分隔，**末尾无换行**）：
 *   probe: "hamster-disc-probe/v1\n" + id + "\n" + n
 *   reply: "hamster-disc-reply/v1\n" + probe_id + "\n" + n + "\n" + self_id + "\n" + port
 *
 * 为什么 MAC 覆盖这些字段（照抄服务端注释，防止实现走样）：
 *   · probe 里的 id/n 被覆盖 → 探测帧不能被篡改；
 *   · reply 里带 probe_id → 捕获到的应答无法重放给另一个客户端；
 *   · reply 里带 self_id/port → 中间人不能把应答改指到另一台机器；
 *   · n 原样回显 → 客户端能把应答配回某一轮探测。
 *
 * 注意：应答里的服务端 IP **不在帧内**，必须取 UDP recvfrom 的源地址
 * （那是唯一无法被载荷伪造的值）；本文件的 [DiscoveryPeer] 因此不携带 IP。
 */
package hamster

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** 发现协议版本；不等于 1 的帧一律丢弃（PROTOCOL §7.1）。 */
const val DISC_VERSION: Int = 1

/** UDP 帧上限（PROTOCOL §7.1：载荷不超过 512 字节）。 */
const val DISC_FRAME_MAX: Int = 512

/** nonce 是 16 字节随机数的十六进制，长度固定 32。 */
const val DISC_NONCE_HEX_LEN: Int = 32

/** HMAC-SHA256 的十六进制长度，固定 64。 */
const val DISC_MAC_HEX_LEN: Int = 64

/** 发现默认 UDP 端口（服务端 discovery_port / 客户端 hamd_discovery_port）。 */
const val DISC_DEFAULT_PORT: Int = 9110

internal const val DISC_PROBE_PREFIX: String = "hamster-disc-probe/v1\n"
internal const val DISC_REPLY_PREFIX: String = "hamster-disc-reply/v1\n"

/**
 * 一条通过校验的发现应答。
 *
 * @param id 服务端 instance_id
 * @param name 服务端显示名（缺失时为空串）
 * @param port 服务端 **TCP** 监听端口（客户端用它建立连接）
 * @param version 服务端版本串（缺失时为空串）
 * @param nonceHex 原样回显的探测 nonce，调用方据此把应答配回某一轮探测
 */
data class DiscoveryPeer(
    val id: String,
    val name: String,
    val port: Int,
    val version: String,
    val nonceHex: String
)

/**
 * HMAC-SHA256，返回小写十六进制串（64 位）。key 与 message 按 UTF-8 取字节，
 * 与服务端 hd_hmac_sha256(codeword, strlen(codeword), ...) 的行为一致
 * （codeword 是配置里的字节串；只要两侧配置文本相同，UTF-8 编码就相同）。
 */
fun hmacSha256Hex(key: String, message: String): String =
    hmacSha256Hex(key.toByteArray(Charsets.UTF_8), message.toByteArray(Charsets.UTF_8))

/** HMAC-SHA256（字节版），返回小写十六进制串。用于校验标准测试向量。 */
fun hmacSha256Hex(key: ByteArray, message: ByteArray): String {
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(SecretKeySpec(key, "HmacSHA256"))
    return toHexLower(mac.doFinal(message))
}

/**
 * HMAC-SHA256 分段版本：把若干段（UTF-8）按顺序拼接后计算，避免调用方自己拼大缓冲。
 * 仅供本文件构造 MAC 原文使用，避免与两参数版本产生重载歧义。
 */
private fun hmacSha256HexParts(key: String, vararg parts: String): String {
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(SecretKeySpec(key.toByteArray(Charsets.UTF_8), "HmacSHA256"))
    for (p in parts) mac.update(p.toByteArray(Charsets.UTF_8))
    return toHexLower(mac.doFinal())
}

/**
 * 定长字符串的常量时间比较。
 *
 * 先比较长度（MAC 长度是公开的，不代表秘密），再对每个字节做异或累加，
 * 不提前返回，避免时序泄露"前缀匹配了多少位"。
 *
 * 与服务端 hd_ct_equal 一致：**区分大小写**。服务端算出的 MAC 是小写十六进制，
 * 因此带大写 MAC 的帧会被判为不符（这也是 hd_disc.c 的实际行为）。
 */
fun constantTimeEquals(a: String, b: String): Boolean {
    val x = a.toByteArray(Charsets.UTF_8)
    val y = b.toByteArray(Charsets.UTF_8)
    var diff = x.size xor y.size
    val n = minOf(x.size, y.size)
    var i = 0
    while (i < n) {
        diff = diff or (x[i].toInt() xor y[i].toInt())
        i++
    }
    return diff == 0
}

/**
 * device_id 是否合法：8–63 个 `[0-9A-Za-z_-]`（PROTOCOL §7.1）。
 * 注意不能用 Char.isLetterOrDigit()：那是 Unicode 语义，会放进非 ASCII 字符。
 */
fun isValidDiscoveryId(s: String): Boolean {
    if (s.length < 8 || s.length > 63) return false
    for (c in s) {
        val ok = c in '0'..'9' || c in 'a'..'z' || c in 'A'..'Z' || c == '_' || c == '-'
        if (!ok) return false
    }
    return true
}

/** 是否恰好 [expectedLen] 个十六进制字符（大小写都接受，与服务端 isxdigit 一致）。 */
fun isHex(s: String, expectedLen: Int): Boolean {
    if (s.length != expectedLen) return false
    for (c in s) {
        val ok = c in '0'..'9' || c in 'a'..'f' || c in 'A'..'F'
        if (!ok) return false
    }
    return true
}

/**
 * 探测帧的 MAC（PROTOCOL §7.1）。
 *
 * 原文 = `"hamster-disc-probe/v1\n" + id + "\n" + nonceHex`（UTF-8，末尾无换行）。
 */
fun probeMac(codeword: String, id: String, nonceHex: String): String {
    require(codeword.isNotEmpty()) { "codeword 不能为空（空口令算不出 MAC）" }
    require(isValidDiscoveryId(id)) { "id 不合法（需 8–63 个 [0-9A-Za-z_-]）：\"$id\"" }
    require(isHex(nonceHex, DISC_NONCE_HEX_LEN)) { "nonce 必须是 32 位十六进制：\"$nonceHex\"" }
    return hmacSha256HexParts(codeword, DISC_PROBE_PREFIX, id, "\n", nonceHex)
}

/**
 * 应答帧的 MAC（PROTOCOL §7.1）。
 *
 * 原文 = `"hamster-disc-reply/v1\n" + probeId + "\n" + nonceHex + "\n" + selfId + "\n" + port`
 * （UTF-8，末尾无换行；port 用十进制、不带前导零，与服务端 snprintf("%d") 一致）。
 */
fun replyMac(codeword: String, probeId: String, nonceHex: String, selfId: String, port: Int): String {
    require(codeword.isNotEmpty()) { "codeword 不能为空（空口令算不出 MAC）" }
    require(isValidDiscoveryId(probeId)) { "探测方 id 不合法：\"$probeId\"" }
    require(isHex(nonceHex, DISC_NONCE_HEX_LEN)) { "nonce 必须是 32 位十六进制：\"$nonceHex\"" }
    require(isValidDiscoveryId(selfId)) { "服务端 id 不合法：\"$selfId\"" }
    require(port in 1..65535) { "端口越界（1–65535）：$port" }
    return hmacSha256HexParts(
        codeword, DISC_REPLY_PREFIX, probeId, "\n", nonceHex, "\n", selfId, "\n", port.toString()
    )
}

/**
 * 构造探测帧（客户端 → 广播地址）。
 *
 * 输出与服务端 hd_disc_build_probe 逐字节一致：
 * `{"t":"hp","v":1,"id":"...","n":"...","m":"..."}`（无换行、无多余空格）。
 * id/nonceHex 的字符集受限（[0-9A-Za-z_-] / 十六进制），因此不需要 JSON 转义。
 *
 * @throws IllegalArgumentException 参数非法（构造侧属于编程错误，与解析侧的"静默丢弃"不同）
 */
fun buildProbe(codeword: String, id: String, nonceHex: String): ByteArray {
    val mac = probeMac(codeword, id, nonceHex)
    val json = buildString {
        append("{\"t\":\"hp\",\"v\":").append(DISC_VERSION)
        append(",\"id\":\"").append(id)
        append("\",\"n\":\"").append(nonceHex)
        append("\",\"m\":\"").append(mac)
        append("\"}")
    }
    val bytes = json.toByteArray(Charsets.UTF_8)
    require(bytes.size <= DISC_FRAME_MAX) {
        "探测帧超过 $DISC_FRAME_MAX 字节上限（实际 ${bytes.size}）"
    }
    return bytes
}

/**
 * 校验一条发现应答帧（客户端侧）。
 *
 * 通过返回 [DiscoveryPeer]；**任何**不符都返回 null（不抛异常）：
 *   · 帧为空 / 超过 512 字节 / 含 NUL / 不是 UTF-8 / 不是 JSON 对象；
 *   · t != "hr" 或 v != 1；
 *   · myId 不是合法的 device_id（算不出预期 MAC，直接 null，不抛异常）；
 *   · id 不符合 §7.1 的字符集/长度，或 id == myId（同机多实例自打自收，忽略）；
 *   · n 不是 32 位十六进制，m 不是 64 位十六进制；
 *   · port 缺失/类型不符/越界；
 *   · MAC 与本地计算值不等（常量时间比较）。
 *
 * 调用方仍需自行完成 §7.3 的其余检查：应答的 nonce 是否属于"本轮 + 上一轮"
 * （防旧应答污染），以及用 recvfrom 的源地址作为对端 IP。
 *
 * @param codeword 与服务端一致的连接口令（空串时直接返回 null，算不出 MAC）
 * @param myId 本机 device_id（进应答 MAC 原文，因此捕获的应答无法重放给别人）
 * @param frame UDP 收到的原始字节
 */
fun parseReply(codeword: String, myId: String, frame: ByteArray): DiscoveryPeer? {
    if (codeword.isEmpty()) return null
    // myId 不合法时算不出合法的预期 MAC；返回 null 而不是让 replyMac 抛异常。
    if (!isValidDiscoveryId(myId)) return null
    if (frame.isEmpty() || frame.size > DISC_FRAME_MAX) return null
    for (b in frame) {
        if (b.toInt() == 0) return null        // 内嵌 NUL：攻击者常用的截断手法
    }
    val text = decodeUtf8Strict(frame) ?: return null
    if (!Json.isObject(text)) return null

    if (Json.getString(text, "t") != "hr") return null
    if (Json.getLong(text, "v") != DISC_VERSION.toLong()) return null

    val id = Json.getString(text, "id") ?: return null
    if (!isValidDiscoveryId(id)) return null
    // 自己发出的广播可能被本机另一实例回给本机：直接当无效。
    if (myId.isNotEmpty() && id == myId) return null

    val nonce = Json.getString(text, "n") ?: return null
    if (!isHex(nonce, DISC_NONCE_HEX_LEN)) return null

    val mac = Json.getString(text, "m") ?: return null
    if (!isHex(mac, DISC_MAC_HEX_LEN)) return null

    val port = Json.getLong(text, "port") ?: return null
    if (port < 1L || port > 65535L) return null
    val portInt = port.toInt()

    // name / ver 是可选项：缺失或类型不符按空串处理（与服务端 hd_disc_parse_reply 一致）。
    val name = Json.getString(text, "name") ?: ""
    val ver = Json.getString(text, "ver") ?: ""

    val want = replyMac(codeword, myId, nonce, id, portInt)
    if (!constantTimeEquals(want, mac)) return null   // 常量时间比较

    return DiscoveryPeer(id = id, name = name, port = portInt, version = ver, nonceHex = nonce)
}

// -------------------------------------------------------------------- 内部实现

private const val HEX_DIGITS = "0123456789abcdef"

private fun toHexLower(bytes: ByteArray): String {
    val sb = StringBuilder(bytes.size * 2)
    for (b in bytes) {
        val v = b.toInt() and 0xFF
        sb.append(HEX_DIGITS[v ushr 4]).append(HEX_DIGITS[v and 0x0F])
    }
    return sb.toString()
}
