/*
 * LiveCheck.kt — Kotlin 客户端 ⇄ 真实 hamsterd 的 §8 端到端检查
 *
 * 自检（TestMain）只能证明"Kotlin 实现自洽 + 与固定向量一致"；
 * 这里把 SecureChannel 接到真的 C 守护进程上，证明三端确实能互通。
 *
 * 用法（先启动一个开着 encrypt_transport 的 hamsterd）：
 *   java -cp build\protocol-core.jar hamster.LiveCheckKt 19303 <codeword>
 *
 * 覆盖：握手、ping、info（features 含 framing:aead）、200 KiB 下载（跨记录）、
 *       以及错误口令必须失败。
 */
package hamster

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.OutputStream
import java.io.InputStream
import java.security.MessageDigest

private var okCount = 0
private var badCount = 0

private fun expect(cond: Boolean, name: String, detail: String = "") {
    if (cond) { okCount++; println("  ok   $name") }
    else { badCount++; println("  FAIL $name" + if (detail.isNotEmpty()) "  → $detail" else "") }
}

private fun writeLine(out: OutputStream, json: String) {
    out.write(json.toByteArray(Charsets.UTF_8))
    out.write('\n'.code)
    out.flush()
}

private fun sha256Hex(b: ByteArray): String {
    val d = MessageDigest.getInstance("SHA-256").digest(b)
    return d.joinToString("") { String.format("%02x", it) }
}

fun main(args: Array<String>) {
    val port = args.getOrNull(0)?.toIntOrNull() ?: 19303
    val secret = args.getOrNull(1) ?: "test-sec-codeword-bbbbbbbbbbbbbbbb"
    val deviceId = args.getOrNull(2) ?: "dev_kotlin_live"

    println("Hamster §8 端到端检查（Kotlin 客户端 ⇄ hamsterd :$port）")

    /* --- 错误口令必须先失败 --- */
    try {
        val bad = SecureChannel.connect("127.0.0.1", port, "definitely-wrong-codeword", deviceId, null, 3000)
        bad.close()
        expect(false, "错误口令必须失败")
    } catch (e: SecureException) {
        expect(true, "错误口令被拒（${e.code}）")
    }

    /* --- 正常握手 --- */
    val ch = SecureChannel.connect("127.0.0.1", port, secret, deviceId, "kotlin-live", 5000)
    try {
        expect(true, "握手成功（server=${ch.peerName} ver=${ch.peerVersion}）")
        val reader = FrameReader(ch.input)

        /* ping */
        writeLine(ch.output, "{\"type\":\"request\",\"id\":\"k1\",\"action\":\"ping\"}")
        val pong = reader.readHeader() ?: throw IllegalStateException("ping 没有响应")
        expect(pong.contains("\"status\":\"ok\"") && pong.contains("\"pong\":true"), "ping 走密文返回 pong", pong.take(120))

        /* info */
        writeLine(ch.output, "{\"type\":\"request\",\"id\":\"k2\",\"action\":\"info\"}")
        val info = reader.readHeader() ?: throw IllegalStateException("info 没有响应")
        expect(info.contains("framing:aead"), "features 含 framing:aead")
        expect(info.contains("framing:raw"), "features 仍含 framing:raw")

        /* download（若服务端监控目录里存在 big.bin） */
        writeLine(ch.output, "{\"type\":\"request\",\"id\":\"k3\",\"action\":\"download\",\"params\":{\"path\":\"big.bin\"}}")
        val header = reader.readHeader() ?: throw IllegalStateException("download 没有响应")
        if (!header.contains("\"status\":\"ok\"")) {
            println("  --   跳过下载检查（服务端没有 big.bin）：${header.take(120)}")
        } else {
            val n = reader.payloadBytes
            val sink = ByteArrayOutputStream()
            val got = reader.readPayload { buf, off, len -> sink.write(buf, off, len) }
            val body = sink.toByteArray()
            expect(got == n && body.size.toLong() == n, "下载负载字节数与声明一致", "$got/$n")
            expect(body.isNotEmpty() && body[0] == 0x5a.toByte(), "下载内容与源文件同源（0x5a 填充）")
            expect(body.size == 200 * 1024, "下载 200 KiB", body.size.toString())
        }
    } finally {
        ch.close()
    }

    println()
    println("=== 结果: 通过 $okCount, 失败 $badCount ===")
    if (badCount != 0) System.exit(1)
}
