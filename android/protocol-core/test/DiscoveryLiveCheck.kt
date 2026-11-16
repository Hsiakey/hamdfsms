/*
 * DiscoveryLiveCheck.kt — Kotlin 发现客户端 ⇄ 真实 hamsterd 的 §7 端到端检查
 *
 * DiscoverySocketTest 用一个假服务端证明收发/去重/静默丢弃都对，但那只证明
 * "Kotlin 与服务端规则一致"；这里把真实的 C 守护进程接进来，证明跨实现互通
 * （MAC 原文、nonce 回显、源地址、限速窗口在真机上真的对得上）。
 *
 * 用法（先启动一个开着 discovery_respond 的 hamsterd）：
 *   java -cp build\disc-live.jar hamster.DiscoveryLiveCheckKt 127.0.0.1 9110 <codeword>
 *
 * 第三个参数是 discovery **UDP** 端口（不是 TCP 9100）；
 * 应答里带的是服务端 TCP 端口，这里会断言它非 0。
 */
package hamster

private var okCount = 0
private var badCount = 0

private fun expect(cond: Boolean, name: String, detail: String = "") {
    if (cond) { okCount++; println("  ok   $name") }
    else { badCount++; println("  FAIL $name" + if (detail.isNotEmpty()) "  → $detail" else "") }
}

fun main(args: Array<String>) {
    val host = args.getOrNull(0) ?: "127.0.0.1"
    val port = args.getOrNull(1)?.toIntOrNull() ?: DISC_DEFAULT_PORT
    val secret = args.getOrNull(2) ?: "test-sec-codeword-bbbbbbbbbbbbbbbb"

    println("Hamster §7 端到端检查（Kotlin 发现客户端 ⇄ hamsterd $host:$port）")

    /* 1) probeOnce：单发命中 */
    val t0 = System.currentTimeMillis()
    val one = DiscoveryClient.probeOnce(secret, host, port, timeoutMs = 1500)
    val ms = System.currentTimeMillis() - t0
    expect(one != null, "probeOnce 发现设备（${ms}ms）")
    if (one != null) {
        expect(one.ip == host, "ip 是探测目标的源地址", "got=${one.ip}")
        expect(one.port != 0, "应答里带服务端 TCP 端口", "port=${one.port}")
        expect(one.id.length in 1..64, "id 非空且合理", "id=${one.id}")
        println("       设备：name='${one.name}' id=${one.id} tcpPort=${one.port} ver=${one.version}")
    }

    /* 2) scan：完整窗口，可能多次应答，去重后仍是一台 */
    val all = DiscoveryClient.scan(secret, timeoutMs = 1800, port = port, target = host)
    expect(all.isNotEmpty(), "scan 发现设备（${all.size} 台）")
    if (all.isNotEmpty()) {
        expect(all.map { it.id }.toSet().size == all.size, "按 id 去重后没有重复项")
        if (one != null) {
            val same = all.firstOrNull { it.id == one.id }
            expect(same != null, "scan 与 probeOnce 命中的是同一台设备")
            if (same != null) {
                expect(same.port == one.port, "两次拿到的 TCP 端口一致")
                expect(same.name == one.name, "两次拿到的名字一致")
            }
        }
    }

    /* 3) 错误暗号：必须一台都发现不了（服务端静默不回应） */
    val wrong = DiscoveryClient.scan("definitely-not-the-codeword", timeoutMs = 900, port = port, target = host)
    expect(wrong.isEmpty(), "错误暗号 → 零应答", "got=${wrong.size}")

    /* 4) 空暗号：本地就拒绝，不发包 */
    val empty = DiscoveryClient.scan("", timeoutMs = 500, port = port, target = host)
    expect(empty.isEmpty(), "空暗号 → 零应答")

    println()
    println("PASS $okCount / FAIL $badCount")
    if (badCount > 0) kotlin.system.exitProcess(1)
}
