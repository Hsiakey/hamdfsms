/*
 * DiscoverySocket.kt — 局域网发现的 UDP 收发层（PROTOCOL.md §7）
 *
 * Discovery.kt 只有纯函数：构造探测帧、校验应答帧。本文件补上它缺的那一半：
 * 真正开 UDP socket、广播探测、循环 recvfrom、用源地址补出对端 IP、去重排序。
 *
 * 帧格式与 MAC 原文见 Discovery.kt / PROTOCOL §7.1。这里的实现要点：
 *   · 每轮探测用 16 字节 SecureRandom nonce（32 位十六进制），两次探测不同 nonce；
 *   · 应答的 n 必须原样回显**本轮**（含本轮第二发）的 nonce，否则静默丢弃；
 *   · MAC 校验交给 parseReply（常量时间比较），失败一律当没收到；
 *   · IP 取 recvfrom 的源地址（packet.address），因为载荷里没有、也无法伪造；
 *   · 按 id 去重，再按 name、ip 排序（name/ip 相同时用 id 兜底，保证稳定）。
 *
 * 与 C 侧（Hamsterd/hd_disc.c）对齐的语义见各函数注释；两边都不对外区分
 * "暗号不对" 与 "根本没有服务端"。
 *
 * 已知限制（Android 上尤其注意）：
 *   · Android 需要 <uses-permission android:name="android.permission.INTERNET"/>；
 *     没有时 DatagramSocket 构造/发送抛 SecurityException，这里按约定返回空列表。
 *   · CHANGE_WIFI_MULTICAST_STATE 权限 / WifiManager.MulticastLock 只影响**组播**；
 *     255.255.255.255 是受限广播，严格说不必申请，但部分 OEM 的 Wi-Fi 省电策略
 *     会过滤广播，真机开发建议在持有 MulticastLock 时也测一遍。
 *   · 广播只在同一广播域内有效；Android 模拟器里 255.255.255.255 到不了宿主机，
 *     要发现宿主机上的 hamsterd 请用单播 target = "10.0.2.2"。
 *   · 同机部署时广播不保证被本机收回（PROTOCOL §7.3），调用方应额外用
 *     target = "127.0.0.1" 扫一次；本 API 一次只发往一个 target。
 *   · timeoutMs 只覆盖 UDP 收发，操作系统的域名解析（getByName）没有独立超时；
 *     传入点分十进制 IP 可以完全避开 DNS。
 *   · 本函数会阻塞到 timeoutMs（除了 probeOnce 命中即返回），**不要在主线程调用**。
 *     它也不负责 §7.3 的 1s 广播节奏、3s 在线窗口与重连退避复位，那些属于应用层循环。
 */
package hamster

import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.SocketException
import java.net.SocketTimeoutException
import java.security.SecureRandom

/**
 * 一条通过校验的发现结果。
 *
 * @param ip UDP recvfrom 的源地址（载荷里没有 IP；这是唯一不可被载荷伪造的值）
 * @param id 服务端 instance_id
 * @param name 服务端显示名（缺失时为空串）
 * @param port 服务端 **TCP** 监听端口（客户端用它建立连接）
 * @param version 服务端版本串（缺失时为空串）
 */
data class DiscoveredDevice(
    val ip: String,
    val id: String,
    val name: String,
    val port: Int,
    val version: String
)

/**
 * 发现客户端：广播（或单播）探测 + 收集应答。
 *
 * 本 object 没有任何可变状态：每次 scan/probeOnce 都新建 SecureRandom 与 socket，
 * 因此可以被多线程同时调用，互不影响。
 */
object DiscoveryClient {

    /** 同一轮 scan 内两次探测的间隔（PROTOCOL §7.3 的 1s 节奏之内的快速补发）。 */
    private const val PROBE_INTERVAL_MS: Long = 200

    /** 单次 receive 的最长阻塞；用小值循环，才能既按时发第二轮、又按 deadline 收尾。 */
    private const val RECV_SLICE_MS: Long = 100

    /** 16 字节 nonce → 32 位十六进制（见 DISC_NONCE_HEX_LEN）。 */
    private const val NONCE_BYTES: Int = 16

    /** 本机 device_id 取 8 字节随机数 → 16 位十六进制，满足 isValidDiscoveryId。 */
    private const val MY_ID_BYTES: Int = 8

    private const val HEX_DIGITS: String = "0123456789abcdef"

    /**
     * 广播（或单播 [target]）探测，收集 [timeoutMs] 内的应答。
     *
     * 一次 scan 发两次探测（间隔约 200ms、各用不同 nonce），提高丢包下的命中率；
     * 收到任何一发的合法应答都算发现。应答按 [DiscoveredDevice.id] 去重，
     * 结果按 name、ip、id 排序后返回。
     *
     * **任何异常都不抛出**：空暗号、端口越界、域名解析失败、无网络权限、发送失败、
     * socket 创建失败……一律返回空列表（与 C 侧"校验失败当没收到"的静默语义一致）。
     *
     * @param secret 与服务端一致的连接口令（空串直接返回空列表，算不出 MAC）
     * @param timeoutMs 总收集窗口（毫秒，含两次探测）；<= 0 直接返回空列表
     * @param port 服务端 UDP 发现端口（默认 9110，必须与服务端一致）
     * @param target 广播地址或单播地址；默认 "255.255.255.255"
     *   （模拟器发现宿主机用 "10.0.2.2"，同机部署补扫 "127.0.0.1"）
     */
    fun scan(
        secret: String,
        timeoutMs: Int = 1500,
        port: Int = DISC_DEFAULT_PORT,
        target: String = "255.255.255.255",
    ): List<DiscoveredDevice> = runDiscovery(
        secret = secret,
        timeoutMs = timeoutMs,
        port = port,
        target = target,
        probeCount = 2,
        stopAtFirst = false
    )

    /**
     * 发一次探测，返回第一条通过校验的应答；超时或任何异常返回 null。
     *
     * 便利函数，供测试和 UI 的"连接测试"使用：只发 1 帧、命中即返回，
     * 不等待完整窗口（因此耗时通常远小于 [timeoutMs]）。
     */
    fun probeOnce(
        secret: String,
        target: String = "255.255.255.255",
        port: Int = DISC_DEFAULT_PORT,
        timeoutMs: Int = 1500,
    ): DiscoveredDevice? = runDiscovery(
        secret = secret,
        timeoutMs = timeoutMs,
        port = port,
        target = target,
        probeCount = 1,
        stopAtFirst = true
    ).firstOrNull()

    // ------------------------------------------------------------------ 内部实现

    /**
     * 一次完整扫描。所有局部状态都在本调用内，天然线程安全。
     *
     * 时间线（timeoutMs 足够大时）：
     *   t=0    发探测 #1（nonce1），随后按 RECV_SLICE_MS 循环 recvfrom
     *   t=200  发探测 #2（nonce2）
     *   t=...  继续收到 deadline，期间每个合法应答按 id 去重
     *   t=timeout 关闭 socket 并返回
     *
     * 两发探测共用同一个 myId（进应答 MAC 原文），但 nonce 必须不同；只有属于
     * 本次 scan 已发出的 nonce 的应答才会被接收，旧应答 / 外来的 nonce 一律丢弃。
     */
    private fun runDiscovery(
        secret: String,
        timeoutMs: Int,
        port: Int,
        target: String,
        probeCount: Int,
        stopAtFirst: Boolean,
    ): List<DiscoveredDevice> {
        if (secret.isEmpty()) return emptyList()
        if (timeoutMs <= 0) return emptyList()
        if (port !in 1..65535) return emptyList()
        if (target.isBlank()) return emptyList()

        return try {
            // 域名解析失败（UnknownHostException）、安全策略拒绝等都在这里被吞掉。
            val address = InetAddress.getByName(target)
            // 每次调用独立 RNG：不复用 nonce，也不与其它线程共享状态。
            val rng = SecureRandom()
            // 本机 device_id 必须能通过 isValidDiscoveryId，否则 parseReply 直接 null。
            val myId = randomHex(rng, MY_ID_BYTES)
            val deadline = System.nanoTime() + timeoutMs.toLong() * 1_000_000L

            val socket = DatagramSocket() // 临时端口：客户端不占 9110（PROTOCOL §7.0）
            socket.use { sock ->
                // 广播目标需要 SO_BROADCAST；单播 target 时开着也无害。
                // 某些受限环境会拒绝，此时单播仍可能成功，所以只忽略、不中止。
                try {
                    sock.broadcast = true
                } catch (_: SocketException) {
                    // 无 SO_BROADCAST 权限：若是广播目标，发送阶段会失败 → 返回空列表。
                }

                val myNonces = HashSet<String>()              // 本次 scan 已发出的 nonce
                val found = LinkedHashMap<String, DiscoveredDevice>() // id → 最新结果
                val buffer = ByteArray(DISC_FRAME_MAX + 1)    // +1：让 >512 的帧长度可见
                val packet = DatagramPacket(buffer, buffer.size)

                var attempted = 0                 // 已成功发送的探测数
                var sendFailed = false            // 发送失败后不再发，但继续收已有应答
                var nextProbeAt = System.nanoTime()

                while (true) {
                    val now = System.nanoTime()
                    if (now >= deadline) break

                    // ---- 发探测（第一发 t=0，第二发 t≈200ms，各用新 nonce） ----
                    if (!sendFailed && attempted < probeCount && now >= nextProbeAt) {
                        val nonce = randomHex(rng, NONCE_BYTES)
                        // buildProbe 的 require 属于编程错误；这里仍兜底成空结果。
                        val frame = try {
                            buildProbe(secret, myId, nonce)
                        } catch (_: IllegalArgumentException) {
                            null
                        }
                        if (frame == null) {
                            sendFailed = true
                        } else {
                            try {
                                sock.send(DatagramPacket(frame, frame.size, address, port))
                                myNonces.add(nonce)   // 只有真正发出的 nonce 才接受回显
                                attempted++
                                nextProbeAt = System.nanoTime() + PROBE_INTERVAL_MS * 1_000_000L
                            } catch (_: IOException) {
                                sendFailed = true     // 发送失败：不重试同一个 nonce
                            } catch (_: SecurityException) {
                                sendFailed = true     // 缺 INTERNET 权限等
                            }
                        }
                    }

                    // 一发都没发出去，继续等也不会有什么可收的。
                    if (sendFailed && myNonces.isEmpty()) break

                    // ---- 计算本次 receive 的阻塞时长（不超过 deadline，也不错过下一发） ----
                    val remainingNs = deadline - System.nanoTime()
                    if (remainingNs <= 0) break
                    var waitMs = minOf(RECV_SLICE_MS, maxOf(1L, remainingNs / 1_000_000L))
                    if (!sendFailed && attempted < probeCount) {
                        val untilNextMs = (nextProbeAt - System.nanoTime()) / 1_000_000L
                        if (untilNextMs in 0 until waitMs) waitMs = maxOf(1L, untilNextMs)
                    }
                    sock.soTimeout = waitMs.toInt()

                    // ---- 收一帧 ----
                    packet.setLength(buffer.size)
                    try {
                        sock.receive(packet)
                    } catch (_: SocketTimeoutException) {
                        continue
                    } catch (_: IOException) {
                        break // socket 被关闭 / 网络错误：返回已收集结果
                    }

                    // 513 字节缓冲：>512 的帧会以 513 长度到达并被 parseReply 拒绝；
                    // 更长的 UDP 报文被截断成 513，同样被拒绝。
                    val frame = packet.data.copyOfRange(
                        packet.offset, packet.offset + packet.length
                    )
                    // 对端签名不对、字段缺失、超长、NUL 注入……一律静默丢弃。
                    val peer = try {
                        parseReply(secret, myId, frame)
                    } catch (_: RuntimeException) {
                        null
                    } ?: continue

                    // 只接受本次 scan 自己发出的 nonce（本轮两发都算）。
                    // C 侧用 (源 IP, nonce) 的重放窗口拒绝旧探测；客户端这边就是这张集合。
                    if (peer.nonceHex !in myNonces) continue

                    // 源地址取 recvfrom，而不是载荷（§7.1：唯一无法伪造的值）。
                    val ip = packet.address?.hostAddress ?: continue
                    found[peer.id] = DiscoveredDevice(
                        ip = ip,
                        id = peer.id,
                        name = peer.name,
                        port = peer.port,
                        version = peer.version
                    )
                    if (stopAtFirst) break
                }

                if (stopAtFirst) {
                    found.values.firstOrNull()?.let { listOf(it) } ?: emptyList()
                } else {
                    // 去重后排序：name → ip → id（id 兜底，保证同 name/ip 时结果稳定）。
                    found.values.sortedWith(
                        compareBy<DiscoveredDevice>({ it.name }, { it.ip }, { it.id })
                    )
                }
            }
        } catch (_: Exception) {
            // 域名解析失败、socket 创建失败、权限缺失……按契约返回空列表，绝不外抛。
            emptyList()
        }
    }

    /** [n] 字节随机数的小写十六进制串（nonce 与 myId 都用它）。 */
    private fun randomHex(rng: SecureRandom, n: Int): String {
        val bytes = ByteArray(n)
        rng.nextBytes(bytes)
        val sb = StringBuilder(n * 2)
        for (b in bytes) {
            val v = b.toInt() and 0xFF
            sb.append(HEX_DIGITS[v ushr 4]).append(HEX_DIGITS[v and 0x0F])
        }
        return sb.toString()
    }
}

/**
 * 顶层便利入口，等价于 [DiscoveryClient.probeOnce]。
 *
 * 保留顶层形式是为了让"只想做一次连接测试"的调用方可以 `probeOnce(secret, "10.0.2.2")`，
 * 不必先写 object 名；两个入口行为、默认值完全一致。
 */
fun probeOnce(
    secret: String,
    target: String = "255.255.255.255",
    port: Int = DISC_DEFAULT_PORT,
    timeoutMs: Int = 1500,
): DiscoveredDevice? = DiscoveryClient.probeOnce(
    secret = secret,
    target = target,
    port = port,
    timeoutMs = timeoutMs
)
