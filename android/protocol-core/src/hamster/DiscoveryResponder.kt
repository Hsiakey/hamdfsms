/*
 * DiscoveryResponder.kt — §7 局域网发现的服务端应答器（UDP）
 *
 * 语义与 C 侧 `hd_disc.c` 完全一致（这是安全要求，不是随便对一对）：
 *   · 只在对上暗号（probe MAC 校验通过）时才**单播**回一帧应答；
 *   · 任何不合法（错口令 / 篡改 / 超长 / 非 UTF-8 / 自己发的探测）都**静默丢弃**，
 *     一个字节都不回 —— 让扫描者无法区分"没有设备"和"有设备但口令不对"；
 *   · 应答里的服务端 IP 不在载荷内，必须靠 UDP 源地址（这里就是 sendto 的目标）；
 *   · 限速（20 帧/秒，突发 40）与重放窗口（同一 (源 IP, nonce) 120 秒内只处理一次）
 *     照抄 C 侧，避免被打成放大器或被当成重放入口。
 *
 * 只依赖 JDK（java.net / java.util），可以在桌面 JVM 上直接测。
 */
package hamster

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.util.ArrayDeque

/**
 * UDP 发现应答器。
 *
 * @param port 监听端口（PROTOCOL §7 默认 9110）
 * @param codeword 服务端口令；为空则**永不回应**（等价于关闭发现）
 * @param serverId 本机 instance_id（16 位 hex，[isValidDiscoveryId] 能过）
 * @param serverName 显示名（出现在客户端设备列表里，建议用机型名）
 * @param tcpPort 应答里告诉客户端的 **TCP** 端口（真正连的是它）
 * @param version 版本串
 */
class DiscoveryResponder(
    private val port: Int = DISC_DEFAULT_PORT,
    private val codeword: String,
    private val serverId: String,
    private val serverName: String,
    private val tcpPort: Int,
    private val version: String,
) {

    @Volatile private var running = false
    private var thread: Thread? = null
    @Volatile private var socket: DatagramSocket? = null

    /** 收到的合法探测数（仅统计，不含被丢弃的）。 */
    @Volatile var acceptedProbes: Long = 0L
        private set

    /** 发出的应答数。 */
    @Volatile var sentReplies: Long = 0L
        private set

    /** 因限速/重放/校验失败被丢弃的帧数。 */
    @Volatile var droppedFrames: Long = 0L
        private set

    val isRunning: Boolean get() = running

    /** 实际绑定的端口（构造时传 0 表示由系统分配，测试用）。未启动/已停止时为 -1。 */
    val boundPort: Int get() = socket?.localPort ?: -1

    fun start() {
        if (running) return
        if (codeword.isEmpty() || !isValidDiscoveryId(serverId)) return
        running = true
        thread = Thread({ loop() }, "hamster-discovery").apply {
            isDaemon = true
            start()
        }
    }

    fun stop() {
        running = false
        try {
            socket?.close()
        } catch (_: Exception) {
        }
        socket = null
        thread?.interrupt()
        thread = null
    }

    /* ------------------------------------------------------------------ */

    private fun loop() {
        // 注意：不能写成 `apply { bind(InetSocketAddress(port)) }` ——
        // apply 里的 `port` 会解析成 DatagramSocket.getPort()（远端端口，未连接时是 -1），
        // 而不是构造参数。这个坑第一次就踩到了，表现为"永远绑不上端口"。
        val bindPort = port
        val sock = try {
            DatagramSocket(null).apply {
                reuseAddress = true
                broadcast = true
                bind(InetSocketAddress(bindPort))
                soTimeout = 500
            }
        } catch (_: Exception) {
            running = false
            return
        }
        socket = sock
        val buf = ByteArray(DISC_FRAME_MAX + 1)
        val bucket = TokenBucket(ratePerSec = 20.0, burst = 40.0)
        val replay = ReplayWindow(windowMs = 120_000L, maxEntries = 512)

        try {
            while (running) {
                val pkt = DatagramPacket(buf, buf.size)
                try {
                    sock.receive(pkt)
                } catch (_: java.net.SocketTimeoutException) {
                    continue
                } catch (_: Exception) {
                    if (!running) break
                    continue
                }
                val len = pkt.length
                // 超过 512 字节的帧直接丢（不解析、不回）
                if (len <= 0 || len > DISC_FRAME_MAX) {
                    droppedFrames++
                    continue
                }
                val frame = pkt.data.copyOfRange(pkt.offset, pkt.offset + len)
                val src = pkt.address.hostAddress ?: continue
                val probe = parseProbe(codeword, serverId, frame) ?: run {
                    droppedFrames++
                    null
                } ?: continue

                if (!bucket.tryTake()) {
                    droppedFrames++
                    continue
                }
                if (!replay.accept(src, probe.nonceHex)) {
                    droppedFrames++
                    continue
                }

                val reply = try {
                    buildReply(codeword, serverId, probe.clientId, probe.nonceHex, serverName, tcpPort, version)
                } catch (_: IllegalArgumentException) {
                    droppedFrames++
                    continue
                }
                acceptedProbes++
                try {
                    sock.send(DatagramPacket(reply, reply.size, pkt.address, pkt.port))
                    sentReplies++
                } catch (_: Exception) {
                    // 发送失败就当没发生：UDP 本来就不保证送达
                }
            }
        } finally {
            try {
                sock.close()
            } catch (_: Exception) {
            }
            if (socket === sock) socket = null
            running = false
        }
    }

    /** 简易令牌桶：20 帧/秒、突发 40，和 C 侧 `hd_disc.c` 的限速一致。 */
    private class TokenBucket(private val ratePerSec: Double, burst: Double) {
        private val capacity = burst
        private var tokens = burst
        private var last = System.nanoTime()

        fun tryTake(): Boolean {
            val now = System.nanoTime()
            val add = (now - last) / 1_000_000_000.0 * ratePerSec
            last = now
            tokens = minOf(capacity, tokens + add)
            if (tokens < 1.0) return false
            tokens -= 1.0
            return true
        }
    }

    /**
     * 重放窗口：同一 (源 IP, nonce) 在窗口期内只处理一次。
     *
     * 客户端每轮探测都用新 nonce（[DiscoveryClient.scan] 的两发探测 nonce 不同），
     * 所以正常使用不会撞上；窗口期内重复出现的同 nonce 帧只可能是重放。
     */
    private class ReplayWindow(private val windowMs: Long, private val maxEntries: Int) {
        private val order = ArrayDeque<Pair<String, Long>>()
        private val seen = HashSet<String>()

        @Synchronized
        fun accept(src: String, nonceHex: String): Boolean {
            val now = System.currentTimeMillis()
            while (order.isNotEmpty() && now - order.peekFirst().second > windowMs) {
                seen.remove(order.removeFirst().first)
            }
            val key = src + "|" + nonceHex
            if (key in seen) return false
            if (order.size >= maxEntries) {
                val old = order.removeFirst()
                seen.remove(old.first)
            }
            seen.add(key)
            order.addLast(key to now)
            return true
        }
    }
}
