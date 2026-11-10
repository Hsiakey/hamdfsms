/*
 * DaemonServer.kt — Hamster 守护端的 TCP 监听层（纯 JVM，不引用任何 Android API）
 *
 * 职责只有四件事：
 *   1. 起一个后台 accept 线程，把连接交给独立的工作线程；
 *   2. 每条连接**先做 §8.2 握手**（SecureServer.handshake），成功后才把
 *      "已解密的明文流"交给 DaemonCore.serve()；握手失败直接关连接，一个字节都不回
 *      （§8.2/§8.4：不做明文降级，不给"口令对不对"的预言机）；
 *   3. 维护活动连接集合，stop() 时全部关掉，让阻塞在 read 上的线程立刻退出；
 *   4. 把活动客户端数同步给 DaemonCore（info/health/stats 用）。
 *
 * 线程全部是 daemon 线程，stop() 还会 join 它们；即使某个环节卡住也不会拖住 JVM 退出。
 *
 * 与 SecureServer 的接口（Secure.kt，由同事实现，已落地）：
 *
 *     object SecureServer {
 *         fun handshake(
 *             rawIn: InputStream,
 *             rawOut: OutputStream,
 *             secrets: List<String>,      // 第 0 个是 codeword，其余是 api_key
 *             timeoutMs: Int = 8000,
 *             random: ((ByteArray) -> Unit)? = null,
 *         ): SecureServerSession?         // 失败/超时返回 null，且不向对端发任何字节
 *     }
 *
 * 注意：challenge 里 advertised 的 server/version 由 SecureServer 固定为
 * "hamsterd"/"0.0.9"（与 C 侧 sec_handshake 逐字节一致），**不**取 core.serverName/
 * core.version —— 后者只出现在 info/health 的响应里。这样 C/JS 客户端不会因为
 * 服务端名字不同而拒绝连接。
 */
package hamster

import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

class DaemonServer(
    val core: DaemonCore,
    val port: Int,
    val host: String = "0.0.0.0",
    /** 候选口令：第一个是 codeword，其余是 api_key（服务端逐把试 proof_C） */
    val secrets: List<String>,
) {

    companion object {
        /** 握手阶段（明文三段）的读超时；握手完成后置 0，长连接由业务层决定何时断。 */
        const val HANDSHAKE_TIMEOUT_MS: Int = 30_000

        /** accept backlog。 */
        private const val BACKLOG = 64
    }

    init {
        require(port in 1..65535) { "端口越界（1–65535）：$port" }
        require(secrets.isNotEmpty()) { "secrets 不能为空（至少要有 codeword）" }
    }

    private val running = AtomicBoolean(false)
    private val clients = AtomicInteger(0)
    private val sockets: MutableSet<Socket> = ConcurrentHashMap.newKeySet()
    private val workers: MutableSet<Thread> = ConcurrentHashMap.newKeySet()

    @Volatile
    private var server: ServerSocket? = null

    @Volatile
    private var acceptThread: Thread? = null

    val isRunning: Boolean
        get() = running.get()

    fun clientCount(): Int = clients.get()

    /**
     * 起后台 accept 线程并立刻返回。
     * 重复调用抛 IllegalStateException（不会起第二个监听）。
     */
    fun start() {
        if (!running.compareAndSet(false, true)) {
            throw IllegalStateException("DaemonServer 已在运行（$host:$port）")
        }
        try {
            val ss = ServerSocket()
            try {
                /* 让 stop() 之后能立刻重新 bind 同一端口（测试要反复起停）。
                   注意这与 C 侧的 SO_EXCLUSIVEADDRUSE 不同：C 是长期驻留进程，防端口劫持；
                   这里只用于测试/嵌入，单实例约束由 running 标志保证。 */
                ss.reuseAddress = true
                ss.bind(InetSocketAddress(InetAddress.getByName(host), port), BACKLOG)
            } catch (e: Exception) {
                try {
                    ss.close()
                } catch (_: IOException) {
                }
                throw e
            }
            server = ss
            val t = Thread({ acceptLoop(ss) }, "hamsterd-accept-$port")
            t.isDaemon = true
            acceptThread = t
            t.start()
        } catch (e: Exception) {
            running.set(false)
            server = null
            throw e
        }
    }

    /**
     * 停止监听并关闭所有活动连接。幂等，不抛异常。
     * 返回后端口已释放（listen socket 已 close），accept/工作线程最多再被 join 2s。
     */
    fun stop() {
        if (!running.getAndSet(false)) return

        val ss = server
        server = null
        try {
            ss?.close()
        } catch (_: IOException) {
        }

        /* 先关连接：阻塞在 read 上的工作线程会立刻以 IOException 结束 */
        for (s in sockets.toList()) {
            try {
                s.close()
            } catch (_: IOException) {
            }
        }
        sockets.clear()

        val at = acceptThread
        acceptThread = null
        joinQuietly(at, 2000)

        val deadline = System.currentTimeMillis() + 2000
        for (t in workers.toList()) {
            val left = deadline - System.currentTimeMillis()
            if (left <= 0) break
            joinQuietly(t, left)
        }
        workers.clear()

        clients.set(0)
        core.setClientCount(0)
    }

    // ------------------------------------------------------------------ 内部

    private fun acceptLoop(ss: ServerSocket) {
        while (running.get() && !ss.isClosed) {
            val sock: Socket = try {
                ss.accept()
            } catch (e: IOException) {
                /* stop() 关掉 listen socket 会让 accept 抛异常：正常退出路径 */
                if (!running.get() || ss.isClosed) break
                try {
                    Thread.sleep(50)
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                    break
                }
                continue
            }

            if (!running.get()) {
                closeQuietly(sock)
                break
            }

            sockets.add(sock)
            val n = clients.incrementAndGet()
            core.setClientCount(n)

            val t = Thread({ handleConnection(sock) }, "hamsterd-conn-$port-${sock.port}")
            t.isDaemon = true
            workers.add(t)
            t.start()
        }
    }

    private fun handleConnection(sock: Socket) {
        try {
            sock.tcpNoDelay = true
            /* SecureServer 自己有一个 deadline 线程；这里再设一层 socket 读超时作为兜底，
               握手成功后立刻清掉（长连接不能有读超时）。 */
            sock.soTimeout = HANDSHAKE_TIMEOUT_MS + 5_000

            val session = SecureServer.handshake(
                rawIn = sock.getInputStream(),
                rawOut = sock.getOutputStream(),
                secrets = secrets,
                timeoutMs = HANDSHAKE_TIMEOUT_MS,
            )

            /* 失败一律静默关闭：不解释原因（§8.2），也不做明文降级（§8.5） */
            if (session == null) return

            sock.soTimeout = 0

            core.serve(session.input, session.output)
        } catch (e: SecureException) {
            /* 握手失败/记录层损坏：静默关闭，不回任何字节（§8.2/§8.3） */
        } catch (e: Exception) {
            /* 业务层异常/连接断开：同样静默关闭 */
        } catch (t: Throwable) {
            /* 连 java.io.IOError 这类 Error 也不能让它逃出连接线程 */
        } finally {
            sockets.remove(sock)
            closeQuietly(sock)
            val n = clients.decrementAndGet().coerceAtLeast(0)
            core.setClientCount(n)
            workers.remove(Thread.currentThread())
        }
    }

    private fun joinQuietly(t: Thread?, ms: Long) {
        if (t == null || ms <= 0) return
        try {
            t.join(ms)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
    }

    private fun closeQuietly(s: Socket) {
        try {
            s.close()
        } catch (_: IOException) {
        }
    }
}
