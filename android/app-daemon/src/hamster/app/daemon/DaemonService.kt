/*
 * DaemonService.kt — 把 DaemonCore / DaemonServer 包成前台服务
 *
 * 职责：
 *   · 从 DaemonPrefs 取口令 / 端口 / 根目录，构造 DaemonCore + DaemonServer 并 start()；
 *   · 用 startForeground() 保持进程存活，通知里显示 "监听 0.0.0.0:PORT · 已连接 N"；
 *   · 每 5 秒刷新一次通知里的客户端数（DaemonServer.clientCount()）；
 *   · 停止/销毁时一定 stop() DaemonServer 并清掉前台状态。
 *
 * 口令策略：**口令为空或解不开时拒绝启动**，绝不使用默认口令。
 *   拒绝时仍会 startForeground 一次（否则用 startForegroundService 拉起的服务
 *   在 5 秒内不调用 startForeground 会被系统判定为 ANR/RemoteServiceException），
 *   然后再停掉自己，并留一条普通通知说明原因。
 *
 * 进程内静态标志的限制：isRunning 只是"本进程最后一次 start/stop 的结果"，
 * 进程被杀后标志丢失；真实状态以"服务是否在跑"为准（例如
 * ActivityManager.getRunningServices 或 dumpsys activity services）。
 * 界面上它只用来做展示和按钮态，不用于任何安全判断。
 *
 * 线程模型：DaemonServer.start()/stop() 假定是非阻塞的（内部自己起线程）；
 * 本服务不在这两个调用外面再包线程，否则 stop 与 start 的时序更难保证。
 * 如果同事的实现里 start() 是阻塞 accept 循环，需要改成内部起线程——
 * 这一点在联调时用 `adb shell dumpsys activity services` 验证。
 */
package hamster.app.daemon

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.util.Log
import hamster.DaemonCore
import hamster.DaemonServer
import hamster.DiscoveryResponder

class DaemonService : Service() {

    private val tickerHandler = Handler(Looper.getMainLooper())

    /** 每 5 秒把最新客户端数写回常驻通知。 */
    private val ticker = object : Runnable {
        override fun run() {
            if (!running) return
            updateNotification()
            tickerHandler.postDelayed(this, REFRESH_MS)
        }
    }

    override fun onCreate() {
        super.onCreate()
        ensureChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        ensureChannel()

        if (intent?.action == ACTION_STOP) {
            Log.i(TAG, "收到停止请求")
            shutdown()
            return START_NOT_STICKY
        }

        // ---- 口令为空：拒绝启动，不用默认口令 ----
        val codeword = DaemonPrefs.loadCodeword(this)
        if (codeword.isNullOrBlank()) {
            val why = "未设置口令（或 Keystore 无法解密），拒绝启动"
            // 先满足前台服务契约，再停掉；否则 startForegroundService 拉起的服务
            // 不调用 startForeground 会被系统判为超时。
            safeStartForeground(why)
            notifyProblem(
                "Hamster 守护未启动",
                "$why。请打开配置页设置至少 ${DaemonPrefs.MIN_CODEWORD_LEN} 位口令。",
            )
            Log.w(TAG, why)
            shutdown()
            return START_NOT_STICKY
        }

        val port = DaemonPrefs.port(this)
        val root = appPrivateRoot(this)
        if (!safeStartForeground("正在启动…")) {
            notifyProblem(
                "Hamster 守护启动失败",
                "系统拒绝进入前台服务状态（权限/后台限制），详见 logcat。",
            )
            shutdown()
            return START_NOT_STICKY
        }

        // 可能是"配置变更后重启"：先释放旧实例，避免端口被占。
        stopServer()

        return try {
            val core = DaemonCore(
                root = root.dir,
                serverName = SERVER_NAME,
                version = VERSION,
            )
            val srv = DaemonServer(
                core = core,
                port = port,
                host = "0.0.0.0",
                secrets = listOf(codeword),
            )
            srv.start()
            activeServer = srv
            running = true
            startDiscovery(
                codeword = codeword,
                tcpPort = port,
                serverId = DaemonPrefs.instanceId(this),
                name = discoveryName(),
            )
            Log.i(TAG, "守护服务已启动: 0.0.0.0:$port root=${root.dir.absolutePath}")
            scheduleTicker()
            updateNotification()
            START_STICKY
        } catch (e: Exception) {
            running = false
            activeServer = null
            Log.e(TAG, "启动失败: ${e.javaClass.name}: ${e.message}", e)
            notifyProblem(
                "Hamster 守护启动失败",
                "端口 $port 启动失败：${e.message ?: e.javaClass.simpleName}",
            )
            shutdown()
            START_NOT_STICKY
        }
    }

    override fun onDestroy() {
        Log.i(TAG, "onDestroy：释放 DaemonServer")
        running = false
        tickerHandler.removeCallbacksAndMessages(null)
        stopServer()
        try {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } catch (_: Exception) {
            // 从未 startForeground 过（例如启动即失败）时这里可能抛，忽略即可。
        }
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    /* ------------------------------------------------------------------ */
    /* 启停与状态                                                          */
    /* ------------------------------------------------------------------ */

    private fun scheduleTicker() {
        tickerHandler.removeCallbacks(ticker)
        tickerHandler.postDelayed(ticker, REFRESH_MS)
    }

    private fun stopServer() {
        stopDiscovery()
        val srv = activeServer ?: return
        activeServer = null
        try {
            srv.stop()
        } catch (e: Exception) {
            Log.w(TAG, "DaemonServer.stop() 失败: ${e.javaClass.simpleName}: ${e.message}")
        }
    }

    /** 设备列表里显示的名字：优先机型，其次 "Android"（长度按 §7 的帧上限留余量）。 */
    private fun discoveryName(): String {
        val model = (Build.MODEL ?: "").trim()
        return if (model.isEmpty()) "Android" else model.take(48)
    }

    /** 停服务：清 ticker、停 server、撤前台通知、stopSelf。幂等。 */
    private fun shutdown() {
        running = false
        tickerHandler.removeCallbacksAndMessages(null)
        stopServer()
        try {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } catch (_: Exception) {
        }
        stopSelf()
    }

    /* ------------------------------------------------------------------ */
    /* 通知                                                                */
    /* ------------------------------------------------------------------ */

    private fun ensureChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val nm = getSystemService(NotificationManager::class.java)
        if (nm.getNotificationChannel(CHANNEL_ID) != null) return
        val ch = NotificationChannel(
            CHANNEL_ID,
            "Hamster 守护服务",
            NotificationManager.IMPORTANCE_LOW,   // 常驻、不响不震
        )
        ch.description = "前台服务常驻通知：监听地址与已连接客户端数"
        ch.setShowBadge(false)
        ch.lockscreenVisibility = Notification.VISIBILITY_PUBLIC
        nm.createNotificationChannel(ch)
    }

    /**
     * startForeground 的兜底：缺权限/后台限制时抛异常不应把进程直接打死。
     * 返回 false 表示没能进入前台状态，调用方应立刻 shutdown。
     */
    private fun safeStartForeground(text: String): Boolean = try {
        startForeground(NOTIF_ID, buildNotification("Hamster 守护", text, ongoing = true))
        true
    } catch (e: Exception) {
        Log.e(TAG, "startForeground 失败: ${e.javaClass.simpleName}: ${e.message}", e)
        false
    }

    @Suppress("DEPRECATION")
    private fun buildNotification(title: String, text: String, ongoing: Boolean): Notification {
        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, ConfigActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            // API 24–25 没有渠道，用低优先级代替。
            Notification.Builder(this).setPriority(Notification.PRIORITY_LOW)
        }
        return builder
            .setContentTitle(title)
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setOngoing(ongoing)
            .setOnlyAlertOnce(true)
            .setShowWhen(false)
            .setContentIntent(open)
            .setCategory(Notification.CATEGORY_SERVICE)
            .build()
    }

    private fun updateNotification() {
        val srv = activeServer ?: return
        val clients = try {
            srv.clientCount()
        } catch (e: Exception) {
            Log.w(TAG, "clientCount() 失败: ${e.javaClass.simpleName}")
            0
        }
        val text = "监听 0.0.0.0:${srv.port} · 已连接 $clients"
        try {
            getSystemService(NotificationManager::class.java)
                .notify(NOTIF_ID, buildNotification("Hamster 守护", text, ongoing = true))
        } catch (e: Exception) {
            // 通知权限被拒时这里可能失败；服务本身必须继续跑。
            Log.w(TAG, "更新常驻通知失败: ${e.javaClass.simpleName}")
        }
    }

    /** 失败/拒绝启动的说明通知；用独立 id，stopSelf 撤掉前台通知后它仍留着。 */
    private fun notifyProblem(title: String, text: String) {
        try {
            getSystemService(NotificationManager::class.java)
                .notify(PROBLEM_NOTIF_ID, buildNotification(title, text, ongoing = false))
        } catch (e: Exception) {
            Log.w(TAG, "发送错误通知失败: ${e.javaClass.simpleName}")
        }
    }

    companion object {
        const val VERSION = "0.0.9"

        /** 显示在 §7 发现里的服务端名字；拿不到机型时退回 Android。 */
        val SERVER_NAME: String = Build.MODEL?.takeIf { it.isNotBlank() } ?: "Android"

        const val ACTION_START = "hamster.app.daemon.action.START"
        const val ACTION_STOP = "hamster.app.daemon.action.STOP"

        private const val CHANNEL_ID = "hamster_daemon"
        private const val NOTIF_ID = 9101
        private const val PROBLEM_NOTIF_ID = 9102
        private const val REFRESH_MS = 5_000L
        private const val TAG = "HamsterDaemon"

        /** PROTOCOL §7 默认发现端口。 */
        private const val DISCOVERY_PORT = 9110

        /**
         * 进程内状态标志。限制：进程被杀后丢失；真实状态以系统服务状态为准。
         * 只用于界面展示/按钮态，不做安全判断。
         */
        @Volatile
        private var running = false

        @Volatile
        private var activeServer: DaemonServer? = null

        /** §7 发现应答器：与 TCP 服务同生共死。 */
        @Volatile
        private var activeDiscovery: DiscoveryResponder? = null

        /**
         * 起应答器。失败不影响 TCP 服务（发现只是"锦上添花"）：
         * 端口被占、权限受限都只记日志。
         */
        private fun startDiscovery(codeword: String, tcpPort: Int, serverId: String, name: String) {
            stopDiscovery()
            val r = DiscoveryResponder(
                port = DISCOVERY_PORT,
                codeword = codeword,
                serverId = serverId,
                serverName = name,
                tcpPort = tcpPort,
                version = VERSION,
            )
            try {
                r.start()
                activeDiscovery = r
                Log.i(TAG, "发现应答器已启动: UDP :$DISCOVERY_PORT（应答名=$name, TCP=$tcpPort）")
            } catch (e: Exception) {
                Log.w(TAG, "发现应答器启动失败: ${e.javaClass.simpleName}: ${e.message}")
            }
        }

        private fun stopDiscovery() {
            val r = activeDiscovery ?: return
            activeDiscovery = null
            try {
                r.stop()
            } catch (e: Exception) {
                Log.w(TAG, "发现应答器停止失败: ${e.javaClass.simpleName}: ${e.message}")
            }
        }

        /** 应答器收到的合法探测数（诊断用）。 */
        fun discoveryProbes(): Long = try {
            activeDiscovery?.acceptedProbes ?: 0L
        } catch (_: Exception) {
            0L
        }

        /** 本进程最后一次 start 是否成功；见上方限制说明。 */
        val isRunning: Boolean get() = running

        /** 当前客户端数；服务没跑时返回 0。 */
        fun clientCount(): Int = try {
            activeServer?.clientCount() ?: 0
        } catch (_: Exception) {
            0
        }

        /** 当前实际监听端口；服务没跑时返回 -1。 */
        fun runningPort(): Int = activeServer?.port ?: -1

        /**
         * 启动前台服务。返回 false 表示系统直接拒绝了 start（例如后台启动限制、
         * 组件被禁用）；返回 true 只代表"请求已交给系统"，服务是否真的起来
         * 由 isRunning / 通知 / logcat 判断。
         */
        fun start(ctx: Context): Boolean {
            val i = Intent(ctx, DaemonService::class.java).setAction(ACTION_START)
            return try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    ctx.startForegroundService(i)
                } else {
                    ctx.startService(i)
                }
                true
            } catch (e: Exception) {
                Log.e(TAG, "start 失败: ${e.javaClass.simpleName}: ${e.message}")
                false
            }
        }

        /** 请求停止；真正的清理在 onDestroy 里完成。 */
        fun stop(ctx: Context) {
            running = false
            try {
                ctx.stopService(Intent(ctx, DaemonService::class.java))
            } catch (e: Exception) {
                Log.w(TAG, "stop 失败: ${e.javaClass.simpleName}: ${e.message}")
            }
        }
    }
}
