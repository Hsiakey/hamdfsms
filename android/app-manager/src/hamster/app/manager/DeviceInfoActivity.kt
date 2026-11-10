/*
 * DeviceInfoActivity.kt — 设备信息页：只读展示 info / health / stats / verify
 *
 * 连接语义与 SearchActivity（以及 FilesActivity）一致：
 *   · HamsterApi 单连接、一问一答，本页所有网络动作串行执行（busy）；
 *   · 传输层错误把 api 置空并自动重连；业务错误只显示；
 *   · 前台每 5 s 用 info() 保活，onPause 停 ping，onResume 断线则重连。
 *
 * info / health / stats / verify(false) 四联查询放在同一次后台任务里顺序执行，
 * 一次刷新只占用连接一小段时间，界面也只渲染一次快照，避免四个回调互相覆盖状态。
 */
package hamster.app.manager

import android.app.Activity
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ListView
import android.widget.ProgressBar
import android.widget.TextView
import hamster.DeviceStats
import hamster.HamsterApi
import hamster.HamsterApiException
import hamster.HealthInfo
import hamster.SecureException
import hamster.ServerInfo
import hamster.VerifyReport
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class DeviceInfoActivity : Activity() {

    private var api: HamsterApi? = null
    @Volatile private var busy = false
    @Volatile private var connecting = false
    @Volatile private var stopping = false
    @Volatile private var resumed = false

    private var host = ""
    private var tcpPort = 9100
    private var secret = ""
    private var label = ""

    private var keepalive: Thread? = null

    private lateinit var header: TextView
    private lateinit var status: TextView
    private lateinit var bar: ProgressBar
    private lateinit var list: ListView
    private lateinit var adapter: TwoLineAdapter

    private lateinit var btnRefresh: Button
    private lateinit var btnVerify: Button
    private lateinit var btnRescan: Button
    private lateinit var btnSync: Button

    private val clock = SimpleDateFormat("HH:mm:ss", Locale.getDefault())

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        host = intent.getStringExtra(EXTRA_HOST) ?: ""
        tcpPort = intent.getIntExtra(EXTRA_PORT, 9100)
        secret = intent.getStringExtra(EXTRA_SECRET) ?: ""
        label = intent.getStringExtra(EXTRA_LABEL) ?: host
        title = "Hamster · 设备信息"

        val root = body()
        header = label("设备信息 · $label", 18f, bold = true)
        root.addView(header)
        root.addView(spacer(6))
        root.addView(hint("只读信息：info / health / stats / verify。数值来自服务端索引。"))

        status = hint("正在连接…")
        root.addView(spacer(8))
        root.addView(status)

        adapter = TwoLineAdapter(this)
        adapter.submit(listOf("连接" to "等待设备信息…"))
        list = ListView(this).apply {
            this.adapter = this@DeviceInfoActivity.adapter
            dividerHeight = dp(1)
            setBackgroundColor(0xFF23232A.toInt())
        }
        root.addView(list, LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f))

        bar = ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal).apply {
            max = 100
            progress = 0
            isIndeterminate = true
            visibility = ProgressBar.GONE
        }
        root.addView(
            bar,
            LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT),
        )
        root.addView(spacer(8))

        // 四个动作分两行，避免小屏上按钮文字被挤成“…”。
        val row1 = row()
        btnRefresh = Button(this).apply {
            text = "刷新"
            setOnClickListener { refreshAll() }
        }
        btnVerify = Button(this).apply {
            text = "立即校验"
            setOnClickListener { runVerifyNow() }
        }
        row1.addView(btnRefresh, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        row1.addView(btnVerify, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        root.addView(row1)

        val row2 = row()
        btnRescan = Button(this).apply {
            text = "重扫"
            setOnClickListener { runRescan() }
        }
        btnSync = Button(this).apply {
            text = "同步索引"
            setOnClickListener { runSync() }
        }
        row2.addView(btnRescan, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        row2.addView(btnSync, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        root.addView(row2)

        setContentView(root)
        connect()
        startKeepalive()
    }

    /* ------------------------------------------------------------------ 刷新 */

    /**
     * 重取四项信息。[notice] 用在动作完成后的自动刷新上，
     * 让“校验完成/已请求重扫”这类结果不会被刷新进度覆盖掉。
     */
    private fun refreshAll(notice: String? = null) {
        if (stopping) return
        val a = api
        if (a == null) {
            status.text = if (connecting) {
                "正在连接，连上后再刷新…"
            } else {
                "连接已断开，正在重连后刷新…"
            }
            if (!connecting) connect()
            return
        }
        if (busy) return

        busy = true
        setButtonsEnabled(false)
        btnRefresh.text = "执行中…"
        showIndeterminate(notice ?: "正在读取 info / health / stats / verify…")
        background(
            work = {
                Snapshot(
                    info = a.info(),
                    health = a.health(),
                    stats = a.stats(),
                    verify = a.verify(false),
                )
            },
            done = { snap ->
                busy = false
                btnRefresh.text = "刷新"
                setButtonsEnabled(true)
                hideBar()
                render(snap)
                val prefix = if (notice != null) "$notice · " else ""
                status.text = "${prefix}已更新 ${clock.format(Date())}"
            },
            failed = { e -> onActionFailed(e, "刷新") },
        )
    }

    /* ------------------------------------------------------------------ 动作 */

    private fun runVerifyNow() {
        val a = requireApi("校验") ?: return
        if (busy) return
        busy = true
        setButtonsEnabled(false)
        btnVerify.text = "执行中…"
        showIndeterminate("正在执行校验，可能需要一段时间…")
        background(
            work = { a.verify(runNow = true) },
            done = { r ->
                busy = false
                btnVerify.text = "立即校验"
                setButtonsEnabled(true)
                hideBar()
                val notice = "校验完成：已校验 ${r.verifiedFiles} 个 · 损坏 ${r.corruptCount} · 缺失 ${r.missingCount}"
                refreshAll(notice)
            },
            failed = { e -> onActionFailed(e, "校验") },
        )
    }

    private fun runRescan() {
        val a = requireApi("重扫") ?: return
        if (busy) return
        busy = true
        setButtonsEnabled(false)
        btnRescan.text = "执行中…"
        showIndeterminate("正在请求服务端重扫索引…")
        background(
            work = { a.rescan() },
            done = { ok ->
                busy = false
                btnRescan.text = "重扫"
                setButtonsEnabled(true)
                hideBar()
                val notice = if (ok) "已请求重扫，索引更新中" else "服务端未接受重扫请求"
                refreshAll(notice)
            },
            failed = { e -> onActionFailed(e, "重扫") },
        )
    }

    private fun runSync() {
        val a = requireApi("同步") ?: return
        if (busy) return
        busy = true
        setButtonsEnabled(false)
        btnSync.text = "执行中…"
        showIndeterminate("正在请求服务端同步索引…")
        background(
            work = { a.sync() },
            done = { ok ->
                busy = false
                btnSync.text = "同步索引"
                setButtonsEnabled(true)
                hideBar()
                val notice = if (ok) "已请求同步索引" else "服务端未接受同步请求"
                refreshAll(notice)
            },
            failed = { e -> onActionFailed(e, "同步") },
        )
    }

    private fun requireApi(what: String): HamsterApi? {
        if (busy) return null
        val a = api
        if (a == null) {
            status.text = if (connecting) {
                "正在连接，连上后再$what…"
            } else {
                "连接已断开，正在重连后$what…"
            }
            if (!connecting) connect()
        }
        return a
    }

    /* ------------------------------------------------------------------ 连接 / 保活 */

    private fun connect() {
        if (connecting || stopping) return
        connecting = true
        header.text = "设备信息 · $label · 连接中…"
        showIndeterminate("正在连接…")
        status.text = "正在与 $host:$tcpPort 做 §8 握手…"
        background(
            work = { HamsterApi.connect(host, tcpPort, secret, androidDeviceIdOf()) },
            done = { a ->
                connecting = false
                api = a
                hideBar()
                header.text = "设备信息 · ${a.peerName.ifEmpty { label }} · v${a.peerVersion}"
                // 保活线程在一次失败后会退出；重连成功后把它补回来。
                if (keepalive?.isAlive != true) startKeepalive()
                refreshAll()
            },
            failed = { e ->
                connecting = false
                api = null
                busy = false
                hideBar()
                setButtonsEnabled(true)
                status.text = "连接失败：${e.message}"
            },
        )
    }

    /** 每 5 s 一次 info()：轻量、免认证、同时顺便刷新 monitor_path 缓存。 */
    private fun startKeepalive() {
        keepalive = Thread {
            while (!stopping) {
                try {
                    Thread.sleep(KEEPALIVE_MS)
                } catch (_: InterruptedException) {
                    return@Thread
                }
                if (stopping || busy || !resumed) continue
                val a = api ?: continue
                try {
                    a.info()
                } catch (e: Exception) {
                    if (stopping) return@Thread
                    runOnUiThread { onKeepaliveLost(e) }
                    return@Thread
                }
            }
        }.apply {
            isDaemon = true
            name = "hamster-deviceinfo-keepalive"
            start()
        }
    }

    private fun onKeepaliveLost(e: Exception) {
        if (stopping || busy) return
        try {
            api?.close()
        } catch (_: Exception) {
        }
        api = null
        status.text = "连接已断开（${e.message}），正在重连…"
        connect()
    }

    override fun onResume() {
        super.onResume()
        resumed = true
        if (api == null && !connecting && !busy && !stopping) connect()
    }

    override fun onPause() {
        resumed = false
        super.onPause()
    }

    override fun onDestroy() {
        stopping = true
        keepalive?.interrupt()
        keepalive = null
        try {
            api?.close()
        } catch (_: Exception) {
        }
        api = null
        super.onDestroy()
    }

    /* ------------------------------------------------------------------ 渲染 */

    private fun render(s: Snapshot) {
        val rows = ArrayList<Pair<String, String>>()
        val info = s.info
        rows.add("服务器" to "server：${v(info.server)}")
        rows.add("版本" to "version：${v(info.version)}")
        rows.add("认证" to "auth_required：${if (info.authRequired) "需要口令（握手时已通过）" else "不需要"}")
        rows.add("监控目录" to "monitor_path：${v(info.monitorPath)}")
        rows.add("心跳" to "heartbeat：${info.heartbeatSec} s")
        rows.add("运行时长" to "uptime：${duration(info.uptimeMs)}（${info.uptimeMs} ms）")
        rows.add("客户端" to "clients：${info.clients}")
        rows.add("对等节点" to "peers：${info.peers}")
        rows.add(
            "能力" to "features：" + if (info.features.isEmpty()) {
                "（无）"
            } else {
                info.features.joinToString(", ")
            },
        )

        val health = s.health
        rows.add("健康状态" to "status：${v(health.status)}")
        rows.add("健康版本" to "version：${v(health.version)}")
        rows.add("健康运行时长" to "uptime_ms：${health.uptimeMs}（${duration(health.uptimeMs)}）")
        rows.add("健康客户端" to "clients：${health.clients}")
        rows.add("健康认证" to "auth_required：${if (health.authRequired) "是" else "否"}")
        rows.add("健康监控目录" to "monitor_path：${v(health.monitorPath)}")

        val stats = s.stats
        rows.add("文件总数" to "total_files：${stats.fileCount}")
        rows.add("总大小" to "total_size：${human(stats.totalBytes)}（${stats.totalBytes} B）")
        // 契约里的 DeviceStats 没有 file_type_count；显式留一行，不伪造数据。
        rows.add("文件类型数" to "file_type_count：—（当前 HamsterApi.DeviceStats 未提供）")
        rows.add("索引设备" to "deviceName：${v(stats.deviceName)}")
        rows.add("索引版本" to "version：${v(stats.version)}")
        rows.add("索引运行时长" to "uptime：${durationSec(stats.uptimeSec)}（${stats.uptimeSec} s）")

        val verify = s.verify
        rows.add("已校验文件" to "verified_files：${verify.verifiedFiles}")
        rows.add("校验次数" to "verify_count：${verify.verifyCount}")
        rows.add("扫描次数" to "scan_count：${verify.scanCount}")
        rows.add("扫描间隔" to "scan_interval：${verify.scanInterval} s")
        rows.add("损坏文件" to "corrupt_count：${verify.corruptCount}")
        rows.add("缺失文件" to "missing_count：${verify.missingCount}")
        rows.add("上次校验" to "last_verify：${v(verify.lastVerify)}")
        rows.add("上次扫描" to "last_scan：${v(verify.lastScan)}")
        rows.add("上次耗时" to "last_duration_ms：${verify.lastDurationMs}（${duration(verify.lastDurationMs)}）")

        adapter.submit(rows)
    }

    /* ------------------------------------------------------------------ 错误 / 进度 */

    private fun onActionFailed(e: Exception, what: String) {
        busy = false
        hideBar()
        setButtonsEnabled(true)
        btnRefresh.text = "刷新"
        btnVerify.text = "立即校验"
        btnRescan.text = "重扫"
        btnSync.text = "同步索引"

        val code = errorCode(e)
        if (code in TRANSPORT_CODES) {
            try {
                api?.close()
            } catch (_: Exception) {
            }
            api = null
            status.text = "$what 失败：连接已断开（$code），将自动重连…"
            connect()
        } else {
            status.text = "$what 失败：${e.message}"
        }
    }

    private fun errorCode(e: Exception): String = when (e) {
        is HamsterApiException -> e.code
        is SecureException -> e.code
        else -> ""
    }

    private fun setButtonsEnabled(enabled: Boolean) {
        btnRefresh.isEnabled = enabled
        btnVerify.isEnabled = enabled
        btnRescan.isEnabled = enabled
        btnSync.isEnabled = enabled
    }

    private fun showIndeterminate(msg: String) {
        status.text = msg
        bar.isIndeterminate = true
        bar.progress = 0
        bar.visibility = View.VISIBLE
    }

    private fun hideBar() {
        bar.visibility = View.GONE
    }

    /* ------------------------------------------------------------------ 小工具 */

    private fun androidDeviceIdOf(): String {
        val id = try {
            android.provider.Settings.Secure.getString(
                contentResolver, android.provider.Settings.Secure.ANDROID_ID,
            )
        } catch (_: Exception) {
            null
        }
        return if (!id.isNullOrBlank()) id else "android-manager-0001"
    }

    private fun v(s: String): String = if (s.isBlank()) "—" else s

    private fun human(n: Long): String = when {
        n < 1024 -> "$n B"
        n < 1024 * 1024 -> String.format(Locale.US, "%.1f KB", n / 1024.0)
        n < 1024L * 1024 * 1024 -> String.format(Locale.US, "%.1f MB", n / 1048576.0)
        else -> String.format(Locale.US, "%.2f GB", n / 1073741824.0)
    }

    private fun duration(ms: Long): String {
        if (ms <= 0L) return "0 秒"
        val totalSec = ms / 1000L
        val days = totalSec / 86400L
        val hours = (totalSec % 86400L) / 3600L
        val minutes = (totalSec % 3600L) / 60L
        val seconds = totalSec % 60L
        return when {
            days > 0L -> "$days 天 $hours 小时"
            hours > 0L -> "$hours 小时 $minutes 分"
            minutes > 0L -> "$minutes 分 $seconds 秒"
            else -> "$seconds 秒"
        }
    }

    private fun durationSec(sec: Long): String = duration(sec * 1000L)

    private data class Snapshot(
        val info: ServerInfo,
        val health: HealthInfo,
        val stats: DeviceStats,
        val verify: VerifyReport,
    )

    companion object {
        const val EXTRA_HOST = "host"
        const val EXTRA_PORT = "port"
        const val EXTRA_SECRET = "secret"
        const val EXTRA_LABEL = "label"

        /** 保活节奏：远小于实测的空闲回收窗口（约 20 s），又不至于太吵。 */
        private const val KEEPALIVE_MS = 5000L

        /** 这些错误码意味着“连接没了”，重连才有意义。 */
        private val TRANSPORT_CODES = setOf(
            "io_error", "socket_closed", "timeout", "connect_failed", "not_encrypted", "closed",
        )
    }
}
