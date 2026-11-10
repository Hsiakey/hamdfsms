/*
 * ConfigActivity.kt — Hamster 守护端配置页（纯代码 UI，不用 XML / AndroidX）
 *
 * 页面职责：
 *   · 展示服务状态：是否在跑、监听地址、根目录绝对路径、客户端数、版本、口令是否已设置；
 *   · 编辑口令 / 端口，保存到 DaemonPrefs（口令走 AndroidKeyStore AES-GCM）；
 *   · 启动 / 停止 DaemonService；
 *   · 把 host:port 复制到剪贴板，方便桌面端手填。
 *
 * 校验（保存前，不合法就状态栏提示且不保存）：
 *   · 口令非空且长度 >= DaemonPrefs.MIN_CODEWORD_LEN（8）；
 *   · 端口是 1024..65535 的整数。
 *
 * 服务在跑时改配置：提示"需重启服务生效"，保存后自动重启服务
 * （再次 start() 会让 DaemonService 先 stop 旧 DaemonServer 再按新配置重建）。
 *
 * API 33+：启动服务前请求 POST_NOTIFICATIONS；被拒也照样启动服务，
 * 只是用户看不到常驻通知（前台服务本身不依赖该权限）。
 *
 * 自动化钩子（只在 debuggable 包里生效，正式包直接 return）：
 *   adb shell am start -n hamster.app.daemon/.ConfigActivity \
 *       --es secret "<codeword>" --ei port 9100 --ez autostart true
 */
package hamster.app.daemon

import android.Manifest
import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import java.net.Inet4Address
import java.net.NetworkInterface

class ConfigActivity : Activity() {

    private lateinit var statusView: TextView
    private lateinit var codewordInput: EditText
    private lateinit var portInput: EditText
    private lateinit var rootView: TextView

    private val handler = Handler(Looper.getMainLooper())

    /** 状态栏消息的"保持时间"：避免 2 秒一次的自动刷新把错误提示立刻覆盖掉。 */
    private var statusHoldUntil = 0L

    /** Keystore 是否可用；不可用时明确告诉用户口令无法安全保存。 */
    private var keystoreOk = true

    private val ticker = object : Runnable {
        override fun run() {
            refreshStatus()
            handler.postDelayed(this, 2_000L)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        title = "Hamster 守护端"

        val scroll = ScrollView(this).apply {
            setFillViewport(true)
            setBackgroundColor(0xFF1B1B1F.toInt())
        }
        val root = body()

        root.addView(label("Hamster 守护端", 24f, bold = true))
        root.addView(spacer(4))
        root.addView(hint("把 DaemonCore / DaemonServer 跑成前台服务 · v${DaemonService.VERSION}"))

        root.addView(spacer(16))
        statusView = label("", 13f).apply { setTextColor(0xFFC9C9D2.toInt()) }
        root.addView(statusView)

        root.addView(spacer(18))
        root.addView(label("口令（codeword，至少 ${DaemonPrefs.MIN_CODEWORD_LEN} 位）", 13f))
        codewordInput = EditText(this).apply {
            hint = "与服务端/桌面端填同一个口令"
            setSingleLine(true)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            setTextColor(0xFFEDEDF0.toInt())
            setHintTextColor(0xFF6E6E77.toInt())
        }
        root.addView(codewordInput)
        root.addView(hint("口令用 AndroidKeyStore AES-GCM 加密后存本机；Keystore 不可用时拒绝保存，绝不落明文。"))

        root.addView(spacer(12))
        root.addView(label("端口（${DaemonPrefs.MIN_PORT}–${DaemonPrefs.MAX_PORT}）", 13f))
        portInput = EditText(this).apply {
            hint = DaemonPrefs.DEFAULT_PORT.toString()
            setSingleLine(true)
            inputType = InputType.TYPE_CLASS_NUMBER
            setTextColor(0xFFEDEDF0.toInt())
            setHintTextColor(0xFF6E6E77.toInt())
        }
        root.addView(portInput)

        root.addView(spacer(12))
        root.addView(label("存储根目录（milestone 1：app 私有目录）", 13f))
        rootView = label(appPrivateRoot(this).displayPath, 13f).apply {
            setTextColor(0xFFB9B9C2.toInt())
            setTextIsSelectable(true)
        }
        root.addView(rootView)
        root.addView(
            hint(
                "打开目录：系统「文件」→ Android/data/hamster.app.daemon/files/shared" +
                    "（部分机型需用 adb 或电脑 MTP 查看）。\n" +
                    "milestone 1 固定为 getExternalFilesDir(null)/shared，无需任何存储权限。" +
                    "自定义目录要 SAF（ACTION_OPEN_DOCUMENT_TREE + DocumentsContract），" +
                    "targetSdk 34 的 scoped storage 不允许直接读写任意路径，留到下一里程碑。",
            ),
        )

        root.addView(spacer(18))
        val row1 = row()
        val saveBtn = Button(this).apply {
            text = "保存"
            setOnClickListener { onSaveClicked() }
        }
        val startBtn = Button(this).apply {
            text = "启动服务"
            setOnClickListener { onStartClicked() }
        }
        row1.addView(saveBtn, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        row1.addView(startBtn, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        root.addView(row1)

        root.addView(spacer(8))
        val row2 = row()
        val stopBtn = Button(this).apply {
            text = "停止服务"
            setOnClickListener { onStopClicked() }
        }
        val copyBtn = Button(this).apply {
            text = "复制地址"
            setOnClickListener { onCopyClicked() }
        }
        row2.addView(stopBtn, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        row2.addView(copyBtn, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        root.addView(row2)

        root.addView(spacer(12))
        root.addView(hint("提示：服务在跑时修改口令/端口并保存，会自动重启服务使新配置生效。"))

        scroll.addView(root)
        setContentView(scroll)

        // 回填已保存配置（口令只有能解密时才回填）。
        DaemonPrefs.loadCodeword(this)?.let { codewordInput.setText(it) }
        portInput.setText(DaemonPrefs.port(this).toString())
        keystoreOk = DaemonPrefs.codewordStorageAvailable(this)

        refreshStatus(force = true)
        applyTestHook()
    }

    override fun onResume() {
        super.onResume()
        refreshStatus(force = true)
        handler.removeCallbacks(ticker)
        handler.postDelayed(ticker, 2_000L)
    }

    override fun onPause() {
        super.onPause()
        handler.removeCallbacks(ticker)
    }

    override fun onDestroy() {
        super.onDestroy()
        handler.removeCallbacksAndMessages(null)
    }

    /* ------------------------------------------------------------------ */
    /* 状态展示                                                            */
    /* ------------------------------------------------------------------ */

    private fun refreshStatus(force: Boolean = false) {
        if (!force && System.currentTimeMillis() < statusHoldUntil) return

        val running = DaemonService.isRunning
        val savedPort = DaemonPrefs.port(this)
        val actualPort = if (running) {
            DaemonService.runningPort().takeIf { it > 0 } ?: savedPort
        } else {
            savedPort
        }
        val clients = if (running) DaemonService.clientCount() else 0
        val rootPath = DaemonPrefs.rootPath(this) ?: appPrivateRoot(this).displayPath
        val codewordState = if (DaemonPrefs.hasCodeword(this)) "已设置（Keystore 加密）" else "未设置"

        val text = StringBuilder()
        text.append(if (running) "服务：运行中" else "服务：已停止")
        text.append("\n监听：0.0.0.0:").append(actualPort)
        if (!running) text.append("（未启动）")
        text.append("\n根目录：").append(rootPath)
        text.append("\n客户端：").append(clients)
        text.append("\n版本：").append(DaemonService.VERSION)
        text.append("\n口令：").append(codewordState)
        if (!keystoreOk) {
            text.append("\n⚠ 本机 Keystore 不可用：口令无法安全保存，服务不能启动（不会落明文）")
        }
        statusView.text = text.toString()
    }

    private fun setStatus(message: String, holdMs: Long = 4_000L) {
        statusView.text = message
        statusHoldUntil = System.currentTimeMillis() + holdMs
    }

    private fun toast(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
    }

    /* ------------------------------------------------------------------ */
    /* 按钮                                                                */
    /* ------------------------------------------------------------------ */

    private fun onSaveClicked() {
        if (validateAndSave(restartIfRunning = true)) {
            toast("已保存")
        }
    }

    private fun onStartClicked() {
        if (!validateAndSave(restartIfRunning = false)) return

        // API 33+ 先要通知权限；被拒也继续启动（只是没有通知）。
        requestNotificationPermissionIfNeeded()

        val ok = DaemonService.start(this)
        if (ok) {
            setStatus("已请求启动前台服务…", holdMs = 1_500L)
            handler.postDelayed({ refreshStatus(force = true) }, 700L)
        } else {
            setStatus("启动失败：系统拒绝启动前台服务（可能受后台启动限制，详见 logcat）", holdMs = 8_000L)
        }
    }

    private fun onStopClicked() {
        DaemonService.stop(this)
        DaemonPrefs.setEnabled(this, false)
        setStatus("已请求停止服务…", holdMs = 1_500L)
        handler.postDelayed({ refreshStatus(force = true) }, 500L)
    }

    private fun onCopyClicked() {
        val port = portInput.text.toString().toIntOrNull()
            ?.takeIf { it in DaemonPrefs.MIN_PORT..DaemonPrefs.MAX_PORT }
            ?: DaemonPrefs.port(this)
        val host = lanIpv4() ?: "127.0.0.1"
        val addr = "$host:$port"
        try {
            val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            cm.setPrimaryClip(ClipData.newPlainText("Hamster 地址", addr))
            toast("已复制 $addr")
            setStatus("已复制 $addr；桌面端连接时填这个地址（需与手机同一局域网）")
        } catch (e: Exception) {
            setStatus("复制失败：${e.message}", holdMs = 8_000L)
        }
    }

    /**
     * 校验并保存。返回 false 时状态栏已经给出原因，调用方直接 return。
     *
     * [restartIfRunning]：保存按钮传 true——服务在跑且配置变化时自动重启；
     * 启动按钮传 false——它紧接着会自己 start()，不需要多一次重启。
     */
    private fun validateAndSave(restartIfRunning: Boolean): Boolean {
        val codeword = codewordInput.text.toString()
        val portText = portInput.text.toString().trim()
        val port = portText.toIntOrNull()

        if (codeword.isEmpty()) {
            setStatus("保存失败：口令不能为空（至少 ${DaemonPrefs.MIN_CODEWORD_LEN} 位）", holdMs = 8_000L)
            return false
        }
        if (codeword.length < DaemonPrefs.MIN_CODEWORD_LEN) {
            setStatus(
                "保存失败：口令至少 ${DaemonPrefs.MIN_CODEWORD_LEN} 位（当前 ${codeword.length} 位）",
                holdMs = 8_000L,
            )
            return false
        }
        if (port == null || port !in DaemonPrefs.MIN_PORT..DaemonPrefs.MAX_PORT) {
            setStatus(
                "保存失败：端口必须是 ${DaemonPrefs.MIN_PORT}–${DaemonPrefs.MAX_PORT} 的整数",
                holdMs = 8_000L,
            )
            return false
        }

        val oldCodeword = DaemonPrefs.loadCodeword(this)
        val oldPort = DaemonPrefs.port(this)
        val wasRunning = DaemonService.isRunning

        if (!DaemonPrefs.saveCodeword(this, codeword)) {
            keystoreOk = false
            setStatus(
                "保存失败：Keystore 不可用或写入失败，口令没有保存（绝不会回退成明文）",
                holdMs = 8_000L,
            )
            return false
        }
        keystoreOk = true
        if (!DaemonPrefs.setPort(this, port)) {
            setStatus("保存失败：端口写入失败", holdMs = 8_000L)
            return false
        }
        DaemonPrefs.setRootPath(this, appPrivateRoot(this).displayPath)
        DaemonPrefs.setEnabled(this, true)

        val changed = oldCodeword != codeword || oldPort != port
        if (wasRunning && changed && restartIfRunning) {
            // start() 会让服务先 stop 旧 DaemonServer 再按新配置重建，等价于重启。
            if (DaemonService.start(this)) {
                setStatus("配置已保存；需重启服务生效，已自动重启…", holdMs = 2_500L)
            } else {
                setStatus("配置已保存；需重启服务生效，但自动重启失败，请手动点【启动服务】", holdMs = 8_000L)
            }
        } else if (wasRunning && changed) {
            setStatus("配置已保存；需重启服务生效（即将按新配置启动）", holdMs = 2_500L)
        } else if (wasRunning) {
            setStatus("配置已保存（未变化，服务继续运行）", holdMs = 2_500L)
        } else {
            setStatus("配置已保存。点【启动服务】开始监听。", holdMs = 2_500L)
        }
        return true
    }

    /* ------------------------------------------------------------------ */
    /* 权限 / 地址                                                         */
    /* ------------------------------------------------------------------ */

    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) {
            return
        }
        try {
            // 不阻塞启动：被拒也继续；前台服务本身不依赖 POST_NOTIFICATIONS。
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQ_NOTIFICATIONS)
        } catch (e: Exception) {
            android.util.Log.w("HamsterDaemonUi", "请求通知权限失败: ${e.javaClass.simpleName}")
        }
    }

    /**
     * 找一个适合给桌面端填的局域网 IPv4：优先 site-local（10/172.16/192.168），
     * 排除 loopback / link-local；找不到时返回 null（界面回退 127.0.0.1）。
     */
    private fun lanIpv4(): String? {
        return try {
            val candidates = ArrayList<Pair<Int, String>>()
            val nifs = NetworkInterface.getNetworkInterfaces() ?: return null
            for (nif in nifs) {
                if (!nif.isUp || nif.isLoopback) continue
                for (addr in nif.inetAddresses) {
                    if (addr is Inet4Address && !addr.isLoopbackAddress && !addr.isLinkLocalAddress) {
                        val ip = addr.hostAddress ?: continue
                        candidates.add((if (addr.isSiteLocalAddress) 0 else 1) to ip)
                    }
                }
            }
            candidates.sortedBy { it.first }.firstOrNull()?.second
        } catch (_: Exception) {
            null
        }
    }

    /**
     * 自动化钩子：只在 debuggable 包里生效。
     *   --es secret <codeword>  预填口令
     *   --ei port <port>        预填端口
     *   --ez autostart true     立即校验+保存+启动
     */
    private fun applyTestHook() {
        val debuggable = (applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
        if (!debuggable) return
        intent?.getStringExtra("secret")?.takeIf { it.isNotEmpty() }?.let { codewordInput.setText(it) }
        if (intent?.hasExtra("port") == true) {
            portInput.setText(intent.getIntExtra("port", DaemonPrefs.port(this)).toString())
        }
        if (intent?.getBooleanExtra("autostart", false) == true) {
            onStartClicked()
        }
    }

    companion object {
        private const val REQ_NOTIFICATIONS = 3301
    }
}
