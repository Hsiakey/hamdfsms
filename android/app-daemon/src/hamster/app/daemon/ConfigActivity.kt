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
 *   · 端口是 1024..65535 的整数；
 *   · 选中的存储目录必须存在、是目录、可读（rootFromPath 返回非 null）。
 *
 * 存储根：默认是 app 私有目录（无需权限）；也可以点【选择目录】挑共享存储里的
 * 真实目录（如 /sdcard/Download）。后者要先拿到授权：
 *   · API 26–29：运行时权限 READ/WRITE_EXTERNAL_STORAGE；
 *   · API 30+：MANAGE_EXTERNAL_STORAGE，只能跳系统设置页授予。
 * 没授权时点【选择目录】会先引导授权，回到本页在 onResume 里刷新状态。
 * 选择结果先记在本地字段里，点【保存】才写入 DaemonPrefs（与口令/端口一致）；
 * 服务在跑时同样"提示需重启并自动重启"。
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
    private lateinit var storageStatusView: TextView

    /**
     * 待保存的存储根：null = 默认（app 私有目录）。
     * 选目录只改这个字段，点【保存】才写 DaemonPrefs。
     *
     * 必须配 [rootTouched] 才能区分两种情况：
     *   · 用户根本没动存储根（"保存"只改了口令/端口）——此时不能清掉已配置的根；
     *   · 用户点了【恢复默认】——此时要把 prefs 里的根清空。
     */
    private var selectedRootPath: String? = null

    /** 用户是否动过存储根（选目录 / 恢复默认）。false 表示保存时保持已配置的值。 */
    private var rootTouched = false

    /** 用户点了【选择目录】但还没授权：授权成功后自动拉起选择器。 */
    private var pickAfterPermission = false

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
        root.addView(label("存储根目录", 13f))
        rootView = label("", 13f).apply {
            setTextColor(0xFFB9B9C2.toInt())
            setTextIsSelectable(true)
        }
        root.addView(rootView)
        storageStatusView = label("", 12f).apply {
            setTextColor(0xFF8A8A93.toInt())
        }
        root.addView(storageStatusView)

        val rootRow = row()
        val pickBtn = Button(this).apply {
            text = "选择目录"
            setOnClickListener { onPickDirectoryClicked() }
        }
        val resetBtn = Button(this).apply {
            text = "恢复默认"
            setOnClickListener { onResetRootClicked() }
        }
        rootRow.addView(pickBtn, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        rootRow.addView(resetBtn, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        root.addView(spacer(6))
        root.addView(rootRow)
        root.addView(
            hint(
                "默认是 app 私有目录（无需权限，系统「文件」里在 Android/data/hamster.app.daemon/files/shared，" +
                    "部分机型需用 adb 或电脑 MTP 查看）。\n" +
                    "想直接服务手机里的真实目录（如 /sdcard/Download）就点【选择目录】：" +
                    "Android 10 及以下要读写存储权限，Android 11+ 要「所有文件访问」权限。" +
                    "该权限在 Google Play 属受限权限（非文件管理器会被拒），本项目为侧载自用。\n" +
                    "注意：Android 11+ 即使授了权，Android/data、Android/obb 仍不可按路径读写。",
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
        root.addView(hint("提示：服务在跑时修改口令/端口/存储根并保存，会自动重启服务使新配置生效。"))

        scroll.addView(root)
        setContentView(scroll)

        // 回填已保存配置（口令只有能解密时才回填）。
        DaemonPrefs.loadCodeword(this)?.let { codewordInput.setText(it) }
        portInput.setText(DaemonPrefs.port(this).toString())
        keystoreOk = DaemonPrefs.codewordStorageAvailable(this)
        // 旋转/重建前选了目录但还没保存：把待保存的选择恢复回来。
        if (savedInstanceState != null) {
            rootTouched = savedInstanceState.getBoolean(STATE_ROOT_TOUCHED, false)
            selectedRootPath = savedInstanceState.getString(STATE_PENDING_ROOT)
        }

        refreshStatus(force = true)
        applyTestHook()
    }

    override fun onResume() {
        super.onResume()
        refreshStatus(force = true)
        handler.removeCallbacks(ticker)
        handler.postDelayed(ticker, 2_000L)
        // API 30+ 的授权页没有回调，只能在这里看"回来时权限是否已经给了"。
        // 用户点【选择目录】时如果没权限，会先记下 pickAfterPermission；
        // 授权成功就自动把选择器拉起来，省一次点击。
        if (pickAfterPermission && hasStorageAccess(this)) {
            launchDirectoryPicker()
        }
    }

    override fun onPause() {
        super.onPause()
        handler.removeCallbacks(ticker)
    }

    override fun onDestroy() {
        super.onDestroy()
        handler.removeCallbacksAndMessages(null)
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putString(STATE_PENDING_ROOT, selectedRootPath)
        outState.putBoolean(STATE_ROOT_TOUCHED, rootTouched)
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
        val configured = rootFromPath(DaemonPrefs.rootPath(this))
        val effectiveRoot = configured ?: appPrivateRoot(this)
        val codewordState = if (DaemonPrefs.hasCodeword(this)) "已设置（Keystore 加密）" else "未设置"

        val text = StringBuilder()
        text.append(if (running) "服务：运行中" else "服务：已停止")
        text.append("\n监听：0.0.0.0:").append(actualPort)
        if (!running) text.append("（未启动）")
        text.append("\n根目录：").append(effectiveRoot.displayPath)
        text.append(if (configured != null) "（已配置）" else "（默认）")
        text.append("\n客户端：").append(clients)
        text.append("\n版本：").append(DaemonService.VERSION)
        text.append("\n口令：").append(codewordState)
        if (!keystoreOk) {
            text.append("\n⚠ 本机 Keystore 不可用：口令无法安全保存，服务不能启动（不会落明文）")
        }
        statusView.text = text.toString()

        refreshRootViews(configured)
    }

    /**
     * 存储根与权限状态（随 2 秒 ticker 刷新，也用于选完目录/授权返回后立即更新）。
     *
     * 展示优先级：待保存的选择 > 已配置且可用的目录 > 默认（app 私有）。
     * 已配置但当前不可用时明确写出来：DaemonService 会回退到默认，不会起不来。
     */
    private fun refreshRootViews(configured: StorageRoot? = rootFromPath(DaemonPrefs.rootPath(this))) {
        val stored = DaemonPrefs.rootPath(this)
        val fallback = appPrivateRoot(this)
        val pending = selectedRootPath

        rootView.text = when {
            rootTouched && pending != null ->
                "已选择：$pending\n（点【保存】生效）"
            rootTouched ->
                "${fallback.displayPath}\n（将恢复默认：app 私有目录；点【保存】生效）"
            configured != null ->
                "${configured.displayPath}\n（已配置：守护端用这个目录）"
            stored != null ->
                "${fallback.displayPath}\n（配置的目录当前不可用：$stored；服务会回退到默认）"
            else ->
                "${fallback.displayPath}\n（默认 · app 私有目录，无需存储权限）"
        }

        val granted = hasStorageAccess(this)
        val prefix = if (granted) "存储权限：已授予\n" else "存储权限：未授予\n"
        storageStatusView.setTextColor(
            if (granted) 0xFF9BD49B.toInt() else 0xFFE0B060.toInt(),
        )
        storageStatusView.text = prefix + storageAccessHint(this)
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
     * 【选择目录】：没授权就先引导授权（API ≤29 弹运行时权限，API 30+ 跳设置页），
     * 授权成功后在 onResume / onRequestPermissionsResult 里自动拉起选择器。
     */
    private fun onPickDirectoryClicked() {
        if (!hasStorageAccess(this)) {
            pickAfterPermission = true
            setStatus("需要先授予存储权限，正在打开授权入口…", holdMs = 5_000L)
            requestStorageAccess(this, REQ_STORAGE_ACCESS)
            return
        }
        launchDirectoryPicker()
    }

    /** 拉起 DirectoryPickerActivity（不导出的内部页面，结果走 onActivityResult）。 */
    private fun launchDirectoryPicker() {
        pickAfterPermission = false
        try {
            startActivityForResult(Intent(this, DirectoryPickerActivity::class.java), REQ_PICK_DIR)
        } catch (e: Exception) {
            setStatus("打不开目录选择器：${e.javaClass.simpleName}", holdMs = 8_000L)
        }
    }

    /** 【恢复默认】：清掉待保存的选择，点【保存】时才真正写 DaemonPrefs。 */
    private fun onResetRootClicked() {
        selectedRootPath = null
        rootTouched = true
        refreshStatus(force = true)
        setStatus("已恢复默认（app 私有目录）；点【保存】生效。", holdMs = 4_000L)
    }

    /* ------------------------------------------------------------------ */
    /* Activity 结果 / 权限结果                                            */
    /* ------------------------------------------------------------------ */

    @Suppress("DEPRECATION")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != REQ_PICK_DIR) return
        if (resultCode != RESULT_OK) {
            setStatus("已取消选择目录。", holdMs = 2_000L)
            return
        }
        val picked = data?.getStringExtra(DirectoryPickerActivity.EXTRA_PATH)
        val root = rootFromPath(picked)
        if (root == null) {
            setStatus(
                "所选目录不可用（不存在 / 不是目录 / 不可读），未保存。",
                holdMs = 8_000L,
            )
            return
        }
        // 选择器已经校验过一次，这里再校验一次：从选择器返回的这段时间里
        // 目录可能被删、SD 卡可能被拔、权限可能被撤。
        selectedRootPath = root.displayPath
        rootTouched = true
        refreshStatus(force = true)
        setStatus("已选择：${root.displayPath}（点【保存】生效）", holdMs = 6_000L)
    }

    @Suppress("DEPRECATION")
    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray,
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode != REQ_STORAGE_ACCESS) return
        refreshStatus(force = true)
        if (hasStorageAccess(this)) {
            setStatus("已授予存储权限。", holdMs = 2_500L)
            if (pickAfterPermission) launchDirectoryPicker()
        } else {
            pickAfterPermission = false
            setStatus(
                "仍未授予存储权限：请在系统设置里允许后，再点【选择目录】。",
                holdMs = 8_000L,
            )
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

        // 根目录：
        //   · rootTouched == false：用户只改了口令/端口，保持 prefs 里的根不变；
        //   · rootTouched == true 且 selectedRootPath == null：【恢复默认】，
        //     把 prefs 里的记录清空（setRootPath 收到空串就是 remove）；
        //   · 否则校验选中的目录，不可用就拒绝保存。
        val oldRoot = DaemonPrefs.rootPath(this) ?: ""
        val newRoot: String? = when {
            !rootTouched -> oldRoot.ifBlank { null }
            else -> {
                val pendingRoot = selectedRootPath
                if (pendingRoot == null) {
                    null
                } else {
                    val r = rootFromPath(pendingRoot)
                    if (r == null) {
                        setStatus(
                            "保存失败：所选目录不存在 / 不是目录 / 不可读（可能被删或权限被撤），" +
                                "请重选或【恢复默认】。",
                            holdMs = 8_000L,
                        )
                        return false
                    }
                    r.displayPath
                }
            }
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
        if (!DaemonPrefs.setRootPath(this, newRoot ?: "")) {
            setStatus("保存失败：存储根目录写入失败", holdMs = 8_000L)
            return false
        }
        DaemonPrefs.setEnabled(this, true)

        // 保存成功：待保存状态归位，界面切回"已配置/默认"（而不是"点【保存】生效"）。
        rootTouched = false
        selectedRootPath = newRoot
        refreshRootViews()

        val changed = oldCodeword != codeword || oldPort != port || oldRoot != (newRoot ?: "")
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
     *   --es root <path>        直接指定存储根（跳过目录选择器；不存在的路径会被 onStartClicked 校验拒绝）
     *   --ez autostart true     立即校验+保存+启动
     */
    private fun applyTestHook() {
        val debuggable = (applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
        if (!debuggable) return
        intent?.getStringExtra("secret")?.takeIf { it.isNotEmpty() }?.let { codewordInput.setText(it) }
        if (intent?.hasExtra("port") == true) {
            portInput.setText(intent.getIntExtra("port", DaemonPrefs.port(this)).toString())
        }
        // 存储根：直接落到"待保存选择"里，随后的 onStartClicked 会按常规校验（存在/是目录/可读）
        intent?.getStringExtra("root")?.takeIf { it.isNotEmpty() }?.let { p ->
            selectedRootPath = p
            rootTouched = true
        }
        if (intent?.getBooleanExtra("autostart", false) == true) {
            onStartClicked()
        }
    }

    companion object {
        private const val REQ_NOTIFICATIONS = 3301

        /** 请求共享存储授权（API ≤29 运行时权限；API 30+ 只是跳设置页，结果在 onResume 查）。 */
        private const val REQ_STORAGE_ACCESS = 3302

        /** 拉起 DirectoryPickerActivity 的请求码。 */
        private const val REQ_PICK_DIR = 3303

        /** 旋转/重建时保住"选了但还没保存"的根目录。 */
        private const val STATE_PENDING_ROOT = "pending_root_path"

        /** 旋转/重建时保住"用户动过存储根"的标记（见 rootTouched）。 */
        private const val STATE_ROOT_TOUCHED = "root_touched"
    }
}
