/*
 * MainActivity.kt — Hamster Manager（安卓端）入口：口令 + 局域网发现 + 连接
 *
 * 设计取舍（写给后来的人）：
 *   · 口令默认只存在本进程内存里；勾选"记住口令"才落 SharedPreferences。
 *     真机长期方案应换 Android Keystore（待办，见 android/README.md）。
 *   · 扫描是 UDP 广播（PROTOCOL §7）：服务端只有在对上暗号时才应答，
 *     所以"没有口令就扫不到设备"是正常现象，不是 bug。
 *   · 安卓模拟器里 255.255.255.255 到不了宿主机所在网段，
 *     联调请用"手动连接"填 10.0.2.2:9100。
 */
package hamster.app.manager

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.provider.Settings
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import hamster.DiscoveredDevice
import hamster.DiscoveryClient
import hamster.HamsterApi
import hamster.parseAddr

class MainActivity : Activity() {

    private lateinit var secretInput: EditText
    private lateinit var addrInput: EditText
    private lateinit var remember: CheckBox
    private lateinit var status: TextView
    private lateinit var spin: ProgressBar
    private lateinit var list: android.widget.ListView
    private lateinit var adapter: TwoLineAdapter

    private val devices = ArrayList<DiscoveredDevice>()

    /** 只有 debuggable 包 + am extra 才会改它；真机 Wi-Fi 下永远是默认广播地址。 */
    private var scanTarget: String? = null

    private val prefs by lazy { getSharedPreferences("hamster", Context.MODE_PRIVATE) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        title = "Hamster Manager"

        val root = body()
        root.addView(label("Hamster Manager", 24f, bold = true))
        root.addView(spacer(4))
        root.addView(hint("局域网端到端加密客户端 · PROTOCOL §7 / §8"))

        root.addView(spacer(18))
        root.addView(label("口令", 13f))
        secretInput = EditText(this).apply {
            hint = "与服务端 codeword 相同"
            setSingleLine(true)
            setTextColor(0xFFEDEDF0.toInt())
            setHintTextColor(0xFF6E6E77.toInt())
            setText(prefs.getString(KEY_SECRET, "") ?: "")
        }
        root.addView(secretInput)

        remember = CheckBox(this).apply {
            text = "记住口令（存本机私有目录）"
            setTextColor(0xFFB9B9C2.toInt())
            isChecked = prefs.getBoolean(KEY_REMEMBER, false)
        }
        root.addView(remember)

        root.addView(spacer(12))
        val actions = row()
        val scanBtn = Button(this).apply { text = "扫描局域网" }
        scanBtn.setOnClickListener { doScan() }
        val manualBtn = Button(this).apply { text = "手动连接" }
        manualBtn.setOnClickListener { doManualConnect() }
        actions.addView(scanBtn, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        actions.addView(manualBtn, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        root.addView(actions)

        addrInput = EditText(this).apply {
            hint = "192.168.1.10:9100（模拟器填 10.0.2.2:9100）"
            setSingleLine(true)
            setTextColor(0xFFEDEDF0.toInt())
            setHintTextColor(0xFF6E6E77.toInt())
            setText(prefs.getString(KEY_ADDR, "") ?: "")
        }
        root.addView(addrInput)

        spin = ProgressBar(this).apply {
            visibility = ProgressBar.GONE
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT, dp(24))
        }
        root.addView(spin)

        status = hint("填入口令后点【扫描局域网】，或直接手动输入地址连接。")
        root.addView(status)

        root.addView(spacer(8))
        adapter = TwoLineAdapter(this)
        list = android.widget.ListView(this).apply {
            this.adapter = this@MainActivity.adapter
            dividerHeight = dp(1)
            setBackgroundColor(0xFF23232A.toInt())
        }
        root.addView(list, LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f))
        list.setOnItemClickListener { _, _, pos, _ ->
            val d = devices.getOrNull(pos) ?: return@setOnItemClickListener
            connect(d.ip, d.port, d.name.ifEmpty { d.id })
        }

        setContentView(root)
        applyTestHook()
    }

    /**
     * 自动化钩子：只在 debuggable 包里生效，供 `adb shell am start --es secret ...`
     * 预填口令/地址并自动连接，这样端到端验证不用靠"点坐标 + input text"。
     *
     * 安全性：extras 里的口令是**调用方提供的**，本 Activity 不会因此泄漏自己存的口令；
     * 且非 debuggable 包直接忽略，用户装正式包时攻击面为零。
     */
    private fun applyTestHook() {
        val dbg = (applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0
        if (!dbg) return
        val s = intent?.getStringExtra("secret")
        val a = intent?.getStringExtra("addr")
        if (!s.isNullOrEmpty()) {
            secretInput.setText(s)
            remember.isChecked = false
        }
        if (!a.isNullOrEmpty()) addrInput.setText(a)
        // 模拟器里 255.255.255.255 到不了宿主机，自动化验证用 disctarget 走单播探测
        intent?.getStringExtra("disctarget")?.let { t -> if (t.isNotEmpty()) scanTarget = t }
        if (intent?.getBooleanExtra("autoconnect", false) == true && !a.isNullOrEmpty()) {
            doManualConnect()
        }
    }

    /* ------------------------------------------------------------------ */

    private fun secret(): String? {
        val s = secretInput.text.toString()
        if (s.isEmpty()) {
            Toast.makeText(this, "先填口令（服务端的 codeword）", Toast.LENGTH_SHORT).show()
            return null
        }
        if (remember.isChecked) {
            prefs.edit().putString(KEY_SECRET, s).putBoolean(KEY_REMEMBER, true).apply()
        } else {
            prefs.edit().remove(KEY_SECRET).putBoolean(KEY_REMEMBER, false).apply()
        }
        return s
    }

    private fun doScan() {
        val s = secret() ?: return
        spin.visibility = ProgressBar.VISIBLE
        status.text = "正在广播探测…"
        background(
            work = {
                val t = scanTarget
                if (t != null) DiscoveryClient.scan(s, timeoutMs = 1800, target = t)
                else DiscoveryClient.scan(s, timeoutMs = 1800)
            },
            done = { found -> onScanned(found) },
            failed = { e ->
                spin.visibility = ProgressBar.GONE
                status.text = "扫描失败：${e.message}"
            },
        )
    }

    private fun onScanned(found: List<DiscoveredDevice>) {
        spin.visibility = ProgressBar.GONE
        devices.clear()
        devices.addAll(found)
        adapter.submit(found.map { d ->
            val name = if (d.name.isEmpty()) d.id else d.name
            name to "${d.ip}:${d.port} · v${d.version.ifEmpty { "?" }} · ${d.id.take(8)}"
        })
        status.text = if (found.isEmpty()) {
            "没有设备应答。口令不对、服务端没开发现、或不在同一网段都会是这种结果。"
        } else {
            "发现 ${found.size} 台设备，点一台进行加密连接。"
        }
    }

    private fun doManualConnect() {
        val raw = addrInput.text.toString().trim()
        if (raw.isEmpty()) {
            Toast.makeText(this, "填一个 host:port", Toast.LENGTH_SHORT).show()
            return
        }
        val (host, port) = parseAddr(raw, 9100)
        prefs.edit().putString(KEY_ADDR, raw).apply()
        connect(host, port, host)
    }

    private fun connect(host: String, port: Int, peerLabel: String) {
        val s = secret() ?: return
        val devId = androidDeviceId()
        spin.visibility = ProgressBar.VISIBLE
        status.text = "正在与 $host:$port 做 §8 握手…"
        background(
            work = { HamsterApi.connect(host, port, s, devId) },
            done = { api ->
                spin.visibility = ProgressBar.GONE
                status.text = "已连接：${api.peerName.ifEmpty { peerLabel }} v${api.peerVersion}"
                val it = Intent(this, FilesActivity::class.java).apply {
                    putExtra(FilesActivity.EXTRA_HOST, host)
                    putExtra(FilesActivity.EXTRA_PORT, port)
                    putExtra(FilesActivity.EXTRA_SECRET, s)
                    putExtra(FilesActivity.EXTRA_LABEL, peerLabel)
                }
                // 这条连接只用来验证握手；文件会话由 FilesActivity 自己建，
                // 留着不关只会让服务端多一条会被空闲回收的连接。
                try {
                    api.close()
                } catch (_: Exception) {
                }
                startActivity(it)
            },
            failed = { e ->
                spin.visibility = ProgressBar.GONE
                status.text = "连接失败：${e.message}"
            },
        )
    }

    private fun androidDeviceId(): String {
        val id = try {
            Settings.Secure.getString(contentResolver, Settings.Secure.ANDROID_ID)
        } catch (_: Exception) {
            null
        }
        if (!id.isNullOrBlank() && id.length in 8..64) return id
        return (1..16).map { "0123456789abcdef"[(Math.random() * 16).toInt()] }.joinToString("")
    }

    companion object {
        private const val KEY_SECRET = "secret"
        private const val KEY_REMEMBER = "remember"
        private const val KEY_ADDR = "addr"
    }
}
