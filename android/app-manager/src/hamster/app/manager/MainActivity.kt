/*
 * MainActivity.kt — Hamster Manager（安卓端）入口：口令 + 设备库 + 连接
 *
 * 设计取舍（写给后来的人）：
 *   · 设备库是**唯一**的设备列表：扫描（§7）与手动连接都把结果写进 DeviceStore，
 *     列表从库里读并按"最近可见"倒序 —— 这样"扫到的"和"以前连过的"不会变成两份互不相干的表。
 *   · 口令默认只在内存里；勾"记住口令"才用 SecretBox 加密落盘（Android Keystore + AES-GCM）。
 *     Keystore 不可用时**明确提示且不落盘**，绝不静默退回明文。
 *   · 扫描是 UDP 广播（PROTOCOL §7）：服务端只有在对上暗号时才应答，
 *     所以"没有口令就扫不到设备"是正常现象，不是 bug。
 *   · 安卓模拟器里 255.255.255.255 到不了宿主机所在网段，
 *     联调请用"手动连接"填 10.0.2.2:9100（或 adb 传 disctarget）。
 */
package hamster.app.manager

import android.app.Activity
import android.app.AlertDialog
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.provider.Settings
import android.view.View
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ListView
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import hamster.DiscoveredDevice
import hamster.DiscoveryClient
import hamster.HamsterApi
import hamster.parseAddr
import java.io.File

class MainActivity : Activity() {

    private lateinit var secretInput: EditText
    private lateinit var addrInput: EditText
    private lateinit var remember: CheckBox
    private lateinit var status: TextView
    private lateinit var spin: ProgressBar
    private lateinit var list: ListView
    private lateinit var adapter: TwoLineAdapter
    private lateinit var store: DeviceStore

    private var rows: List<KnownDevice> = emptyList()

    /** 只有 debuggable 包 + am extra 才会改它；真机 Wi-Fi 下永远是默认广播地址。 */
    private var scanTarget: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        title = "Hamster Manager"
        store = DeviceStore(File(filesDir, "devices.json"))

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
        }
        root.addView(secretInput)

        remember = CheckBox(this).apply {
            text = "记住口令（Keystore 加密后存本机）"
            setTextColor(0xFFB9B9C2.toInt())
            isChecked = SecretBox.load(this@MainActivity) != null
        }
        root.addView(remember)
        // 只有确实存过才回填，避免把"上次没记住"变成默认行为
        if (remember.isChecked) {
            SecretBox.load(this)?.let { secretInput.setText(it) }
        }

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
        }
        root.addView(addrInput)

        spin = ProgressBar(this).apply {
            visibility = ProgressBar.GONE
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT, dp(24))
        }
        root.addView(spin)

        status = hint("填入口令后点【扫描局域网】，或手动输入地址连接。长按设备可删除。")
        root.addView(status)

        root.addView(spacer(8))
        adapter = TwoLineAdapter(this)
        list = ListView(this).apply {
            this.adapter = this@MainActivity.adapter
            dividerHeight = dp(1)
            setBackgroundColor(0xFF23232A.toInt())
        }
        root.addView(list, LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f))
        list.setOnItemClickListener { _, _, pos, _ ->
            val d = rows.getOrNull(pos) ?: return@setOnItemClickListener
            addrInput.setText("${d.host}:${d.port}")
            connect(d.host, d.port, d.name.ifEmpty { d.host })
        }
        list.setOnItemLongClickListener { _, _, pos, _ ->
            val d = rows.getOrNull(pos) ?: return@setOnItemLongClickListener true
            confirmForget(d)
            true
        }

        setContentView(root)
        reloadDevices()
        applyTestHook()
    }

    /**
     * 自动化钩子：只在 debuggable 包里生效，供 `adb shell am start` 预填口令/地址并自动连接，
     * 这样端到端验证不用靠"点坐标 + input text"。
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
        intent?.getStringExtra("disctarget")?.let { t -> if (t.isNotEmpty()) scanTarget = t }
        if (intent?.getBooleanExtra("autoconnect", false) == true && !a.isNullOrEmpty()) {
            doManualConnect()
        }
    }

    /* ------------------------------------------------------------------ */

    private fun reloadDevices() {
        rows = try {
            store.load()
        } catch (e: Exception) {
            status.text = "设备库读取失败：${e.message}"
            emptyList()
        }
        adapter.submit(rows.map { d ->
            val title = if (d.name.isEmpty()) d.host else d.name
            val ver = if (d.version.isEmpty()) "?" else d.version
            title to "${d.host}:${d.port} · v$ver · ${agoText(d.lastSeenMs)}"
        })
    }

    private fun agoText(ms: Long): String {
        if (ms <= 0) return "从未"
        val diff = System.currentTimeMillis() - ms
        return when {
            diff < 60_000 -> "刚刚"
            diff < 3600_000 -> "${diff / 60_000} 分钟前"
            diff < 86_400_000 -> "${diff / 3600_000} 小时前"
            else -> "${diff / 86_400_000} 天前"
        }
    }

    private fun confirmForget(d: KnownDevice) {
        AlertDialog.Builder(this)
            .setTitle("从设备库移除")
            .setMessage("${d.name.ifEmpty { d.host }}（${d.host}:${d.port}）")
            .setNegativeButton("取消", null)
            .setPositiveButton("移除") { _, _ ->
                store.remove(d.host, d.port, d.deviceId)
                reloadDevices()
                status.text = "已移除该设备记录（不影响服务端）"
            }
            .show()
    }

    private fun secret(): String? {
        val s = secretInput.text.toString()
        if (s.isEmpty()) {
            Toast.makeText(this, "先填口令（服务端的 codeword）", Toast.LENGTH_SHORT).show()
            return null
        }
        if (remember.isChecked) {
            if (!SecretBox.save(this, s)) {
                remember.isChecked = false
                status.text = "本机 Keystore 不可用，口令没有落盘（仅本次运行有效）"
            }
        } else {
            SecretBox.clear(this)
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
        val now = System.currentTimeMillis()
        for (d in found) {
            store.upsert(
                KnownDevice(
                    host = d.ip,
                    port = d.port,
                    deviceId = d.id,
                    name = d.name,
                    version = d.version,
                    lastSeenMs = now,
                ),
            )
        }
        reloadDevices()
        status.text = if (found.isEmpty()) {
            "没有设备应答。口令不对、服务端没开发现、或不在同一网段都会是这种结果。"
        } else {
            "发现 ${found.size} 台设备，已写入设备库；点一台进行加密连接。"
        }
    }

    private fun doManualConnect() {
        val raw = addrInput.text.toString().trim()
        if (raw.isEmpty()) {
            Toast.makeText(this, "填一个 host:port", Toast.LENGTH_SHORT).show()
            return
        }
        val (host, port) = parseAddr(raw, 9100)
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
                val name = api.peerName.ifEmpty { peerLabel }
                val version = api.peerVersion
                status.text = "已连接：$name v$version"
                // 成功的连接是把设备写进库的最好时机：版本/显示名都拿到了
                store.upsert(
                    KnownDevice(
                        host = host,
                        port = port,
                        deviceId = knownDeviceId(host, port),
                        name = name,
                        version = version,
                        lastSeenMs = System.currentTimeMillis(),
                    ),
                )
                reloadDevices()
                // 这条连接只用来验证握手；文件会话由 FilesActivity 自己建，
                // 留着不关只会让服务端多一条会被空闲回收的连接。
                try {
                    api.close()
                } catch (_: Exception) {
                }
                startActivity(
                    Intent(this, FilesActivity::class.java).apply {
                        putExtra(FilesActivity.EXTRA_HOST, host)
                        putExtra(FilesActivity.EXTRA_PORT, port)
                        putExtra(FilesActivity.EXTRA_SECRET, s)
                        putExtra(FilesActivity.EXTRA_LABEL, name)
                    },
                )
            },
            failed = { e ->
                spin.visibility = ProgressBar.GONE
                status.text = "连接失败：${e.message}"
            },
        )
    }

    /** 库里已有同一 host:port 就沿用它的 deviceId，避免手动连接产生重复记录。 */
    private fun knownDeviceId(host: String, port: Int): String =
        rows.firstOrNull { it.host == host && it.port == port }?.deviceId ?: ""

    private fun androidDeviceId(): String {
        val id = try {
            Settings.Secure.getString(contentResolver, Settings.Secure.ANDROID_ID)
        } catch (_: Exception) {
            null
        }
        if (!id.isNullOrBlank() && id.length in 8..64) return id
        return (1..16).map { "0123456789abcdef"[(Math.random() * 16).toInt()] }.joinToString("")
    }

    override fun onResume() {
        super.onResume()
        // 从文件页回来时刷新"最近可见"，并让 Keystore 状态与勾选一致
        reloadDevices()
    }
}
