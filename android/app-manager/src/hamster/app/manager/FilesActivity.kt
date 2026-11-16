/*
 * FilesActivity.kt — 连上之后的文件浏览 / 下载 / 上传 / 目录管理
 *
 * 线程模型：每个网络动作都在后台线程跑，主线程只做界面更新；
 * HamsterApi 内部是 @Synchronized 的单连接，所以这里刻意串行：一次只允许一个动作
 * 在飞（busy 标记），避免两个动作交叉写同一条记录层。
 *
 * 断线处理（踩过的坑）：安卓会在重装/系统回收时把进程连同 socket 一起带走，
 * 界面却还拿着旧句柄 —— 表现为 upload 报 "io_error: Software caused connection abort"。
 * 因此任何传输层错误都会把 api 置空，下一次动作自动重连，用户不需要退出重进。
 *
 * 分页：列表一次只取 PAGE 条（服务端 list 支持 limit/offset），滚到底再取下一页，
 * 避免大目录一次性拉几千条把 UI 卡死。
 */
package hamster.app.manager

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import android.view.View
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ListView
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import hamster.HamsterApi
import hamster.HamsterApiException
import hamster.ListPage
import hamster.RemoteFile
import hamster.SecureException
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class FilesActivity : Activity() {

    private var api: HamsterApi? = null
    @Volatile private var busy = false

    /** 正在握手（避免 onResume 与 onCreate 重复发起连接）。 */
    @Volatile private var connecting = false

    @Volatile private var stopping = false

    /** 前台可见才做保活：进程被冻结时发 ping 只会得到假失败并触发重连风暴。 */
    @Volatile private var resumed = false

    /** 选完文件回来时如果连接已断，先重连再续传。 */
    private var pendingUpload: File? = null

    /** 传的过程中被断线打断时，最多自动重传几次。 */
    private var uploadRetries = 0

    private var keepalive: Thread? = null

    /* ---- 列表状态 ---- */
    private var dir = "/"
    private val stack = ArrayList<String>()
    private val files = ArrayList<RemoteFile>()
    private var total = 0
    private var loadingMore = false

    private var host = ""
    private var tcpPort = 9100
    private var secret = ""
    private var label = ""

    private lateinit var header: TextView
    private lateinit var status: TextView
    private lateinit var bar: ProgressBar
    private lateinit var list: ListView
    private lateinit var adapter: TwoLineAdapter
    private lateinit var cancelBtn: Button
    private lateinit var overwriteBox: CheckBox

    private val stamp = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault())

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        host = intent.getStringExtra(EXTRA_HOST) ?: ""
        tcpPort = intent.getIntExtra(EXTRA_PORT, 9100)
        secret = intent.getStringExtra(EXTRA_SECRET) ?: ""
        label = intent.getStringExtra(EXTRA_LABEL) ?: host
        title = "Hamster · $label"

        val root = body()
        header = label("连接中…", 18f, bold = true)
        root.addView(header)
        root.addView(spacer(6))

        status = hint("正在握手…")
        root.addView(status)

        bar = ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal).apply {
            max = 100
            progress = 0
            visibility = ProgressBar.GONE
        }
        root.addView(bar)

        root.addView(spacer(8))
        val navRow = row()
        val search = Button(this).apply { text = "搜索" }
        search.setOnClickListener { openSearch() }
        val info = Button(this).apply { text = "详情" }
        info.setOnClickListener { openInfo() }
        navRow.addView(search, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        navRow.addView(info, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        root.addView(navRow)

        val actions = row()
        val refresh = Button(this).apply { text = "刷新" }
        refresh.setOnClickListener { loadDir(dir) }
        val up = Button(this).apply { text = "上传" }
        up.setOnClickListener { pickFile() }
        val mk = Button(this).apply { text = "新建" }
        mk.setOnClickListener { askMkdir() }
        cancelBtn = Button(this).apply {
            text = "取消"
            visibility = View.GONE
            setOnClickListener { cancelTransfer() }
        }
        actions.addView(refresh, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        actions.addView(up, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        actions.addView(mk, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        actions.addView(cancelBtn, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        root.addView(actions)

        overwriteBox = CheckBox(this).apply {
            text = "上传时覆盖同名文件"
            setTextColor(0xFFB9B9C2.toInt())
        }
        root.addView(overwriteBox)

        adapter = TwoLineAdapter(this)
        list = ListView(this).apply {
            this.adapter = this@FilesActivity.adapter
            dividerHeight = dp(1)
            setBackgroundColor(0xFF23232A.toInt())
        }
        root.addView(list, LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f))
        list.setOnItemClickListener { _, _, pos, _ ->
            val f = files.getOrNull(pos) ?: return@setOnItemClickListener
            if (f.dir) {
                stack.add(dir)
                dir = f.path
                loadDir(dir)
            } else {
                download(f)
            }
        }
        list.setOnItemLongClickListener { _, _, pos, _ ->
            val f = files.getOrNull(pos) ?: return@setOnItemLongClickListener true
            showItemMenu(f)
            true
        }
        list.setOnScrollListener(object : android.widget.AbsListView.OnScrollListener {
            override fun onScrollStateChanged(view: android.widget.AbsListView?, state: Int) {}
            override fun onScroll(
                view: android.widget.AbsListView?,
                firstVisibleItem: Int,
                visibleItemCount: Int,
                totalItemCount: Int,
            ) {
                if (totalItemCount > 0 && firstVisibleItem + visibleItemCount >= totalItemCount - 3) {
                    loadMore()
                }
            }
        })

        setContentView(root)
        connect()
        startKeepalive()
    }

    /* ------------------------------------------------------------------ */
    /* 会话                                                               */
    /* ------------------------------------------------------------------ */

    private fun connect() {
        connecting = true
        header.text = "$label · v…"
        status.text = "正在与 $host:$tcpPort 做 §8 握手…"
        background(
            work = {
                val id = androidDeviceIdOf()
                HamsterApi.connect(host, tcpPort, secret, id)
            },
            done = { a ->
                connecting = false
                api = a
                header.text = "${a.peerName.ifEmpty { label }} · v${a.peerVersion}"
                loadDir(dir)
                val f = pendingUpload
                if (f != null) {
                    pendingUpload = null
                    doUpload(a, f)
                }
            },
            failed = { e ->
                connecting = false
                api = null
                status.text = "连接失败：${e.message}"
            },
        )
    }

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

    /**
     * 保活：移动网络/NAT/服务端的空闲回收都会掐掉静默连接（模拟器上实测约 20 s），
     * 而用户可能正在挑文件。每 5 s 发一次轻量请求（走 §8 记录层，密文）把链路焐住；
     * 一旦失败就自动重连，用户无感。
     */
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
                    a.protocolInfo() // 内部就是一次 ping → pong
                } catch (e: Exception) {
                    if (stopping) return@Thread
                    runOnUiThread { onKeepaliveLost(e) }
                    return@Thread
                }
            }
        }.apply {
            isDaemon = true
            name = "hamster-keepalive"
            start()
        }
    }

    private fun onKeepaliveLost(e: Exception) {
        if (stopping || busy) return
        dropApi()
        status.text = "连接已断开（${e.message}），正在重连…"
        connect()
    }

    private fun dropApi() {
        try {
            api?.close()
        } catch (_: Exception) {
        }
        api = null
    }

    override fun onResume() {
        super.onResume()
        resumed = true
        // 从文件选择器/其它页面回来时连接多半已经断了（进程被冻结过），这里补一次重连
        if (api == null && !connecting && !busy && !stopping) connect()
        else reloadCurrent()
    }

    override fun onPause() {
        resumed = false
        super.onPause()
    }

    @Deprecated("framework Activity 只有 onBackPressed 可用（没有 OnBackPressedDispatcher）")
    override fun onBackPressed() {
        if (busy) return
        if (stack.isEmpty()) {
            super.onBackPressed()
            return
        }
        dir = stack.removeAt(stack.size - 1)
        loadDir(dir)
    }

    override fun onDestroy() {
        stopping = true
        keepalive?.interrupt()
        keepalive = null
        dropApi()
        super.onDestroy()
    }

    /* ------------------------------------------------------------------ */
    /* 列表                                                               */
    /* ------------------------------------------------------------------ */

    private fun reloadCurrent() {
        if (files.isNotEmpty()) renderList()
    }

    /** 重新从第一页取当前目录。 */
    private fun loadDir(path: String) {
        val a = api
        if (a == null) {
            if (!busy && !connecting) connect()
            return
        }
        if (busy) return
        dir = path
        files.clear()
        total = 0
        loadingMore = false
        status.text = "读取 ${if (path.isEmpty()) "/" else path} …"
        fetchPage(a, 0, first = true)
    }

    private fun loadMore() {
        val a = api ?: return
        if (busy || loadingMore || connecting) return
        if (files.size >= total) return
        loadingMore = true
        fetchPage(a, files.size, first = false)
    }

    private fun fetchPage(a: HamsterApi, offset: Int, first: Boolean) {
        background(
            work = { a.listPage(dir, offset, PAGE_SIZE) },
            done = { page: ListPage ->
                loadingMore = false
                if (first) files.clear()
                files.addAll(page.entries)
                total = page.total
                renderList()
                val shown = if (dir.isEmpty()) "/" else dir
                status.text = "$shown · 已显示 ${files.size}/$total 项"
            },
            failed = { e ->
                loadingMore = false
                onActionFailed(e, "列表")
            },
        )
    }

    private fun renderList() {
        adapter.submit(files.map { f ->
            if (f.dir) {
                "📁 ${f.name}" to "目录"
            } else {
                val when0 = if (f.mtime > 0) stamp.format(Date(f.mtime * 1000)) else "时间未知"
                f.name to "${human(f.size)} · $when0 · 点击下载 · 长按更多"
            }
        })
    }

    private fun showItemMenu(f: RemoteFile) {
        val actions = if (f.dir) arrayOf("打开", "删除", "详情") else arrayOf("下载", "删除", "详情")
        AlertDialog.Builder(this)
            .setTitle(f.name)
            .setItems(actions) { _, which ->
                when (actions[which]) {
                    "打开" -> {
                        stack.add(dir)
                        dir = f.path
                        loadDir(dir)
                    }
                    "下载" -> download(f)
                    "删除" -> confirmDelete(f)
                    "详情" -> showDetail(f)
                }
            }
            .show()
    }

    private fun showDetail(f: RemoteFile) {
        val when0 = if (f.mtime > 0) stamp.format(Date(f.mtime * 1000)) else "未知"
        AlertDialog.Builder(this)
            .setTitle("详情")
            .setMessage(
                "名称：${f.name}\n路径：${f.path}\n类型：${if (f.dir) "目录" else "文件"}\n" +
                    "大小：${human(f.size)}（${f.size} 字节）\n修改时间：$when0",
            )
            .setPositiveButton("关闭", null)
            .show()
    }

    private fun confirmDelete(f: RemoteFile) {
        AlertDialog.Builder(this)
            .setTitle("删除")
            .setMessage("确认删除 ${f.name}？此操作直接作用于服务端，不可撤销。")
            .setNegativeButton("取消", null)
            .setPositiveButton("删除") { _, _ -> doDelete(f) }
            .show()
    }

    private fun doDelete(f: RemoteFile) {
        val a = api
        if (a == null) {
            connect()
            return
        }
        if (busy) return
        busy = true
        cancelBtn.visibility = View.VISIBLE
        status.text = "删除 ${f.name} …"
        background(
            work = { a.delete(f.path) },
            done = { path ->
                busy = false
                cancelBtn.visibility = View.GONE
                status.text = "已删除 $path"
                loadDir(dir)
            },
            failed = { e -> onActionFailed(e, "删除") },
        )
    }

    private fun askMkdir() {
        val a = api
        if (a == null) {
            connect()
            return
        }
        if (busy) return
        val input = EditText(this).apply { hint = "新目录名" }
        AlertDialog.Builder(this)
            .setTitle("在 ${if (dir.isEmpty()) "/" else dir} 下新建目录")
            .setView(input)
            .setNegativeButton("取消", null)
            .setPositiveButton("创建") { _, _ ->
                val name = input.text.toString().trim()
                if (name.isEmpty()) {
                    status.text = "目录名不能为空"
                } else {
                    doMkdir(a, name)
                }
            }
            .show()
    }

    private fun doMkdir(a: HamsterApi, name: String) {
        busy = true
        cancelBtn.visibility = View.VISIBLE
        status.text = "创建 $name …"
        val target = if (dir.isEmpty() || dir == "/") name else "${dir.trimEnd('/')}/$name"
        background(
            work = { a.mkdir(target) },
            done = { path ->
                busy = false
                cancelBtn.visibility = View.GONE
                status.text = "已创建 $path"
                loadDir(dir)
            },
            failed = { e -> onActionFailed(e, "新建目录") },
        )
    }

    /* ------------------------------------------------------------------ */
    /* 传输                                                               */
    /* ------------------------------------------------------------------ */

    private fun download(f: RemoteFile) {
        val a = api
        if (a == null) {
            connect()
            return
        }
        if (busy) return
        val destDir = File(getExternalFilesDir(null), "Downloads").apply { mkdirs() }
        val dest = File(destDir, f.name)
        busy = true
        bar.visibility = ProgressBar.VISIBLE
        bar.progress = 0
        cancelBtn.visibility = View.VISIBLE
        status.text = "下载 ${f.name} …"
        background(
            work = {
                a.download(f.path, dest) { done, tot ->
                    if (tot > 0) {
                        val pct = (done * 100 / tot).toInt()
                        runOnUiThread { bar.progress = pct }
                    }
                }
            },
            done = { n ->
                busy = false
                bar.visibility = ProgressBar.GONE
                cancelBtn.visibility = View.GONE
                status.text = "已下载 ${human(n)} → ${dest.absolutePath}"
                Toast.makeText(this, "保存到 ${dest.name}", Toast.LENGTH_SHORT).show()
            },
            failed = { e -> onActionFailed(e, "下载") },
        )
    }

    /** 取消当前传输：直接打断连接（协议没有取消帧），随后自动重连。 */
    private fun cancelTransfer() {
        if (!busy) return
        val a = api
        api = null
        status.text = "已取消，正在重连…"
        background(
            work = { a?.abort() },
            done = { connect() },
            failed = { connect() },
        )
        busy = false
        bar.visibility = ProgressBar.GONE
        cancelBtn.visibility = View.GONE
    }

    private fun pickFile() {
        // 注意：这里**不**要求 api 活着。系统文件选择器会把本进程冻结，
        // 冻结期间连接必断、新连接也超时；所以流程是"先选文件，回来再连再传"。
        val i = Intent(Intent.ACTION_GET_CONTENT).apply { type = "*/*" }
        @Suppress("DEPRECATION")
        startActivityForResult(i, REQ_PICK)
    }

    @Deprecated("framework Activity 没有 ActivityResult API 时只能用这个")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != REQ_PICK || resultCode != RESULT_OK) return
        val uri: Uri = data?.data ?: return
        if (busy) return
        val name = displayName(uri)
        val tmp = File(cacheDir, name)
        busy = true
        bar.visibility = ProgressBar.VISIBLE
        bar.progress = 0
        status.text = "准备上传 $name …"
        background(
            work = {
                contentResolver.openInputStream(uri)?.use { input ->
                    tmp.outputStream().use { out -> input.copyTo(out) }
                } ?: throw IllegalStateException("无法读取所选文件")
                tmp
            },
            done = { f ->
                busy = false
                startUploadOrReconnect(f)
            },
            failed = { e ->
                busy = false
                bar.visibility = ProgressBar.GONE
                tmp.delete()
                status.text = "读取所选文件失败：${e.message}"
            },
        )
    }

    /** api 活着就直接传；已经断了就先重连，连上后由 connect() 的 done 续传。 */
    private fun startUploadOrReconnect(f: File) {
        uploadRetries = 2
        val a = api
        if (a == null || connecting) {
            pendingUpload = f
            if (connecting) {
                status.text = "正在重连，连上后继续上传…"
            } else {
                status.text = "连接已断开，重连后继续上传…"
                connect()
            }
            return
        }
        doUpload(a, f)
    }

    private fun doUpload(a: HamsterApi, f: File) {
        busy = true
        bar.visibility = ProgressBar.VISIBLE
        bar.progress = 0
        cancelBtn.visibility = View.VISIBLE
        val overwrite = overwriteBox.isChecked
        status.text = "上传 ${f.name}${if (overwrite) "（覆盖）" else ""} …"
        background(
            work = {
                a.upload(f, dir, overwrite = overwrite) { done, tot ->
                    if (tot > 0) {
                        val pct = (done * 100 / tot).toInt()
                        runOnUiThread { bar.progress = pct }
                    }
                }
            },
            done = { remote ->
                busy = false
                bar.visibility = ProgressBar.GONE
                cancelBtn.visibility = View.GONE
                f.delete()
                status.text = "已上传 → $remote"
                loadDir(dir)
            },
            failed = { e ->
                busy = false
                bar.visibility = ProgressBar.GONE
                cancelBtn.visibility = View.GONE
                val code = errorCode(e)
                if (code in TRANSPORT_CODES && uploadRetries > 0) {
                    // 连接在传的过程中断了：留着临时文件，重连后重传
                    uploadRetries--
                    pendingUpload = f
                    api = null
                    status.text = "上传中断（$code），重连后自动重传…"
                    connect()
                } else {
                    f.delete()
                    onActionFailed(e, "上传")
                }
            },
        )
    }

    /* ------------------------------------------------------------------ */
    /* 杂项                                                               */
    /* ------------------------------------------------------------------ */

    private fun openSearch() {
        val s = secret
        if (s.isEmpty()) return
        startActivity(
            Intent(this, SearchActivity::class.java).apply {
                putExtra(SearchActivity.EXTRA_HOST, host)
                putExtra(SearchActivity.EXTRA_PORT, tcpPort)
                putExtra(SearchActivity.EXTRA_SECRET, s)
                putExtra(SearchActivity.EXTRA_LABEL, label)
            },
        )
    }

    private fun openInfo() {
        val s = secret
        if (s.isEmpty()) return
        startActivity(
            Intent(this, DeviceInfoActivity::class.java).apply {
                putExtra(DeviceInfoActivity.EXTRA_HOST, host)
                putExtra(DeviceInfoActivity.EXTRA_PORT, tcpPort)
                putExtra(DeviceInfoActivity.EXTRA_SECRET, s)
                putExtra(DeviceInfoActivity.EXTRA_LABEL, label)
            },
        )
    }

    /**
     * 统一失败出口：传输层错误（对端关闭/超时/连接被中止）就把连接置空，
     * 下次动作自动重连；业务错误（exists/path_denied/…）原样显示。
     */
    private fun onActionFailed(e: Exception, what: String) {
        busy = false
        bar.visibility = ProgressBar.GONE
        cancelBtn.visibility = View.GONE
        val code = errorCode(e)
        if (code in TRANSPORT_CODES) {
            dropApi()
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

    private fun displayName(uri: Uri): String {
        try {
            contentResolver.query(uri, null, null, null, null)?.use { c ->
                if (c.moveToFirst()) {
                    val idx = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    if (idx >= 0) {
                        val v = c.getString(idx)
                        if (!v.isNullOrBlank()) return v
                    }
                }
            }
        } catch (_: Exception) {
        }
        return uri.lastPathSegment ?: "upload.bin"
    }

    private fun human(n: Long): String = when {
        n < 1024 -> "$n B"
        n < 1024 * 1024 -> String.format(Locale.US, "%.1f KB", n / 1024.0)
        n < 1024L * 1024 * 1024 -> String.format(Locale.US, "%.1f MB", n / 1048576.0)
        else -> String.format(Locale.US, "%.2f GB", n / 1073741824.0)
    }

    companion object {
        const val EXTRA_HOST = "host"
        const val EXTRA_PORT = "port"
        const val EXTRA_SECRET = "secret"
        const val EXTRA_LABEL = "label"
        private const val REQ_PICK = 1001

        /** 一页条数：服务端 list 的 limit 上限是 1000，这里取小一点保证滚动流畅。 */
        private const val PAGE_SIZE = 100

        /** 保活节奏：远小于实测的空闲回收窗口（约 20 s），又不至于太吵。 */
        private const val KEEPALIVE_MS = 5000L

        /** 这些错误码意味着"连接没了"，重连才有意义。 */
        private val TRANSPORT_CODES = setOf(
            "io_error", "socket_closed", "timeout", "connect_failed", "not_encrypted", "closed",
        )
    }
}
