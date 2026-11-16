/*
 * SearchActivity.kt — 搜索页：关键词 → 分页结果 → 下载
 *
 * 与 FilesActivity 共用同一套连接语义：
 *   · HamsterApi 是单连接、一问一答，界面一次只允许一个动作在飞（busy）；
 *   · 传输层错误一律把 api 置空并自动重连，用户不用退出重进；
 *   · 前台每 5 s 用 info() 保活，onPause 停 ping，onResume 发现断线就重连。
 *
 * 分页：服务端按 offset/limit 返回 total；列表滑到底部自动取下一页，
 * 直到取满 total 或某页返回空。搜索页只负责找文件，目录浏览仍回文件页。
 */
package hamster.app.manager

import android.app.Activity
import android.os.Bundle
import android.view.View
import android.view.inputmethod.EditorInfo
import android.widget.AbsListView
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ListView
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import hamster.HamsterApi
import hamster.HamsterApiException
import hamster.SearchHit
import hamster.SearchPage
import hamster.SecureException
import java.io.File
import java.util.Locale

class SearchActivity : Activity() {

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

    /** 断线期间点搜索时先记下来，握手成功后自动补一次。 */
    private var pendingSearch: String? = null

    /** search() 返回的 path 是服务端视角；用 info().monitorPath 转成页面上的相对路径。 */
    @Volatile private var monitorPath = ""

    private var query = ""
    private var total = 0
    private var hasMore = false
    private val hits = ArrayList<SearchHit>()

    private lateinit var header: TextView
    private lateinit var queryInput: EditText
    private lateinit var status: TextView
    private lateinit var bar: ProgressBar
    private lateinit var list: ListView
    private lateinit var adapter: TwoLineAdapter

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        host = intent.getStringExtra(EXTRA_HOST) ?: ""
        tcpPort = intent.getIntExtra(EXTRA_PORT, 9100)
        secret = intent.getStringExtra(EXTRA_SECRET) ?: ""
        label = intent.getStringExtra(EXTRA_LABEL) ?: host
        title = "Hamster · 搜索"

        val root = body()
        header = label("搜索 · $label", 18f, bold = true)
        root.addView(header)
        root.addView(spacer(6))
        root.addView(hint("在设备索引里按文件名/路径搜索；每页 $PAGE_SIZE 条，滑到底部自动加载。"))
        root.addView(spacer(10))

        val searchRow = row()
        queryInput = EditText(this).apply {
            hint = "关键词（不能为空）"
            setSingleLine(true)
            setTextColor(0xFFEDEDF0.toInt())
            setHintTextColor(0xFF6E6E77.toInt())
            imeOptions = EditorInfo.IME_ACTION_SEARCH
            setOnEditorActionListener { _, actionId, _ ->
                if (actionId == EditorInfo.IME_ACTION_SEARCH || actionId == EditorInfo.IME_ACTION_DONE) {
                    searchFromInput()
                    true
                } else {
                    false
                }
            }
        }
        val searchBtn = Button(this).apply {
            text = "搜索"
            setOnClickListener { searchFromInput() }
        }
        searchRow.addView(
            queryInput,
            LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f),
        )
        searchRow.addView(
            searchBtn,
            LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT),
        )
        root.addView(searchRow)

        adapter = TwoLineAdapter(this)
        list = ListView(this).apply {
            this.adapter = this@SearchActivity.adapter
            dividerHeight = dp(1)
            setBackgroundColor(0xFF23232A.toInt())
        }
        root.addView(list, LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f))
        list.setOnItemClickListener { _, _, pos, _ ->
            val hit = hits.getOrNull(pos) ?: return@setOnItemClickListener
            if (hit.dir) {
                // 不在这里做目录导航：搜索页只管找文件，浏览仍回 FilesActivity。
                Toast.makeText(this, "目录请回文件页浏览", Toast.LENGTH_SHORT).show()
                status.text = "「${hit.name}」是目录，请回文件页浏览。"
            } else {
                download(hit)
            }
        }
        list.setOnScrollListener(object : AbsListView.OnScrollListener {
            override fun onScrollStateChanged(view: AbsListView?, scrollState: Int) {
                // 只需要 onScroll 的位置判断
            }

            override fun onScroll(
                view: AbsListView?,
                firstVisibleItem: Int,
                visibleItemCount: Int,
                totalItemCount: Int,
            ) {
                if (totalItemCount == 0) return
                // 提前两行预取，滑动时不容易看到“卡住”的空档。
                if (firstVisibleItem + visibleItemCount >= totalItemCount - 2) maybeLoadMore()
            }
        })

        root.addView(spacer(8))
        status = hint("输入关键词后点【搜索】。")
        root.addView(status)

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

        setContentView(root)
        connect()
        startKeepalive()
    }

    /* ------------------------------------------------------------------ 搜索 / 分页 */

    private fun searchFromInput() {
        val q = queryInput.text.toString().trim()
        if (q.isEmpty()) {
            status.text = "请输入关键词"
            Toast.makeText(this, "请输入关键词", Toast.LENGTH_SHORT).show()
            return
        }
        requestSearch(q, firstPage = true)
    }

    private fun requestSearch(q: String, firstPage: Boolean) {
        val a = api
        if (a == null) {
            pendingSearch = q
            status.text = if (connecting) {
                "正在连接，连上后自动搜索…"
            } else {
                "连接已断开，正在重连后搜索…"
            }
            if (!connecting) connect()
            return
        }
        if (busy) return

        busy = true
        if (firstPage) {
            query = q
            hits.clear()
            total = 0
            hasMore = false
            adapter.submit(emptyList())
            showIndeterminate("正在搜索「$q」…")
        } else {
            showIndeterminate("加载更多…")
        }

        val offset = if (firstPage) 0 else hits.size
        background(
            work = {
                // 第一次搜索顺手取 monitor_path，用于把服务端绝对路径显示成相对路径。
                if (monitorPath.isEmpty()) monitorPath = a.info().monitorPath
                a.search(q, offset = offset, limit = PAGE_SIZE)
            },
            done = { page -> applyPage(q, page) },
            failed = { e -> onActionFailed(e, "搜索") },
        )
    }

    private fun applyPage(q: String, page: SearchPage) {
        busy = false
        hideBar()
        hits.addAll(page.files)
        total = page.total
        hasMore = page.files.isNotEmpty() && hits.size < total

        adapter.submit(hits.map { h ->
            if (h.dir) {
                "📁 ${h.name}" to "目录 · ${relativePath(h.path)}"
            } else {
                h.name to "${human(h.size)} · ${relativePath(h.path)}"
            }
        })

        status.text = when {
            hits.isEmpty() -> "没有找到与「$q」匹配的文件。"
            else -> "「$q」 · 共 $total 条 · 已加载 ${hits.size} 条" +
                if (hasMore) " · 继续下滑加载更多" else " · 已全部加载"
        }
    }

    /** 滑到底部时取下一页；api 为空说明链路已断，不在这里偷偷重连（交给搜索/刷新动作）。 */
    private fun maybeLoadMore() {
        if (!hasMore || busy || connecting) return
        if (api == null) return
        requestSearch(query, firstPage = false)
    }

    /* ------------------------------------------------------------------ 下载 */

    private fun download(hit: SearchHit) {
        val a = api
        if (a == null) {
            status.text = "连接已断开，正在重连…"
            connect()
            return
        }
        if (busy) return

        val destDir = File(getExternalFilesDir(null), "Downloads").apply { mkdirs() }
        val safeName = File(hit.name).name.ifEmpty { "download.bin" }
        val dest = File(destDir, safeName)

        busy = true
        bar.isIndeterminate = false
        bar.progress = 0
        bar.visibility = View.VISIBLE
        status.text = "下载 ${hit.name} …"
        background(
            work = {
                a.download(hit.path, dest) { done, totalBytes ->
                    if (totalBytes > 0) {
                        val pct = (done * 100 / totalBytes).toInt()
                        runOnUiThread { showProgress(pct) }
                    }
                }
            },
            done = { n ->
                busy = false
                hideBar()
                val msg = "已下载 ${human(n)} → ${dest.absolutePath}"
                status.text = msg
                Toast.makeText(this, "已保存到 ${dest.absolutePath}", Toast.LENGTH_SHORT).show()
            },
            failed = { e -> onActionFailed(e, "下载") },
        )
    }

    /* ------------------------------------------------------------------ 连接 / 保活 */

    private fun connect() {
        if (connecting || stopping) return
        connecting = true
        header.text = "搜索 · $label · 连接中…"
        status.text = "正在与 $host:$tcpPort 做 §8 握手…"
        background(
            work = { HamsterApi.connect(host, tcpPort, secret, androidDeviceIdOf()) },
            done = { a ->
                connecting = false
                api = a
                header.text = "搜索 · ${a.peerName.ifEmpty { label }} · v${a.peerVersion}"
                // 保活线程在一次失败后会退出；重连成功后把它补回来。
                if (keepalive?.isAlive != true) startKeepalive()

                val q = pendingSearch
                pendingSearch = null
                if (q != null) {
                    requestSearch(q, firstPage = true)
                } else {
                    status.text = "已连接。输入关键词后点【搜索】。"
                }
            },
            failed = { e ->
                connecting = false
                api = null
                busy = false
                hideBar()
                status.text = "连接失败：${e.message}"
            },
        )
    }

    /**
     * 保活：移动网络/NAT/服务端的空闲回收都会掐掉静默连接（模拟器上实测约 20 s）。
     * 每 5 s 发一次轻量 info() 把链路焐住；失败就交给主线程清空 api 并重连。
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
                    val info = a.info()
                    if (info.monitorPath.isNotEmpty()) monitorPath = info.monitorPath
                } catch (e: Exception) {
                    if (stopping) return@Thread
                    runOnUiThread { onKeepaliveLost(e) }
                    return@Thread
                }
            }
        }.apply {
            isDaemon = true
            name = "hamster-search-keepalive"
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
        // 从后台回来时连接多半已经被冻结/回收，这里补一次重连。
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

    /* ------------------------------------------------------------------ 错误 / 进度 */

    /**
     * 统一失败出口：传输层错误（对端关闭/超时/连接被中止）就把连接置空，
     * 自动重连；业务错误（path_denied/…）只显示，不重连。
     */
    private fun onActionFailed(e: Exception, what: String) {
        busy = false
        hideBar()
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

    private fun showIndeterminate(msg: String) {
        status.text = msg
        bar.isIndeterminate = true
        bar.progress = 0
        bar.visibility = View.VISIBLE
    }

    private fun showProgress(pct: Int) {
        if (bar.isIndeterminate) bar.isIndeterminate = false
        bar.progress = pct.coerceIn(0, 100)
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

    /** 把服务端绝对路径按 monitor_path 缩短；拿不到根目录时原样显示。 */
    private fun relativePath(path: String): String {
        val p = path.replace('\\', '/')
        val root = monitorPath.trimEnd('/', '\\').replace('\\', '/')
        if (root.isEmpty()) return path
        if (p.length > root.length && p.startsWith(root, ignoreCase = true) &&
            p[root.length] == '/'
        ) {
            val rest = p.substring(root.length).trimStart('/')
            if (rest.isNotEmpty()) return rest
        }
        return path
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

        /** 服务端 search 的 limit 上限是 1000；100 条一页在手机列表里滑动足够顺。 */
        private const val PAGE_SIZE = 100

        /** 保活节奏：远小于实测的空闲回收窗口（约 20 s），又不至于太吵。 */
        private const val KEEPALIVE_MS = 5000L

        /** 这些错误码意味着“连接没了”，重连才有意义。 */
        private val TRANSPORT_CODES = setOf(
            "io_error", "socket_closed", "timeout", "connect_failed", "not_encrypted", "closed",
        )
    }
}
