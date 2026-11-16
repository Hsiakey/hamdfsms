/*
 * DirectoryPickerActivity.kt — 纯代码目录选择器（不用 XML / 不用 AndroidX）
 *
 * 只列出**目录**（不显示文件，避免误选一个文件当根）。从共享存储根
 * （通常是 /storage/emulated/0）开始，逐级向下浏览；"上级"在最顶层会被禁用，
 * 避免用户一路点到 / 选出一个系统目录当守护端的文件树根。
 *
 * 权限：没授权时列不出共享存储的内容（listFiles() 返回 null 或空），顶部会给出
 * 一句话说明并显示【去授权】按钮；API ≤29 走运行时权限，API 30+ 跳系统设置页，
 * 回到本页后 onResume 会自动重试列目录。
 *
 * 结果：选中时
 *   setResult(RESULT_OK, Intent().putExtra(EXTRA_PATH, <绝对路径>))
 * 由 ConfigActivity 用 startActivityForResult 拉起并把路径写进 DaemonPrefs。
 *
 * 为什么不用 SAF：见 StorageRoot.kt 顶部注释——DaemonCore 全部基于 java.io.File，
 * 换 URI 语义要重写 1554 行业务层并失去随机读写。
 */
package hamster.app.daemon

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.graphics.drawable.ColorDrawable
import android.os.Bundle
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ListView
import android.widget.TextView
import android.widget.Toast
import java.io.File

class DirectoryPickerActivity : Activity() {

    private lateinit var pathView: TextView
    private lateinit var noteView: TextView
    private lateinit var listView: ListView
    private lateinit var adapter: TwoLineAdapter
    private lateinit var grantButton: Button
    private lateinit var upButton: Button

    /** 浏览起点：共享存储根；不允许再往上。 */
    private lateinit var browseRoot: File

    private lateinit var currentDir: File

    /** 与 [adapter] 的行一一对应（按下标取目录）。 */
    private val entries = ArrayList<File>()

    /** 上一次 listFiles 是否失败（没权限/系统限制），用于刷新提示文案。 */
    private var listingFailed = false

    /** 首次 onResume 只是普通进入页面，不做"从授权页返回"的重试。 */
    private var resumedOnce = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        title = "选择存储目录"

        val root = body()
        root.addView(label("选择守护端的存储根目录", 20f, bold = true))
        root.addView(spacer(4))
        root.addView(
            hint(
                "只列出子目录。选中的目录会成为守护端文件树的根：" +
                    "桌面端所有路径都被限制在这个目录内（无法用 .. 跳出）。",
            ),
        )

        root.addView(spacer(12))
        pathView = label("", 13f).apply {
            setTextColor(0xFFEDEDF0.toInt())
            setTextIsSelectable(true)
        }
        root.addView(pathView)

        noteView = hint("").apply { setTextColor(0xFFE0B060.toInt()) }
        root.addView(noteView)

        grantButton = Button(this).apply {
            text = "去授权"
            visibility = View.GONE
            setOnClickListener { requestStorageAccess(this@DirectoryPickerActivity, REQ_STORAGE) }
        }
        root.addView(
            grantButton,
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT),
        )

        root.addView(spacer(8))
        listView = ListView(this).apply {
            divider = ColorDrawable(0xFF303036.toInt())
            dividerHeight = dp(1)
            setBackgroundColor(Color.parseColor("#1B1B1F"))
        }
        adapter = TwoLineAdapter(this)
        listView.adapter = adapter
        listView.setOnItemClickListener { _, _, position, _ -> onEntryClicked(position) }
        root.addView(
            listView,
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f),
        )

        val row1 = row()
        upButton = Button(this).apply {
            text = "上级"
            setOnClickListener { onUpClicked() }
        }
        val chooseButton = Button(this).apply {
            text = "选择此目录"
            setOnClickListener { onChooseClicked() }
        }
        row1.addView(upButton, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        row1.addView(chooseButton, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        root.addView(spacer(8))
        root.addView(row1)

        val row2 = row()
        val cancelButton = Button(this).apply {
            text = "取消"
            setOnClickListener {
                setResult(RESULT_CANCELED)
                finish()
            }
        }
        row2.addView(cancelButton, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        root.addView(spacer(4))
        root.addView(row2)

        setContentView(root)

        browseRoot = sharedStorageRoot().dir
        if (!tryEnter(browseRoot)) {
            // 没权限时的常见路径：仍然显示起点路径，列表为空，提示去授权。
            currentDir = browseRoot
            pathView.text = browseRoot.absolutePath
            upButton.isEnabled = false
            entries.clear()
            adapter.submit(emptyList())
            listingFailed = true
            refreshNotes()
        }
    }

    override fun onResume() {
        super.onResume()
        if (!resumedOnce) {
            resumedOnce = true
            refreshNotes()
            return
        }
        // 从系统授权页返回：拿到权限就自动重试当前目录，用户不用再点一次。
        if (hasStorageAccess(this)) {
            tryEnter(currentDir)
        }
        refreshNotes()
    }

    @Suppress("DEPRECATION", "OVERRIDE_DEPRECATION")
    override fun onBackPressed() {
        if (currentDir.absolutePath != browseRoot.absolutePath) {
            val parent = currentDir.parentFile
            if (parent != null && tryEnter(parent)) return
        }
        setResult(RESULT_CANCELED)
        super.onBackPressed()
    }

    @Suppress("DEPRECATION")
    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray,
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode != REQ_STORAGE) return
        if (hasStorageAccess(this)) {
            tryEnter(currentDir)
        }
        refreshNotes()
    }

    /* ------------------------------------------------------------------ */
    /* 目录浏览                                                            */
    /* ------------------------------------------------------------------ */

    /** 列出 [dir] 并切换过去；读不到返回 false（调用方保留原状态并提示）。 */
    private fun tryEnter(dir: File): Boolean {
        if (!safeCanRead(dir)) return false
        val children = try {
            dir.listFiles()
        } catch (_: Exception) {
            null
        } ?: return false

        currentDir = dir
        pathView.text = dir.absolutePath
        upButton.isEnabled = dir.parentFile != null && dir.absolutePath != browseRoot.absolutePath

        val dirs = children
            .filter { it.isDirectory }
            .sortedWith(compareBy(String.CASE_INSENSITIVE_ORDER) { it.name })
        entries.clear()
        entries.addAll(dirs)
        adapter.submit(
            dirs.map { d ->
                d.name to if (safeCanRead(d)) "" else "不可读（无权限）"
            },
        )
        listingFailed = false
        refreshNotes()
        return true
    }

    private fun onEntryClicked(position: Int) {
        val dir = entries.getOrNull(position) ?: return
        if (!tryEnter(dir)) {
            toast("无权限读取：${dir.name}")
        }
    }

    private fun onUpClicked() {
        if (currentDir.absolutePath == browseRoot.absolutePath) {
            toast("已经是共享存储根目录，不能再往上")
            return
        }
        val parent = currentDir.parentFile
        if (parent == null || !tryEnter(parent)) {
            toast("无法读取上级目录")
        }
    }

    private fun onChooseClicked() {
        val root = rootFromPath(currentDir.absolutePath)
        if (root == null) {
            toast("这个目录不可用（不存在 / 不是目录 / 不可读），请换一个")
            return
        }
        setResult(RESULT_OK, Intent().putExtra(EXTRA_PATH, root.displayPath))
        finish()
    }

    /* ------------------------------------------------------------------ */
    /* 提示                                                                */
    /* ------------------------------------------------------------------ */

    private fun refreshNotes() {
        val granted = hasStorageAccess(this)
        grantButton.visibility = if (granted) View.GONE else View.VISIBLE
        noteView.visibility = View.VISIBLE
        noteView.text = when {
            !granted -> if (requiredStorageAccess() == StorageAccess.ALL_FILES_ACCESS) {
                "尚未授予「所有文件访问」权限：点【去授权】跳系统设置页，授权后返回这里会自动刷新。"
            } else {
                "尚未授予读写存储权限：点【去授权】允许后返回这里即可浏览。"
            }
            listingFailed -> "无法读取这个目录（权限不足，或已被系统限制）。"
            entries.isEmpty() -> "（这个目录下没有子目录）"
            else -> {
                noteView.visibility = View.GONE
                ""
            }
        }
    }

    private fun safeCanRead(f: File): Boolean = try {
        f.canRead()
    } catch (_: Exception) {
        false
    }

    private fun toast(message: String) {
        try {
            Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
        } catch (_: Exception) {
            // 界面提示失败不能影响浏览流程。
        }
    }

    companion object {
        /** 返回给 ConfigActivity 的绝对路径。 */
        const val EXTRA_PATH = "hamster.app.daemon.extra.DIRECTORY_PATH"

        private const val REQ_STORAGE = 3401
    }
}
