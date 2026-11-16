/*
 * Ui.kt — 纯代码界面小工具（不用 XML、不用 AndroidX）
 *
 * 与 app-manager 的 Ui.kt 各自一份，**刻意不共享**：
 *   · app-manager 与 app-daemon 是两个独立 APK，各自只有一个源码目录；
 *   · 打包流水线（tools/build-apk.ps1）按模块传 -Src，不引入跨模块的源码依赖；
 *   · 共享一个小文件省不了多少代码，却会让两个应用之间出现隐形耦合。
 * 因此这里是从 app-manager 复制过来的同款工具，包名改成 hamster.app.daemon；
 * 改这个文件时不需要（也不应该）去动 app-manager 的那一份。
 *
 * 为什么全是代码：安卓端的打包链路刻意不带第三方依赖（AppCompat/Material 的
 * 缓存版本在离线环境下凑不齐），因此界面只用 framework 的 View/Widget。
 * 代价是没有主题化控件，收益是 `kotlinc + d8 + aapt2 + apksigner` 就能出包。
 */
package hamster.app.daemon

import android.content.Context
import android.graphics.Color
import android.graphics.Typeface
import android.os.Handler
import android.os.Looper
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.BaseAdapter
import android.widget.LinearLayout
import android.widget.TextView

/** 后台线程执行 [work]，结果回主线程交给 [done]；异常交给 [failed]。 */
fun <T> background(
    work: () -> T,
    done: (T) -> Unit,
    failed: (Exception) -> Unit,
) {
    val main = Handler(Looper.getMainLooper())
    Thread {
        try {
            val r = work()
            main.post { done(r) }
        } catch (e: Exception) {
            // 界面只显示一行消息，完整栈必须留在 logcat，否则线上问题没法查
            android.util.Log.e("HamsterDaemonUi", "后台任务失败: ${e.javaClass.name}", e)
            var c: Throwable? = e.cause
            var depth = 0
            while (c != null && depth < 6) {
                android.util.Log.e("HamsterDaemonUi", "  cause[$depth]: ${c.javaClass.name}: ${c.message}")
                c = c.cause
                depth++
            }
            main.post { failed(e) }
        }
    }.apply { isDaemon = true }.start()
}

fun Context.dp(v: Int): Int =
    TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v.toFloat(), resources.displayMetrics).toInt()

fun Context.label(text: String, sizeSp: Float = 14f, bold: Boolean = false): TextView =
    TextView(this).apply {
        this.text = text
        setTextSize(TypedValue.COMPLEX_UNIT_SP, sizeSp)
        if (bold) setTypeface(typeface, Typeface.BOLD)
        setTextColor(Color.parseColor("#E6E6E6"))
    }

fun Context.body(): LinearLayout = LinearLayout(this).apply {
    orientation = LinearLayout.VERTICAL
    setPadding(dp(20), dp(24), dp(20), dp(16))
    setBackgroundColor(Color.parseColor("#1B1B1F"))
}

fun Context.spacer(h: Int): View = View(this).apply {
    layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(h))
}

fun Context.hint(text: String): TextView = label(text, 12f).apply {
    setTextColor(Color.parseColor("#8A8A93"))
}

/** 两行列表项适配器：主标题 + 副标题（framework 的 BaseAdapter，零依赖）。 */
class TwoLineAdapter(
    private val ctx: Context,
    private val items: MutableList<Pair<String, String>> = mutableListOf(),
) : BaseAdapter() {

    fun submit(next: List<Pair<String, String>>) {
        items.clear()
        items.addAll(next)
        notifyDataSetChanged()
    }

    override fun getCount(): Int = items.size
    override fun getItem(position: Int): Any = items[position]
    override fun getItemId(position: Int): Long = position.toLong()

    override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
        val row = (convertView as? LinearLayout) ?: LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(ctx.dp(16), ctx.dp(12), ctx.dp(16), ctx.dp(12))
            addView(TextView(ctx).apply {
                id = 1
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 16f)
                setTextColor(Color.parseColor("#EDEDF0"))
            })
            addView(TextView(ctx).apply {
                id = 2
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
                setTextColor(Color.parseColor("#8A8A93"))
                setPadding(0, ctx.dp(3), 0, 0)
            })
        }
        val (title, subtitle) = items[position]
        (row.findViewById<TextView>(1)).text = title
        val sub = row.findViewById<TextView>(2)
        sub.text = subtitle
        sub.visibility = if (subtitle.isEmpty()) View.GONE else View.VISIBLE
        return row
    }
}

/** 简单横条：给按钮行用。 */
fun Context.row(): LinearLayout = LinearLayout(this).apply {
    orientation = LinearLayout.HORIZONTAL
    gravity = Gravity.CENTER_VERTICAL
}
