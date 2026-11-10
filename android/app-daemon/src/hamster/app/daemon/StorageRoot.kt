/*
 * StorageRoot.kt — 守护端"存储根"抽象
 *
 * 为什么需要这层接口：守护端要告诉 DaemonCore 一个可读写的根目录。当前
 * （milestone 1）只实现 app 私有目录；下一里程碑要做 SAF 自定义目录
 * （ACTION_OPEN_DOCUMENT_TREE + DocumentsContract），届时只换实现，不动
 * DaemonService / DaemonCore 的调用点。
 *
 * milestone 1 的实现 [appPrivateRoot]：
 *   getExternalFilesDir(null)/shared
 *   · 属于应用私有外部存储，API 24+ 都可用；
 *   · 不需要 READ/WRITE_EXTERNAL_STORAGE，也不需要 MANAGE_EXTERNAL_STORAGE；
 *   · 卸载应用时随应用一起删除，不会碰到用户的其他真实数据目录；
 *   · 在系统「文件」里位于 Android/data/hamster.app.daemon/files/shared
 *     （部分 OEM / Android 11+ 的「文件」应用可能不展示 Android/data，
 *     这时要用 adb 或电脑 MTP 访问）。
 *
 * TODO(milestone 2)：SAF 自定义目录。
 *   targetSdk 34 下 scoped storage 不允许应用直接按路径读写任意目录，
 *   即使拿到 ACTION_OPEN_DOCUMENT_TREE 的 Uri 也只能通过 DocumentsContract
 *   / ContentResolver 访问，而不是 java.io.File。因此 SAF 实现无法满足当前
 *   StorageRoot.dir: File 的契约，届时需要把接口扩展成"File 或 Uri"两种形态
 *   （例如加一个 openStream 的抽象），或者由 DaemonCore 增加一个基于
 *   ContentResolver 的适配层。现在保留这个接口就是为了让上层先不感知差异。
 */
package hamster.app.daemon

import android.content.Context
import java.io.File

/** 守护端可用的存储根：展示路径 + 真实目录。 */
interface StorageRoot {
    /** 给界面展示的路径（当前就是绝对路径）。 */
    val displayPath: String

    /** 给 DaemonCore 用的真实目录。 */
    val dir: File
}

/**
 * app 私有存储根：`getExternalFilesDir(null)/shared`。
 *
 * 无需任何存储权限，API 24+ 可用；外部存储暂不可用（极少数情况会返回 null）时
 * 退回内部私有目录 `filesDir/shared`，保证守护端仍能启动。
 */
fun appPrivateRoot(ctx: Context): StorageRoot {
    val base = ctx.getExternalFilesDir(null) ?: ctx.filesDir
    val target = File(base, "shared")
    if (!target.exists()) {
        // mkdirs 失败不在这里抛：DaemonCore 打开文件时会给出更具体的错误；
        // 界面仍能显示路径，便于排查是权限/存储挂载问题。
        target.mkdirs()
    }
    return object : StorageRoot {
        override val displayPath: String = target.absolutePath
        override val dir: File = target
    }
}
