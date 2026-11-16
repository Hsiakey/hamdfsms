/*
 * StorageRoot.kt — 守护端"存储根"抽象 + 共享存储授权
 *
 * 为什么需要这层接口：守护端要告诉 DaemonCore 一个可读写的根目录。
 * 现在有两种根：
 *   · appPrivateRoot()：`getExternalFilesDir(null)/shared`，默认值，无需任何权限；
 *   · sharedStorageRoot() / rootFromPath()：手机共享存储（/storage/emulated/0）
 *     里的真实目录，例如 /sdcard/Download。这才是"用户能看见的文件"。
 *
 * 为什么走"权限"而不是 SAF（ACTION_OPEN_DOCUMENT_TREE + DocumentsContract）：
 *   DaemonCore（protocol-core，1554 行）完全基于 java.io.File，带一整套路径白名单
 *   （拒绝 ..、盘符、UNC、软链接逃逸）。SAF 只能通过 ContentResolver 流式访问，
 *   没有 File 语义、不能随机读写、也没有稳定路径；改造成本极高且会牺牲性能。
 *   因此这里保持 File 语义，按 API 级别要权限：
 *
 *     API 26–28  WRITE_EXTERNAL_STORAGE（运行时权限）→ 共享存储下直接 File 读写
 *     API 29     同上 + manifest 的 requestLegacyExternalStorage="true"
 *     API 30+    MANAGE_EXTERNAL_STORAGE（"所有文件访问"，跳系统设置页授权）
 *
 *   代价（必须在交付文档里写清楚）：
 *   · MANAGE_EXTERNAL_STORAGE 在 Google Play 上属于受限权限，非文件管理器类
 *     应用上架会被拒；本项目是侧载自用（debug 包），不走 Play。
 *   · requestLegacyExternalStorage 在 API 30+ 被系统**忽略**（targetSdk 30+
 *     强制 scoped storage），所以 30+ 只能靠 MANAGE_EXTERNAL_STORAGE。
 *   · 即使拿到权限，Android/data、Android/obb 等目录在 API 30+ 仍不可按路径读写，
 *     目录选择器会把它们标成"不可读"。
 *
 * 本文件所有函数都不向调用方抛异常：权限/系统 API 包在 try/catch 里，
 * 失败一律按"没有权限 / 不可用"处理（返回 false / null / 空提示），
 * 因为它们的调用点是 Activity 生命周期与服务启动路径，抛出去只会打死进程。
 */
package hamster.app.daemon

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.Settings
import android.widget.Toast
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
    // getExternalFilesDir() 在极少数定制 ROM 上会抛（存储服务异常）；按"外部存储
    // 暂不可用"处理，退回内部私有目录，绝不把异常抛给界面/服务启动路径。
    val external = try {
        ctx.getExternalFilesDir(null)
    } catch (_: Exception) {
        null
    }
    val base = external ?: ctx.filesDir
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

/**
 * 共享存储根（通常是 `/storage/emulated/0`）。
 *
 * **无权限时也返回对象**：路径本身是常量，界面仍要能显示它（并提示去授权）。
 * 调用方应先查 [hasStorageAccess]，否则列目录/读写会失败（返回 null/空）。
 */
fun sharedStorageRoot(): StorageRoot {
    val base = sharedBaseDir()
    return object : StorageRoot {
        override val displayPath: String = base.absolutePath
        override val dir: File = base
    }
}

/**
 * 把用户选的路径变成 [StorageRoot]。
 *
 * 返回 null 表示这个路径不能用：空串 / 非绝对路径 / 不存在 / 不是目录 / 不可读。
 * 不抛异常（Activity 结果回调里直接调用）。
 */
fun rootFromPath(path: String?): StorageRoot? {
    val raw = path?.trim().orEmpty()
    if (raw.isEmpty()) return null
    val target: File = try {
        File(raw)
    } catch (_: Exception) {
        return null
    }
    if (!target.isAbsolute) return null
    val usable = try {
        target.exists() && target.isDirectory && target.canRead()
    } catch (_: Exception) {
        false
    }
    if (!usable) return null
    return object : StorageRoot {
        override val displayPath: String = target.absolutePath
        override val dir: File = target
    }
}

/* ------------------------------------------------------------------ */
/* 授权                                                                */
/* ------------------------------------------------------------------ */

/** 当前 API 级别下，访问共享存储需要哪种授权。 */
enum class StorageAccess {
    /** 不需要任何授权（API < 23，本项目 minSdk 26，实际不会出现）。 */
    NONE,

    /** API 26–29：运行时权限 READ/WRITE_EXTERNAL_STORAGE。 */
    RUNTIME_PERMISSION,

    /** API 30+：MANAGE_EXTERNAL_STORAGE（"所有文件访问"），只能在系统设置页授予。 */
    ALL_FILES_ACCESS,
}

/** 当前 API 级别需要哪种授权；按 [Build.VERSION.SDK_INT] 判断，不碰系统状态。 */
fun requiredStorageAccess(): StorageAccess = when {
    Build.VERSION.SDK_INT >= Build.VERSION_CODES.R -> StorageAccess.ALL_FILES_ACCESS   // API 30+
    Build.VERSION.SDK_INT >= Build.VERSION_CODES.M -> StorageAccess.RUNTIME_PERMISSION // API 23–29
    else -> StorageAccess.NONE
}

/**
 * 是否已拿到当前 API 级别所需的共享存储授权。
 *
 * · API ≤29：`checkSelfPermission(WRITE_EXTERNAL_STORAGE)`（读权限与它同组，
 *   系统一次授予；manifest 里 WRITE 的 maxSdkVersion=29）。
 * · API 30+：`Environment.isExternalStorageManager()`。
 *   这里包了 `Throwable`：在 API 26–29 上这个方法不存在，虽然调用点已被 SDK
 *   判断挡住，但 ART 的解析/链接失败仍可能冒出来，不能让它打死配置页。
 */
fun hasStorageAccess(ctx: Context): Boolean = try {
    when (requiredStorageAccess()) {
        StorageAccess.NONE -> true
        StorageAccess.RUNTIME_PERMISSION ->
            ctx.checkSelfPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE) ==
                PackageManager.PERMISSION_GRANTED
        StorageAccess.ALL_FILES_ACCESS ->
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && Environment.isExternalStorageManager()
    }
} catch (_: Throwable) {
    false
}

/**
 * 请求共享存储授权。
 *
 * · API ≤29：`requestPermissions(READ/WRITE_EXTERNAL_STORAGE)`，结果回到
 *   `Activity.onRequestPermissionsResult`；
 * · API 30+：**不能**再请求 WRITE_EXTERNAL_STORAGE（系统会直接拒绝、不弹框），
 *   改为跳 `Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION`（带 package: uri）；
 *   跳不过去（部分 ROM 没这个页面）就退回 `ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION`。
 *   结果不会回调，调用方要在 `onResume` 里重新查 [hasStorageAccess]。
 *
 * 任何一步失败都不抛给调用方，只记日志 + （最后兜底）Toast 指路。
 */
fun requestStorageAccess(activity: Activity, requestCode: Int) {
    try {
        when (requiredStorageAccess()) {
            StorageAccess.NONE -> Unit
            StorageAccess.RUNTIME_PERMISSION -> {
                activity.requestPermissions(
                    arrayOf(
                        Manifest.permission.WRITE_EXTERNAL_STORAGE,
                        Manifest.permission.READ_EXTERNAL_STORAGE,
                    ),
                    requestCode,
                )
            }
            StorageAccess.ALL_FILES_ACCESS -> openAllFilesAccessSettings(activity)
        }
    } catch (e: Exception) {
        android.util.Log.w(TAG, "requestStorageAccess 失败: ${e.javaClass.simpleName}: ${e.message}")
    }
}

/** 给 UI 显示：一句人话说明现在缺什么、去哪点。 */
fun storageAccessHint(ctx: Context): String {
    val access = try {
        requiredStorageAccess()
    } catch (_: Throwable) {
        StorageAccess.NONE
    }
    val granted = hasStorageAccess(ctx)
    return when (access) {
        StorageAccess.NONE ->
            "当前系统版本不需要存储权限，可直接选择共享存储里的目录。"
        StorageAccess.RUNTIME_PERMISSION ->
            if (granted) {
                "已获得读写存储权限（READ/WRITE_EXTERNAL_STORAGE）：可直接读写 /storage/emulated/0 下的目录。"
            } else {
                "缺少读写存储权限：点【选择目录】时系统会弹出授权框，选【允许】后即可浏览 /storage/emulated/0。"
            }
        StorageAccess.ALL_FILES_ACCESS ->
            if (granted) {
                "已获得「所有文件访问」权限：可以按路径稳定读写 /storage/emulated/0 下的目录。"
            } else {
                "Android 11+ 需要「所有文件访问」权限：点【选择目录】会跳到系统设置页，" +
                    "请打开「Hamster 守护端」的「允许访问所有文件」，返回后这里会自动刷新。"
            }
    }
}

/* ------------------------------------------------------------------ */
/* 内部实现                                                            */
/* ------------------------------------------------------------------ */

private const val TAG = "HamsterStorage"

/**
 * `/storage/emulated/0`。用 framework 的 `getExternalStorageDirectory()` 是为了
 * 兼容少数把共享存储挂在别处的设备；它被标记为 deprecated（API 29），但在
 * minSdk 26–34 上仍然可用，且这里是唯一能拿到"用户可见共享存储根"的 File API。
 */
@Suppress("DEPRECATION")
private fun sharedBaseDir(): File = try {
    Environment.getExternalStorageDirectory() ?: File("/storage/emulated/0")
} catch (_: Throwable) {
    File("/storage/emulated/0")
}

/**
 * 跳"所有文件访问"设置页。先试 app 专属页（带 package:），失败再试全局列表，
 * 都失败就 Toast 告诉用户手动去哪找——绝不把 ActivityNotFoundException 抛给调用方。
 */
private fun openAllFilesAccessSettings(activity: Activity) {
    val packageUri = try {
        Uri.parse("package:" + activity.packageName)
    } catch (_: Exception) {
        null
    }
    val candidates = ArrayList<Intent>(2)
    if (packageUri != null) {
        candidates.add(Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, packageUri))
    }
    candidates.add(Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION))
    for (intent in candidates) {
        try {
            activity.startActivity(intent)
            return
        } catch (e: Exception) {
            // 覆盖 ActivityNotFoundException / SecurityException：换下一个候选。
            android.util.Log.w(TAG, "跳转授权页失败: ${e.javaClass.simpleName}")
        }
    }
    try {
        Toast.makeText(
            activity,
            "打不开系统授权页，请到 设置 → 应用 → 特殊应用权限 → 所有文件访问 手动授予",
            Toast.LENGTH_LONG,
        ).show()
    } catch (_: Throwable) {
        // 连 Toast 都失败（极少数定制 ROM）：只能靠 logcat。
        android.util.Log.w(TAG, "无法显示授权提示 Toast")
    }
}
