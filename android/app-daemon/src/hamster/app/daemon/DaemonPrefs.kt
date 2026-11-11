/*
 * DaemonPrefs.kt — 守护端配置持久化（口令必须加密，绝不落明文）
 *
 * 存什么：codeword（加密）、port（默认 9100）、rootPath、enabled。
 *
 * 口令为什么不能明文：SharedPreferences 虽然位于 app 私有目录，但 root、
 * adb backup（旧系统）、部分 OEM 云备份/换机迁移都能把它读走。这里的做法与
 * app-manager 的 SecretBox 相同——密钥在 AndroidKeyStore（不可导出），
 * 密文在 SharedPreferences：
 *   · 密钥别名 hamster.daemon.codeword.v1，AES-256，GCM，NoPadding；
 *   · 不要求用户认证（setUserAuthenticationRequired(false)）：守护端要能
 *     在锁屏/后台自动启动，不能每次读口令都要求指纹；
 *   · 每次加密由 Keystore 生成新的 12 字节随机 IV（setRandomizedEncryptionRequired），
 *     不重用 IV；GCM tag 128 位；
 *   · Cipher.doFinal() 的返回值末尾已经包含 GCM tag，落盘只存 "v1:<IV>:<密文>"。
 *
 * 失败路径（重要）：
 *   · Keystore 不可用 / 密钥生成失败 / 加密失败 / prefs 写入失败：
 *     saveCodeword() 返回 false，并**清掉旧密文**，绝不回退成明文；
 *   · 解密失败（被篡改、密钥永久失效，如恢复出厂/锁屏凭据变更）：
 *     loadCodeword() 返回 null，并清掉坏数据；
 *   · 上层（ConfigActivity / DaemonService）必须把 false/null 当成"没有口令"，
 *     服务端拒绝启动，而不是拿默认口令凑合。
 *
 * 为什么没法在桌面 JVM 上单测：AndroidKeyStore 是 Android framework 提供的
 * JCA Provider，桌面 JDK 没有；SharedPreferences 也没有。因此本文件只能做
 * kotlinc 类型检查，行为要在真机/模拟器上验证。
 */
package hamster.app.daemon

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** 守护端配置：加密口令 + 端口 + 根目录 + 启用标记。 */
object DaemonPrefs {

    private const val PREFS = "hamster_daemon"

    /** 口令密文（"v1:<IV>:<cipher+tag>"）。 */
    private const val KEY_CODEWORD = "codeword_v1"

    /** 历史/误写的明文 key；本文件不写它，只在 save/clear 时顺手清掉。 */
    private const val KEY_LEGACY_CODEWORD = "codeword"

    private const val KEY_PORT = "port"
    private const val KEY_ROOT = "root_path"
    private const val KEY_ENABLED = "enabled"

    /** §7 发现用的本机 instance_id（16 位 hex，首次生成后固定）。 */
    private const val KEY_INSTANCE_ID = "instance_id"

    /** 默认监听端口，与桌面端 hamsterd 的默认值一致。 */
    const val DEFAULT_PORT = 9100

    /** 端口校验范围：1024 以下需要 root，65535 是 TCP 上限。 */
    const val MIN_PORT = 1024
    const val MAX_PORT = 65535

    /** 口令最短长度；低于这个值不允许启动服务。 */
    const val MIN_CODEWORD_LEN = 8

    /* ---- Keystore / AES-GCM 参数（改任何一个旧密文都会解不开） ---- */
    private const val ALIAS = "hamster.daemon.codeword.v1"
    private const val KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALGORITHM = KeyProperties.KEY_ALGORITHM_AES
    private const val TRANSFORM = "AES/GCM/NoPadding"
    private const val GCM_TAG_BITS = 128
    private const val GCM_IV_BYTES = 12
    private const val GCM_TAG_BYTES = GCM_TAG_BITS / 8
    private const val BLOB_PREFIX = "v1"

    private const val TAG = "HamsterDaemonPrefs"

    /** save/load/clear 串行化，避免"刚写完 IV 就被 clear"这类交错。 */
    private val lock = Any()

    /* ------------------------------------------------------------------ */
    /* 口令                                                                */
    /* ------------------------------------------------------------------ */

    /**
     * 读回口令。没存过、解不开、被篡改、密钥永久失效时返回 null。
     *
     * 进入"坏数据"分支会顺手清掉 prefs 里的密文：留着它下次还会失败，
     * 而且会让用户误以为口令还在。
     */
    fun loadCodeword(ctx: Context): String? = synchronized(lock) {
        val blob = prefs(ctx).getString(KEY_CODEWORD, null) ?: return@synchronized null
        val parts = blob.split(':')
        if (parts.size != 3 || parts[0] != BLOB_PREFIX) {
            clearLocked(ctx)
            return@synchronized null
        }
        val iv = unb64(parts[1])
        val ct = unb64(parts[2])
        if (iv == null || ct == null || iv.size != GCM_IV_BYTES || ct.size < GCM_TAG_BYTES) {
            clearLocked(ctx)
            return@synchronized null
        }
        if (!keystoreSupported()) {
            clearLocked(ctx)
            return@synchronized null
        }
        try {
            val cipher = Cipher.getInstance(TRANSFORM)
            cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(GCM_TAG_BITS, iv))
            // tag 不符时 doFinal 抛 AEADBadTagException（GeneralSecurityException 子类）
            String(cipher.doFinal(ct), Charsets.UTF_8)
        } catch (e: android.security.keystore.KeyPermanentlyInvalidatedException) {
            // 密钥被系统作废（恢复出厂 / 锁屏凭据变更）：密文永远解不开了。
            android.util.Log.w(TAG, "loadCodeword 失败: 密钥已永久失效")
            clearLocked(ctx)
            null
        } catch (e: java.security.GeneralSecurityException) {
            android.util.Log.w(TAG, "loadCodeword 失败: ${e.javaClass.simpleName}")
            clearLocked(ctx)
            null
        } catch (e: Exception) {
            android.util.Log.w(TAG, "loadCodeword 失败: ${e.javaClass.simpleName}")
            clearLocked(ctx)
            null
        }
    }

    /**
     * 加密并保存口令。空串等价于 [clearCodeword]（返回 true）。
     *
     * 返回 false 表示"没有落盘"：Keystore 不可用、密钥生成失败、加密失败或
     * prefs 写入失败。失败时会清掉旧密文，避免用户以为新口令已生效、
     * 实际却还在用上一次保存的旧口令。
     */
    fun saveCodeword(ctx: Context, codeword: String): Boolean = synchronized(lock) {
        if (codeword.isEmpty()) {
            clearLocked(ctx)
            return@synchronized true
        }
        if (!keystoreSupported()) {
            clearLocked(ctx)
            return@synchronized false
        }
        try {
            val cipher = Cipher.getInstance(TRANSFORM)
            cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
            val iv = cipher.iv
            val ct = cipher.doFinal(codeword.toByteArray(Charsets.UTF_8))
            if (iv == null || iv.size != GCM_IV_BYTES || ct.size < GCM_TAG_BYTES) {
                clearLocked(ctx)
                false
            } else {
                val blob = "$BLOB_PREFIX:" + b64(iv) + ":" + b64(ct)
                val ok = prefs(ctx).edit()
                    .putString(KEY_CODEWORD, blob)
                    .remove(KEY_LEGACY_CODEWORD)
                    .commit()                       // 同步写，返回值才是真实的
                if (!ok) {
                    clearLocked(ctx)
                    false
                } else {
                    true
                }
            }
        } catch (e: Exception) {
            // 不打印口令/密文，只记类型，方便 logcat 定位"为什么没记住"。
            android.util.Log.w(TAG, "saveCodeword 失败: ${e.javaClass.simpleName}")
            clearLocked(ctx)
            false
        }
    }

    /** 是否存过口令（只看 key 在不在，不做解密，适合界面高频刷新）。 */
    fun hasCodeword(ctx: Context): Boolean = try {
        prefs(ctx).contains(KEY_CODEWORD)
    } catch (_: Exception) {
        false
    }

    /** 删除密文（不删 Keystore 里的密钥，避免频繁生成密钥）。 */
    fun clearCodeword(ctx: Context) = synchronized(lock) { clearLocked(ctx) }

    /**
     * Keystore 是否可用（API 够、provider 在、密钥能取到/生成）。
     * 副作用：首次调用会生成密钥——幂等，调用方无需在意。
     *
     * 界面用它在保存失败时给出更准确的提示（"Keystore 不可用"而不是"写入失败"）。
     */
    fun codewordStorageAvailable(ctx: Context): Boolean = synchronized(lock) {
        if (!keystoreSupported()) return@synchronized false
        try {
            getOrCreateKey()
            Cipher.getInstance(TRANSFORM)
            true
        } catch (e: Exception) {
            android.util.Log.w(TAG, "codewordStorageAvailable=false: ${e.javaClass.simpleName}")
            false
        }
    }

    /* ------------------------------------------------------------------ */
    /* 端口 / 根目录 / 启用标记                                            */
    /* ------------------------------------------------------------------ */

    /** 端口；越界或没存过时返回 [DEFAULT_PORT]。 */
    fun port(ctx: Context): Int {
        val p = try {
            prefs(ctx).getInt(KEY_PORT, DEFAULT_PORT)
        } catch (_: Exception) {
            DEFAULT_PORT
        }
        return if (p in MIN_PORT..MAX_PORT) p else DEFAULT_PORT
    }

    /** 保存端口；不在 [MIN_PORT]..[MAX_PORT] 内直接拒绝并返回 false。 */
    fun setPort(ctx: Context, p: Int): Boolean {
        if (p !in MIN_PORT..MAX_PORT) return false
        return try {
            prefs(ctx).edit().putInt(KEY_PORT, p).commit()
        } catch (_: Exception) {
            false
        }
    }

    /**
     * §7 发现用的本机 instance_id：16 位小写 hex，首次调用生成后固定。
     *
     * 它出现在探测应答里，客户端据此去重；重启后必须保持不变，否则同一台设备
     * 会在客户端设备库里变成两条（桌面端 hamsterd 的 instance_id 也是持久化的）。
     */
    fun instanceId(ctx: Context): String = synchronized(lock) {
        val p = prefs(ctx)
        val cur = try {
            p.getString(KEY_INSTANCE_ID, null)
        } catch (_: Exception) {
            null
        }
        if (!cur.isNullOrBlank() && cur.length in 8..63) return cur
        val bytes = ByteArray(8)
        java.security.SecureRandom().nextBytes(bytes)
        val id = bytes.joinToString("") { String.format("%02x", it) }
        try {
            p.edit().putString(KEY_INSTANCE_ID, id).commit()
        } catch (_: Exception) {
        }
        id
    }

    /**
     * 已保存的根目录路径；没存过返回 null。
     *
     * 现在这个值**真的生效**：DaemonService 启动时用 [rootFromPath] 校验它，
     * 可用就用它当 DaemonCore 的根（共享存储里的真实目录，如 /sdcard/Download），
     * 不可用（目录被删、权限被撤、脏数据）就回退到 [appPrivateRoot]。
     * 空串/null 表示"用默认的 app 私有目录"。
     */
    fun rootPath(ctx: Context): String? = try {
        prefs(ctx).getString(KEY_ROOT, null)?.takeIf { it.isNotBlank() }
    } catch (_: Exception) {
        null
    }

    /** 保存根目录展示路径；空串表示清除（即恢复默认的 app 私有目录）。 */
    fun setRootPath(ctx: Context, p: String): Boolean = try {
        val edit = prefs(ctx).edit()
        if (p.isBlank()) edit.remove(KEY_ROOT) else edit.putString(KEY_ROOT, p)
        edit.commit()
    } catch (_: Exception) {
        false
    }

    /** 用户是否希望守护端保持启用（配置页"启动/停止"时同步写入）。 */
    fun enabled(ctx: Context): Boolean = try {
        prefs(ctx).getBoolean(KEY_ENABLED, false)
    } catch (_: Exception) {
        false
    }

    fun setEnabled(ctx: Context, on: Boolean): Boolean = try {
        prefs(ctx).edit().putBoolean(KEY_ENABLED, on).commit()
    } catch (_: Exception) {
        false
    }

    /* ------------------------------------------------------------------ */

    private fun prefs(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    private fun clearLocked(ctx: Context) {
        try {
            prefs(ctx).edit()
                .remove(KEY_CODEWORD)
                .remove(KEY_LEGACY_CODEWORD)
                .commit()
        } catch (_: Exception) {
            // 清不掉也只能算了；loadCodeword 还会再判断一次。
        }
    }

    private fun keystoreSupported(): Boolean =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.N    // API 24：KeyGenParameterSpec 稳定可用

    /**
     * 取已有密钥，没有就生成。
     *
     * 密钥规格（必须与注释一致，改一个参数旧密文就解不开）：
     *   AES-256 / GCM / NoPadding / 不要求用户认证 / 随机 IV。
     */
    private fun getOrCreateKey(): SecretKey {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        val existing = (ks.getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry)?.secretKey
        if (existing != null) return existing

        val spec = KeyGenParameterSpec.Builder(
            ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setUserAuthenticationRequired(false)
            .setRandomizedEncryptionRequired(true)
            .build()

        val kg = KeyGenerator.getInstance(KEY_ALGORITHM, KEYSTORE)
        kg.init(spec)
        return kg.generateKey()
    }

    private fun b64(bytes: ByteArray): String = Base64.encodeToString(bytes, Base64.NO_WRAP)

    private fun unb64(text: String): ByteArray? = try {
        Base64.decode(text, Base64.NO_WRAP)
    } catch (_: IllegalArgumentException) {
        null
    }
}
