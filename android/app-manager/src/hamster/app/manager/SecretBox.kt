/*
 * SecretBox.kt — 口令安全存储（Android Keystore + AES/GCM）
 *
 * 要解决的问题：MainActivity 之前把口令明文写进 SharedPreferences（"记住口令"），
 * 任何能读 App 私有目录的途径（root、adb backup、部分厂商的云备份）都能直接拿到
 * 服务端 codeword。本文件把它换成"密钥在 Keystore、密文在 SharedPreferences"。
 *
 * 实现要点：
 *   · 密钥别名 [ALIAS]，AES 256 位，用途 ENCRYPT|DECRYPT，GCM 模式、无填充，
 *     **不要求用户认证**——若 setUserAuthenticationRequired(true)，每次读取都要
 *     指纹/锁屏验证，后台重连会直接不可用，体验上不可接受。
 *   · 每次加密由 Keystore 生成新的随机 IV（setRandomizedEncryptionRequired(true)），
 *     不重用 IV；IV 长度 12 字节，GCM tag 128 位（16 字节）。
 *   · Android 的 Cipher("AES/GCM/NoPadding").doFinal() 返回的密文**末尾已含 tag**，
 *     所以落盘只存 IV + 密文；解密时 tag 校验失败（AEADBadTagException）即视为
 *     被篡改，返回 null 并清掉坏数据。
 *   · Keystore 不可用 / 密钥永久失效（KeyPermanentlyInvalidatedException，
 *     例如系统恢复出厂密钥、锁屏凭据变更）时**明确失败**：save() 返回 false 并
 *     清掉旧密文，load() 返回 null 并清掉坏数据。绝不回退成明文落盘。
 *   · API 24+（KeyGenParameterSpec / GCMParameterSpec 的可用版本），零 androidx。
 *
 * 为什么没法在 JVM 上单测：AndroidKeyStore 是 Android framework 提供的
 * JCA Provider（Bouncy Castle 变体 + keystore daemon），桌面 JDK 上没有这个
 * provider，也没有 android.content.Context / SharedPreferences，因此
 * SecretBox 只能在真机或模拟器上验证；JVM 侧只能做 kotlinc 类型检查。
 */
package hamster.app.manager

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

/**
 * 口令存储：Android Keystore 生成不可导出的 AES 密钥，用它 AES/GCM 加密口令，
 * 密文 + IV 以 Base64 存 SharedPreferences。Keystore 不可用时必须**明确失败**，
 * 绝不能静默回退成明文落盘。
 */
object SecretBox {

    private const val PREFS = "hamster"
    private const val KEY_BLOB = "secret_v1"

    /**
     * 旧版 MainActivity 明文口令用的 key。本文件不主动写它，只在 save/clear 时
     * 顺手清掉，避免迁移后旧明文继续躺在同一个 prefs 文件里。
     */
    private const val LEGACY_PLAINTEXT_KEY = "secret"

    private const val ALIAS = "hamster.secret.v1"
    private const val KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALGORITHM = KeyProperties.KEY_ALGORITHM_AES
    private const val TRANSFORM = "AES/GCM/NoPadding"
    private const val GCM_TAG_BITS = 128
    private const val GCM_IV_BYTES = 12
    private const val GCM_TAG_BYTES = GCM_TAG_BITS / 8

    private const val BLOB_PREFIX = "v1"
    private const val TAG = "HamsterSecret"

    /** save/load/clear 串行化：避免"刚写完 IV 就被 clear"这类交错。 */
    private val lock = Any()

    /**
     * 加密并保存口令。空串等价于 [clear]（返回 true）。
     *
     * 返回 false 表示"没有落盘"：Keystore 不可用、密钥生成失败、加密失败或
     * prefs 写入失败。失败时会把旧密文一起清掉，避免用户以为新口令已生效、
     * 实际却还在用上一次保存的旧口令。
     */
    fun save(ctx: Context, secret: String): Boolean = synchronized(lock) {
        if (secret.isEmpty()) {
            clearLocked(ctx)
            return true
        }
        if (!keystoreSupported()) {
            clearLocked(ctx)
            return false
        }
        return try {
            val cipher = Cipher.getInstance(TRANSFORM)
            cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
            val iv = cipher.iv
            val ct = cipher.doFinal(secret.toByteArray(Charsets.UTF_8))
            if (iv == null || iv.size != GCM_IV_BYTES || ct.size < GCM_TAG_BYTES) {
                clearLocked(ctx)
                false
            } else {
                val blob = "$BLOB_PREFIX:" + b64(iv) + ":" + b64(ct)
                val ok = prefs(ctx).edit()
                    .putString(KEY_BLOB, blob)
                    .remove(LEGACY_PLAINTEXT_KEY)
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
            android.util.Log.w(TAG, "save 失败: ${e.javaClass.simpleName}")
            clearLocked(ctx)
            false
        }
    }

    /**
     * 读回口令。没存过、解不开、被篡改、密钥失效时返回 null。
     *
     * 只要进入"坏数据"分支就清掉 prefs 里的密文：留着它下次还会失败，
     * 而且会让用户以为口令还在。
     */
    fun load(ctx: Context): String? = synchronized(lock) {
        val blob = prefs(ctx).getString(KEY_BLOB, null) ?: return null
        val parts = blob.split(':')
        if (parts.size != 3 || parts[0] != BLOB_PREFIX) {
            clearLocked(ctx)
            return null
        }
        val iv = unb64(parts[1])
        val ct = unb64(parts[2])
        if (iv == null || ct == null || iv.size != GCM_IV_BYTES || ct.size < GCM_TAG_BYTES) {
            clearLocked(ctx)
            return null
        }
        if (!keystoreSupported()) {
            clearLocked(ctx)
            return null
        }
        return try {
            val cipher = Cipher.getInstance(TRANSFORM)
            cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(GCM_TAG_BITS, iv))
            // tag 不符时 doFinal 抛 AEADBadTagException（GeneralSecurityException 子类）
            String(cipher.doFinal(ct), Charsets.UTF_8)
        } catch (e: android.security.keystore.KeyPermanentlyInvalidatedException) {
            // 密钥被系统作废（恢复出厂 / 锁屏凭据变更）：密文永远解不开了。
            android.util.Log.w(TAG, "load 失败: 密钥已永久失效")
            clearLocked(ctx)
            null
        } catch (e: java.security.GeneralSecurityException) {
            android.util.Log.w(TAG, "load 失败: ${e.javaClass.simpleName}")
            clearLocked(ctx)
            null
        } catch (e: Exception) {
            android.util.Log.w(TAG, "load 失败: ${e.javaClass.simpleName}")
            clearLocked(ctx)
            null
        }
    }

    /** 删除密文（不删 Keystore 里的密钥，避免频繁生成密钥）。 */
    fun clear(ctx: Context) = synchronized(lock) { clearLocked(ctx) }

    /**
     * Keystore 是否可用（API 够、provider 在、密钥能取到/生成）。
     * 副作用：首次调用会生成密钥——这是幂等的，调用方无需在意。
     */
    fun isAvailable(ctx: Context): Boolean = synchronized(lock) {
        if (!keystoreSupported()) return false
        try {
            getOrCreateKey()
            Cipher.getInstance(TRANSFORM)
            true
        } catch (e: Exception) {
            android.util.Log.w(TAG, "isAvailable=false: ${e.javaClass.simpleName}")
            false
        }
    }

    /* ------------------------------------------------------------------ */

    private fun prefs(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    private fun clearLocked(ctx: Context) {
        try {
            prefs(ctx).edit()
                .remove(KEY_BLOB)
                .remove(LEGACY_PLAINTEXT_KEY)
                .commit()
        } catch (_: Exception) {
            // 清不掉也只能算了；load 还会再判断一次。
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
