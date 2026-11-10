/*
 * DeviceStore.kt — 设备库持久化（纯 JVM，不引用任何 Android API）
 *
 * 为什么单独抽出来：设备库是"本机记住哪些 hamsterd"的唯一状态，它的正确性
 * 只跟文件格式/原子性有关，跟 Activity 无关。因此构造函数只吃一个 [java.io.File]，
 * 单测可以用 kotlinc 把本文件 + 测试文件一起编成普通 JVM 程序跑（见
 * android/protocol-core/test/DeviceStoreTest.kt）。
 *
 * 文件格式（单行 JSON 对象，UTF-8）：
 *   {"v":1,"devices":[{"host":"192.168.1.10","port":9100,"deviceId":"ab12cd34",
 *    "name":"my-pc","version":"0.0.9","lastSeenMs":1730000000000}]}
 *
 * 设计取舍：
 *   · 键 = (host, port, deviceId)；deviceId 可能是空串（服务端老版本/未应答），
 *     此时 (host, port, "") 就是 host:port 兜底键，不会和"同机另一实例"混淆。
 *   · 坏文件不能让 App 起不来：解析失败 → 返回空表，并把原文件改名成 `.bad`
 *     保留证据（不删除、不覆盖成空文件——那样以后想查为什么丢数据就没线索了）。
 *   · 写入一律"先写 <file>.tmp → fsync → 原子 rename"，且同一路径的
 *     所有读写用同一把锁串行化；读者永远只会看到旧版本或新版本，不会看到半个文件。
 *   · 只依赖 java.io / java.nio.charset：minSdk 是 24，而 java.nio.file 到 API 26
 *     才存在，所以这里绝不能用 Files.move/toPath（会在 Android 7.x 上 NoClassDefFoundError）。
 *   · 列表最多保留 [MAX_RECORDS] 条（按 lastSeenMs 取最近），防止文件无限增长。
 *   · 未知字段忽略（向前兼容：以后加字段，旧版 App 不会把文件当坏文件删掉）。
 */
package hamster.app.manager

import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.util.concurrent.ConcurrentHashMap

/** 设备库里的一条记录。 */
data class KnownDevice(
    val host: String,
    val port: Int,
    val deviceId: String,     // 服务端 instance_id（可能是空串，用 host:port 兜底作 key）
    val name: String,         // 服务端显示名
    val version: String,
    val lastSeenMs: Long,     // 最近一次成功连接/发现的时间（毫秒）
)

/**
 * 设备库：一个 JSON 文件，原子写（先写 .tmp 再 replace），
 * 坏文件不能让 App 崩 —— 解析失败时返回空表并把坏文件改名成 .bad 保留证据。
 */
class DeviceStore(private val file: File) {

    /** 设备键：deviceId 为空串时等价于 host:port 兜底。 */
    private data class DeviceKey(val host: String, val port: Int, val deviceId: String)

    private val KnownDevice.key: DeviceKey get() = DeviceKey(host, port, deviceId)

    /**
     * 同一路径共享一把锁：两个 [DeviceStore] 实例指向同一个文件时也必须串行，
     * 否则两个写入者的 rename 可能互相踩掉对方刚写好的内容。
     */
    private val lock: Any = lockForFile(file)

    /** 按 lastSeenMs 倒序返回全部记录（去重、最多 [MAX_RECORDS] 条）。 */
    fun load(): List<KnownDevice> = synchronized(lock) { loadLocked() }

    /**
     * 插入或覆盖同 key 的记录，返回更新后的完整列表。
     *
     * host 为空或 port 越界是**调用方 bug**：这里直接抛 IllegalArgumentException，
     * 而不是把坏记录写进文件——否则下次 [load] 会把整份文件当坏文件隔离，
     * 一条坏记录就能让用户丢掉整个设备库。负数 lastSeenMs 按 0 处理。
     */
    fun upsert(d: KnownDevice): List<KnownDevice> = synchronized(lock) {
        require(d.host.isNotEmpty()) { "KnownDevice.host 不能为空" }
        require(d.port in 1..65535) { "KnownDevice.port 越界: ${d.port}" }
        val safe = if (d.lastSeenMs < 0) d.copy(lastSeenMs = 0L) else d
        val next = normalize(mergeLocked(loadLocked(), safe))
        writeLocked(next)
        next
    }

    /**
     * 合并一条记录。
     *
     * key 是 (host, port, deviceId)，但 **deviceId 可能为空**：手动连接时还没从服务端
     * 拿到 instance_id，只能先写一条空 id 的记录；之后发现（§7）或下一次握手会带来真实 id。
     * 这两种记录指的是同一台设备，必须合并成一条 —— 否则设备库里会出现同一 host:port
     * 的两行（真机上实测踩到过）。
     *
     * 合并规则：非空字段覆盖空字段；`lastSeenMs` 取较大者（时间只增不减）。
     */
    private fun mergeLocked(cur: List<KnownDevice>, d: KnownDevice): List<KnownDevice> {
        val existing = cur.firstOrNull {
            it.host == d.host && it.port == d.port &&
                (it.deviceId == d.deviceId || it.deviceId.isEmpty() || d.deviceId.isEmpty())
        } ?: return cur + d

        val merged = KnownDevice(
            host = d.host,
            port = d.port,
            deviceId = if (d.deviceId.isNotEmpty()) d.deviceId else existing.deviceId,
            name = if (d.name.isNotEmpty()) d.name else existing.name,
            version = if (d.version.isNotEmpty()) d.version else existing.version,
            lastSeenMs = maxOf(d.lastSeenMs, existing.lastSeenMs),
        )
        val rest = cur
            .filterNot { it.key == existing.key }
            // 顺手清掉历史遗留的"同 host:port 且 id 为空"的重复项
            .filterNot { it.host == d.host && it.port == d.port && it.deviceId.isEmpty() }
        return rest + merged
    }

    /** 删除一条记录；不存在时原样返回。 */
    fun remove(host: String, port: Int, deviceId: String): List<KnownDevice> = synchronized(lock) {
        val key = DeviceKey(host, port, deviceId)
        val cur = loadLocked()
        if (cur.none { it.key == key }) return cur
        val next = cur.filterNot { it.key == key }
        writeLocked(next)
        next
    }

    /**
     * 刷新一条记录的 lastSeenMs 并重新排序；记录不存在时不做任何事。
     *
     * 时间只增不减（取 `max(旧值, atMs)`）：发现列表可能带着稍旧的时间戳回来，
     * 不能让一次迟到的回调把刚连上的设备重新排到后面。
     */
    fun touch(host: String, port: Int, deviceId: String, atMs: Long): List<KnownDevice> =
        synchronized(lock) {
            val key = DeviceKey(host, port, deviceId)
            val at = atMs.coerceAtLeast(0L)
            val cur = loadLocked()
            var changed = false
            val merged = cur.map { d ->
                if (d.key == key && at > d.lastSeenMs) {
                    changed = true
                    d.copy(lastSeenMs = at)
                } else {
                    d
                }
            }
            if (!changed) return cur
            val next = normalize(merged)
            writeLocked(next)
            next
        }

    /** 清空设备库（删文件 + 可能残留的 .tmp）。 */
    fun clear(): Unit = synchronized(lock) {
        deleteQuietly(file)
        deleteQuietly(tmpFile())
    }

    /* ------------------------------------------------------------------ */

    private fun loadLocked(): List<KnownDevice> {
        if (!file.exists()) return emptyList()
        if (!file.isFile) return emptyList()          // 目录/设备文件：不碰它，也不当坏文件
        if (file.length() > MAX_FILE_BYTES) return quarantineLocked()

        val bytes = try {
            file.readBytes()
        } catch (_: IOException) {
            return emptyList()                        // 读不了（权限/被占用）→ 空表，别删用户数据
        }
        if (bytes.isEmpty()) return emptyList()       // 空文件是合法初始状态

        val text = decodeUtf8(bytes) ?: return quarantineLocked()
        if (text.isBlank()) return emptyList()        // 只剩空白：当作空库

        val parsed = parseDocument(text) ?: return quarantineLocked()
        return normalize(parsed)
    }

    /** 原子写：<file>.tmp → fsync → replace。失败会抛 [IOException]（调用方自行兜住）。 */
    private fun writeLocked(items: List<KnownDevice>) {
        val dir = file.absoluteFile.parentFile
        if (dir != null && !dir.isDirectory && !dir.mkdirs() && !dir.isDirectory) {
            throw IOException("无法创建设备库目录: $dir")
        }
        val tmp = tmpFile()
        val payload = encode(items).toByteArray(StandardCharsets.UTF_8)
        try {
            FileOutputStream(tmp).use { out ->
                out.write(payload)
                out.flush()
                out.fd.sync()                         // 先落盘，再 rename，断电也不会得到空文件
            }
            replace(tmp, file)
        } catch (e: Exception) {
            deleteQuietly(tmp)
            throw e
        }
    }

    private fun replace(from: File, to: File) {
        // Android/Linux 上 File.renameTo 走 rename(2)：目标存在时**原子替换**。
        // 只有 Windows 开发机的 JVM 不允许 rename 覆盖已存在文件，才需要先删目标；
        // 同一路径的所有读写都持有同一把锁，所以本地测试里读者也不会看到这个空档。
        if (from.renameTo(to)) return
        if (to.exists() && !to.delete()) {
            throw IOException("无法替换设备库文件: $to")
        }
        if (!from.renameTo(to)) {
            throw IOException("无法写入设备库文件: $to")
        }
    }

    /**
     * 坏文件：改名成 `<file>.bad`（覆盖上一个证据）后返回空表。
     * 改名失败也只能返回空表——绝不能因为改名失败把整个 App 带崩。
     */
    private fun quarantineLocked(): List<KnownDevice> {
        val bad = File(file.path + BAD_SUFFIX)
        try {
            deleteQuietly(bad)
            replace(file, bad)
        } catch (_: Exception) {
            try {
                file.renameTo(bad)                    // 最后兜底
            } catch (_: Exception) {
            }
        }
        return emptyList()
    }

    private fun tmpFile(): File = File(file.path + TMP_SUFFIX)

    /* ------------------------------------------------------------------ */
    /* JSON 编解码：自带严格解析器，保证本文件不依赖 Android API / 第三方库 */
    /* ------------------------------------------------------------------ */

    private fun encode(items: List<KnownDevice>): String {
        val sb = StringBuilder(64 + items.size * 128)
        sb.append("{\"v\":").append(FORMAT_VERSION).append(",\"devices\":[")
        for ((i, d) in items.withIndex()) {
            if (i > 0) sb.append(',')
            sb.append("{\"host\":\"").append(escape(d.host))
            sb.append("\",\"port\":").append(d.port)
            sb.append(",\"deviceId\":\"").append(escape(d.deviceId))
            sb.append("\",\"name\":\"").append(escape(d.name))
            sb.append("\",\"version\":\"").append(escape(d.version))
            sb.append("\",\"lastSeenMs\":").append(d.lastSeenMs)
            sb.append('}')
        }
        sb.append("]}\n")
        return sb.toString()
    }

    /**
     * 解析整份文档；任何结构性/类型问题都返回 null（交给 quarantine）。
     * 只对**必填**字段严格：host、port 必须存在且类型正确；deviceId/name/version
     * 缺失按空串，lastSeenMs 缺失按 0（以后加字段/旧文件都能读）。
     */
    private fun parseDocument(text: String): List<KnownDevice>? {
        val root = try {
            JsonReader(text).parseDocument()
        } catch (_: BadJson) {
            return null
        }
        val obj = root as? JObj ?: return null
        val arr = obj.fields["devices"] as? JArr ?: return null
        val out = ArrayList<KnownDevice>(arr.items.size)
        for (item in arr.items) {
            val d = item as? JObj ?: return null
            out.add(parseDevice(d) ?: return null)
        }
        return out
    }

    private fun parseDevice(d: JObj): KnownDevice? {
        val host = (d.fields["host"] as? JStr)?.value ?: return null
        if (host.isEmpty()) return null
        val portRaw = (d.fields["port"] as? JNum)?.raw ?: return null
        val port = portRaw.toIntOrNull() ?: return null      // 拒绝 9100.0 / 9.1e3 / 越界
        if (port !in 1..65535) return null
        val deviceId = optString(d, "deviceId") ?: return null
        val name = optString(d, "name") ?: return null
        val version = optString(d, "version") ?: return null
        val lastSeen = optLong(d, "lastSeenMs") ?: return null
        return KnownDevice(host, port, deviceId, name, version, lastSeen.coerceAtLeast(0L))
    }

    private fun optString(d: JObj, key: String): String? {
        val v = d.fields[key] ?: return ""
        return (v as? JStr)?.value
    }

    private fun optLong(d: JObj, key: String): Long? {
        val v = d.fields[key] ?: return 0L
        val raw = (v as? JNum)?.raw ?: return null
        return raw.toLongOrNull()
    }

    private fun escape(s: String): String {
        var extra = 0
        for (c in s) if (c == '"' || c == '\\' || c.code < 0x20) extra++
        if (extra == 0) return s
        val sb = StringBuilder(s.length + extra * 2)
        for (c in s) {
            when {
                c == '"' -> sb.append("\\\"")
                c == '\\' -> sb.append("\\\\")
                c == '\n' -> sb.append("\\n")
                c == '\r' -> sb.append("\\r")
                c == '\t' -> sb.append("\\t")
                c.code < 0x20 -> {
                    sb.append("\\u")
                    appendHex4(sb, c.code)
                }
                else -> sb.append(c)
            }
        }
        return sb.toString()
    }

    private fun appendHex4(sb: StringBuilder, code: Int) {
        val digits = "0123456789abcdef"
        sb.append(digits[(code ushr 12) and 0xF])
        sb.append(digits[(code ushr 8) and 0xF])
        sb.append(digits[(code ushr 4) and 0xF])
        sb.append(digits[code and 0xF])
    }

    /** 严格 UTF-8 解码：坏字节返回 null（而不是替换成 U+FFFD 后继续解析）。 */
    private fun decodeUtf8(bytes: ByteArray): String? = try {
        StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes))
            .toString()
    } catch (_: CharacterCodingException) {
        null
    }

    /* ------------------------------------------------------------------ */

    private fun normalize(items: List<KnownDevice>): List<KnownDevice> {
        // 去重：同 key 保留 lastSeenMs 大的；相等时保留先出现的（文件顺序 = 上次排序）。
        val byKey = LinkedHashMap<DeviceKey, KnownDevice>(items.size)
        for (d in items) {
            val prev = byKey[d.key]
            if (prev == null || d.lastSeenMs > prev.lastSeenMs) byKey[d.key] = d
        }
        return byKey.values.sortedWith(ORDER).take(MAX_RECORDS)
    }

    private fun deleteQuietly(f: File) {
        try {
            if (f.exists()) f.delete()
        } catch (_: Exception) {
        }
    }

    companion object {
        /** 设备库最多保留的条数（按 lastSeenMs 取最近的）。 */
        const val MAX_RECORDS: Int = 200

        /** 文件格式版本；目前只写 1，读的时候不校验（旧版/新版互不误删）。 */
        const val FORMAT_VERSION: Int = 1

        private const val TMP_SUFFIX = ".tmp"
        private const val BAD_SUFFIX = ".bad"

        /** 正常 200 条 ≈ 60 KB；超过 2 MiB 的一定不是我们写的，直接隔离。 */
        private const val MAX_FILE_BYTES: Long = 2L * 1024 * 1024

        /** lastSeenMs 倒序；时间相同按 host/port/deviceId 稳定排序，便于测试与 UI。 */
        private val ORDER: Comparator<KnownDevice> =
            compareByDescending<KnownDevice> { it.lastSeenMs }
                .thenBy { it.host }
                .thenBy { it.port }
                .thenBy { it.deviceId }

        private val LOCKS = ConcurrentHashMap<String, Any>()

        private fun lockForFile(f: File): Any {
            val key = try {
                f.canonicalPath
            } catch (_: IOException) {
                f.absolutePath
            }
            val fresh = Any()
            return LOCKS.putIfAbsent(key, fresh) ?: fresh
        }
    }
}

/* ==========================================================================
 * 极简严格 JSON 解析（只服务本文件，故意不导出）
 *
 * 与 android/protocol-core 里的 hamster.Json 不同，这里要保留完整结构
 * （devices 是对象数组），因此是一个小型的递归下降解析器：
 *   · 拒绝尾随垃圾、裸控制字符、非法转义、数值格式错误；
 *   · 嵌套深度上限 32，挡住恶意构造；
 *   · 不区分 null 与缺失（上层按"缺失/类型错"处理）。
 * ========================================================================== */

private sealed class JVal
private class JStr(val value: String) : JVal()
private class JNum(val raw: String) : JVal()
private class JBool(val value: Boolean) : JVal()
private object JNull : JVal()
private class JArr(val items: List<JVal>) : JVal()
private class JObj(val fields: Map<String, JVal>) : JVal()

private class BadJson : Exception() {
    override fun fillInStackTrace(): Throwable = this
}

private class JsonReader(private val s: String) {
    private var i = 0

    fun parseDocument(): JVal {
        skipWs()
        val v = parseValue(1)
        skipWs()
        if (i != s.length) throw BadJson()
        return v
    }

    private fun parseValue(depth: Int): JVal {
        if (depth > MAX_DEPTH) throw BadJson()
        if (i >= s.length) throw BadJson()
        return when (val c = s[i]) {
            '{' -> parseObject(depth)
            '[' -> parseArray(depth)
            '"' -> JStr(parseString())
            't' -> {
                expectLiteral("true"); JBool(true)
            }
            'f' -> {
                expectLiteral("false"); JBool(false)
            }
            'n' -> {
                expectLiteral("null"); JNull
            }
            else -> {
                if (c == '-' || c in '0'..'9') JNum(parseNumber()) else throw BadJson()
            }
        }
    }

    private fun parseObject(depth: Int): JObj {
        expect('{')
        val fields = LinkedHashMap<String, JVal>()
        skipWs()
        if (peek() == '}') {
            i++
            return JObj(fields)
        }
        while (true) {
            skipWs()
            if (peek() != '"') throw BadJson()
            val key = parseString()
            skipWs()
            expect(':')
            skipWs()
            val value = parseValue(depth + 1)
            if (!fields.containsKey(key)) fields[key] = value   // 重复 key：先到先得
            skipWs()
            when (next()) {
                ',' -> Unit
                '}' -> return JObj(fields)
                else -> throw BadJson()
            }
        }
    }

    private fun parseArray(depth: Int): JArr {
        expect('[')
        val items = ArrayList<JVal>()
        skipWs()
        if (peek() == ']') {
            i++
            return JArr(items)
        }
        while (true) {
            skipWs()
            items.add(parseValue(depth + 1))
            skipWs()
            when (next()) {
                ',' -> Unit
                ']' -> return JArr(items)
                else -> throw BadJson()
            }
        }
    }

    private fun parseString(): String {
        expect('"')
        val sb = StringBuilder()
        while (true) {
            if (i >= s.length) throw BadJson()
            val c = s[i++]
            when {
                c == '"' -> return sb.toString()
                c == '\\' -> {
                    if (i >= s.length) throw BadJson()
                    when (s[i++]) {
                        '"' -> sb.append('"')
                        '\\' -> sb.append('\\')
                        '/' -> sb.append('/')
                        'b' -> sb.append('\b')
                        'f' -> sb.append('\u000C')
                        'n' -> sb.append('\n')
                        'r' -> sb.append('\r')
                        't' -> sb.append('\t')
                        'u' -> sb.append(readHex4().toChar())
                        else -> throw BadJson()
                    }
                }
                c.code < 0x20 -> throw BadJson()          // JSON 不允许裸控制字符
                else -> sb.append(c)
            }
        }
    }

    private fun readHex4(): Int {
        if (i + 4 > s.length) throw BadJson()
        var v = 0
        repeat(4) {
            val d = hexVal(s[i++])
            if (d < 0) throw BadJson()
            v = (v shl 4) or d
        }
        return v
    }

    private fun parseNumber(): String {
        val start = i
        if (i < s.length && s[i] == '-') i++
        if (i >= s.length) throw BadJson()
        when {
            s[i] == '0' -> i++
            s[i] in '1'..'9' -> while (i < s.length && s[i] in '0'..'9') i++
            else -> throw BadJson()
        }
        if (i < s.length && s[i] == '.') {
            i++
            if (i >= s.length || s[i] !in '0'..'9') throw BadJson()
            while (i < s.length && s[i] in '0'..'9') i++
        }
        if (i < s.length && (s[i] == 'e' || s[i] == 'E')) {
            i++
            if (i < s.length && (s[i] == '+' || s[i] == '-')) i++
            if (i >= s.length || s[i] !in '0'..'9') throw BadJson()
            while (i < s.length && s[i] in '0'..'9') i++
        }
        return s.substring(start, i)
    }

    private fun expectLiteral(lit: String) {
        if (i + lit.length > s.length) throw BadJson()
        for (k in lit.indices) if (s[i + k] != lit[k]) throw BadJson()
        i += lit.length
    }

    private fun skipWs() {
        while (i < s.length) {
            when (s[i]) {
                ' ', '\t', '\r', '\n' -> i++
                else -> return
            }
        }
    }

    private fun peek(): Char = if (i < s.length) s[i] else throw BadJson()

    private fun next(): Char = if (i < s.length) s[i++] else throw BadJson()

    private fun expect(c: Char) {
        if (next() != c) throw BadJson()
    }

    private fun hexVal(c: Char): Int = when (c) {
        in '0'..'9' -> c - '0'
        in 'a'..'f' -> c - 'a' + 10
        in 'A'..'F' -> c - 'A' + 10
        else -> -1
    }

    companion object {
        private const val MAX_DEPTH = 32
    }
}
