/*
 * HamsterApi.kt — Hamster 协议核心之上的高层门面（Android / 桌面 JVM 通用）
 *
 * 只组合既有的协议原语，不重复实现任何握手或密码学：
 *   · SecureChannel（Secure.kt）     §8.2 握手 + §8.3 记录层 + 认证；
 *   · FrameReader（Protocol.kt）     §1 一行一个 JSON + §3 payload_bytes 分帧；
 *   · Json（Protocol.kt）            读取响应里的顶层字段与 data 对象。
 *
 * 对上层只暴露「连接 / 探活 / 列表 / 统计 / 下载 / 上传 / 关闭」七件事。
 * 所有错误都是 SecureException（握手、记录层）或 HamsterApiException（命令、IO、超时），
 * 不会把 SocketTimeoutException / ProtocolException 原样漏给 UI。
 *
 * 线程模型：**非线程安全**。明文 API 的使用方式是"后台线程单线程调用"；为了让误用
 * 不至于把帧流交错，公开方法都加了 @Synchronized（同一时刻只有一个请求在途）。
 * 代价是 download/upload 期间其它线程的调用会阻塞，这与"单连接一问一答"的协议一致。
 *
 * 命令通道空闲 240s 会被服务端按设计关闭（PROTOCOL §1）；本类不做自动重连：
 * 关闭后调用会抛 HamsterApiException("socket_closed")，由应用层决定是否重连。
 */
package hamster

import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.ConnectException
import java.net.SocketTimeoutException

/** 服务端 `list` 返回的一条目录项。path 是服务端视角的绝对路径。 */
data class RemoteFile(
    val name: String,
    val path: String,
    val size: Long,
    val dir: Boolean,
    /** 秒；服务端无法取到修改时间时为 0。 */
    val mtime: Long,
)

/** 设备概览。字段来源见 stats() 的实现注释。 */
data class DeviceStats(
    val deviceName: String,
    val version: String,
    val fileCount: Int,
    val totalBytes: Long,
    val uptimeSec: Long,
)

/** 协议/IO 错误。code 是稳定的机器可读标识（服务端错误码原样透传）。 */
class HamsterApiException(val code: String, message: String) : Exception("$code: $message")

class HamsterApi private constructor(
    private val channel: SecureChannel,
    private val reader: FrameReader,
    private val host: String,
    private val port: Int,
    private val appName: String,
) {
    companion object {
        private const val IO_CHUNK = 64 * 1024
        private const val LIST_PAGE = 1000

        /**
         * 建立 §8 加密连接并完成认证（口令不进线上报文，见 PROTOCOL §8.2）。
         *
         * @throws SecureException 握手失败（错误口令通常是 socket_closed/auth_timeout；
         *         对端不是加密 daemon 是 not_encrypted）。
         * @throws HamsterApiException 地址非法、连接被拒、连接超时。
         */
        fun connect(
            host: String,
            port: Int,
            secret: String,
            deviceId: String,
            appName: String = "Hamster Manager (Android)",
            timeoutMs: Int = 8000,
        ): HamsterApi {
            if (host.isBlank()) throw HamsterApiException("bad_address", "host 不能为空")
            if (port !in 1..65535) throw HamsterApiException("bad_address", "端口越界（1–65535）：$port")
            if (timeoutMs <= 0) throw HamsterApiException("bad_timeout", "timeoutMs 必须为正：$timeoutMs")

            val ch = try {
                SecureChannel.connect(host, port, secret, deviceId, appName, timeoutMs)
            } catch (e: SecureException) {
                throw mapConnectFailure(e, host, port, timeoutMs)
            } catch (e: IllegalArgumentException) {
                throw HamsterApiException("bad_address", e.message ?: "地址非法")
            } catch (e: SocketTimeoutException) {
                /* SecureChannel 的 socket 建立阶段在它自己的 try 之外，超时会原样抛出。 */
                throw HamsterApiException("timeout", "连接 $host:$port 超时（${timeoutMs}ms）")
            } catch (e: ConnectException) {
                throw HamsterApiException("connect_failed", "连接 $host:$port 被拒绝")
            } catch (e: IOException) {
                throw HamsterApiException(
                    "connect_failed",
                    "无法连接 $host:$port：${e.message ?: e.javaClass.simpleName}",
                )
            }
            return HamsterApi(ch, FrameReader(ch.input), host, port, appName)
        }

        /**
         * SecureChannel 把 socket 层异常统一包成 SecureException("socket_error", msg)，
         * 这里再把 UI 真正需要区分的三种情况拆出来：
         *   · 超时        → HamsterApiException("timeout")
         *   · 连接被拒/不可达 → HamsterApiException("connect_failed")
         *   · 明文守护进程 → SecureException("not_encrypted")
         * 其余保持原样（例如错误口令的 socket_closed）。
         */
        private fun mapConnectFailure(
            e: SecureException,
            host: String,
            port: Int,
            timeoutMs: Int,
        ): Exception {
            val msg = e.message ?: ""
            val low = msg.lowercase()
            if (e.code == "socket_error") {
                return when {
                    low.contains("timed out") || low.contains("timeout") ->
                        HamsterApiException("timeout", "连接 $host:$port 超时（${timeoutMs}ms）")
                    low.contains("refused") ->
                        HamsterApiException("connect_failed", "连接 $host:$port 被拒绝")
                    else ->
                        HamsterApiException("connect_failed", "无法连接 $host:$port：$msg")
                }
            }
            /* 明文 hamsterd 会把 §8 的 hello 当普通请求解析，回一条 JSON error
               （missing_action / unknown_action）。SecureChannel 看到"不是 auth challenge"
               就报 bad_auth_step/bad_auth_json；这里把它翻译成有意义的 not_encrypted。 */
            if ((e.code == "bad_auth_step" || e.code == "bad_auth_json") &&
                (msg.contains("\"type\":\"response\"") ||
                    msg.contains("missing_action") ||
                    msg.contains("unknown_action"))
            ) {
                return SecureException("not_encrypted", "对端不是 §8 加密 daemon（收到了明文响应）")
            }
            return e
        }
    }

    /** 请求序号；每条命令的 id 唯一（同一连接内不复用）。 */
    private var nextRequestId = 0L

    /** close() 或协议流损坏后置位；所有公开方法先检查。 */
    private var closed = false

    /** 服务端 monitor_path（来自 info/stats），用于判断远端绝对路径是否在监控根内。 */
    private var cachedMonitorPath: String? = null
    private var monitorPathKnown = false

    /** 服务端在 §8 握手 challenge 里报出的显示名（hamsterd）。 */
    val peerName: String get() = channel.peerName

    /** 服务端版本（握手 challenge 里的 version，例如 0.0.9）。 */
    val peerVersion: String get() = channel.peerVersion

    /**
     * 探活（ping）+ 协议摘要（info 的 data 原文），调试用。
     * 返回值是服务端 info 的 JSON，包含 server/version/monitor_path/features/uptime_ms 等。
     *
     * 明文 daemon 在 connect() 阶段就会抛 SecureException("not_encrypted")，走不到这里。
     */
    @Synchronized
    fun protocolInfo(): String {
        ensureOpen()
        try {
            val pong = call("ping", null)
            if (Json.getBoolean(pong, "pong") != true) {
                throw HamsterApiException("protocol_error", "ping 响应缺少 pong=true")
            }
            val info = call("info", null)
            rememberInfo(info)
            return info
        } catch (e: Exception) {
            throw mapException(e)
        }
    }

    /**
     * 设备统计。
     *
     * 字段来源（hamsterd 的真实契约）：
     *   · fileCount / totalBytes —— `stats` 的 total_files / total_size（索引库总数）；
     *   · version / uptimeSec   —— `info` 的 version / uptime_ms；
     *   · deviceName            —— §8 握手 challenge 的 server 字段。
     * 守护进程在握手后不再暴露主机名（发现协议 §7 才有 name），因此这里只能给握手名。
     */
    @Synchronized
    fun stats(): DeviceStats {
        ensureOpen()
        try {
            val info = call("info", null)
            rememberInfo(info)
            val data = call("stats", null)

            val rawCount = Json.getLong(data, "total_files") ?: 0L
            val fileCount = when {
                rawCount < 0L -> 0
                rawCount > Int.MAX_VALUE.toLong() -> Int.MAX_VALUE
                else -> rawCount.toInt()
            }
            val totalBytes = Json.getLong(data, "total_size") ?: 0L
            val uptimeMs = Json.getLong(info, "uptime_ms") ?: 0L
            val version = Json.getString(info, "version") ?: channel.peerVersion

            return DeviceStats(
                deviceName = channel.peerName,
                version = version,
                fileCount = fileCount,
                totalBytes = if (totalBytes < 0L) 0L else totalBytes,
                uptimeSec = if (uptimeMs > 0L) uptimeMs / 1000L else 0L,
            )
        } catch (e: Exception) {
            throw mapException(e)
        }
    }

    /**
     * 列目录（daemon 的 `list` action，服务端真实字段 name/path/dir/size/mtime）。
     *
     * dir 可以是 "/"（监控根）、相对路径（"sub"）、或监控根内的绝对路径
     * （`RemoteFile.path` 的父目录）。超过 1000 项时自动翻页拿完。
     */
    @Synchronized
    fun listFiles(dir: String = "/"): List<RemoteFile> {
        ensureOpen()
        try {
            val path = normalizeDir(dir)
            val out = ArrayList<RemoteFile>()
            var offset = 0
            while (true) {
                val data = call(
                    "list",
                    params(
                        "path" to path,
                        "limit" to LIST_PAGE,
                        "offset" to offset,
                    ),
                )
                val entries = parseEntries(data)
                out.addAll(entries)
                val total = Json.getLong(data, "total")?.toInt() ?: out.size
                if (entries.isEmpty() || out.size >= total) break
                offset = out.size
            }
            return out
        } catch (e: Exception) {
            throw mapException(e)
        }
    }

    /**
     * 下载到本地文件，返回字节数。
     *
     * §3 语义：响应头 data.payload_bytes 之后紧跟恰好 N 字节裸数据；这里流式落盘，
     * 边读边写，绝不把整个文件读进内存。先写 `<目标>.part-<nano>`，成功后才改名，
     * 任何失败（长度不足、IO 错误、回调抛异常）都会删除半成品。
     *
     * progress(已传, 总长) 可以为 null；总长来自响应头。
     */
    @Synchronized
    fun download(
        remote: String,
        localFile: File,
        progress: ((Long, Long) -> Unit)? = null,
    ): Long {
        ensureOpen()
        val target = localFile.absoluteFile
        val parent = target.parentFile
        if (parent != null && !parent.isDirectory && !parent.mkdirs()) {
            throw HamsterApiException("write_failed", "无法创建本地目录：$parent")
        }
        val part = File(parent, target.name + ".part-" + System.nanoTime())
        var out: FileOutputStream? = null
        try {
            val remotePath = normalizeFile(remote)
            val id = startRequest("download", params("path" to remotePath))
            val header = readResponse(id)

            if (!isOk(header)) {
                if (reader.hasPayload) reader.skipPayload()
                throw errorFrom(header)
            }

            val data = Json.getRawObject(header, "data") ?: ""
            val declared = reader.payloadBytes
            val sizeField = Json.getLong(data, "size")
            val pbField = Json.getLong(data, "payload_bytes")
            if (pbField != null && pbField != declared) {
                throw HamsterApiException(
                    "size_mismatch",
                    "data.payload_bytes=$pbField，分帧声明=$declared",
                )
            }
            if (sizeField != null && sizeField != declared) {
                reader.skipPayload()
                throw HamsterApiException(
                    "size_mismatch",
                    "data.size=$sizeField，payload_bytes=$declared",
                )
            }

            var got = 0L
            var lastReport = 0L
            val os = FileOutputStream(part)
            out = os
            if (progress != null) progress(0L, declared)
            val reportEvery = maxOf(IO_CHUNK.toLong(), declared / 100L)
            reader.readFully(declared) { buf, off, len ->
                os.write(buf, off, len)
                got += len.toLong()
                if (progress != null && (got - lastReport >= reportEvery || got == declared)) {
                    progress(got, declared)
                    lastReport = got
                }
            }
            os.flush()
            os.close()
            out = null

            if (got != declared) {
                throw HamsterApiException("size_mismatch", "实收 $got 字节，声明 $declared 字节")
            }
            if (progress != null && lastReport != got) progress(got, declared)

            if (target.exists() && !target.delete()) {
                throw HamsterApiException("write_failed", "无法覆盖本地文件：$target")
            }
            if (!part.renameTo(target)) {
                throw HamsterApiException("write_failed", "无法把临时文件改名为：$target")
            }
            return got
        } catch (e: Exception) {
            try {
                out?.close()
            } catch (_: Exception) {
            }
            part.delete()
            throw mapException(e)
        }
    }

    /**
     * 上传本地文件到远端目录，返回服务端落盘的**绝对路径**。
     *
     * 请求头：params{path,size,overwrite:false,mkdir:true} + 顶层 payload_bytes；
     * 负载边读边发（64 KiB 一块），不把文件读进内存。overwrite 固定为 false：
     * 目标已存在时服务端返回 exists，避免静默覆盖（与 PROTOCOL §5 的迁移要求一致）。
     *
     * remoteDir 支持 "/"（监控根）、相对路径（"sub"）、监控根内绝对路径。
     * 0 字节文件无法上传：§3 的 payload_bytes 必须是正整数，这里提前给出明确错误。
     */
    @Synchronized
    fun upload(
        localFile: File,
        remoteDir: String = "/",
        progress: ((Long, Long) -> Unit)? = null,
    ): String {
        ensureOpen()
        if (!localFile.isFile) {
            throw HamsterApiException("file_not_found", "本地文件不存在或不是普通文件：${localFile.absolutePath}")
        }
        val total = localFile.length()
        if (total <= 0L) {
            throw HamsterApiException("empty_file", "§3 的 payload_bytes 必须为正，无法上传 0 字节文件")
        }

        try {
            val remotePath = remoteTarget(remoteDir, localFile.name)
            val id = startRequest(
                "upload",
                params(
                    "path" to remotePath,
                    "size" to total,
                    "overwrite" to false,
                    "mkdir" to true,
                ),
                total,
            )

            var sent = 0L
            var lastReport = 0L
            val reportEvery = maxOf(IO_CHUNK.toLong(), total / 100L)
            if (progress != null) progress(0L, total)
            FileInputStream(localFile).use { input ->
                val buf = ByteArray(IO_CHUNK)
                while (true) {
                    val n = input.read(buf)
                    if (n < 0) break
                    if (n == 0) continue
                    channel.output.write(buf, 0, n)
                    sent += n.toLong()
                    if (progress != null && (sent - lastReport >= reportEvery || sent == total)) {
                        progress(sent, total)
                        lastReport = sent
                    }
                }
            }
            channel.output.flush()

            if (sent != total) {
                throw HamsterApiException(
                    "size_mismatch",
                    "本地文件在发送期间被改动：已发 $sent / 声明 $total",
                )
            }
            if (progress != null && lastReport != sent) progress(sent, total)

            val header = readResponse(id)
            ensureOk(header)
            val data = Json.getRawObject(header, "data") ?: ""
            return Json.getString(data, "path") ?: remotePath
        } catch (e: Exception) {
            throw mapException(e)
        }
    }

    /** 关闭连接。幂等，不抛异常（关闭时的 IO 错误一律吞掉）。 */
    @Synchronized
    fun close() {
        if (closed) return
        closed = true
        try {
            channel.close()
        } catch (_: Exception) {
        }
    }

    // ------------------------------------------------------------------ 请求/响应

    private fun ensureOpen() {
        if (closed) throw HamsterApiException("closed", "连接已关闭（或协议流已损坏）")
    }

    /** 协议流不可恢复：立即关闭 socket，后续调用一律 closed。 */
    private fun markBroken() {
        if (closed) return
        closed = true
        try {
            channel.close()
        } catch (_: Exception) {
        }
    }

    private fun call(action: String, paramsJson: String?): String {
        val id = startRequest(action, paramsJson)
        val header = readResponse(id)
        ensureOk(header)
        return Json.getRawObject(header, "data") ?: ""
    }

    private fun startRequest(
        action: String,
        paramsJson: String?,
        payloadBytes: Long = 0L,
    ): String {
        ensureOpen()
        val id = "api-" + (++nextRequestId)
        val sb = StringBuilder(160)
        sb.append("{\"type\":\"request\",\"id\":\"").append(id)
        sb.append("\",\"action\":\"").append(escape(action)).append('"')
        if (paramsJson != null) sb.append(",\"params\":").append(paramsJson)
        if (payloadBytes > 0L) sb.append(",\"payload_bytes\":").append(payloadBytes)
        sb.append('}')
        writeLine(sb.toString())
        return id
    }

    private fun writeLine(line: String) {
        val bytes = line.toByteArray(Charsets.UTF_8)
        channel.output.write(bytes)
        channel.output.write('\n'.code)
        channel.output.flush()
    }

    /**
     * 读一条响应并按 id 配对。事件（type=event）可能与响应交错到达，直接跳过；
     * 响应 id 不符说明请求/响应已经错位，连接状态不可信 → 关闭并报 protocol_mismatch。
     */
    private fun readResponse(id: String): String {
        while (true) {
            val header = try {
                reader.readHeader()
            } catch (e: ProtocolException) {
                markBroken()
                throw HamsterApiException("protocol_error", e.message ?: "协议流错误")
            } ?: run {
                markBroken()
                throw HamsterApiException("socket_closed", "等待响应时对端关闭了连接")
            }

            val type = Json.getString(header, "type")
            if (type == "event") {
                if (reader.hasPayload) reader.skipPayload()
                continue
            }
            if (type != "response") {
                if (reader.hasPayload) reader.skipPayload()
                markBroken()
                throw HamsterApiException("protocol_error", "意外的消息类型：${type ?: "?"}")
            }
            val gotId = Json.getString(header, "id")
            if (gotId != id) {
                markBroken()
                throw HamsterApiException(
                    "protocol_mismatch",
                    "响应 id=${gotId ?: "?"} 与请求 id=$id 不匹配",
                )
            }
            return header
        }
    }

    private fun isOk(header: String): Boolean = Json.getString(header, "status") == "ok"

    private fun ensureOk(header: String) {
        if (!isOk(header)) throw errorFrom(header)
    }

    /** 顶层 status=error → {data:{error,detail}}。code 原样透传，detail 可空。 */
    private fun errorFrom(header: String): HamsterApiException {
        val data = Json.getRawObject(header, "data")
        val code = data?.let { Json.getString(it, "error") } ?: "unknown_error"
        val detail = data?.let { Json.getString(it, "detail") }
        return HamsterApiException(code, detail ?: "服务端返回错误")
    }

    private fun mapException(e: Exception): Exception = when (e) {
        is SecureException -> e
        is HamsterApiException -> e
        is SocketTimeoutException -> HamsterApiException("timeout", e.message ?: "网络超时")
        is ProtocolException -> HamsterApiException("protocol_error", e.message ?: "协议流错误")
        is IOException -> HamsterApiException("io_error", e.message ?: e.javaClass.simpleName)
        else -> HamsterApiException("io_error", e.message ?: e.javaClass.simpleName)
    }

    // ------------------------------------------------------------------ 路径归一化

    /**
     * 把用户给的目录 / 文件路径翻译成守护进程能接受的写法：
     *   · ""、"/"、"." → "."（`list` 明确把 "." 当监控根）；
     *   · 监控根内的绝对路径 → 原样（daemon 接受根内绝对路径）；
     *   · 看起来是绝对路径但不在根内 → 去掉前导分隔符当相对路径用
     *     （例如 Android 侧常见写法 "/sub" 对 Windows daemon 只是"根下 sub"）；
     *   · 盘符绝对路径不在根内 → 原样交给 daemon，让它回 path_denied（不猜）。
     */
    private fun normalizeDir(dir: String): String {
        val t = dir.trim()
        if (t.isEmpty() || t == "/" || t == "\\" || t == "." || t == "./" || t == ".\\") return "."
        if (isPosixAbsolute(t)) {
            val root = ensureMonitorPath()
            if (root != null && isUnderRoot(t, root)) return t
            val rel = t.trimStart('/', '\\')
            return if (rel.isEmpty()) "." else rel
        }
        return t
    }

    private fun normalizeFile(path: String): String {
        val t = path.trim()
        if (t.isEmpty()) throw HamsterApiException("missing_path", "远端路径为空")
        if (isPosixAbsolute(t)) {
            val root = ensureMonitorPath()
            if (root != null && isUnderRoot(t, root)) return t
            val rel = t.trimStart('/', '\\')
            if (rel.isEmpty()) throw HamsterApiException("missing_path", "远端路径是监控根目录，不是文件")
            return rel
        }
        return t
    }

    private fun remoteTarget(remoteDir: String, name: String): String {
        val t = remoteDir.trim()
        if (t.isEmpty() || t == "/" || t == "\\" || t == "." || t == "./" || t == ".\\") return name
        if (isPosixAbsolute(t) || isDriveAbsolute(t)) {
            val root = ensureMonitorPath()
            if (root != null && isUnderRoot(t, root)) return joinPath(t, name)
            if (isDriveAbsolute(t)) {
                /* 盘符路径不在监控根内：原样发送，由 daemon 统一返回 path_denied。 */
                return joinPath(t, name)
            }
            return joinPath(t.trimStart('/', '\\'), name)
        }
        return joinPath(t, name)
    }

    /** 懒取 monitor_path（第一次需要判断绝对路径时发一条 info，之后用缓存）。 */
    private fun ensureMonitorPath(): String? {
        cachedMonitorPath?.let { return it }
        if (monitorPathKnown) return null
        val info = call("info", null)
        rememberInfo(info)
        monitorPathKnown = true
        return cachedMonitorPath
    }

    private fun rememberInfo(info: String) {
        val mp = Json.getString(info, "monitor_path")
        if (mp != null && mp.isNotEmpty()) cachedMonitorPath = mp
        monitorPathKnown = true
    }

    private fun isPosixAbsolute(p: String): Boolean = p.startsWith("/") || p.startsWith("\\")

    private fun isDriveAbsolute(p: String): Boolean =
        p.length >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') &&
            ((p[0] in 'a'..'z') || (p[0] in 'A'..'Z'))

    private fun isUnderRoot(path: String, root: String): Boolean {
        val a = normalizeForCompare(path)
        val b = normalizeForCompare(root).trimEnd('\\')
        if (b.isEmpty()) return true
        return a == b || a.startsWith("$b\\")
    }

    private fun normalizeForCompare(p: String): String =
        p.replace('/', '\\').lowercase()

    private fun joinPath(dir: String, name: String): String {
        val d = dir.trimEnd('/', '\\')
        return if (d.isEmpty()) name else "$d/$name"
    }

    // ------------------------------------------------------------------ 参数字面量

    private fun params(vararg pairs: Pair<String, Any?>): String {
        val sb = StringBuilder(96)
        sb.append('{')
        var first = true
        for ((k, v) in pairs) {
            if (!first) sb.append(',')
            first = false
            sb.append('"').append(escape(k)).append("\":").append(literal(v))
        }
        sb.append('}')
        return sb.toString()
    }

    private fun literal(v: Any?): String = when (v) {
        null -> "null"
        is Boolean -> v.toString()
        is Int -> v.toString()
        is Long -> v.toString()
        is String -> "\"" + escape(v) + "\""
        else -> "\"" + escape(v.toString()) + "\""
    }

    private fun escape(s: String): String {
        val sb = StringBuilder(s.length + 8)
        val hex = "0123456789abcdef"
        for (c in s) {
            when (c) {
                '"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                else -> if (c.code < 0x20) {
                    sb.append("\\u00").append(hex[(c.code shr 4) and 15]).append(hex[c.code and 15])
                } else {
                    sb.append(c)
                }
            }
        }
        return sb.toString()
    }

    // ------------------------------------------------------------------ list 响应解析

    /**
     * Json 只提供"顶层对象取字段"，而 list 的 entries 是对象数组，这里补一个
     * 只做数组切分的极简扫描器：字符串感知、括号配对，不猜结构。
     * 每个 entry 原文再交给 Json 按顶层字段读取（name/path/dir/size/mtime）。
     */
    private fun parseEntries(data: String): List<RemoteFile> {
        val inner = extractArray(data, "entries") ?: return emptyList()
        val out = ArrayList<RemoteFile>()
        for (raw in splitObjects(inner)) {
            val name = Json.getString(raw, "name") ?: continue
            val path = Json.getString(raw, "path") ?: ""
            val size = Json.getLong(raw, "size") ?: 0L
            val mtime = Json.getLong(raw, "mtime") ?: 0L
            /* daemon 发的是数字 0/1（"dir":%d），不是 JSON bool。 */
            val dir = Json.getBoolean(raw, "dir") ?: (Json.getLong(raw, "dir") == 1L)
            out.add(RemoteFile(name, path, size, dir, mtime))
        }
        return out
    }

    /** 在顶层对象里找 key 的数组值，返回方括号**内部**原文。 */
    private fun extractArray(obj: String, key: String): String? {
        if (obj.isEmpty() || obj[0] != '{') return null
        var i = 1
        val n = obj.length
        while (i < n) {
            i = skipSpace(obj, i)
            if (i >= n) return null
            if (obj[i] == ',') {
                i++
                continue
            }
            if (obj[i] == '}') return null
            if (obj[i] != '"') return null
            val keyEnd = skipString(obj, i)
            if (keyEnd < 0) return null
            val nameRaw = obj.substring(i + 1, keyEnd - 1)
            i = skipSpace(obj, keyEnd)
            if (i >= n || obj[i] != ':') return null
            i = skipSpace(obj, i + 1)
            if (nameRaw == key) {
                if (i >= n || obj[i] != '[') return null
                val end = skipComposite(obj, i)
                if (end < 0) return null
                return obj.substring(i + 1, end - 1)
            }
            val end = skipValue(obj, i)
            if (end < 0) return null
            i = end
        }
        return null
    }

    private fun splitObjects(arrayInner: String): List<String> {
        val out = ArrayList<String>()
        var i = 0
        val n = arrayInner.length
        while (i < n) {
            i = skipSpace(arrayInner, i)
            if (i >= n) break
            if (arrayInner[i] == ',') {
                i++
                continue
            }
            if (arrayInner[i] != '{') {
                val end = skipValue(arrayInner, i)
                if (end < 0) break
                i = end
                continue
            }
            val end = skipComposite(arrayInner, i)
            if (end < 0) break
            out.add(arrayInner.substring(i, end))
            i = end
        }
        return out
    }

    /** s[start] 是 '{' 或 '['；返回配对闭合符之后的索引。 */
    private fun skipComposite(s: String, start: Int): Int {
        if (start >= s.length) return -1
        val open = s[start]
        val close = when (open) {
            '{' -> '}'
            '[' -> ']'
            else -> return -1
        }
        var depth = 0
        var i = start
        while (i < s.length) {
            val c = s[i]
            when {
                c == '"' -> {
                    val e = skipString(s, i)
                    if (e < 0) return -1
                    i = e
                    continue
                }
                c == open -> depth++
                c == close -> {
                    depth--
                    if (depth == 0) return i + 1
                }
            }
            i++
        }
        return -1
    }

    /** s[start] 是 '"'；返回闭合引号之后的索引。 */
    private fun skipString(s: String, start: Int): Int {
        if (start >= s.length || s[start] != '"') return -1
        var i = start + 1
        while (i < s.length) {
            when (s[i]) {
                '\\' -> i += 2
                '"' -> return i + 1
                else -> i++
            }
        }
        return -1
    }

    private fun skipValue(s: String, start: Int): Int {
        if (start >= s.length) return -1
        return when (s[start]) {
            '"' -> skipString(s, start)
            '{', '[' -> skipComposite(s, start)
            else -> {
                var i = start
                while (i < s.length) {
                    val c = s[i]
                    if (c == ',' || c == '}' || c == ']' || c == ' ' || c == '\t' ||
                        c == '\r' || c == '\n'
                    ) {
                        break
                    }
                    i++
                }
                if (i == start) -1 else i
            }
        }
    }

    private fun skipSpace(s: String, start: Int): Int {
        var i = start
        while (i < s.length) {
            when (s[i]) {
                ' ', '\t', '\r', '\n' -> i++
                else -> return i
            }
        }
        return i
    }
}
