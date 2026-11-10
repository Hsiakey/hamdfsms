/*
 * DaemonCore.kt — Hamster 守护端业务层（纯 JVM，不引用任何 Android API）
 *
 * 契约来源：PROTOCOL.md §1（分帧）/ §3（二进制负载）/ §4（动作与错误码），
 * 以及 Hamsterd/hd_net.c（各 action 的请求参数、响应字段、错误码、路径白名单）。
 *
 * 这一层只做"已经完成 §8.2 握手之后的那条明文流"：
 *   · 一行一个 JSON 请求（FrameReader 负责分帧，单行 256 KiB 上限）；
 *   · 响应 {type:"response",id,status:"ok"|"error",data:{...}}；
 *   · download 的 payload_bytes 在 data 里、响应行之后紧跟裸数据（§3）；
 *   · upload 的 payload_bytes 在请求顶层，服务端必须精确读满。
 *
 * 有意与 C 侧不同的地方（详见交付报告）：
 *   · 没有索引数据库：search/stats/verify 直接走真实文件树；
 *   · 没有 max_transfer_mb / verify_interval 配置：不限大小、scan_interval=0；
 *   · download 头里的 hash 是**真实计算**的 xxHash3_128（与 C 逐字节一致，见 Xxh3_128），
 *     search 结果里的 modified 是文件真实 mtime（C 侧是"入库时间"）；
 *   · 不支持 sync-database / key:*（返回 unknown_action），features 里也不谎报。
 *
 * 线程模型：serve() 可以被多个线程同时调用；除少量统计计数（Atomic*）外没有共享可变
 * 状态。每个连接的读写只碰自己的流，因此天然并发安全。
 */
package hamster

import java.io.BufferedOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.file.FileVisitResult
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.SimpleFileVisitor
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.BasicFileAttributes
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.concurrent.atomic.AtomicInteger

class DaemonCore(
    /** 服务根目录（必须已存在；不存在时抛 IllegalArgumentException） */
    val root: java.io.File,
    val serverName: String,
    val version: String,
    /** 只读统计用：客户端数由 DaemonServer 提供 */
    val startedAtMs: Long = System.currentTimeMillis(),
) {

    companion object {
        /** PROTOCOL §1：单行 JSON 上限（按字节；二进制负载不计入）。 */
        const val MAX_LINE_BYTES: Int = 256 * 1024

        /** PROTOCOL §4：单条响应上限 1 MiB。 */
        const val MAX_RESPONSE_BYTES: Int = 1024 * 1024

        /** 传输分块（与 C 侧 HD_CHUNK 一致）。 */
        const val IO_CHUNK: Int = 64 * 1024

        /** list 的默认/上限（hd_net.c handle_list：越界按 200）。 */
        const val LIST_DEFAULT_LIMIT: Int = 200
        const val LIST_MAX_LIMIT: Int = 1000

        /** search 的默认/上限（hd_db.c：<=0 → 200，>1000 → 1000）。 */
        const val SEARCH_DEFAULT_LIMIT: Int = 200
        const val SEARCH_MAX_LIMIT: Int = 1000

        /** 被拒请求最多排空这么多负载；再大就直接断连接（与 C 的 64 MiB 兜底同量级）。 */
        const val MAX_DRAIN_BYTES: Long = 64L * 1024 * 1024

        /** info.heartbeat：配置项 heartbeat_time，C 侧默认 3 秒。 */
        const val HEARTBEAT_SEC: Int = 3

        /**
         * 能力声明。只写**真的实现了**的动作：
         * 不含 sync-database / keys（本层没有索引库与密钥表）。
         */
        val FEATURES: List<String> = listOf(
            "search", "download", "upload", "list", "mkdir", "delete",
            "verify", "rescan", "sync", "framing:raw", "framing:aead",
        )

        private val ISO_LOCAL: DateTimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss")

        /**
         * FrameReader 对"消息头不是 JSON 对象"抛出的文案前缀（Protocol.kt 固定写法）。
         * 用它把 C 侧的 malformed_json / 空行心跳两个分支区分出来，见 serve()。
         */
        private const val MALFORMED_PREFIX = "消息头不是合法的 JSON 对象："
    }

    init {
        if (!root.exists()) {
            throw IllegalArgumentException("服务根目录不存在：${root.absolutePath}")
        }
        if (!root.isDirectory) {
            throw IllegalArgumentException("服务根不是目录：${root.absolutePath}")
        }
    }

    /* ---------------------------------------------------------------- 共享状态 */

    /** 根目录的**真实**绝对路径（已解析符号链接/重解析点），所有白名单比较都以它为准。 */
    private val rootReal: Path = root.absoluteFile.toPath().toRealPath()

    private val rootRealString: String = rootReal.toString()

    /** 前缀比较用（带分隔符，避免 /data 匹配到 /database）。 */
    private val rootPrefix: String =
        if (rootRealString.endsWith(File.separator)) rootRealString else rootRealString + File.separator

    /** Windows 下路径比较不区分大小写（与 hd_path_within 的 path_char_eq 一致）。 */
    private val caseInsensitive: Boolean =
        System.getProperty("os.name", "").lowercase().contains("win")

    private val clients = AtomicInteger(0)

    private val verifyLock = Any()
    private var verifyCount = 0
    private var scanCount = 0
    private var verifiedFiles = 0
    private var corruptCount = 0
    private var lastDurationMs = 0L
    private var lastVerify = ""
    private var lastScan = ""

    /** 客户端数由 DaemonServer 提供（info/health/stats 里原样上报）。 */
    fun setClientCount(n: Int) {
        clients.set(if (n < 0) 0 else n)
    }

    /* ==========================================================================
     * 连接主循环（§1 keep-alive：一条连接上可以连续处理多条请求）
     * ========================================================================== */
    fun serve(ins: java.io.InputStream, outs: java.io.OutputStream) {
        val reader = FrameReader(ins, MAX_LINE_BYTES)
        val out = BufferedOutputStream(outs, IO_CHUNK)
        try {
            while (true) {
                val header: String? = try {
                    reader.readHeader()
                } catch (e: LineTooLongException) {
                    /* 该行已被 FrameReader 丢弃到行尾，流仍然对齐：报错后继续（与 C 一致） */
                    sendError(out, "", "line_too_long", "单行 JSON 超过上限，已丢弃该行")
                    continue
                } catch (e: ProtocolException) {
                    /*
                     * FrameReader 把"行级错误"和"流级错误"都包成 ProtocolException，
                     * 这里按状态区分，尽量对齐 hd_net.c 的行为：
                     *   · 还有未读负载 → 流已错位，只能关闭；
                     *   · 超长行丢弃超过上限 → 流不可信，关闭；
                     *   · 行不是 JSON 对象 → malformed_json，连接继续（C 的 jx_is_object 分支）；
                     *   · 空行 → 心跳，静默忽略（C 的 line[0]=='\0' 分支）。
                     * 依赖 FrameReader 的文案是这里的已知耦合点（见交付报告）。
                     */
                    if (reader.payloadRemaining > 0L) return
                    val msg = e.message ?: ""
                    if (msg.contains("不可信")) return
                    if (msg.startsWith(MALFORMED_PREFIX)) {
                        if (msg.length == MALFORMED_PREFIX.length) continue
                        sendError(out, "", "malformed_json", null)
                        continue
                    }
                    return
                }
                if (header == null) return          /* 对端关闭 */
                if (header.isEmpty()) continue      /* 心跳空行 */
                if (!handleRequest(reader, out, header)) return
            }
        } catch (e: IOException) {
            /* 对端断开 / 写失败：调用方负责关连接 */
        } finally {
            try {
                out.flush()
            } catch (_: IOException) {
            }
        }
    }

    /** @return false 表示必须关闭连接（流已错位，或请求带了不该带的负载）。 */
    private fun handleRequest(reader: FrameReader, out: OutputStream, line: String): Boolean {
        if (!Json.isObject(line)) {
            sendError(out, "", "malformed_json", null)
            return true
        }
        val id = Json.getString(line, "id") ?: ""
        val action = Json.getString(line, "action")
        if (action.isNullOrEmpty()) {
            sendError(out, id, "missing_action", null)
            return true
        }
        val params = Json.getRawObject(line, "params") ?: "{}"

        /* §3：upload 的 payload_bytes 在请求顶层；FrameReader 也认 data.payload_bytes。 */
        val topLevelPayload = Json.getLong(line, "payload_bytes")
        val declaredPayload = reader.payloadBytes
        val hasPayload = topLevelPayload != null && topLevelPayload > 0L

        val keepGoing = try {
            when (action) {
                "ping" -> {
                    sendOk(out, id, "{\"pong\":true,\"time\":${nowSec()}}")
                    true
                }
                "info" -> {
                    sendOkLimited(out, id, serverInfoJson())
                    true
                }
                "health" -> {
                    sendOkLimited(out, id, healthJson())
                    true
                }
                "stats" -> {
                    sendOkLimited(out, id, statsJson())
                    true
                }
                "search" -> {
                    sendOkLimited(out, id, searchJson(params))
                    true
                }
                "verify" -> {
                    sendOkLimited(out, id, verifyJson(params))
                    true
                }
                "list" -> {
                    val (json, code, detail) = listJson(params)
                    if (code == null) sendOkLimited(out, id, json)
                    else sendError(out, id, code, detail)
                    true
                }
                "mkdir" -> {
                    val (path, code, detail) = mkdir(params)
                    if (code == null) sendOk(out, id, "{\"path\":${jstr(path)}}")
                    else sendError(out, id, code, detail)
                    true
                }
                "delete" -> {
                    val (path, code, detail) = delete(params)
                    if (code == null) sendOk(out, id, "{\"path\":${jstr(path)}}")
                    else sendError(out, id, code, detail)
                    true
                }
                "download" -> handleDownload(out, id, params)
                "upload" -> handleUpload(reader, out, id, params, declaredPayload, hasPayload)
                "rescan" -> {
                    /* 无索引：这里做一次真实的文件树清点，scan_count 不是编的 */
                    val scan = scanTree()
                    synchronized(verifyLock) {
                        scanCount++
                        lastScan = isoNow()
                    }
                    sendOk(out, id, "{\"status\":\"rescan_requested\",\"files\":${scan.count}}")
                    true
                }
                "sync" -> {
                    /* 无索引可同步：如实返回"已受理"，不写任何假字段 */
                    sendOk(out, id, "{\"status\":\"sync_requested\"}")
                    true
                }
                "hello" -> {
                    /* §8.4：认证在握手阶段完成，命令层不再处理口令（与 C 一致） */
                    sendError(out, id, "unknown_action", "传输加密已接管认证（PROTOCOL §8.4）")
                    true
                }
                "sync-database" -> {
                    sendError(out, id, "unknown_action", "本实现无索引数据库，不支持 sync-database")
                    true
                }
                else -> {
                    if (action.startsWith("key:")) {
                        sendError(out, id, "unknown_action", "本实现无密钥表，不支持 $action")
                    } else {
                        sendError(out, id, "unknown_action", action)
                    }
                    true
                }
            }
        } catch (e: IOException) {
            return false
        } catch (e: Exception) {
            /* 兜底：不让一个动作的异常打死整条连接，但也不谎报成功 */
            sendError(out, id, "internal_error", e.message ?: e.javaClass.simpleName)
            true
        }

        /* 非 upload 的动作不该带负载；带了就必须关闭，否则下一条请求会读到二进制垃圾（与 C 一致） */
        if (keepGoing && hasPayload && action != "upload") return false
        return keepGoing
    }

    /* ==========================================================================
     * info / health / stats
     * ========================================================================== */

    private fun uptimeMs(): Long = maxOf(0L, System.currentTimeMillis() - startedAtMs)

    private fun serverInfoJson(): String {
        val sb = StringBuilder(512)
        sb.append("{\"server\":").append(jstr(serverName))
        sb.append(",\"version\":").append(jstr(version))
        sb.append(",\"auth_required\":1")
        sb.append(",\"monitor_path\":").append(jstr(rootRealString))
        sb.append(",\"heartbeat\":").append(HEARTBEAT_SEC)
        sb.append(",\"uptime_ms\":").append(uptimeMs())
        sb.append(",\"clients\":").append(clients.get())
        sb.append(",\"peers\":0")
        sb.append(",\"features\":[")
        for ((i, f) in FEATURES.withIndex()) {
            if (i > 0) sb.append(',')
            sb.append(jstr(f))
        }
        sb.append("]}")
        return sb.toString()
    }

    private fun healthJson(): String =
        "{\"status\":\"ok\",\"time\":${jstr(isoNow())},\"version\":${jstr(version)}" +
            ",\"uptime_ms\":${uptimeMs()},\"clients\":${clients.get()},\"auth_required\":1" +
            ",\"monitor_path\":${jstr(rootRealString)}}"

    private fun statsJson(): String {
        val scan = scanTree()
        val sb = StringBuilder(1024)
        sb.append("{\"total_files\":").append(scan.count)
        sb.append(",\"total_size\":").append(scan.size)
        sb.append(",\"file_type_count\":").append(scan.types.size)
        sb.append(",\"last_update\":").append(scan.lastUpdateMs / 1000L)
        sb.append(",\"file_types\":[")
        /* 与 C 一致：按数量降序，最多 50 种 */
        val sorted = scan.types.entries.sortedWith(
            compareByDescending<Map.Entry<String, LongArray>> { it.value[0] }.thenBy { it.key },
        ).take(50)
        for ((i, e) in sorted.withIndex()) {
            if (i > 0) sb.append(',')
            sb.append("{\"ext\":").append(jstr(e.key))
            sb.append(",\"count\":").append(e.value[0])
            sb.append(",\"size_bytes\":").append(e.value[1]).append('}')
        }
        sb.append(']')
        sb.append(",\"monitor_path\":").append(jstr(rootRealString))
        sb.append(",\"peers\":[]")
        sb.append(",\"clients\":").append(clients.get())
        sb.append('}')
        return sb.toString()
    }

    /* ==========================================================================
     * search（无索引：真实文件树 + 白名单排序）
     * ========================================================================== */

    private data class Hit(
        val name: String,
        val path: Path,
        val size: Long,
        val mtimeMs: Long,
        val ext: String,
    )

    private fun searchJson(params: String): String {
        val q = Json.getString(params, "q") ?: ""
        val type = Json.getString(params, "type") ?: ""
        val sort = Json.getString(params, "sort") ?: ""
        val sizeMin = Json.getLong(params, "size_min") ?: 0L
        val sizeMax = Json.getLong(params, "size_max") ?: 0L
        var limit = Json.getInt(params, "limit") ?: 0
        var offset = Json.getInt(params, "offset") ?: 0
        if (limit <= 0) limit = SEARCH_DEFAULT_LIMIT
        if (limit > SEARCH_MAX_LIMIT) limit = SEARCH_MAX_LIMIT
        if (offset < 0) offset = 0

        val hits = ArrayList<Hit>()
        walkTree { name, path, size, mtimeMs, ext ->
            if (q.isNotEmpty() && !name.contains(q, ignoreCase = true) &&
                !path.toString().contains(q, ignoreCase = true)
            ) {
                return@walkTree
            }
            /* 与 C 的 file_type 精确等值（小写扩展名、无点）一致 */
            if (type.isNotEmpty() && ext != type) return@walkTree
            if (sizeMin > 0L && size < sizeMin) return@walkTree
            if (sizeMax > 0L && size > sizeMax) return@walkTree
            hits.add(Hit(name, path, size, mtimeMs, ext))
        }

        sortHits(hits, sort)

        val total = hits.size
        val sb = StringBuilder(1024)
        sb.append("{\"total\":").append(total)
        sb.append(",\"limit\":").append(limit)
        sb.append(",\"offset\":").append(offset)
        sb.append(",\"files\":[")
        var written = 0
        var i = offset
        while (i < hits.size && written < limit) {
            val h = hits[i]
            if (written > 0) sb.append(',')
            written++
            /* hash 只对本页真正要返回的条目计算，避免为一棵大树白算一遍 */
            val hash = try {
                Xxh3_128.hexFile(h.path.toFile())
            } catch (_: IOException) {
                ""
            }
            sb.append("{\"hash\":").append(jstr(hash))
            sb.append(",\"name\":").append(jstr(h.name))
            sb.append(",\"path\":").append(jstr(h.path.toString()))
            sb.append(",\"type\":").append(jstr(h.ext))
            sb.append(",\"size\":").append(h.size)
            sb.append(",\"modified\":").append(jstr(isoLocal(h.mtimeMs)))
            sb.append('}')
            i++
        }
        sb.append("]}")
        return sb.toString()
    }

    /**
     * sort 白名单（与 hd_db.c order_by_clause 一一对应）：
     * name / size / modified / type / path，前缀 '-' 表示降序；
     * 白名单之外一律按 path 升序 —— 不会把客户端文本拼进任何查询。
     */
    private fun sortHits(hits: MutableList<Hit>, sort: String) {
        val desc = sort.startsWith("-")
        val key = if (desc) sort.substring(1) else sort
        val cmp: Comparator<Hit> = when (key) {
            "name" -> compareBy { it.name }
            "size" -> compareBy { it.size }
            "modified" -> compareBy { it.mtimeMs }
            "type" -> compareBy { it.ext }
            "path" -> compareBy { it.path.toString() }
            else -> compareBy { it.path.toString() }
        }
        val effective = if (desc) cmp.reversed() else cmp
        hits.sortWith(effective.thenBy { it.path.toString() })
    }

    /* ==========================================================================
     * list
     * ========================================================================== */

    /** @return Triple(JSON, 错误码, detail)；错误码为 null 表示成功。 */
    private fun listJson(params: String): Triple<String, String?, String?> {
        val raw = Json.getString(params, "path") ?: ""
        var limit = Json.getInt(params, "limit") ?: LIST_DEFAULT_LIMIT
        var offset = Json.getInt(params, "offset") ?: 0
        if (limit <= 0 || limit > LIST_MAX_LIMIT) limit = LIST_DEFAULT_LIMIT
        if (offset < 0) offset = 0

        val dir: Path = if (raw.isEmpty() || raw == "." || raw == "./" || raw == ".\\") {
            rootReal
        } else {
            when (val r = resolvePath(raw)) {
                is Resolved.Bad -> return Triple("", r.code, r.detail)
                is Resolved.Ok -> r.path
            }
        }

        if (!Files.exists(dir)) return Triple("", "not_found", dir.toString())
        if (!Files.isDirectory(dir)) return Triple("", "not_a_directory", dir.toString())

        val children: Array<File> = dir.toFile().listFiles()
            ?: return Triple("", "open_failed", dir.toString())

        /* C 侧用 FindFirstFile/readdir 的原始顺序；这里按名字排序，保证分页稳定可复现 */
        children.sortBy { it.name.lowercase() }

        val total = children.size
        val sb = StringBuilder(1024)
        sb.append("{\"path\":").append(jstr(dir.toString()))
        sb.append(",\"entries\":[")
        var written = 0
        var i = offset
        while (i < total && written < limit) {
            val child = children[i]
            i++
            val p = child.toPath()
            val isDir = Files.isDirectory(p)
            val size = if (isDir) 0L else try {
                Files.size(p)
            } catch (_: IOException) {
                0L
            }
            val mtimeSec = try {
                Files.getLastModifiedTime(p).toMillis() / 1000L
            } catch (_: IOException) {
                0L
            }
            if (written > 0) sb.append(',')
            written++
            sb.append("{\"name\":").append(jstr(child.name))
            /* 路径是**词法**拼接（不解析链接）：绝不把 root 之外的绝对路径泄露给客户端 */
            sb.append(",\"path\":").append(jstr(dir.resolve(child.name).toString()))
            sb.append(",\"dir\":").append(if (isDir) 1 else 0)
            sb.append(",\"size\":").append(size)
            sb.append(",\"mtime\":").append(mtimeSec)
            sb.append('}')
        }
        sb.append(']')
        sb.append(",\"total\":").append(total)
        sb.append(",\"limit\":").append(limit)
        sb.append(",\"offset\":").append(offset)
        sb.append('}')
        return Triple(sb.toString(), null, null)
    }

    /* ==========================================================================
     * mkdir / delete
     * ========================================================================== */

    private fun mkdir(params: String): Triple<String, String?, String?> {
        val raw = Json.getString(params, "path")
            ?: return Triple("", "missing_path", null)
        val path = when (val r = resolvePath(raw)) {
            is Resolved.Bad -> return Triple("", r.code, r.detail)
            is Resolved.Ok -> r.path
        }
        if (Files.exists(path)) {
            if (Files.isDirectory(path)) return Triple(path.toString(), null, null)
            return Triple("", "mkdir_failed", "$path 已存在且不是目录")
        }
        try {
            Files.createDirectories(path)
        } catch (e: IOException) {
            return Triple("", "mkdir_failed", e.message ?: path.toString())
        }
        return Triple(path.toString(), null, null)
    }

    private fun delete(params: String): Triple<String, String?, String?> {
        val raw = Json.getString(params, "path")
            ?: return Triple("", "missing_path", null)
        if (Json.getBoolean(params, "confirm") != true) {
            return Triple("", "confirm_required", "删除必须显式携带 confirm=true")
        }
        val resolved = when (val r = resolvePath(raw)) {
            is Resolved.Bad -> return Triple("", r.code, r.detail)
            is Resolved.Ok -> r
        }
        val path = resolved.path
        if (resolved.isRoot) {
            return Triple("", "path_denied", "不能删除监控根目录")
        }
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            return Triple("", "not_found", path.toString())
        }
        try {
            if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
                /* 只删空目录：与 C 的 hd_rmdir（非空即失败）一致 */
                var nonEmpty = false
                Files.newDirectoryStream(path).use { stream ->
                    if (stream.iterator().hasNext()) nonEmpty = true
                }
                if (nonEmpty) return Triple("", "dir_not_empty", path.toString())
                Files.delete(path)
            } else {
                Files.delete(path)
            }
        } catch (e: IOException) {
            return Triple("", "remove_failed", e.message ?: path.toString())
        }
        return Triple(path.toString(), null, null)
    }

    /* ==========================================================================
     * download（§3：data.payload_bytes + 紧跟裸数据）
     * ========================================================================== */

    private fun handleDownload(out: OutputStream, id: String, params: String): Boolean {
        val raw = Json.getString(params, "path")
        if (raw == null) {
            sendError(out, id, "missing_path", null)
            return true
        }
        val path = when (val r = resolvePath(raw)) {
            is Resolved.Bad -> {
                sendError(out, id, r.code, r.detail)
                return true
            }
            is Resolved.Ok -> r.path
        }
        if (!Files.exists(path)) {
            sendError(out, id, "file_not_found", path.toString())
            return true
        }
        if (Files.isDirectory(path)) {
            sendError(out, id, "is_directory", path.toString())
            return true
        }
        val size = try {
            Files.size(path)
        } catch (e: IOException) {
            sendError(out, id, "open_failed", path.toString())
            return true
        }

        /* 权威哈希：对**实际要发送的字节**计算（§3）。算不出来就发空串，不编一个值。 */
        val hash = try {
            Xxh3_128.hexFile(path.toFile())
        } catch (_: IOException) {
            ""
        }

        val header = StringBuilder(512)
        header.append("{\"type\":\"response\",\"id\":").append(jstr(id))
        header.append(",\"status\":\"ok\",\"data\":{\"action\":\"download\"")
        header.append(",\"name\":").append(jstr(path.fileName?.toString() ?: ""))
        header.append(",\"path\":").append(jstr(path.toString()))
        header.append(",\"hash\":").append(jstr(hash))
        header.append(",\"index_hash\":\"\"")
        header.append(",\"size\":").append(size)
        header.append(",\"payload_bytes\":").append(size)
        header.append(",\"framing\":\"raw\"}}")
        out.write(header.toString().toByteArray(Charsets.UTF_8))
        out.write('\n'.code)

        /* 流式发送：不整文件进内存 */
        var sent = 0L
        FileInputStream(path.toFile()).use { input ->
            val buf = ByteArray(IO_CHUNK)
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                if (n == 0) continue
                out.write(buf, 0, n)
                sent += n.toLong()
            }
        }
        out.flush()
        if (sent != size) {
            /* 文件在发送期间被改动：客户端会因"实收 < payload_bytes"而失败，这里直接断连接 */
            throw IOException("download 发送字节数与声明不符：$sent/$size")
        }
        return true
    }

    /* ==========================================================================
     * upload（§3：请求顶层 payload_bytes + 紧跟裸数据）
     * ========================================================================== */

    private fun handleUpload(
        reader: FrameReader,
        out: OutputStream,
        id: String,
        params: String,
        declaredPayload: Long,
        hasTopLevelPayload: Boolean,
    ): Boolean {
        /* 声明了 payload_bytes 才叫上传；否则 missing_payload（§4.1） */
        if (!hasTopLevelPayload || declaredPayload <= 0L) {
            sendError(out, id, "missing_payload", "上传必须携带 payload_bytes")
            return drainOrClose(reader)
        }

        val raw = Json.getString(params, "path")
        if (raw == null) {
            sendError(out, id, "missing_path", null)
            return drainOrClose(reader)
        }

        val sizeParam = Json.getLong(params, "size") ?: declaredPayload
        if (sizeParam != declaredPayload) {
            sendError(out, id, "bad_size", "size 与 payload_bytes 不一致")
            return drainOrClose(reader)
        }

        val path = when (val r = resolvePath(raw)) {
            is Resolved.Bad -> {
                sendError(out, id, r.code, r.detail)
                return drainOrClose(reader)
            }
            is Resolved.Ok -> r.path
        }

        val overwrite = Json.getBoolean(params, "overwrite") == true
        val mkdirParents = Json.getBoolean(params, "mkdir") == true
        val wantHash = Json.getString(params, "hash") ?: ""

        if (Files.exists(path)) {
            if (Files.isDirectory(path)) {
                sendError(out, id, "is_directory", path.toString())
                return drainOrClose(reader)
            }
            if (!overwrite) {
                sendError(out, id, "exists", path.toString())
                return drainOrClose(reader)
            }
        }

        val parent = path.parent
        if (parent != null && !Files.isDirectory(parent)) {
            if (!mkdirParents) {
                sendError(out, id, "open_failed", "父目录不存在（需显式 mkdir:true）：$parent")
                return drainOrClose(reader)
            }
            try {
                Files.createDirectories(parent)
            } catch (e: IOException) {
                sendError(out, id, "mkdir_failed", parent.toString())
                return drainOrClose(reader)
            }
        }

        val part = File(path.toString() + ".part-" + System.currentTimeMillis())
        val hasher = Xxh3_128.Hasher()
        try {
            FileOutputStream(part).use { fos ->
                reader.readFully(declaredPayload) { buf, off, len ->
                    fos.write(buf, off, len)
                    hasher.update(buf, off, len)
                }
            }
        } catch (e: ProtocolException) {
            /* 负载没读满：流已错位，只能关闭（与 C 的 payload_incomplete 一致） */
            part.delete()
            try {
                sendError(out, id, "payload_incomplete", "负载长度不足")
            } catch (_: IOException) {
            }
            return false
        } catch (e: IOException) {
            part.delete()
            sendError(out, id, "write_failed", part.toString())
            return drainOrClose(reader)
        }

        val gotHash = hasher.hex()

        /* hash 可选；给了就必须一致（常量时间比较，与 C 的 hd_ct_equal 同义） */
        if (wantHash.isNotEmpty() && !constantTimeHexEquals(wantHash, gotHash)) {
            part.delete()
            sendError(out, id, "hash_mismatch", null)
            return true
        }

        /* Windows 上 rename 可能因瞬时共享冲突失败：重试几次（与 C 一致） */
        var moved = false
        for (attempt in 0 until 5) {
            if (attempt > 0) {
                try {
                    Thread.sleep(60L * attempt)
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                    break
                }
            }
            try {
                Files.move(
                    part.toPath(), path,
                    StandardCopyOption.REPLACE_EXISTING,
                )
                moved = true
                break
            } catch (_: IOException) {
            }
        }
        if (!moved) {
            part.delete()
            sendError(out, id, "rename_failed", path.toString())
            return true
        }

        val name = path.fileName?.toString() ?: ""
        sendOk(
            out, id,
            "{\"path\":${jstr(path.toString())},\"name\":${jstr(name)}" +
                ",\"size\":$declaredPayload,\"hash\":${jstr(gotHash)}}",
        )
        return true
    }

    /** 排空被拒请求的负载，使连接仍然可用；过大或流出错时返回 false（调用方关连接）。 */
    private fun drainOrClose(reader: FrameReader): Boolean {
        val remaining = reader.payloadRemaining
        if (remaining <= 0L) return true
        if (remaining > MAX_DRAIN_BYTES) return false
        return try {
            reader.skipPayload()
            true
        } catch (_: ProtocolException) {
            false
        } catch (_: IOException) {
            false
        }
    }

    /* ==========================================================================
     * verify（无索引：真实读一遍文件，只报真实结果）
     * ========================================================================== */

    private fun verifyJson(params: String): String {
        val run = Json.getBoolean(params, "run") == true
        if (run) {
            val started = System.nanoTime()
            var files = 0
            var bad = 0
            walkTree { _, path, _, _, _ ->
                files++
                try {
                    FileInputStream(path.toFile()).use { input ->
                        val buf = ByteArray(IO_CHUNK)
                        while (true) {
                            if (input.read(buf) < 0) break
                        }
                    }
                } catch (_: IOException) {
                    bad++
                }
            }
            val elapsed = (System.nanoTime() - started) / 1_000_000L
            synchronized(verifyLock) {
                verifiedFiles = files
                corruptCount = bad
                verifyCount++
                lastDurationMs = elapsed
                lastVerify = isoNow()
            }
        }
        val (vf, vc, sc, cc, dur, lv, ls) = synchronized(verifyLock) {
            VerifySnapshot(verifiedFiles, verifyCount, scanCount, corruptCount, lastDurationMs, lastVerify, lastScan)
        }
        return "{\"verified_files\":$vf,\"verify_count\":$vc,\"scan_count\":$sc" +
            ",\"scan_interval\":0,\"corrupt_count\":$cc,\"missing_count\":0" +
            ",\"last_duration_ms\":$dur,\"last_verify\":${jstr(lv)},\"last_scan\":${jstr(ls)}}"
    }

    private data class VerifySnapshot(
        val verifiedFiles: Int,
        val verifyCount: Int,
        val scanCount: Int,
        val corruptCount: Int,
        val lastDurationMs: Long,
        val lastVerify: String,
        val lastScan: String,
    )

    /* ==========================================================================
     * 文件树遍历（search / stats / verify / rescan 共用）
     * ========================================================================== */

    private class ScanResult(
        val count: Long,
        val size: Long,
        val types: Map<String, LongArray>,
        val lastUpdateMs: Long,
    )

    /**
     * 遍历真实文件树。规则与 C 的扫描一致：
     *   · 不进入符号链接 / Windows 目录联接（junction 在 Java 里 isOther=true）——
     *     否则 search/stats 会把 root 之外的文件也报出来；
     *   · 双保险：进目录前把它的真实路径与 root 比较一次，逃逸的子树直接跳过；
     *   · 跳过运行时产物（*.part-* / hamster.db* / hamsterd.log*）。
     */
    private fun walkTree(visitor: (name: String, path: Path, size: Long, mtimeMs: Long, ext: String) -> Unit) {
        try {
            Files.walkFileTree(rootReal, object : SimpleFileVisitor<Path>() {
                override fun preVisitDirectory(dir: Path, attrs: BasicFileAttributes): FileVisitResult {
                    if (dir == rootReal) return FileVisitResult.CONTINUE
                    if (attrs.isSymbolicLink || attrs.isOther) return FileVisitResult.SKIP_SUBTREE
                    return try {
                        if (within(dir.toRealPath())) FileVisitResult.CONTINUE
                        else FileVisitResult.SKIP_SUBTREE
                    } catch (_: IOException) {
                        FileVisitResult.SKIP_SUBTREE
                    }
                }

                override fun visitFile(file: Path, attrs: BasicFileAttributes): FileVisitResult {
                    if (attrs.isSymbolicLink || attrs.isOther || !attrs.isRegularFile) {
                        return FileVisitResult.CONTINUE
                    }
                    val name = file.fileName?.toString() ?: return FileVisitResult.CONTINUE
                    if (isArtifactName(name)) return FileVisitResult.CONTINUE
                    visitor(name, file, attrs.size(), attrs.lastModifiedTime().toMillis(), extOf(name))
                    return FileVisitResult.CONTINUE
                }

                override fun visitFileFailed(file: Path, exc: IOException): FileVisitResult =
                    FileVisitResult.CONTINUE
            })
        } catch (_: IOException) {
            /* 树在遍历中被改动：能统计多少算多少，不编造 */
        }
    }

    private fun scanTree(): ScanResult {
        var count = 0L
        var size = 0L
        var lastUpdate = 0L
        val types = HashMap<String, LongArray>()
        walkTree { _, _, sz, mtimeMs, ext ->
            count++
            size += sz
            if (mtimeMs > lastUpdate) lastUpdate = mtimeMs
            if (ext.isNotEmpty()) {
                val e = types[ext]
                if (e == null) {
                    types[ext] = longArrayOf(1L, sz)
                } else {
                    e[0]++
                    e[1] += sz
                }
            }
        }
        return ScanResult(count, size, types, lastUpdate)
    }

    private fun isArtifactName(name: String): Boolean =
        name.contains(".part-") || name.startsWith("hamster.db") || name.startsWith("hamsterd.log")

    /** file_type：小写扩展名、无点（与 C 侧入库规则一致）。 */
    private fun extOf(name: String): String {
        val dot = name.lastIndexOf('.')
        if (dot <= 0 || dot == name.length - 1) return ""
        return name.substring(dot + 1).lowercase()
    }

    /* ==========================================================================
     * 路径白名单（安全边界）
     *
     * 规则（对应 hd_net.c resolve_under_root + hd_util.c hd_path_sanitize_rel，
     * 并额外解析符号链接，因为 Java 的 getCanonicalPath 在 Windows 上不保证解析链接）：
     *   1. 空路径、控制字符 → 拒绝；
     *   2. 绝对路径（/ \ 或 X:）：只允许落在 root 真实路径之内；
     *   3. 相对路径：逐组件净化 —— 跳过 "."、折叠重复分隔符、拒绝 ".."、拒绝 ':'；
     *   4. 候选路径先解析到**最深已存在的祖先**的真实路径，再拼回不存在的尾部，
     *      然后做前缀包含性判断（Windows 不区分大小写）——软链接逃逸在这里被挡住；
     *   5. 返回给客户端的路径一律是解析后的真实路径，绝不泄露 root 之外的绝对路径。
     * ========================================================================== */

    private sealed class Resolved {
        class Ok(val path: Path, val isRoot: Boolean) : Resolved()
        class Bad(val code: String, val detail: String) : Resolved()
    }

    private fun resolvePath(raw: String): Resolved {
        if (raw.isEmpty()) return Resolved.Bad("path_denied", "空路径")
        for (c in raw) {
            if (c.code < 0x20 || c.code == 0x7F) {
                return Resolved.Bad("path_denied", "路径含控制字符")
            }
        }
        /* "/" 与 "\" 明确表示监控根（C 侧会把它解析成盘符根而拒绝；这里放宽且安全） */
        if (raw == "/" || raw == "\\") {
            return Resolved.Ok(rootReal, true)
        }

        val candidate: Path = if (isAbsoluteLike(raw)) {
            try {
                Paths.get(raw)
            } catch (e: Exception) {
                return Resolved.Bad("path_denied", "非法路径：${e.message ?: raw}")
            }
        } else {
            val parts = ArrayList<String>(4)
            var i = 0
            while (i < raw.length) {
                while (i < raw.length && isSep(raw[i])) i++
                val start = i
                while (i < raw.length && !isSep(raw[i])) i++
                if (i == start) continue
                val seg = raw.substring(start, i)
                when {
                    seg == "." -> Unit
                    seg == ".." -> return Resolved.Bad("path_denied", "相对路径中不允许 ..")
                    seg.indexOf(':') >= 0 -> return Resolved.Bad("path_denied", "路径不允许包含 ':'")
                    else -> parts.add(seg)
                }
            }
            if (parts.isEmpty()) return Resolved.Bad("path_denied", "空路径")
            var p = rootReal
            for (s in parts) p = p.resolve(s)
            p
        }

        val real = try {
            realOf(candidate)
        } catch (_: Throwable) {
            null
        } ?: return Resolved.Bad("path_denied", "无法解析路径")

        if (!within(real)) {
            return Resolved.Bad("path_denied", "路径越权：$raw")
        }
        val isRoot = pathEquals(real.toString(), rootRealString)
        return Resolved.Ok(real, isRoot)
    }

    /**
     * 把路径解析成真实路径：找到最深的**已存在**祖先，toRealPath()（解析链接），
     * 再把不存在的尾部组件原样拼回去。这样：
     *   · root/link-out/new.bin（link-out 指向 root 外）→ 解析后落在 root 外 → 被拒；
     *   · root/不存在/子目录 → 落在 root 内 → 允许（mkdir/upload 要用）。
     */
    private fun realOf(candidate: Path): Path? {
        /*
         * 注意：Windows 上 "a:b.txt" 这种盘符相对路径会让 toAbsolutePath() 抛
         * java.io.IOError（不是 Exception！）—— 必须按 Throwable 兜住，
         * 否则一个畸形路径就能把连接线程打死。
         */
        val abs = try {
            candidate.toAbsolutePath().normalize()
        } catch (_: Throwable) {
            return null
        }
        var cur: Path? = abs
        val missing = ArrayList<String>(4)
        while (cur != null && !Files.exists(cur, LinkOption.NOFOLLOW_LINKS)) {
            val name = cur.fileName?.toString() ?: return null
            missing.add(name)
            cur = cur.parent
        }
        val base = cur ?: return null
        var result = try {
            base.toRealPath()
        } catch (_: Throwable) {
            return null
        }
        for (k in missing.asReversed()) result = result.resolve(k)
        return result
    }

    private fun within(p: Path): Boolean {
        val s = p.toString()
        return if (caseInsensitive) {
            s.equals(rootRealString, ignoreCase = true) ||
                s.startsWith(rootPrefix, ignoreCase = true)
        } else {
            s == rootRealString || s.startsWith(rootPrefix)
        }
    }

    private fun pathEquals(a: String, b: String): Boolean =
        if (caseInsensitive) a.equals(b, ignoreCase = true) else a == b

    private fun isAbsoluteLike(t: String): Boolean {
        if (t.isEmpty()) return false
        if (t[0] == '/' || t[0] == '\\') return true
        return t.length >= 2 && t[1] == ':' &&
            ((t[0] in 'a'..'z') || (t[0] in 'A'..'Z'))
    }

    private fun isSep(c: Char): Boolean = c == '/' || c == '\\'

    /* ==========================================================================
     * 响应 / JSON 工具
     * ========================================================================== */

    private fun sendOk(out: OutputStream, id: String, data: String) {
        val body = if (data.isEmpty()) "{}" else data
        val line = "{\"type\":\"response\",\"id\":${jstr(id)},\"status\":\"ok\",\"data\":$body}\n"
        out.write(line.toByteArray(Charsets.UTF_8))
        out.flush()
    }

    /** §4.1 response_too_large：data 超过 1 MiB 就拒绝，而不是截断成半条 JSON。 */
    private fun sendOkLimited(out: OutputStream, id: String, data: String) {
        if (data.toByteArray(Charsets.UTF_8).size > MAX_RESPONSE_BYTES) {
            sendError(out, id, "response_too_large", "响应超过 1 MiB，请降低 limit 或缩小关键词")
            return
        }
        sendOk(out, id, data)
    }

    private fun sendError(out: OutputStream, id: String, code: String, detail: String?) {
        val d = if (detail.isNullOrEmpty()) "" else ",\"detail\":${jstr(detail)}"
        val line = "{\"type\":\"response\",\"id\":${jstr(id)},\"status\":\"error\"" +
            ",\"data\":{\"error\":${jstr(code)}$d}}\n"
        out.write(line.toByteArray(Charsets.UTF_8))
        out.flush()
    }

    private fun jstr(s: String): String {
        val sb = StringBuilder(s.length + 8)
        sb.append('"')
        for (c in s) {
            when (c) {
                '"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                '\b' -> sb.append("\\b")
                '\u000C' -> sb.append("\\f")
                else -> if (c.code < 0x20) {
                    sb.append("\\u00")
                    sb.append("0123456789abcdef"[(c.code shr 4) and 15])
                    sb.append("0123456789abcdef"[c.code and 15])
                } else {
                    sb.append(c)
                }
            }
        }
        sb.append('"')
        return sb.toString()
    }

    private fun nowSec(): Long = System.currentTimeMillis() / 1000L

    private fun isoNow(): String = isoLocal(System.currentTimeMillis())

    private fun isoLocal(epochMs: Long): String =
        ISO_LOCAL.format(LocalDateTime.ofInstant(Instant.ofEpochMilli(epochMs), ZoneId.systemDefault()))

    /** 十六进制字符串的常量时间比较（上传声明的 hash 与实收 hash）。 */
    private fun constantTimeHexEquals(a: String, b: String): Boolean {
        if (a.length != b.length) return false
        var diff = 0
        for (i in a.indices) {
            diff = diff or (a[i].lowercaseChar().code xor b[i].lowercaseChar().code)
        }
        return diff == 0
    }
}

/* ==========================================================================
 * xxHash3-128（默认 secret、seed=0），与 Hamsterd 的 XXH3_128bits 逐字节一致
 *
 * 为什么要自己写：PROTOCOL §3 里 download 响应头的 hash 是"实际发送字节的
 * xxHash3_128"，客户端会拿它做端到端校验、迁移时回传给 upload.hash。
 * 如果这里换成 SHA-256，Kotlin 守护端与 C 守护端之间就无法互认哈希。
 *
 * 实现依据 Hamsterd/xxhash.h（XXH3_128bits 的标量路径），并且用 gcc 编译
 * 同一份 xxhash.h 生成参考向量做了长度 0..300 与 1 MiB 的逐字节比对。
 * 只实现默认 secret + seed=0（守护进程只用这一种），因此代码里所有 seed 项都消失了。
 * ========================================================================== */
internal object Xxh3_128 {

    private val K_SECRET: ByteArray = hex(
        "b8fe6c3923a44bbe7c01812cf721ad1c" +
            "ded46de9839097db7240a4a4b7b3671f" +
            "cb79e64eccc0e578825ad07dccff7221" +
            "b8084674f743248ee03590e6813a264c" +
            "3c2852bb91c300cb88d0658b1b532ea3" +
            "71644897a20df94e3819ef46a9deacd8" +
            "a8fa763fe39c343ff9dcbbc7c70b4f1d" +
            "8a51e04bcdb45931c89f7ec9d9787364" +
            "eac5ac8334d3ebc3c581a0fffa1363eb" +
            "170ddd51b7f0da49d316552629d4689e" +
            "2b16be587d47a1fc8ff8b8d17ad031ce" +
            "45cb3a8f95160428afd7fbcabb4b407e",
    )

    private val P32_1: Long = 0x9E3779B1uL.toLong()
    private val P32_2: Long = 0x85EBCA77uL.toLong()
    private val P32_3: Long = 0xC2B2AE3DuL.toLong()
    private val P32_4: Long = 0x27D4EB2FuL.toLong()
    private val P32_5: Long = 0x165667B1uL.toLong()

    private val P64_1: Long = 0x9E3779B185EBCA87uL.toLong()
    private val P64_2: Long = 0xC2B2AE3D27D4EB4FuL.toLong()
    private val P64_3: Long = 0x165667B19E3779F9uL.toLong()
    private val P64_4: Long = 0x85EBCA77C2B2AE63uL.toLong()
    private val P64_5: Long = 0x27D4EB2F165667C5uL.toLong()

    private val MX1: Long = 0x165667919E3779F9uL.toLong()
    private val MX2: Long = 0x9FB21C651E98DF25uL.toLong()

    private const val STRIPE_LEN = 64
    private const val SECRET_CONSUME_RATE = 8
    private const val SECRET_LASTACC_START = 7
    private const val SECRET_MERGEACCS_START = 11
    private const val MIDSIZE_MAX = 240
    private const val MIDSIZE_STARTOFFSET = 3
    private const val MIDSIZE_LASTOFFSET = 17
    private const val INTERNAL_BUFFER = 256
    private const val SECRET_SIZE_MIN = 136
    private const val K_SECRET_SIZE = 192
    private const val SECRET_LIMIT = K_SECRET_SIZE - STRIPE_LEN
    private const val STRIPES_PER_BLOCK = SECRET_LIMIT / SECRET_CONSUME_RATE

    private val INIT_ACC = longArrayOf(P32_3, P64_1, P64_2, P64_3, P64_4, P32_2, P64_5, P32_1)

    /** 流式哈希器：与 XXH3_128bits_reset/update/digest 等价。 */
    class Hasher {
        private val acc = INIT_ACC.copyOf()
        private val buffer = ByteArray(INTERNAL_BUFFER)
        private val stripesSoFar = intArrayOf(0)
        private var bufferedSize = 0
        private var totalLen = 0L

        fun update(b: ByteArray, off0: Int, len0: Int) {
            if (len0 <= 0) return
            var off = off0
            var len = len0
            totalLen += len

            if (len <= INTERNAL_BUFFER - bufferedSize) {
                System.arraycopy(b, off, buffer, bufferedSize, len)
                bufferedSize += len
                return
            }

            if (bufferedSize > 0) {
                val loadSize = INTERNAL_BUFFER - bufferedSize
                System.arraycopy(b, off, buffer, bufferedSize, loadSize)
                off += loadSize
                len -= loadSize
                consumeStripes(acc, stripesSoFar, buffer, 0, INTERNAL_BUFFER / STRIPE_LEN)
                bufferedSize = 0
            }

            if (len > INTERNAL_BUFFER) {
                val nbStripes = (len - 1) / STRIPE_LEN
                val end = consumeStripes(acc, stripesSoFar, b, off, nbStripes)
                System.arraycopy(b, end - STRIPE_LEN, buffer, INTERNAL_BUFFER - STRIPE_LEN, STRIPE_LEN)
                off = end
                len -= nbStripes * STRIPE_LEN
            }

            System.arraycopy(b, off, buffer, 0, len)
            bufferedSize = len
        }

        /** @return [low64, high64] */
        fun digest(): LongArray {
            if (totalLen > MIDSIZE_MAX) {
                val accCopy = acc.copyOf()
                val lastStripe: ByteArray
                if (bufferedSize >= STRIPE_LEN) {
                    val nbStripes = (bufferedSize - 1) / STRIPE_LEN
                    val holder = intArrayOf(stripesSoFar[0])
                    consumeStripes(accCopy, holder, buffer, 0, nbStripes)
                    lastStripe = buffer.copyOfRange(bufferedSize - STRIPE_LEN, bufferedSize)
                } else {
                    val catchup = STRIPE_LEN - bufferedSize
                    lastStripe = ByteArray(STRIPE_LEN)
                    System.arraycopy(buffer, INTERNAL_BUFFER - catchup, lastStripe, 0, catchup)
                    System.arraycopy(buffer, 0, lastStripe, catchup, bufferedSize)
                }
                accumulate512(accCopy, lastStripe, 0, K_SECRET, SECRET_LIMIT - SECRET_LASTACC_START)
                val low = mergeAccs(accCopy, SECRET_MERGEACCS_START, totalLen * P64_1)
                val high = mergeAccs(
                    accCopy,
                    K_SECRET_SIZE - 64 - SECRET_MERGEACCS_START,
                    (totalLen * P64_2).inv(),
                )
                return longArrayOf(low, high)
            }
            return shortHash128(buffer, 0, totalLen.toInt())
        }

        /** 与 C 侧 hd_hash_file 的输出一致：先 high64 再 low64，各 16 位小写十六进制。 */
        fun hex(): String {
            val h = digest()
            return String.format("%016x%016x", h[1], h[0])
        }
    }

    fun hashHex(data: ByteArray): String {
        val h = Hasher()
        h.update(data, 0, data.size)
        return h.hex()
    }

    /** 流式计算文件哈希（64 KiB 一块，不整文件进内存）。 */
    fun hexFile(f: File): String {
        val h = Hasher()
        FileInputStream(f).use { input ->
            val buf = ByteArray(64 * 1024)
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                if (n == 0) continue
                h.update(buf, 0, n)
            }
        }
        return h.hex()
    }

    /* ---------------------------------------------------------------- 长输入路径 */

    private fun accumulate512(acc: LongArray, input: ByteArray, inOff: Int, secret: ByteArray, secOff: Int) {
        var lane = 0
        while (lane < 8) {
            val dataVal = readLE64(input, inOff + lane * 8)
            val dataKey = dataVal xor readLE64(secret, secOff + lane * 8)
            acc[lane xor 1] = acc[lane xor 1] + dataVal
            acc[lane] = acc[lane] + (dataKey and 0xFFFFFFFFL) * (dataKey ushr 32)
            lane++
        }
    }

    private fun accumulate(
        acc: LongArray, input: ByteArray, inOff: Int,
        secret: ByteArray, secOff: Int, nbStripes: Int,
    ) {
        var n = 0
        while (n < nbStripes) {
            accumulate512(acc, input, inOff + n * STRIPE_LEN, secret, secOff + n * SECRET_CONSUME_RATE)
            n++
        }
    }

    private fun scrambleAcc(acc: LongArray, secret: ByteArray, secOff: Int) {
        var lane = 0
        while (lane < 8) {
            var a = acc[lane]
            a = a xor (a ushr 47)
            a = a xor readLE64(secret, secOff + lane * 8)
            a *= P32_1
            acc[lane] = a
            lane++
        }
    }

    /** 与 XXH3_consumeStripes 等价；返回处理完的输入偏移。 */
    private fun consumeStripes(
        acc: LongArray,
        stripesSoFar: IntArray,
        input: ByteArray,
        inOff: Int,
        nbStripes: Int,
    ): Int {
        var stripes = nbStripes
        var off = inOff
        var secretOff = stripesSoFar[0] * SECRET_CONSUME_RATE

        if (stripes >= STRIPES_PER_BLOCK - stripesSoFar[0]) {
            var thisIter = STRIPES_PER_BLOCK - stripesSoFar[0]
            do {
                accumulate(acc, input, off, K_SECRET, secretOff, thisIter)
                scrambleAcc(acc, K_SECRET, SECRET_LIMIT)
                off += thisIter * STRIPE_LEN
                stripes -= thisIter
                thisIter = STRIPES_PER_BLOCK
                secretOff = 0
            } while (stripes >= STRIPES_PER_BLOCK)
            stripesSoFar[0] = 0
        }
        if (stripes > 0) {
            accumulate(acc, input, off, K_SECRET, secretOff, stripes)
            off += stripes * STRIPE_LEN
            stripesSoFar[0] += stripes
        }
        return off
    }

    private fun mergeAccs(acc: LongArray, secretOff: Int, start: Long): Long {
        var result = start
        var i = 0
        while (i < 4) {
            val a = acc[2 * i] xor readLE64(K_SECRET, secretOff + 16 * i)
            val b = acc[2 * i + 1] xor readLE64(K_SECRET, secretOff + 16 * i + 8)
            result += mul128Fold64(a, b)
            i++
        }
        return avalanche(result)
    }

    /* ---------------------------------------------------------------- 短输入路径（≤240） */

    private fun shortHash128(b: ByteArray, off: Int, len: Int): LongArray = when {
        len > 128 -> len129to240(b, off, len)
        len > 16 -> len17to128(b, off, len)
        else -> len0to16(b, off, len)
    }

    private fun len0to16(b: ByteArray, off: Int, len: Int): LongArray = when {
        len > 8 -> len9to16(b, off, len)
        len >= 4 -> len4to8(b, off, len)
        len > 0 -> len1to3(b, off, len)
        else -> {
            val bitflipL = readLE64(K_SECRET, 64) xor readLE64(K_SECRET, 72)
            val bitflipH = readLE64(K_SECRET, 80) xor readLE64(K_SECRET, 88)
            longArrayOf(xxh64Avalanche(bitflipL), xxh64Avalanche(bitflipH))
        }
    }

    private fun len1to3(b: ByteArray, off: Int, len: Int): LongArray {
        val c1 = b[off].toInt() and 0xFF
        val c2 = b[off + (len shr 1)].toInt() and 0xFF
        val c3 = b[off + len - 1].toInt() and 0xFF
        val combinedL = (c1 shl 16) or (c2 shl 24) or c3 or (len shl 8)
        val combinedH = rotl32(Integer.reverseBytes(combinedL), 13)
        val bitflipL = (readLE32(K_SECRET, 0) xor readLE32(K_SECRET, 4)).toLong() and 0xFFFFFFFFL
        val bitflipH = (readLE32(K_SECRET, 8) xor readLE32(K_SECRET, 12)).toLong() and 0xFFFFFFFFL
        val keyedLo = (combinedL.toLong() and 0xFFFFFFFFL) xor bitflipL
        val keyedHi = (combinedH.toLong() and 0xFFFFFFFFL) xor bitflipH
        return longArrayOf(xxh64Avalanche(keyedLo), xxh64Avalanche(keyedHi))
    }

    private fun len4to8(b: ByteArray, off: Int, len: Int): LongArray {
        val inputLo = readLE32(b, off).toLong() and 0xFFFFFFFFL
        val inputHi = readLE32(b, off + len - 4).toLong() and 0xFFFFFFFFL
        val input64 = inputLo + (inputHi shl 32)
        val bitflip = readLE64(K_SECRET, 16) xor readLE64(K_SECRET, 24)
        val keyed = input64 xor bitflip
        val m = mul128(keyed, P64_1 + (len.toLong() shl 2))
        var mLow = m[0]
        var mHigh = m[1]
        mHigh += mLow shl 1
        mLow = mLow xor (mHigh ushr 3)
        mLow = mLow xor (mLow ushr 35)
        mLow *= MX2
        mLow = mLow xor (mLow ushr 28)
        mHigh = avalanche(mHigh)
        return longArrayOf(mLow, mHigh)
    }

    private fun len9to16(b: ByteArray, off: Int, len: Int): LongArray {
        val bitflipL = readLE64(K_SECRET, 32) xor readLE64(K_SECRET, 40)
        val bitflipH = readLE64(K_SECRET, 48) xor readLE64(K_SECRET, 56)
        val inputLo = readLE64(b, off)
        var inputHi = readLE64(b, off + len - 8)
        val m = mul128(inputLo xor inputHi xor bitflipL, P64_1)
        var mLow = m[0]
        var mHigh = m[1]
        mLow += (len - 1).toLong() shl 54
        inputHi = inputHi xor bitflipH
        mHigh += inputHi + (inputHi and 0xFFFFFFFFL) * (P32_2 - 1L)
        mLow = mLow xor java.lang.Long.reverseBytes(mHigh)
        val h = mul128(mLow, P64_2)
        var hLow = h[0]
        var hHigh = h[1]
        hHigh += mHigh * P64_2
        hLow = avalanche(hLow)
        hHigh = avalanche(hHigh)
        return longArrayOf(hLow, hHigh)
    }

    /** XXH128_mix32B（seed=0）。 */
    private fun mix32B(
        acc: LongArray, b: ByteArray, off: Int,
        in1: Int, in2: Int, secOff: Int,
    ) {
        acc[0] += mix16B(b, off + in1, secOff)
        acc[0] = acc[0] xor (readLE64(b, off + in2) + readLE64(b, off + in2 + 8))
        acc[1] += mix16B(b, off + in2, secOff + 16)
        acc[1] = acc[1] xor (readLE64(b, off + in1) + readLE64(b, off + in1 + 8))
    }

    private fun mix16B(b: ByteArray, inOff: Int, secOff: Int): Long {
        val lo = readLE64(b, inOff)
        val hi = readLE64(b, inOff + 8)
        return mul128Fold64(
            lo xor readLE64(K_SECRET, secOff),
            hi xor readLE64(K_SECRET, secOff + 8),
        )
    }

    private fun len17to128(b: ByteArray, off: Int, len: Int): LongArray {
        val acc = longArrayOf(len.toLong() * P64_1, 0L)
        if (len > 32) {
            if (len > 64) {
                if (len > 96) {
                    mix32B(acc, b, off, 48, len - 64, 96)
                }
                mix32B(acc, b, off, 32, len - 48, 64)
            }
            mix32B(acc, b, off, 16, len - 32, 32)
        }
        mix32B(acc, b, off, 0, len - 16, 0)
        return finalizeMid(acc, len)
    }

    private fun len129to240(b: ByteArray, off: Int, len: Int): LongArray {
        val acc = longArrayOf(len.toLong() * P64_1, 0L)
        var i = 32
        while (i < 160) {
            mix32B(acc, b, off, i - 32, i - 16, i - 32)
            i += 32
        }
        acc[0] = avalanche(acc[0])
        acc[1] = avalanche(acc[1])
        i = 160
        while (i <= len) {
            mix32B(acc, b, off, i - 32, i - 16, MIDSIZE_STARTOFFSET + i - 160)
            i += 32
        }
        /* 最后 32 字节：C 侧用 secret + SECRET_SIZE_MIN - MIDSIZE_LASTOFFSET - 16 */
        mix32B(acc, b, off, len - 16, len - 32, SECRET_SIZE_MIN - MIDSIZE_LASTOFFSET - 16)
        return finalizeMid(acc, len)
    }

    private fun finalizeMid(acc: LongArray, len: Int): LongArray {
        val low = acc[0] + acc[1]
        val high = acc[0] * P64_1 + acc[1] * P64_4 + len.toLong() * P64_2
        return longArrayOf(avalanche(low), 0L - avalanche(high))
    }

    /* ---------------------------------------------------------------- 基础运算 */

    private fun mul128Fold64(a: Long, b: Long): Long {
        val p = mul128(a, b)
        return p[0] xor p[1]
    }

    /** 64x64 → 128（无符号语义，返回 [low, high]）。 */
    private fun mul128(a: Long, b: Long): LongArray {
        val aLo = a and 0xFFFFFFFFL
        val aHi = a ushr 32
        val bLo = b and 0xFFFFFFFFL
        val bHi = b ushr 32

        val lo = aLo * bLo
        val mid1 = aHi * bLo
        val mid2 = aLo * bHi
        val mid = (lo ushr 32) + (mid1 and 0xFFFFFFFFL) + (mid2 and 0xFFFFFFFFL)
        val low = (mid shl 32) or (lo and 0xFFFFFFFFL)
        val high = aHi * bHi + (mid1 ushr 32) + (mid2 ushr 32) + (mid ushr 32)
        return longArrayOf(low, high)
    }

    private fun avalanche(h: Long): Long {
        var x = h
        x = x xor (x ushr 37)
        x *= MX1
        x = x xor (x ushr 32)
        return x
    }

    private fun xxh64Avalanche(h: Long): Long {
        var x = h
        x = x xor (x ushr 33)
        x *= P64_2
        x = x xor (x ushr 29)
        x *= P64_3
        x = x xor (x ushr 32)
        return x
    }

    private fun rotl32(x: Int, r: Int): Int = (x shl r) or (x ushr (32 - r))

    private fun readLE64(b: ByteArray, off: Int): Long {
        var v = 0L
        var i = 0
        while (i < 8) {
            v = v or ((b[off + i].toLong() and 0xFFL) shl (8 * i))
            i++
        }
        return v
    }

    private fun readLE32(b: ByteArray, off: Int): Int =
        (b[off].toInt() and 0xFF) or
            ((b[off + 1].toInt() and 0xFF) shl 8) or
            ((b[off + 2].toInt() and 0xFF) shl 16) or
            ((b[off + 3].toInt() and 0xFF) shl 24)

    private fun hex(s: String): ByteArray {
        val out = ByteArray(s.length / 2)
        for (i in out.indices) {
            out[i] = s.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
        return out
    }
}
