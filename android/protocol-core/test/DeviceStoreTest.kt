/*
 * DeviceStoreTest.kt — DeviceStore 零依赖自检（纯 JVM，不碰 Android）
 *
 * 为什么放在 protocol-core/test：DeviceStore.kt 刻意不引用任何 Android API，
 * 所以可以用 kotlinc 把它和本文件一起编成普通 JVM 程序，直接验证文件格式、
 * 原子性、坏文件隔离这些"错了就丢用户数据"的细节。
 *
 * 运行（仓库根目录）：
 *   kotlinc android\app-manager\src\hamster\app\manager\DeviceStore.kt ^
 *           android\protocol-core\test\DeviceStoreTest.kt ^
 *           -include-runtime -d android\protocol-core\build\devstore\devstore-test.jar
 *   java -jar android\protocol-core\build\devstore\devstore-test.jar
 *
 * 退出码：0 = 全部通过，1 = 有失败。
 * 临时文件：android/protocol-core/build/devstore/tmp/（每次运行前清空）。
 * 供人工复核的样例：android/protocol-core/build/devstore/sample-devices.json。
 */
package hamster.app.manager

import java.io.File
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

private var pass = 0
private var fail = 0

private fun section(title: String) {
    println()
    println("== $title")
}

private fun check(cond: Boolean, name: String, detail: String = "") {
    if (cond) {
        pass++
        println("  ok   $name")
    } else {
        fail++
        println("  FAIL $name" + if (detail.isNotEmpty()) "  → $detail" else "")
    }
}

private fun <T> eq(actual: T, expected: T, name: String) {
    check(actual == expected, name, "期望=$expected 实际=$actual")
}

private fun bytes(s: String): ByteArray = s.toByteArray(Charsets.UTF_8)

private fun writeBytes(f: File, data: ByteArray) {
    f.parentFile?.mkdirs()
    f.writeBytes(data)
}

private fun writeText(f: File, text: String) = writeBytes(f, bytes(text))

private fun bytesEq(actual: ByteArray, expected: ByteArray, name: String) {
    check(actual.contentEquals(expected), name, "期望 ${expected.size} 字节，实际 ${actual.size} 字节")
}

/* ========================================================================== */

private lateinit var buildDir: File
private lateinit var workDir: File
private var caseSeq = 0

private fun caseDir(name: String): File {
    caseSeq++
    val d = File(workDir, "%02d-%s".format(caseSeq, name))
    d.deleteRecursively()
    d.mkdirs()
    return d
}

fun main() {
    println("DeviceStore 自检（纯 JVM / Kotlin）")
    println("文件格式：{\"v\":1,\"devices\":[{host,port,deviceId,name,version,lastSeenMs}]}")

    buildDir = File(System.getProperty("user.dir"), "android/protocol-core/build/devstore")
    workDir = File(buildDir, "tmp")
    workDir.deleteRecursively()
    check(workDir.mkdirs() || workDir.isDirectory, "准备临时目录：$workDir")

    testMissingAndEmpty()
    testRoundTripAndShape()
    testDedupeOrderTouch()
    testRemoveAndClear()
    testBadFiles()
    testDuplicateEntriesAndDefaults()
    testCap200()
    testEscapes()
    testAtomicAndConcurrent()
    testNestedPath()

    println()
    println("PASS $pass / FAIL $fail")
    if (fail != 0) System.exit(1)
}

/* ==========================================================================
 * 1. 不存在 / 空 / 只含空白
 * ========================================================================== */
private fun testMissingAndEmpty() {
    section("1. 不存在 / 空文件")

    val dir = caseDir("missing")
    val f = File(dir, "devices.json")
    val st = DeviceStore(f)

    eq(st.load(), emptyList<KnownDevice>(), "文件不存在 → 空表")
    check(!f.exists(), "load 不会创建文件")
    check(!File(f.path + ".bad").exists(), "文件不存在不会产生 .bad")

    writeBytes(f, ByteArray(0))
    eq(DeviceStore(f).load(), emptyList<KnownDevice>(), "空文件 → 空表")
    check(f.exists(), "空文件不会被删掉")
    check(!File(f.path + ".bad").exists(), "空文件不算坏文件")

    writeText(f, " \r\n\t ")
    eq(DeviceStore(f).load(), emptyList<KnownDevice>(), "只有空白的文件 → 空表")
    check(!File(f.path + ".bad").exists(), "只含空白不算坏文件")
}

/* ==========================================================================
 * 2. 正常存取 + 落盘 JSON 形状
 * ========================================================================== */
private fun testRoundTripAndShape() {
    section("2. 正常存取 / JSON 形状 / 不残留 .tmp")

    val dir = caseDir("roundtrip")
    val f = File(dir, "devices.json")
    val st = DeviceStore(f)
    val dev = KnownDevice(
        host = "192.168.1.10",
        port = 9100,
        deviceId = "ab12cd34ef567890",
        name = "my-pc",
        version = "0.0.9",
        lastSeenMs = 1_730_000_000_000L,
    )

    eq(st.upsert(dev), listOf(dev), "upsert 返回更新后的列表")
    eq(st.load(), listOf(dev), "load 读回同一条记录")

    val text = f.readText()
    println("    落盘样例: " + text.trim())
    check(text.startsWith("{"), "文件是一个 JSON 对象")
    check(text.contains("\"devices\":["), "含 devices 数组")
    check(text.contains("\"lastSeenMs\":1730000000000"), "lastSeenMs 写成整数（不是字符串/小数）")
    check(!File(f.path + ".tmp").exists(), "写完后没有残留 .tmp")
    check(!File(f.path + ".bad").exists(), "正常文件不产生 .bad")

    val before = f.readText()
    st.load()
    eq(f.readText(), before, "load 不会改写文件")

    // 给外部用 node/JSON.parse 复核的样例（test 报告里会贴出来）
    runCatching { f.copyTo(File(buildDir, "sample-devices.json"), overwrite = true) }
        .onFailure { println("    （样例复制失败：${it.message}）") }
}

/* ==========================================================================
 * 3. key 去重 / lastSeenMs 倒序 / touch
 * ========================================================================== */
private fun testDedupeOrderTouch() {
    section("3. key 去重 / 排序 / touch")

    val dir = caseDir("order")
    val f = File(dir, "devices.json")
    val st = DeviceStore(f)

    val a = KnownDevice("10.0.0.1", 9100, "idA", "A", "1", 1000)
    val b = KnownDevice("10.0.0.2", 9100, "idB", "B", "1", 3000)
    val c = KnownDevice("10.0.0.3", 9100, "", "C", "1", 2000)

    st.upsert(a)
    st.upsert(b)
    st.upsert(c)
    eq(st.load().map { it.name }, listOf("B", "C", "A"), "按 lastSeenMs 倒序")

    st.upsert(a.copy(name = "A2", version = "2", lastSeenMs = 4000))
    val after = st.load()
    eq(after.size, 3, "同 key 覆盖而不是新增")
    eq(after.first().name, "A2", "覆盖后取最新值")
    eq(after.first().lastSeenMs, 4000L, "覆盖后 lastSeenMs 更新")
    eq(after.first().deviceId, "idA", "key 里的 deviceId 不变")

    // 同 host:port、不同 deviceId → 两条（同一台机器上的不同实例）
    st.upsert(KnownDevice("10.0.0.1", 9100, "idA2", "A-other", "1", 5000))
    eq(
        st.load().count { it.host == "10.0.0.1" && it.port == 9100 },
        2,
        "deviceId 参与 key：同 host:port 不同 deviceId 是两条",
    )
    // 同 host、不同 port → 两条（key 含 port）
    st.upsert(KnownDevice("10.0.0.1", 9200, "idA", "A-other-port", "1", 5000))
    eq(
        st.load().count { it.host == "10.0.0.1" && it.deviceId == "idA" },
        2,
        "port 参与 key：同 host 不同 port 是两条",
    )
    // deviceId 为空串的两条不同 host → 两条（空串不能把不同设备并成一条）
    st.upsert(KnownDevice("10.0.0.4", 9100, "", "D", "1", 5000))
    eq(
        st.load().count { it.deviceId.isEmpty() },
        2,
        "空 deviceId 用 host:port 兜底，不同 host 不会合并",
    )

    // touch：更新的时间 → 立刻排到最前
    val touched = st.touch("10.0.0.2", 9100, "idB", 9000)
    eq(touched.first().name, "B", "touch 后该记录排到最前")
    eq(touched.first().lastSeenMs, 9000L, "touch 写入新的 lastSeenMs")

    // touch：旧时间不能把记录排回去
    val noRegress = st.touch("10.0.0.2", 9100, "idB", 1)
    eq(
        noRegress.first { it.name == "B" }.lastSeenMs,
        9000L,
        "touch 用更旧的时间不会倒退",
    )

    // touch 不存在的 key：不新增、文件不变
    val countBefore = st.load().size
    val same = st.touch("9.9.9.9", 9100, "nope", 12345)
    eq(same.size, countBefore, "touch 不存在的 key 不会新增记录")
    eq(st.load(), same, "touch 不存在的 key 不落盘")

    // 倒序是严格按 lastSeenMs
    val times = st.load().map { it.lastSeenMs }
    eq(times, times.sortedDescending(), "返回列表的 lastSeenMs 严格倒序")

    // 调用方传入非法 port：显式失败，且不能把坏记录写进文件
    var rejected = false
    try {
        st.upsert(KnownDevice("10.0.0.1", 0, "bad", "bad", "1", 1))
    } catch (_: IllegalArgumentException) {
        rejected = true
    }
    check(rejected, "port 越界的 upsert 抛 IllegalArgumentException")
    check(!File(f.path + ".bad").exists(), "非法 upsert 没有污染文件（不产生 .bad）")
    check(st.load().none { it.name == "bad" }, "非法 upsert 没有写进设备库")
}

/* ==========================================================================
 * 4. remove / clear
 * ========================================================================== */
private fun testRemoveAndClear() {
    section("4. remove / clear")

    val dir = caseDir("remove")
    val f = File(dir, "devices.json")
    val st = DeviceStore(f)
    st.upsert(KnownDevice("10.0.0.1", 9100, "a", "A", "1", 1))
    st.upsert(KnownDevice("10.0.0.2", 9100, "b", "B", "1", 2))
    st.upsert(KnownDevice("10.0.0.3", 9100, "c", "C", "1", 3))

    val removed = st.remove("10.0.0.2", 9100, "b")
    eq(removed.map { it.name }, listOf("C", "A"), "remove 删掉指定 key")
    eq(st.load(), removed, "remove 已落盘")
    eq(st.remove("10.0.0.2", 9100, "b"), removed, "remove 不存在的 key 是幂等的")

    // 写一个假 .tmp，clear 应一并清掉
    val tmp = File(f.path + ".tmp")
    writeText(tmp, "junk")
    st.clear()
    check(!f.exists(), "clear 删掉库文件")
    check(!tmp.exists(), "clear 删掉残留的 .tmp")
    eq(st.load(), emptyList<KnownDevice>(), "clear 后 load 空表")
    check(!File(f.path + ".bad").exists(), "clear 不会产生 .bad")
}

/* ==========================================================================
 * 5. 坏文件：空表 + .bad 保留证据
 * ========================================================================== */
private fun testBadFiles() {
    section("5. 坏文件 → 空表 + .bad 证据")

    fun quarantineCase(tag: String, content: ByteArray, why: String) {
        val dir = caseDir("bad-$tag")
        val f = File(dir, "devices.json")
        writeBytes(f, content)
        val bad = File(f.path + ".bad")

        eq(DeviceStore(f).load(), emptyList<KnownDevice>(), "$why → 空表")
        check(!f.exists(), "$why → 原文件已被移走（不留在原位冒充正常数据）")
        check(bad.exists(), "$why → 生成 .bad")
        bytesEq(bad.readBytes(), content, "$why → .bad 内容逐字节保留")
        eq(DeviceStore(f).load(), emptyList<KnownDevice>(), "$why → 再次 load 仍是空表")
        check(bad.exists(), "$why → 第二次 load 不会再改 .bad")
    }

    // 截断 JSON（磁盘写满 / 进程被杀最可能产生的形态）
    quarantineCase(
        "truncated",
        bytes("{\"v\":1,\"devices\":[{\"host\":\"1.2.3.4\",\"port\":9100"),
        "截断的 JSON",
    )
    // 非法 UTF-8 / 二进制乱码
    quarantineCase(
        "garbage",
        byteArrayOf(0xFF.toByte(), 0xFE.toByte(), 0x00, 0x7B, 0x22, 0x0A),
        "乱码（非法 UTF-8）",
    )
    // 字段类型不对
    quarantineCase(
        "type",
        bytes("{\"v\":1,\"devices\":[{\"host\":123,\"port\":9100," +
            "\"deviceId\":\"x\",\"name\":\"n\",\"version\":\"1\",\"lastSeenMs\":1}]}"),
        "host 类型错误（数字）",
    )
    quarantineCase(
        "port-string",
        bytes("{\"v\":1,\"devices\":[{\"host\":\"h\",\"port\":\"9100\"}]}"),
        "port 类型错误（字符串）",
    )
    quarantineCase(
        "lastseen-float",
        bytes("{\"v\":1,\"devices\":[{\"host\":\"h\",\"port\":9100,\"lastSeenMs\":1.5}]}"),
        "lastSeenMs 是小数",
    )
    quarantineCase(
        "port-zero",
        bytes("{\"v\":1,\"devices\":[{\"host\":\"h\",\"port\":0}]}"),
        "port 为 0",
    )
    quarantineCase(
        "port-overflow",
        bytes("{\"v\":1,\"devices\":[{\"host\":\"h\",\"port\":70000}]}"),
        "port 越界",
    )
    quarantineCase(
        "missing-host",
        bytes("{\"v\":1,\"devices\":[{\"port\":9100}]}"),
        "缺 host",
    )
    quarantineCase(
        "root-array",
        bytes("[{\"host\":\"1.2.3.4\",\"port\":9100}]"),
        "根不是对象",
    )
    quarantineCase(
        "devices-object",
        bytes("{\"v\":1,\"devices\":{}}"),
        "devices 不是数组",
    )
    quarantineCase("json-null", bytes("null"), "JSON null")
    quarantineCase("empty-obj", bytes("{}"), "缺 devices 字段")

    // 第二个坏文件到来时，.bad 被新的证据替换（只保留最近一次）
    val dir = caseDir("bad-replace")
    val f = File(dir, "devices.json")
    writeBytes(f, bytes("{\"v\":1,\"devices\":[{\"host\":\"a\""))
    DeviceStore(f).load()
    bytesEq(File(f.path + ".bad").readBytes(), bytes("{\"v\":1,\"devices\":[{\"host\":\"a\""), "第一次隔离的 .bad 内容")
    writeBytes(f, bytes("!!!not json!!!"))
    DeviceStore(f).load()
    bytesEq(File(f.path + ".bad").readBytes(), bytes("!!!not json!!!"), "再次隔离时 .bad 被最新证据替换")
}

/* ==========================================================================
 * 6. 文件里的重复项 / 未知字段 / 缺可选字段
 * ========================================================================== */
private fun testDuplicateEntriesAndDefaults() {
    section("6. 重复项去重 / 未知字段 / 缺可选字段")

    val dir = caseDir("duplicates")
    val f = File(dir, "devices.json")

    writeText(
        f,
        """
        {"v":1,"devices":[
          {"host":"10.0.0.9","port":9100,"deviceId":"k","name":"old","version":"1","lastSeenMs":5},
          {"host":"10.0.0.9","port":9100,"deviceId":"k","name":"new","version":"2","lastSeenMs":9},
          {"host":"10.0.0.9","port":9100,"deviceId":"k","name":"older","version":"0","lastSeenMs":1}
        ]}
        """.trimIndent(),
    )
    val list = DeviceStore(f).load()
    eq(list.size, 1, "同 key 三条 → 去重成一条")
    eq(list[0].name, "new", "保留 lastSeenMs 最大的那条")
    check(!File(f.path + ".bad").exists(), "重复项不是坏文件")

    // 未知字段忽略（向前兼容）+ 缺可选字段按默认值
    writeText(f, "{\"v\":1,\"devices\":[{\"host\":\"10.0.0.7\",\"port\":9200,\"extra\":{\"a\":1}}]}")
    val minimal = DeviceStore(f).load()
    eq(minimal.size, 1, "未知字段被忽略，记录仍可读")
    eq(minimal[0].deviceId, "", "缺 deviceId → 空串")
    eq(minimal[0].name, "", "缺 name → 空串")
    eq(minimal[0].version, "", "缺 version → 空串")
    eq(minimal[0].lastSeenMs, 0L, "缺 lastSeenMs → 0")
    check(!File(f.path + ".bad").exists(), "缺可选字段不是坏文件")

    // 顶层未知字段也必须容忍（以后加 v2 字段时旧版不该删文件）
    writeText(f, "{\"v\":1,\"devices\":[],\"future\":true}")
    eq(DeviceStore(f).load(), emptyList<KnownDevice>(), "顶层未知字段被忽略")
}

/* ==========================================================================
 * 7. 200 条截断
 * ========================================================================== */
private fun testCap200() {
    section("7. 200 条截断")

    val dir = caseDir("cap")
    val f = File(dir, "devices.json")
    val st = DeviceStore(f)

    repeat(250) { i ->
        st.upsert(KnownDevice("10.0.0.$i", 9100 + i, "id-$i", "dev-$i", "1", i.toLong()))
    }

    eq(st.upsert(KnownDevice("10.0.0.0", 9100, "id-0", "dev-0", "1", 0L)).size, 200, "upsert 返回值也不超过 200 条")
    val list = st.load()
    eq(list.size, 200, "最多保留 200 条")
    eq(list.first().deviceId, "id-249", "最新的一条在最前")
    eq(list.last().deviceId, "id-50", "保留第 51..250 新的记录")
    check(list.none { it.deviceId == "id-49" }, "最旧的 50 条被截掉")
    eq(DeviceStore(f).load().size, 200, "重新 load 仍是 200 条")
    check(!File(f.path + ".bad").exists(), "截断不产生 .bad")

    // 直接往文件里塞 250 条（模拟旧版本/外部写入）：load 自身也必须截断
    val many = buildString {
        append("{\"v\":1,\"devices\":[")
        repeat(250) { i ->
            if (i > 0) append(',')
            append("{\"host\":\"10.2.0.").append(i)
            append("\",\"port\":").append(9300 + i)
            append(",\"deviceId\":\"raw-").append(i)
            append("\",\"name\":\"raw\",\"version\":\"1\",\"lastSeenMs\":").append(i)
            append('}')
        }
        append("]}")
    }
    writeText(f, many)
    val fromFile = DeviceStore(f).load()
    eq(fromFile.size, 200, "文件里已有 250 条 → load 截断到 200")
    eq(fromFile.first().deviceId, "raw-249", "文件内截断同样保留最新的")
    check(!File(f.path + ".bad").exists(), "超长列表不是坏文件")
}

/* ==========================================================================
 * 8. 特殊字符往返
 * ========================================================================== */
private fun testEscapes() {
    section("8. 特殊字符往返")

    val dir = caseDir("escapes")
    val f = File(dir, "devices.json")
    val st = DeviceStore(f)
    val weird = KnownDevice(
        host = "fe80::1",
        port = 9100,
        deviceId = "",
        name = "a\"b\\c\nd\te中😀",
        version = "0.0.9-β",
        lastSeenMs = 42,
    )
    st.upsert(weird)
    eq(st.load(), listOf(weird), "引号/反斜杠/换行/制表符/中文/emoji/非 ASCII 版本号往返一致")
    check(f.readText().contains("\\n") && f.readText().contains("\\t"), "控制字符在文件里被转义（不是裸字符）")
}

/* ==========================================================================
 * 9. 原子写 / 并发
 * ========================================================================== */
private fun testAtomicAndConcurrent() {
    section("9. 原子写 / 并发读写")

    val dir = caseDir("atomic")
    val f = File(dir, "devices.json")
    val st = DeviceStore(f)
    st.upsert(KnownDevice("10.9.9.9", 9100, "seed", "seed", "1", 1))

    val writers = 4
    val readers = 4
    val perWriter = 40
    val start = CountDownLatch(1)
    val done = CountDownLatch(writers + readers)
    val errors = Collections.synchronizedList(ArrayList<String>())

    for (w in 0 until writers) {
        Thread {
            try {
                start.await()
                repeat(perWriter) { i ->
                    st.upsert(
                        KnownDevice(
                            "10.8.$w.${i % 7}",
                            9200 + i,
                            "w$w-$i",
                            "w$w",
                            "1",
                            10_000L + w * 1000L + i,
                        ),
                    )
                }
            } catch (e: Throwable) {
                errors.add("writer$w: ${e.javaClass.simpleName}: ${e.message}")
            } finally {
                done.countDown()
            }
        }.start()
    }
    for (r in 0 until readers) {
        Thread {
            try {
                start.await()
                repeat(200) {
                    val snapshot = st.load()
                    if (snapshot.size > DeviceStore.MAX_RECORDS) {
                        errors.add("reader$r 看到 ${snapshot.size} 条")
                    }
                }
            } catch (e: Throwable) {
                errors.add("reader$r: ${e.javaClass.simpleName}: ${e.message}")
            } finally {
                done.countDown()
            }
        }.start()
    }

    start.countDown()
    check(done.await(60, TimeUnit.SECONDS), "并发线程在 60s 内全部结束")
    check(errors.isEmpty(), "并发读写没有抛异常", errors.joinToString("; "))
    check(!File(f.path + ".tmp").exists(), "并发结束后没有残留 .tmp")
    check(
        !File(f.path + ".bad").exists(),
        "并发读从未看到半个文件（没有触发 .bad 隔离）",
    )

    val finalList = DeviceStore(f).load()
    eq(finalList.size, 1 + writers * perWriter, "并发写入没有丢更新（seed + 160 条）")
    eq(finalList.map { it.deviceId }.toSet().size, finalList.size, "并发写入没有重复 key")
    eq(
        finalList.map { it.lastSeenMs },
        finalList.map { it.lastSeenMs }.sortedDescending(),
        "并发写入后文件仍严格按 lastSeenMs 倒序",
    )
}

/* ==========================================================================
 * 10. 父目录不存在
 * ========================================================================== */
private fun testNestedPath() {
    section("10. 父目录自动创建")

    val dir = caseDir("nested")
    val f = File(dir, "a/b/c/devices.json")
    val st = DeviceStore(f)
    val dev = KnownDevice("127.0.0.1", 9100, "", "local", "1", 7)
    eq(st.upsert(dev), listOf(dev), "父目录不存在时 upsert 自动 mkdirs 并写入")
    check(f.isFile, "嵌套路径文件真的存在")
    eq(DeviceStore(f).load(), listOf(dev), "嵌套路径也能读回")
}
