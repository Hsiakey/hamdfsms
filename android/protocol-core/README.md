# Android 协议核心库（Kotlin / 纯 JVM）

`android/protocol-core/` 是 Hamster 协议（`PROTOCOL.md`）的 Kotlin 协议核心：
它只依赖 JDK（`javax.crypto.Mac` 来自 JDK 自带的 JCE）与 Kotlin 标准库，**不引用任何
Android API**，因此既能被未来的 Android 客户端直接复用，也能在桌面 JVM 上独立编译、
测试。当前实现五块契约：§3 的二进制分帧（`FrameReader`，按字节精确读取 `payload_bytes`
之后紧随的裸数据）、§7 的局域网发现帧（`buildProbe` / `parseReply` 与 probe/reply 两种
MAC）、§7 的 UDP 收发（`DiscoverySocket.kt` 的 `DiscoveryClient.scan` / `probeOnce`：
广播或单播探测、两发不同 nonce、从 `recvfrom` 源地址补 IP、按 id 去重排序）、§7 用到的
`host:port` 地址解析（`parseAddr`，支持 `[::1]:9100` 与裸 IPv6）、§8 传输加密
（`Crypto.kt` 的 ChaCha20-Poly1305 + HKDF-SHA256，`Secure.kt` 的记录层与握手
`SecureChannel`）。
只做协议层，不含按 1s 节奏的广播调度、3s 在线窗口与 UI；`parseReply` 只校验单帧，
对端 IP 由 `DiscoverySocket` 从 `recvfrom` 的源地址补出（帧里不存在该字段）。

`test/TestMain.kt` 是零依赖自检程序，覆盖 RFC 4231 / 8439 / 5869 向量、发现协议固定
MAC 向量、分帧的拆包/粘包/长度不符、地址解析、§8.2 跨实现已知值，以及各类篡改拒绝
路径；`test/DiscoverySocketTest.kt` 在回环上起假 hamsterd，真发 UDP 验证 `scan` /
`probeOnce`；`test/LiveCheck.kt` 则连真 hamsterd 做 §8 端到端检查。

> ChaCha20-Poly1305 自带实现的原因：JDK 11 才把它放进 JCE，而 Android 上 Conscrypt
> 的支持还要看系统版本。自带一份纯 Kotlin 实现，能让 JDK 8、JDK 17、Android 上的
> 行为完全一致 —— 传输加密最怕"某个平台上算法悄悄不一样"。

## 目录结构

```
android/protocol-core/
├── README.md
├── .gitignore              # 忽略 build/
├── src/hamster/
│   ├── Protocol.kt         # Json / FrameReader / parseAddr
│   ├── Discovery.kt        # probeMac / replyMac / buildProbe / parseReply
│   ├── DiscoverySocket.kt  # DiscoveryClient.scan / probeOnce（真 UDP 收发）
│   ├── Crypto.kt           # ChaCha20-Poly1305（RFC 8439）+ HKDF-SHA256（RFC 5869）
│   └── Secure.kt           # §8 记录层 + 客户端握手（SecureChannel）
├── test/
│   ├── TestMain.kt         # 自检程序（main()，不使用 JUnit）
│   ├── DiscoverySocketTest.kt # 真 UDP 发现测试（回环假服务端）
│   └── LiveCheck.kt        # 对真 hamsterd 的 §8 端到端检查
└── build/                  # 构建产物（已忽略）
```

## 编译与运行自检

需要 Kotlin 命令行编译器（本仓库脚本以 `C:\Program Files\kotlinc\bin\kotlinc.bat` 为准）
和 Java 8。在 PowerShell 里执行：

```powershell
cd C:\aaa_mydata\projects\Hamster\Hamster\android\protocol-core

# 编译（首次调用 kotlinc 较慢，属正常现象）
& "C:\Program Files\kotlinc\bin\kotlinc.bat" `
    src\hamster\Protocol.kt src\hamster\Discovery.kt `
    src\hamster\Crypto.kt src\hamster\Secure.kt test\TestMain.kt `
    -include-runtime -d build\protocol-core.jar

# 运行自检；退出码 0 = 全通过，非 0 = 有失败
& "C:\Program Files\Zulu\zulu-8\bin\java.exe" -jar build\protocol-core.jar
```

`-include-runtime` 会把 Kotlin 标准库打进 jar，并自动写入 `Main-Class: hamster.TestMainKt`，
因此运行时不需额外 classpath。如果只想在 Gradle/Android 工程里引用源码，按需拷贝
`src/hamster/` 下对应的 `.kt` 文件即可，包名固定为 `hamster`。

> 若终端代码页不是 UTF-8（中文输出显示为乱码），可在 `java` 后加
> `"-Dfile.encoding=UTF-8"`（JDK 19+ 还可用 `-Dstdout.encoding=UTF-8`），
> 或先执行 `chcp 65001`。这只影响控制台显示，不影响自检结果。

## 发现收发自检（真 UDP，回环假服务端）

`DiscoverySocket.kt` 会真正开 UDP socket，单独编一个测试 jar，**不要覆盖**
`build/protocol-core.jar`：

```powershell
cd C:\aaa_mydata\projects\Hamster\Hamster\android\protocol-core
$env:JAVA_HOME = "C:\Program Files\Android\Android Studio\jbr"   # JDK 21，可选

& "C:\Program Files\kotlinc\bin\kotlinc.bat" `
    src\hamster\Protocol.kt src\hamster\Discovery.kt src\hamster\DiscoverySocket.kt `
    test\DiscoverySocketTest.kt `
    -include-runtime -d build\disc\disc-test.jar

& "C:\Program Files\Android\Android Studio\jbr\bin\java.exe" `
    "-Dstdout.encoding=UTF-8" -jar build\disc\disc-test.jar
```

测试在本机 `127.0.0.1` 起一个假 hamsterd（`replyMac` 按 §7.1 造合法应答），覆盖：正常
应答与源 IP、错误暗号、nonce 不匹配、MAC 篡改、完全不响应（记录超时耗时）、丢第一帧
后第二轮命中、重复应答去重、超大帧/乱序旧 nonce、按 name/ip 排序、`probeOnce`、非法
输入与并发 `scan`。输出 `PASS n / FAIL m`，退出码非 0 表示有失败。

## 使用示例

```kotlin
// 分帧：先读消息头，再按 payload_bytes 流式落盘
val reader = FrameReader(socket.getInputStream())
while (true) {
    val header = reader.readHeader() ?: break
    val type = Json.getString(header, "type")
    if (type == "response" && reader.hasPayload) {
        reader.readPayload { buf, off, len -> fileOut.write(buf, off, len) }
        // 实收字节数已由 FrameReader 精确校验；不足会抛 ProtocolException
    }
}

// 发现：构造探测帧（UDP 发出），收到应答后校验
val probe = buildProbe(codeword, deviceId, nonceHex)
// ... udp send / recv ...
val peer = parseReply(codeword, deviceId, receivedBytes)   // 不符一律 null

// 发现：一次 scan 内发两轮探测，返回已去重、按 name/ip 排序的结果
val devices = DiscoveryClient.scan(codeword, timeoutMs = 1500)
for (d in devices) println("${d.name} @ ${d.ip}:${d.port} (${d.version})")

// 只做一次连接测试；命中即返回，失败/超时返回 null
val one = DiscoveryClient.probeOnce(codeword, target = "10.0.2.2")

// 地址：可直接喂给 Socket 连接
val (host, port) = parseAddr("127.0.0.1:9100", 9100)
```

## 自检覆盖范围

* HMAC-SHA256 对齐 RFC 4231（Test Case 1/2/3/6 与 `tests/test_crypto.c` 同一批向量）；
* 发现协议 probe/reply MAC 固定向量（C 服务端、Node 客户端、Python 三方交叉核对）；
* 分帧：单字节到达、半行跨读取、负载分块、多条消息粘连、CRLF、负载含 `0x00/0xff`、
  `payload_bytes` 偏少/偏多/非整数/为负、未读完负载就解析下一行、256 KiB 边界
  （含"按字节而非字符"的汉字用例）；
* `parseAddr`：IPv4、主机名、`[::1]:9100`、`[::1]`、裸 `::1`、内嵌 IPv4 的 IPv6，
  以及空主机/空端口/端口越界/IPv4 段越界/方括号错误等非法输入；
* 发现帧：正确暗号通过；错暗号、篡改 nonce/MAC/端口、换探测方 id、自打自收、
  `t/v` 不符、截断、内嵌 NUL、超 512 字节等一律返回 `null`（不抛异常）；
* **§8 传输加密**（共 40 项）：
  * ChaCha20-Poly1305：RFC 8439 §2.4.2 块函数、§2.5.2 Poly1305、§2.8.2 完整 AEAD；
  * HKDF-SHA256：RFC 5869 附录 A.1；
  * §8.2 五组已知值（master / proof_C / proof_S / key_c2s / key_s2c）——
    与 C、JS 两端逐字节相同；
  * 跨语言记录向量：解开 JS/C 产出的记录，且重新封出的字节完全相同；
  * §8.3 记录层：64 KiB 边界、往返、篡改密文、counter 跳跃、方向反射、
    长度越界、空明文、逐字节喂入；
  * 握手：对 mock 服务端跑通"hello → challenge → 验 proof_S → proof → ok"，
    以及服务端证明不成立、口令不一致两种拒绝路径。

## §8 与真守护进程互通

自检只能证明"实现自洽"。要证明三端真的能对话，跑 LiveCheck（需要先起一个
`encrypt_transport: on` 的 hamsterd）：

```powershell
& "C:\Program Files\kotlinc\bin\kotlinc.bat" `
    src\hamster\Protocol.kt src\hamster\Discovery.kt `
    src\hamster\Crypto.kt src\hamster\Secure.kt test\LiveCheck.kt `
    -include-runtime -d build\livecheck.jar

# 参数：端口、口令、[device_id]
& "C:\Program Files\Zulu\zulu-8\bin\java.exe" -cp build\livecheck.jar `
    hamster.LiveCheckKt 19303 <codeword>
```

它覆盖：错误口令必须被拒、握手、ping、info（`features` 含 `framing:aead`）、
200 KiB 下载（跨多条 64 KiB 记录）。

## 已知边界（本库不做的事）

* `DiscoveryClient.scan` / `probeOnce` 只做一次调用内的有限窗口收发（默认各发 2 / 1 帧）：
  §7.3 的 1s 广播节奏、各网卡子网广播与 `127.0.0.1` 的补扫、3s 在线窗口、重连退避复位
  仍由应用层决定；`parseReply` 也只校验单帧，不维护 nonce 历史；
* Android 上需要 `android.permission.INTERNET`；`CHANGE_WIFI_MULTICAST_STATE` /
  `WifiManager.MulticastLock` 只影响**组播**，255.255.255.255 是受限广播，严格说不必申请，
  但部分 OEM 的 Wi-Fi 省电策略会过滤广播，真机建议实测。Android 模拟器里
  255.255.255.255 到不了宿主机，发现宿主机上的 hamsterd 请用单播 `target = "10.0.2.2"`；
* `buildReply`（服务端方向）未实现：本库面向客户端；
* 不对 `host` 做 DNS 解析（`parseAddr` 只做语法校验）；
* 协议版本固定为当前 `0.0.8` / 发现协议 `v=1`；§8 加密按 `1` 版握手（`v=2`）实现，
  守护进程侧由 `encrypt_transport` 开关控制，正式版本号随 0.0.9 一起升；
* `SecureChannel` 只负责握手与记录层；连接超时、重连、设备库、UI 仍由 Android 应用层决定；
* 不含 APK 构建脚本（本库只产出 `protocol-core.jar`；打包成 Android 应用需要 Gradle 工程）；
* 流式分帧只能发现"负载偏少"（对端提前关闭时报错）；"多送的裸字节"会在解析下一条
  消息头时表现为非 JSON 而报错，无法在读完 N 字节的当下断言"对方多送了"；
* 单行上限按 262144 字节（含）实现，比服务端 262144 字节缓冲区（含结尾 `'\0'`）宽松
  1 字节；服务端不会发出超限行，客户端放宽不影响互通。
