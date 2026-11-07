# Android 协议核心库（Kotlin / 纯 JVM）

`android/protocol-core/` 是 Hamster 协议（`PROTOCOL.md` ver.0.0.8）的 Kotlin 协议核心：
它只依赖 JDK（`javax.crypto.Mac` 来自 JDK 自带的 JCE）与 Kotlin 标准库，**不引用任何
Android API**，因此既能被未来的 Android 客户端直接复用，也能在桌面 JVM 上独立编译、
测试。当前实现三块契约：§3 的二进制分帧（`FrameReader`，按字节精确读取 `payload_bytes`
之后紧随的裸数据）、§7 的局域网发现帧（`buildProbe` / `parseReply` 与 probe/reply 两种
MAC）、§7 用到的 `host:port` 地址解析（`parseAddr`，支持 `[::1]:9100` 与裸 IPv6）。
只做协议层，不含 socket 线程、广播调度与 UI；发现应答里的对端 IP 仍须由调用方从
`recvfrom` 的源地址取得（帧里不存在该字段）。`test/TestMain.kt` 是零依赖自检程序，
覆盖 RFC 4231 向量、发现协议固定 MAC 向量、分帧的拆包/粘包/长度不符、地址解析与
各类篡改拒绝路径。

## 目录结构

```
android/protocol-core/
├── README.md
├── .gitignore              # 忽略 build/
├── src/hamster/
│   ├── Protocol.kt         # Json / FrameReader / parseAddr
│   └── Discovery.kt        # probeMac / replyMac / buildProbe / parseReply
├── test/
│   └── TestMain.kt         # 自检程序（main()，不使用 JUnit）
└── build/                  # 构建产物（已忽略）
```

## 编译与运行自检

需要 Kotlin 命令行编译器（本仓库脚本以 `C:\Program Files\kotlinc\bin\kotlinc.bat` 为准）
和 Java 8。在 PowerShell 里执行：

```powershell
cd C:\aaa_mydata\projects\Hamster\Hamster\android\protocol-core

# 编译（首次调用 kotlinc 较慢，属正常现象）
& "C:\Program Files\kotlinc\bin\kotlinc.bat" `
    src\hamster\Protocol.kt src\hamster\Discovery.kt test\TestMain.kt `
    -include-runtime -d build\protocol-core.jar

# 运行自检；退出码 0 = 全通过，非 0 = 有失败
& "C:\Program Files\Zulu\zulu-8\bin\java.exe" -jar build\protocol-core.jar
```

`-include-runtime` 会把 Kotlin 标准库打进 jar，并自动写入 `Main-Class: hamster.TestMainKt`，
因此运行时不需额外 classpath。如果只想在 Gradle/Android 工程里引用源码，拷贝
`src/hamster/` 下的两个文件即可，包名固定为 `hamster`。

> 若终端代码页不是 UTF-8（中文输出显示为乱码），可在 `java` 后加
> `"-Dfile.encoding=UTF-8"`，或先执行 `chcp 65001`。这只影响控制台显示，不影响自检结果。

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
  `t/v` 不符、截断、内嵌 NUL、超 512 字节等一律返回 `null`（不抛异常）。

## 已知边界（本库不做的事）

* 不含 UDP socket、广播循环、按轮次 nonce 窗口与速率限制：`parseReply` 只校验单帧，
  调用方仍须按 §7.3 检查 nonce 是否属于"本轮 + 上一轮"，并做去重与超时；
* `buildReply`（服务端方向）未实现：本库面向客户端；
* 不对 `host` 做 DNS 解析（`parseAddr` 只做语法校验）；
* 协议版本固定为当前 `0.0.8` / 发现协议 `v=1`；
* 流式分帧只能发现"负载偏少"（对端提前关闭时报错）；"多送的裸字节"会在解析下一条
  消息头时表现为非 JSON 而报错，无法在读完 N 字节的当下断言"对方多送了"；
* 单行上限按 262144 字节（含）实现，比服务端 262144 字节缓冲区（含结尾 `'\0'`）宽松
  1 字节；服务端不会发出超限行，客户端放宽不影响互通。
