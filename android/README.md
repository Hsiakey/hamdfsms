# Hamster Android 打包说明

本目录负责把 Android 侧 Kotlin 源码打成 **可安装、能启动的 debug APK**。当前有一条
**已实测可用** 的手工流水线（不依赖 Gradle），以及一份**离线暂不可用**的 Gradle 工程。

| 路径 | 状态 | 入口 |
| --- | --- | --- |
| A. 手工流水线 | ✅ 可用，已产出并装进模拟器验证 | `android/tools/build-apk.ps1` |
| B. Gradle 离线工程 | ❌ 当前不可用（缓存缺包，见第 4 节） | `android/settings.gradle.kts` 等 |

> 本机约定：JDK 用 Android Studio 自带的 JBR 21
> （`C:\Program Files\Android\Android Studio\jbr`），**PATH 上的 `java` 是 8，不能用于打包**。
> 脚本内部全部写死绝对路径，不依赖 PATH。

---

## 1. 手工流水线（推荐，当前唯一可用路径）

### 1.1 一键命令

从仓库根执行：

```powershell
pwsh -NoProfile -File android/tools/build-apk.ps1 `
    -Module app-manager `
    -Src "android/app-manager/src,android/protocol-core/src/hamster" `
    -Out android/build/out/hamster-manager-debug.apk `
    -Version 0.0.9
```

成功时最后一行固定为：

```
BUILD OK: <apk 绝对路径> <大小> MB
```

> 上面这条就是**当前真 UI 的实测命令**（2026-11-10，产出 2.34 MB APK，已装进 API 35
> 模拟器并跑通 §7 发现 + §8 加密连接的下载/上传）。
>
> `-Src` 必须把 `android/protocol-core/src/hamster` 一起带上，否则 kotlinc 会报
> `unresolved reference: HamsterApi / DiscoverySocket`。二选一：
>
> ```powershell
> # 方案 1：把 protocol-core 的源码目录一起编译（推荐，源码始终最新）
> -Src "android/app-manager/src,android/protocol-core/src/hamster"
>
> # 方案 2：用预编译的 fat jar 作为额外 classpath
> -Src "android/app-manager/src" `
> -Classpath "android/protocol-core/build/protocol-core.jar"
> ```
>
> `-Classpath` 的 jar 会同时参与 kotlinc 编译和 d8 dex；脚本会检测 jar 里是否自带
> `kotlin/*`（protocol-core.jar 是 fat jar），自带则不会重复加入 `kotlin-stdlib.jar`，
> 避免 d8 重复类报错。方案 1 已实测；方案 2 未实测。
>
> 注意只带 `src/hamster`：`android/protocol-core/src` 下没有别的目录，但这能避免以后
> 加了 `test/` 或资源目录时被误当源码扫进来。

### 1.2 参数

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| `-Module` | 是 | 模块目录名，`app-manager` / `app-daemon`；读取 `android/<Module>/AndroidManifest.xml` |
| `-Src` | 是 | 逗号分隔的 Kotlin 源码目录**或**单个 `.kt` 文件；目录会递归收集所有 `.kt` |
| `-Out` | 是 | 输出 APK 路径（相对路径以仓库根为基准），目录不存在会自动创建 |
| `-Version` | 否 | versionName，默认 `0.0.1` |
| `-Classpath` | 否 | 额外 classpath（逗号分隔 jar/class 目录），也进 dex；默认只有 `android.jar` |
| `-Res` | 否 | 资源目录；默认 `android/<Module>/res`，没有就跳过 aapt2 compile |
| `-MinSdk` / `-TargetSdk` | 否 | 默认 24 / 34 |
| `-VersionCode` | 否 | 默认 0 = 由 `-Version` 推算（major*10000+minor*100+patch） |
| `-KotlinHome` | 否 | Kotlin 安装目录（含 `lib\kotlin-compiler.jar`），默认自动找 `C:\Program Files\kotlinc` |
| `-AndroidJar` / `-BuildTools` / `-JavaHome` / `-Keystore` | 否 | 显式覆盖自动探测结果 |
| `-KeepWork` | 否 | 保留中间产物（classes/dex/未签名 APK）便于排错 |

### 1.3 流水线做了什么

1. **kotlinc** 编译 Kotlin → `.class`（`-no-reflect`、`-jvm-target 1.8`、默认 classpath 只有 `android.jar`）
2. **aapt2 compile/link**：manifest + 资源 → 未签名 APK；有资源时输出 `R.java`
3. **javac** 编译 `R.java`（本模块无资源，这一步自动跳过）
4. `.class` 打 jar → **d8** 连同 `kotlin-stdlib.jar` 打成 `classes.dex`（`--min-api 24`）
5. 解包 aapt2 产物 + 放入 `classes.dex`，用 JDK `jar cfM0` 重新打包
6. **zipalign -p 4** → **apksigner**（`~/.android/debug.keystore`，缺失会 keytool 现场生成，
   别名 `androiddebugkey` / 口令 `android`）
7. 打印 APK 路径、大小、sha256，并以 `BUILD OK:` 收尾

几个实现上的坑（已处理，改脚本时别踩回去）：

- **不要用 `kotlinc.bat`**：cmd 会把分号分隔的 `-classpath` 拆成多个参数，额外 jar 会被当成
  源码报 `source entry is not a Kotlin file`。脚本直接用 JBR `java` 调
  `org.jetbrains.kotlin.cli.jvm.K2JVMCompiler`。
- **d8 不接受目录输入**：先把 class 目录打成 `classes.jar` 再喂给 d8。
- **d8 对 Kotlin 2.1 metadata 会刷几百行警告**（R8 8.6.2 只认识 2.0），脚本按关键字过滤，
  不影响结果；真正的错误仍会打印。
- **APK 内所有条目按 STORED 打包**：保证 `resources.arsc` 未压缩且能被 zipalign 对齐
  （targetSdk 30+ 的硬要求）。代价是体积略大，探针 APK 约 2.2 MB，仍在 MB 级。

### 1.4 产物位置

- APK：`android/build/out/<名字>.apk`（可自定义 `-Out`）
- 中间物：`android/build/apk-work/<Module>/`（默认构建结束即删，`-KeepWork` 保留）
- 上述目录都在 `.gitignore` 里，不会误提交

### 1.5 安装与启动验证

```powershell
$adb = "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe"
& $adb install -r android/build/out/hamster-manager-debug.apk
& $adb shell am start -n hamster.app.manager/.MainActivity
& $adb shell dumpsys activity activities | Select-String topResumedActivity
& $adb logcat -d -s HamsterUi
```

探针阶段（`HelloActivity`，已随真 UI 移除）实测过 `am start -W` → `Status: ok` /
`COLD` / `+1s237ms`、`NO FATAL EXCEPTION`；真 UI 阶段改用下面的自动化钩子复测，
见 §1.6。

---

### 1.6 真 UI：结构、自动化钩子与端到端验证

界面刻意**不用 XML、不用 AndroidX**（离线缓存里 AndroidX 版本凑不齐），全部纯代码
构造 framework 控件，好处是打包链路只要 `kotlinc + d8 + aapt2 + apksigner` 四件套。

```
android/app-manager/
├── AndroidManifest.xml          # aapt2 用（必须带 package）
├── build.gradle.kts             # 仅 Gradle 路径用（当前不可用）
├── src/main/AndroidManifest.xml # AGP 8 用（不许带 package）
└── src/hamster/app/manager/
    ├── Ui.kt                    # dp()/背景线程/两行列表适配器
    ├── DeviceStore.kt           # 设备库持久化（原子写、坏文件隔离、200 条上限）
    ├── SecretBox.kt             # 口令存储：AndroidKeyStore AES-GCM（不可用则明确失败）
    ├── MainActivity.kt          # 口令、设备库、局域网扫描、手动连接
    ├── FilesActivity.kt         # 浏览/分页/下载/上传(覆盖)/新建/删除/保活/自动重连
    ├── SearchActivity.kt        # 索引搜索 + 结果下载 + 滚动加载
    └── DeviceInfoActivity.kt    # info/health/stats/verify + 立即校验/重扫/同步索引
```

复用的协议层（`android/protocol-core/src/hamster/`）：
`Protocol.kt`（分帧）、`Discovery.kt` + `DiscoverySocket.kt`（§7 UDP 发现）、
`Crypto.kt` + `Secure.kt`（§8）、`HamsterApi.kt`（连接/列表/统计/下载/上传门面）。

**自动化钩子**（只在 debuggable 包里生效，正式包这段代码直接 return）：

```powershell
# 预填口令 + 地址并直接连接（跳过手点）
& $adb shell am start -n hamster.app.manager/.MainActivity `
    --es secret "<codeword>" --es addr "10.0.2.2:9100" --ez autoconnect true
```

- `secret` / `addr`：预填两个输入框
- `autoconnect true`：立刻发起连接（会进到文件页）
- `disctarget <ip>`：把扫描目标从 `255.255.255.255` 改成单播地址（模拟器验证发现协议用）

**2026-11-10 端到端实测结果**（模拟器 `Medium_Phone_API_35` ⇄ 宿主机 hamsterd 0.0.9，
`encrypt_transport: on`，口令中不含真实凭据）：

| 能力 | 实现位置 | 设备实测证据 |
| --- | --- | --- |
| 设备库 | `DeviceStore.kt` + `MainActivity` | 手动连接与扫描结果都入库；重启后显示 `hamsterd · 10.0.2.2:9100 · v0.0.9 · 刚刚`；点一条即加密连接；长按可移除 |
| 口令安全存储 | `SecretBox.kt`（AndroidKeyStore AES-256-GCM） | `shared_prefs/hamster.xml` 里只有 `secret_v1=v1:<IV>:<密文>`；`force-stop` 后重新启动，口令自动回填 |
| §7 发现 | `DiscoverySocket.kt` | 应用内 `发现 1 台设备`，写入设备库 |
| §8 握手 | `Secure.kt` / `HamsterApi` | 服务端 `AUTH 握手通过 id=d591f5cb… 方式=codeword（此后全程加密）` |
| 目录分页 | `HamsterApi.listPage` + `FilesActivity` | `/ · 已显示 6/6 项`，滚到底自动取下一页（每页 100） |
| 搜索 | `SearchActivity` | 关键词 `png` → `「png」 · 共 3 条 · 已加载 3 条 · 已全部加载`，点结果直接下载 |
| 设备信息 | `DeviceInfoActivity` | 显示 info/health/stats/verify 全字段；`立即校验` → 服务端 `VERIFY 完整性校验完成: 总计=6 正常=6 内容不一致=0 缺失=0`；`同步索引` → `DB checkpoint 完成` + `APP 已按请求同步数据库` |
| 新建目录 | `FilesActivity` + `HamsterApi.mkdir` | 服务端 `MKDIR …\watch\e2edir`，列表 6→7 项 |
| 删除 | `FilesActivity` + `HamsterApi.delete` | 长按 → 删除 → 二次确认 → 服务端 `DEL 已删除 …\e2edir`，列表 7→6 项 |
| 上传（覆盖） | `FilesActivity` + `upload(overwrite=true)` | 服务端 `UP 已接收 …s2.png (72031 字节)`，文件时间戳由 12:51:22 变为 13:27:55 |
| 传输取消 | `HamsterApi.abort()` | API 级由 `ApiTest` 覆盖；UI 按钮的竞态窗口未做自动化（见 §5） |
| 下载 | `HamsterApi.download` | `hello.txt` 内容一致；`blob.bin` 300 000 B MD5 与服务端一致 `b07d539d…a64e64` |
| 子目录 / 返回 | `FilesActivity` 目录栈 | 进 `docs/` 只见 `note.md`，返回键逐级回退，根目录再返回才退出 |
| 错口令 | — | 应用 `连接失败：socket_closed: proof 后连接被关闭（口令不对？）`；服务端 `AUTH 握手认证失败`，异常文本不含口令 |
| 无崩溃 | — | `logcat -s HamsterUi` 全程无 `FATAL EXCEPTION` |

**协议核心自动化测试**（都能在桌面 JVM 上跑，不需要安卓设备）：

| 套件 | 项数 | 覆盖 |
| --- | --- | --- |
| `test/TestMain.kt` | 175 | RFC 4231/8439/5869 向量、发现 MAC、分帧、地址解析、§8.2 跨实现已知值 |
| `test/DiscoverySocketTest.kt` | 58 | 真 UDP 回环：两轮探测、去重、错口令/篡改/旧 nonce/超大帧静默丢弃、并发 scan |
| `test/ApiTest.kt` | 119 | 起真 hamsterd：list/listPage/search/info/health/stats/verify/rescan/sync/mkdir/delete/download/upload(overwrite)/abort/错口令 |
| `test/DeviceStoreTest.kt` | 147 | 设备库：坏文件隔离、去重排序、200 条截断、8 线程并发、原子写 |
| `test/LiveCheck.kt` / `DiscoveryLiveCheck.kt` | 8 / 11 | 真守护进程互通（§8 握手+下载、§7 发现） |

> 模拟器注意事项：`10.0.2.2` 是 QEMU 里"宿主机回环"的固定别名，所以 hamsterd 绑
> `127.0.0.1` 也能被模拟器连上；但 `255.255.255.255` 广播**到不了**宿主机网段，
> 验证发现协议要用 `--es disctarget 10.0.2.2` 走单播。真机 Wi-Fi 下广播才是正常路径。

---

## 2. Gradle 离线工程（当前不可用，见第 4 节）

工程文件已就位，AGP 8.7.3 + Kotlin 1.9.24 + compileSdk 34 + minSdk 24，**零第三方运行时依赖
（不用 AndroidX）**：

- `android/settings.gradle.kts`、`android/build.gradle.kts`、`android/gradle.properties`
- `android/app-manager/build.gradle.kts`（`namespace = "hamster.app.manager"`）
- Gradle 用 8.9 发行版：`C:\Users\Hsiak\.gradle\wrapper\dists\gradle-8.9-bin\*\gradle-8.9\bin\gradle.bat`

构建命令（需要先设好 JBR 与 SDK 环境变量）：

```powershell
$env:JAVA_HOME     = 'C:\Program Files\Android\Android Studio\jbr'
$env:ANDROID_HOME  = "$env:LOCALAPPDATA\Android\Sdk"
$env:ANDROID_SDK_ROOT = $env:ANDROID_HOME
Set-Location android
& 'C:\Users\Hsiak\.gradle\wrapper\dists\gradle-8.9-bin\90cnw93cvbtalezasaz0blq0a\gradle-8.9\bin\gradle.bat' `
    --offline --console=plain :app-manager:assembleDebug
```

> `gradle.properties` 里的 `org.gradle.offline=true` 是按要求保留的，但 Gradle 并不识别这个
> 属性，**离线一定要带 `--offline`**。

### 2.1 需要的两个 workaround（仅第一个有效）

1. aapt2 的 maven 产物没缓存 → 用 build-tools 里的 aapt2 覆盖：

   ```
   -Pandroid.aapt2FromMavenOverride=C:\Users\Hsiak\AppData\Local\Android\Sdk\build-tools\35.0.0\aapt2.exe
   ```

2. Kotlin 编译器的 classpath 也缺包，**这个没法绕**（见下节报错）。

---

## 3. 两个 AndroidManifest.xml 为什么分开维护

- `android/app-manager/AndroidManifest.xml`：**手工 aapt2 用**，必须带 `package="hamster.app.manager"`。
- `android/app-manager/src/main/AndroidManifest.xml`：**Gradle/AGP 8 用**，不能带 `package`
  （namespace 在 `build.gradle.kts` 里声明，AGP 8 会直接报错），所以拆成两份、内容保持同步。

两份 manifest 都用 `@android:drawable/sym_def_app_icon`、`@android:style/Theme.Material`，
不自造 `res/`，因此手工路径可以完全跳过资源编译。

---

## 4. Gradle 路径：结论是「当前不可用」

两轮离线构建的真实报错原文：

**第一轮（不带 override）—— `aapt2` 不在缓存里：**

```
Execution failed for task ':app-manager:processDebugResources'.
> Could not resolve all files for configuration ':app-manager:detachedConfiguration2'.
   > Could not resolve com.android.tools.build:aapt2:8.7.3-12006047.
      > No cached version of com.android.tools.build:aapt2:8.7.3-12006047 available for offline mode.
```

**第二轮（带 `android.aapt2FromMavenOverride` 指向 build-tools/35.0.0/aapt2.exe）—— 资源链接通过，
Kotlin 编译器 classpath 缺两个包：**

```
Execution failed for task ':app-manager:compileDebugKotlin'.
> Could not resolve all files for configuration ':app-manager:kotlinCompilerClasspath'.
   > Could not resolve org.jetbrains.kotlin:kotlin-script-runtime:1.9.24.
      > No cached version of org.jetbrains.kotlin:kotlin-script-runtime:1.9.24 available for offline mode.
   > Could not resolve org.jetbrains.kotlin:kotlin-reflect:1.6.10.
      > No cached version of org.jetbrains.kotlin:kotlin-reflect:1.6.10 available for offline mode.
```

本机 Gradle 缓存实测：`kotlin-script-runtime` **完全没有**，`kotlin-reflect` 只有 `1.9.23`（要 1.6.10），
`kotlin-compiler-embeddable` / `kotlin-gradle-plugin` 是 1.9.24。在无网络前提下无法补齐，
所以 **Gradle 路径暂时不可用；请用第 1 节的 `tools/build-apk.ps1` 出包**。

好消息是 AGP 本身没问题：加了 aapt2 override 后 `processDebugResources` 是成功执行的，
说明缺的只是缓存里的 maven 产物。

**恢复条件**：任选其一

- 联网跑一次 `gradle :app-manager:assembleDebug`（不带 `--offline`）把缓存补齐，之后离线可用；
- 或者把 `kotlin-script-runtime:1.9.24`、`kotlin-reflect:1.6.10`、`aapt2:8.7.3-12006047` 手动放进
  `~/.gradle/caches/modules-2/files-2.1/...`，并带上 `android.aapt2FromMavenOverride`。

补齐后还要注意：Gradle 模块的 `sourceSets.main.java.srcDirs("src")` 目前会把
`src/hamster/app/manager/*.kt` 一起编译，这些文件依赖 protocol-core 的 `hamster.*`，
届时需要在 `app-manager/build.gradle.kts` 里把 protocol-core 接进来（例如把
`../protocol-core/src` 加进 Kotlin srcDirs，或依赖本地 jar）。

---

## 5. 已知限制 / 未完成项

- **Gradle 离线构建不可用**（第 4 节），只有手工流水线能出包。
- `app-daemon` 模块只在 `-Module` 里预留了名字，目录/源码/验证都没做；当前只有 `app-manager`。
- `R.java`/资源分支（`aapt2 compile` → `javac` → 并入 dex）代码已实现，但本模块无 `res/`，
  **没有被真实资源实际跑过**。
- APK 全部条目 STORED（未压缩），体积偏大；要压缩需引入额外的 zip 工具以保持
  `resources.arsc` 未压缩 + 4 字节对齐。
- 签名是 debug keystore（v2/v3 通过，v1 关闭）；上架需换正式签名。
- **口令存储**：默认只存内存；勾"记住口令"才写 `SharedPreferences`（应用私有目录）。
  长期方案应换 Android Keystore + EncryptedSharedPreferences，当前未做。
- **文件选择器会冻结进程**：`ACTION_GET_CONTENT` 打开期间本进程被系统冻结，连接必断、
  冻结期间新建连接必然超时（实测两次复现）。因此上传流程改成"先选文件、回来再重连再传"，
  并对传输层中断做最多 2 次自动重传；不要改回"选文件前就要求连接活着"。
- **连接会被空闲回收**：模拟器经 QEMU NAT 的链路实测约 18–20 s 静默就断（同一 daemon 的
  JVM 直连不受影响）。文件页每 5 s 发一次 §8 内的 ping 保活；保活本身失败会立刻重连。
- **真机未验证**：以上全部实测都在 API 35 模拟器 + 宿主机 hamsterd 上完成；真机 Wi-Fi
  下的广播发现、OEM 后台策略、Doze 下的保活行为都还没测过。
- **取消传输的 UI 竞态未自动化**：`abort()` 本身由 `ApiTest` 覆盖，但"点击取消的瞬间传输刚好结束"
  这条竞态路径只有代码审查，没有自动化用例。
- **搜索结果的字段残缺**：服务端 `search` 只返回 `{hash,name,path,type,size,modified}`，
  **没有 `dir` 也没有文件真实 mtime**，所以 `SearchHit.dir` 恒为 `false`、`mtime` 恒为 `0`；
  `modified` 是"入库时间"而不是文件修改时间，界面刻意不拿它冒充 mtime。
- **`stats.file_type_count` 未展示**：`DeviceStats` 里没有这个字段（服务端有），
  设备信息页显式显示为"—（当前 API 未提供）"，没有伪造数据。
- **`verify.last_duration_ms` 恒为 0**：服务端 `hd_db_record_verify` 里 `sqlite3_bind_int(...,5,0)`
  写死了 0，所以界面上这个值永远是 0，不是客户端 bug。
- **无列表分页 UI**（旧限制已解除，保留说明）：现在是每页 100 条滚动加载，但**搜索页**只按
  文件名/路径匹配，没有按类型/大小过滤的界面（API 支持，界面未暴露）。
- **上传覆盖策略**：默认 `overwrite=false` + `mkdir=true`（服务端 `mkdir` 默认是 `false`，
  客户端显式打开）；界面用"上传时覆盖同名文件"勾选框控制覆盖。
- 生成时间点：真 UI（`MainActivity` + `FilesActivity` + `SearchActivity` + `DeviceInfoActivity`）
  已装进 API 35 模拟器，跑通上表全部能力。
