// app-daemon：AGP 8.7.3 + Kotlin 1.9.24，零第三方运行时依赖。
// 源码沿用 android/app-daemon/src（与 tools/build-apk.ps1 手工流水线共用同一份 Kotlin）。
//
// ⚠ minSdk 是 26（不是 app-manager 的 24）：`DaemonCore` 用了 java.nio.file 与
//   java.time（API 26 才有）。API 24/25 上编译能过，运行时会 NoClassDefFoundError。
//   手工流水线出包时也要带 -MinSdk 26，两边必须一致。
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "hamster.app.daemon"
    compileSdk = 34

    defaultConfig {
        applicationId = "hamster.app.daemon"
        minSdk = 26
        targetSdk = 34
        versionCode = 9
        versionName = "0.0.9"
    }

    buildTypes {
        getByName("debug") {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }

    kotlinOptions {
        jvmTarget = "1.8"
    }

    sourceSets {
        getByName("main") {
            // 手工流水线和 Gradle 共用 android/app-daemon/src，外加协议核心。
            java.srcDirs("src", "../protocol-core/src/hamster")
        }
    }
}

dependencies {
    // 刻意留空：不使用 AndroidX / 任何第三方库（离线缓存里版本不齐会直接失败）。
}
