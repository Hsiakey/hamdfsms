// app-manager：AGP 8.7.3 + Kotlin 1.9.24，零第三方运行时依赖。
// 源码沿用 android/app-manager/src（与 tools/build-apk.ps1 手工流水线共用同一份 Kotlin）。
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "hamster.app.manager"
    compileSdk = 34

    defaultConfig {
        applicationId = "hamster.app.manager"
        minSdk = 24
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
            // 手工流水线和 Gradle 共用 android/app-manager/src。
            java.srcDirs("src", "../protocol-core/src/hamster")
        }
    }
}

dependencies {
    // 刻意留空：不使用 AndroidX / 任何第三方库，离线缓存里版本不齐会直接失败。
}
