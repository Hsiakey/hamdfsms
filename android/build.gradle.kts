// Hamster Android 根构建脚本。
// 只用本机 Gradle 缓存里的 AGP 8.7.3 + Kotlin 1.9.24，按离线工程维护。
plugins {
    id("com.android.application") version "8.7.3" apply false
    id("org.jetbrains.kotlin.android") version "1.9.24" apply false
}
