plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.hu.cfpixiv"
    compileSdk = 35

    defaultConfig {
        applicationId = "cn.hugengron"
        minSdk = 28
        targetSdk = 35
        versionCode = 2
        versionName = "1.1"
        ndk { abiFilters += "arm64-v8a" }
    }

    packaging {
        jniLibs {
            // 必须解压：nginx / Go DNS 是可执行 ELF，跑在 nativeLibraryDir
            useLegacyPackaging = true
            keepDebugSymbols += "**/*.so"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}

dependencies {
}
