# Android bindings for `libdia`

This document explains how to **build** the native libraries (`.so`) for Android and how to **use** them in an Android app or AAR.

---

## Prerequisites

- **Android NDK** r26+ (tested with r27).  
  Set one of these before building:

  ```bash
  export ANDROID_NDK_ROOT=/path/to/Android/Sdk/ndk/27.x.y
  # or
  export ANDROID_NDK_HOME=/path/to/Android/Sdk/ndk/27.x.y
````

* **CMake** (comes with Android Studio).
* Optional: **Ninja** (faster builds, otherwise Makefiles are used).

---

## Build outputs

The build artifacts are placed under:

```
bindings/android/builds/<ABI>/
  ├── src/       # libdia_jni.so sometimes here
  ├── lib/       # libmcl.so / libmcl.a and other libs
  └── jniLibs/   # staged .so’s ready to copy into your app or AAR
```

Common ABIs: `arm64-v8a` (phones) and `x86_64` (emulators).

---

## Build the .so files

From the repo root:

```bash
# Default ABI = arm64-v8a
./bindings/android/build.sh

# Or specify ABI explicitly (May fail for x86_64. only tested for arm64-v8a)
./bindings/android/build.sh x86_64
```

The script:

1. Configures CMake with the Android toolchain.
2. Builds `libdia_jni.so` and dependencies (MCL, DIA core).
3. Stages the required `.so` files into `jniLibs`.

---

## Stage/collect the .so files

After build, you should have:

```
bindings/android/builds/<ABI>/jniLibs/
  libdia_jni.so
  libmcl.so
```

---

## Use in an Android app

1. Copy staged libs into your app:

```
app/src/main/jniLibs/arm64-v8a/libdia_jni.so
app/src/main/jniLibs/arm64-v8a/libmcl.so     # if required
```

2. Restrict ABIs in `app/build.gradle.kts`:

```kotlin
android {
    defaultConfig {
        ndk {
            abiFilters += listOf("arm64-v8a") // add x86_64 if built
        }
    }
}
```

3. Load library in Kotlin:

```kotlin
object LibDia {
    init { System.loadLibrary("dia_jni") }

    external fun dhKeygen(): Array<ByteArray>
    // ... other JNI methods
}
```

Or simply use the bindings defined in ```android/LibDia.kt```
---

## Build and publish an AAR

1. Create a library module (e.g. `:libdia`).
2. Place staged `.so` files into:

```
libdia/src/main/jniLibs/arm64-v8a/libdia_jni.so
libdia/src/main/jniLibs/arm64-v8a/libmcl.so
```

3. Minimal `build.gradle.kts`:

```kotlin
plugins {
    id("com.android.library")
    kotlin("android")
    `maven-publish`
}

android {
    namespace = "io.github.lokingdav.libdia"
    compileSdk = 35
    defaultConfig {
        minSdk = 24
        ndk { abiFilters += listOf("arm64-v8a") }
    }
}

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("releaseAar") {
                from(components["release"])
                groupId = "io.github.lokingdav"
                artifactId = "libdia"
                version = "0.1.0"
            }
        }
    }
}
```

4. Build:

```bash
./gradlew :libdia:assembleRelease
```

Result: `libdia-release.aar`.

---

## Verify runtime dependencies

Check which libs `libdia_jni.so` needs:

```bash
readelf -d bindings/android/builds/arm64-v8a/jniLibs/libdia_jni.so | grep NEEDED
```

* If `libmcl.so` is listed → must be shipped.
* If not listed → MCL is statically linked.
* If `c++_shared.so` appears → ensure your APK includes it.

---

## Troubleshooting

* **`UnsatisfiedLinkError: libmcl.so not found`**
  Copy `libmcl.so` into `jniLibs/<ABI>/`.

* **`c++_shared.so not found`**
  Bundle the C++ shared runtime or rebuild with static STL.

* **ABI mismatch**
  Match your `abiFilters` with built ABIs.

* **JNI class not found**
  Keep class name: `io/github/lokingdav/libdia/LibDia`.

---
