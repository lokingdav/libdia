# LibDia Android Bindings

Android JNI bindings for the libdia cryptographic protocol library.

## Building

### Prerequisites

- Android NDK r26+ 
- CMake 3.22+
- Supported host platforms: Linux, macOS, Windows

Set NDK path using one of these environment variables (the build script checks all three):
```bash
# Option 1: ANDROID_NDK (preferred)
export ANDROID_NDK=/path/to/android-ndk

# Option 2: ANDROID_NDK_ROOT (Android Studio default)
export ANDROID_NDK_ROOT=/path/to/android-ndk

# Option 3: ANDROID_NDK_HOME (legacy)
export ANDROID_NDK_HOME=/path/to/android-ndk
```

Common NDK locations:
```bash
# Android Studio (Linux/macOS)
export ANDROID_NDK=$HOME/Android/Sdk/ndk/<version>

# Android Studio (Windows)
export ANDROID_NDK=$LOCALAPPDATA/Android/Sdk/ndk/<version>

# Standalone NDK
export ANDROID_NDK=$HOME/android-ndk
```

### Build Native Libraries

```bash
cd bindings/android
./build.sh                 # Build for arm64-v8a (default)
./build.sh --clean arm64-v8a  # Clean build
./build.sh --help         # Show all options
```

**Note:** Currently only `arm64-v8a` (64-bit ARM) is fully tested and supported. Other ABIs (x86_64, armeabi-v7a) may have issues with the MCL cryptographic library's assembly optimizations.

Libraries are staged in `builds/<ABI>/jniLibs/<ABI>/`:
- `libdia_jni.so` - JNI bindings
- `libmcl.so` - MCL cryptographic library dependency

## Integration

### 1. Copy Libraries

```bash
cp bindings/android/builds/arm64-v8a/jniLibs/arm64-v8a/*.so \
   app/src/main/jniLibs/arm64-v8a/
```

### 2. Copy Kotlin Interface

```bash
cp bindings/android/LibDia.kt \
   app/src/main/java/io/github/lokingdav/libdia/
```

### 3. Update build.gradle.kts

```kotlin
android {
    defaultConfig {
        ndk {
            abiFilters += listOf("arm64-v8a")
        }
    }
}
```

### 4. Load Library

```kotlin
System.loadLibrary("dia_jni")
LibDia.init()
```

## API Overview

### DiaConfig

Client configuration management:

```kotlin
// Create from enrollment
val config = DiaConfig.fromEnv(enrollmentString)

// Serialize for storage
val envString = config.toEnv()

// Always close when done
config.close()
// or use AutoCloseable:
config.use { ... }
```

### CallState

Protocol state machine:

```kotlin
CallState.create(config, remotePhone, isInitiator = true).use { call ->
    // AKE phase
    call.akeInit()
    val topic = call.akeTopic()
    val request = call.akeRequest()
    val response = call.akeResponse(incomingRequest)
    val complete = call.akeComplete(incomingResponse)
    call.akeFinalize(incomingComplete)
    
    // Get shared key
    val sharedKey = call.sharedKey()
    
    // RUA phase
    call.transitionToRua()
    val ruaReq = call.ruaRequest()
    val ruaResp = call.ruaResponse(incomingRuaReq)
    call.ruaFinalize(incomingRuaResp)
    
    // Get remote party info
    val remote = call.remoteParty()
    println("Verified: ${remote.phone}, ${remote.name}")
    
    // Messaging
    val encrypted = call.encrypt("Hello")
    val plaintext = call.decrypt(incomingEncrypted)
}
```

### DiaMessage

Message parsing:

```kotlin
DiaMessage.deserialize(messageBytes).use { msg ->
    when (msg.getType()) {
        LibDia.MSG_AKE_REQUEST -> handleAkeRequest()
        LibDia.MSG_AKE_RESPONSE -> handleAkeResponse()
        LibDia.MSG_RUA_REQUEST -> handleRuaRequest()
        LibDia.MSG_RUA_RESPONSE -> handleRuaResponse()
        LibDia.MSG_HEARTBEAT -> handleHeartbeat()
        LibDia.MSG_BYE -> handleBye()
    }
    
    // Or use helpers:
    if (msg.isAkeRequest) { ... }
    if (msg.isHeartbeat) { ... }
}
```

### Enrollment

Client enrollment:

```kotlin
// Create enrollment request
val keysHandle = LibDia.enrollmentCreateRequest(phone, name, logoUrl, numTickets)
val request = LibDia.enrollmentGetRequest(keysHandle)

// Send request to enrollment server, get response

// Finalize enrollment
val configHandle = LibDia.enrollmentFinalize(keysHandle, response, phone, name, logoUrl)
val config = DiaConfig(configHandle)

// Save config
val envString = config.toEnv()
saveSecurely(envString)

// Cleanup
LibDia.enrollmentKeysDestroy(keysHandle)
config.close()
```

Server enrollment (for testing):

```kotlin
// Generate server config (only do this once!)
val serverConfig = LibDia.serverConfigGenerate(durationDays = 30)

// Process enrollment request
val response = LibDia.enrollmentProcess(serverConfig, request)

// Cleanup
LibDia.serverConfigDestroy(serverConfig)
```

## Examples

See `examples/` directory:

- **EnrollmentExample.kt**: Complete enrollment flow
- **CallFlowExample.kt**: Full AKE + RUA + messaging

Run examples:
```bash
# Generate configs
./gradlew :examples:enrollment:run --args="+1234567890 Alice"
./gradlew :examples:enrollment:run --args="+9876543210 Bob"

# Run call flow
./gradlew :examples:callflow:run --args="alice.env bob.env"
```

## Testing

See `test/DiaTest.kt` for comprehensive unit tests covering:
- Config enrollment and serialization
- CallState creation and roles
- Full AKE protocol exchange
- RUA identity verification
- Double Ratchet messaging
- Message type parsing

Run tests:
```bash
./gradlew test
```

## Memory Management

**Important**: All handles must be closed to avoid memory leaks.

**Bad** (memory leak):
```kotlin
val config = DiaConfig.fromEnv(envStr)
// Never closed!
```

**Good** (automatic cleanup):
```kotlin
DiaConfig.fromEnv(envStr).use { config ->
    // Automatically closed
}
```

Manual cleanup:
```kotlin
val config = DiaConfig.fromEnv(envStr)
try {
    // use config
} finally {
    config.close()
}
```

## ProGuard Rules

Add to `app/proguard-rules.pro`:

```proguard
# Keep JNI methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep LibDia classes
-keep class io.github.lokingdav.libdia.** { *; }

# Keep AutoCloseable
-keep class * implements java.lang.AutoCloseable {
    public void close();
}
```

Full rules in `proguard-rules.pro`.

## Troubleshooting

### Library not found

```
Error: library "libdia_jni.so" not found
```

**Solution:**
1. Build native libraries: `./build.sh`
2. Copy to `jniLibs/<ABI>/`
3. Verify ABI matches device: `adb shell getprop ro.product.cpu.abi`

### JNI method not found

```
Error: No implementation found for long io.github.lokingdav.libdia.LibDia.xxx
```

**Solution:**
1. Ensure `System.loadLibrary("dia_jni")` is called before using LibDia
2. Rebuild native libraries
3. Check method signature matches between LibDia.kt and dia_jni.cpp

### Protocol errors

```
Error: Invalid state for operation
```

**Solution:**
- Follow correct protocol order: akeInit → akeRequest/akeResponse → akeComplete → akeFinalize → transitionToRua → ruaRequest/ruaResponse → ruaFinalize
- Check you're using correct initiator/responder role
- Ensure both parties complete each phase before proceeding

## Architecture

```
Android App (Kotlin/Java)
         ↓
   LibDia.kt (Kotlin wrappers)
   DiaConfig, CallState, DiaMessage
         ↓
   dia_jni.cpp (JNI bindings)
         ↓
   dia_c.h (C interface)
         ↓
   libdia (C++ implementation)
   ├── dia.cpp (protocol)
   ├── ecgroup.cpp (crypto)
   ├── dh.cpp, voprf.cpp, amf.cpp, bbs.cpp
   └── libmcl (MCL library)
```

## API Reference

### LibDia Object

Core JNI function declarations (see LibDia.kt):

**Initialization:**
- `init()` - Initialize library

**Config:**
- `configFromEnv(String): Long` - Parse config from string
- `configToEnv(Long): String` - Serialize config
- `configDestroy(Long)` - Free config

**CallState:**
- `callstateCreate(Long, String, Boolean): Long` - Create call state
- `callstateDestroy(Long)` - Free call state
- `callstateIsCaller(Long): Boolean` - Check if initiator
- `callstateIsRecipient(Long): Boolean` - Check if responder
- `callstateGetRemoteParty(Long): RemoteParty` - Get verified remote party

**AKE:**
- `akeInit(Long)` - Initialize AKE
- `akeRequest(Long): ByteArray` - Create AKE request
- `akeResponse(Long, ByteArray): ByteArray` - Process request, create response
- `akeComplete(Long, ByteArray): ByteArray` - Process response, create complete
- `akeFinalize(Long, ByteArray)` - Process complete message
- `callstateGetAkeTopic(Long): String` - Get AKE topic
- `callstateGetSharedKey(Long): ByteArray` - Get shared key
- `callstateGetTicket(Long): ByteArray` - Get ticket
- `callstateGetSenderId(Long): String` - Get sender ID

**RUA:**
- `callstateTransitionToRua(Long)` - Switch to RUA topic
- `ruaRequest(Long): ByteArray` - Create RUA request
- `ruaResponse(Long, ByteArray): ByteArray` - Process request, create response
- `ruaFinalize(Long, ByteArray)` - Process response
- `callstateIsRuaActive(Long): Boolean` - Check if RUA active
- `callstateGetCurrentTopic(Long): String` - Get current topic

**Messaging:**
- `drEncrypt(Long, String): ByteArray` - Encrypt message
- `drDecrypt(Long, ByteArray): String` - Decrypt message
- `createHeartbeat(): ByteArray` - Create heartbeat message
- `createBye(): ByteArray` - Create BYE message

**Message Parsing:**
- `deserializeMessage(ByteArray): Long` - Parse message
- `messageGetType(Long): Int` - Get message type
- `messageDestroy(Long)` - Free message

**Enrollment (Client):**
- `enrollmentCreateRequest(String, String, String, Int): Long` - Create enrollment keys
- `enrollmentGetRequest(Long): ByteArray` - Get enrollment request
- `enrollmentFinalize(Long, ByteArray, String, String, String): Long` - Finalize enrollment
- `enrollmentKeysDestroy(Long)` - Free enrollment keys

**Enrollment (Server):**
- `serverConfigGenerate(Int): Long` - Generate server config
- `serverConfigFromEnv(String): Long` - Load server config
- `serverConfigToEnv(Long): String` - Serialize server config
- `enrollmentProcess(Long, ByteArray): ByteArray` - Process enrollment request
- `serverConfigDestroy(Long)` - Free server config

**Message Type Constants:**
```kotlin
MSG_UNSPECIFIED = 0
MSG_AKE_REQUEST = 1
MSG_AKE_RESPONSE = 2
MSG_AKE_COMPLETE = 3
MSG_RUA_REQUEST = 4
MSG_RUA_RESPONSE = 5
MSG_HEARTBEAT = 6
MSG_BYE = 7
```

### RemoteParty Data Class

```kotlin
data class RemoteParty(
    val phone: String,
    val name: String,
    val logo: String,
    val verified: Boolean
)
```

## License

Same as libdia - see [LICENSE](../../LICENSE)
