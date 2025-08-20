#!/usr/bin/env bash
set -euo pipefail

AllowedABIs=(arm64-v8a x86_64 armeabi-v7a)

# Default ABI is arm64-v8a if not provided
ABI="${1:-arm64-v8a}"

# Validate ABI
if [[ ! " ${AllowedABIs[*]} " =~ " ${ABI} " ]]; then
  echo "Error: ABI '$ABI' is not supported. Allowed ABIs are: ${AllowedABIs[*]}"
  exit 1
fi

DN="bindings/android/builds/$ABI"
rm -rf "$DN"
mkdir -p "$DN"
cd "$DN"

# Require either ANDROID_NDK_ROOT or ANDROID_NDK_HOME
if [[ -n "${ANDROID_NDK_ROOT:-}" ]]; then
  NDK_PATH="$ANDROID_NDK_ROOT"
elif [[ -n "${ANDROID_NDK_HOME:-}" ]]; then
  NDK_PATH="$ANDROID_NDK_HOME"
else
  echo "Error: ANDROID_NDK_ROOT or ANDROID_NDK_HOME must be set."
  echo "Please export one of them to your Android NDK path (e.g., \$HOME/Android/Sdk/ndk/27.x.y)."
  exit 1
fi

if [[ ! -d "$NDK_PATH" ]]; then
  echo "Error: NDK path does not exist: $NDK_PATH"
  exit 1
fi

echo "Building for ABI=$ABI with NDK at $NDK_PATH"

# Configure + build
cmake \
  -DCMAKE_TOOLCHAIN_FILE="$NDK_PATH/build/cmake/android.toolchain.cmake" \
  -DANDROID_ABI="$ABI" \
  -DANDROID_PLATFORM=android-24 \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_DIA_JNI=ON \
  -DBUILD_DIA_TESTING=OFF \
  -DBUILD_DIA_BENCHMARK=OFF \
  -DMCL_TEST_WITH_GMP=OFF \
  ../../../..

cmake --build . --config Release -j
