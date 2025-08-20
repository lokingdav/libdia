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

# Prefer ANDROID_NDK_ROOT if set, else try common defaults
ANDROID_NDK_ROOT="${ANDROID_NDK_ROOT:-${ANDROID_NDK_HOME:-$HOME/Library/Android/sdk/ndk/27.0.12077973}}"
if [[ ! -d "$ANDROID_NDK_ROOT" ]]; then
  echo "Error: ANDROID_NDK_ROOT not found at: $ANDROID_NDK_ROOT"
  echo "Set ANDROID_NDK_ROOT (or ANDROID_NDK_HOME) to your NDK path."
  exit 1
fi
export ANDROID_NDK_ROOT

echo "Building for ABI=$ABI with NDK at $ANDROID_NDK_ROOT"

# Configure + build
cmake -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK_ROOT/build/cmake/android.toolchain.cmake" \
  -DANDROID_ABI="$ABI" \
  -DANDROID_PLATFORM=android-24 \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_DIA_JNI=ON \
  -DBUILD_DIA_TESTING=OFF \
  -DBUILD_DIA_BENCHMARK=OFF \
  -DMCL_TEST_WITH_GMP=OFF \
  ../../../..

ninja
