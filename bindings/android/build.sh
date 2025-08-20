#!/usr/bin/env bash
set -euo pipefail

AllowedABIs=(arm64-v8a)

ABI=$1

if [[ ! " ${AllowedABIs[*]} " =~ " ${ABI} " ]]; then
  echo "Error: ABI '$ABI' is not supported. Allowed ABIs are: ${AllowedABIs[*]}"
  exit 1
fi

DN="build-android-$ABI"
rm -rf "$DN"
mkdir "$DN" && cd "$DN"

export ANDROID_NDK_ROOT="$HOME/Library/Android/sdk/ndk/27.0.12077973"

# 1) Initial configure to fetch MCL into _deps/mcl-src
cmake -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK_ROOT/build/cmake/android.toolchain.cmake" \
  -DANDROID_ABI=$ABI \
  -DANDROID_PLATFORM=android-24 \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_DIA_JNI=ON \
  -DBUILD_DIA_TESTING=OFF \
  -DBUILD_DIA_BENCHMARK=OFF \
  -DMCL_TEST_WITH_GMP=OFF \
  ..

ninja
