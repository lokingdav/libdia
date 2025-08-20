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
  exit 1
fi
[[ -d "$NDK_PATH" ]] || { echo "Error: NDK path does not exist: $NDK_PATH"; exit 1; }

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

# ================== Stage JNI libs into $DN/jniLibs ==================
STAGE_DIR="jniLibs"
mkdir -p "$STAGE_DIR"

# Helper: copy first existing match
copy_first() {
  local outdir="$1"; shift
  local name="$1"; shift
  local found=""
  for p in "$@"; do
    if [[ -f "$p" ]]; then
      found="$p"
      break
    fi
  done
  if [[ -z "$found" ]]; then
    # Fallback: search under current build dir
    found="$(find . -type f -name "$name" -print -quit || true)"
  fi
  if [[ -n "$found" && -f "$found" ]]; then
    cp -v "$found" "$outdir/"
    return 0
  else
    echo "WARN: $name not found in expected locations."
    return 1
  fi
}

# Try common locations (CMake can place outputs in src/ or lib/)
COPIED=0
copy_first "$STAGE_DIR" "libdia_jni.so" \
  "src/libdia_jni.so" \
  "lib/libdia_jni.so" \
  "./libdia_jni.so" && ((COPIED++)) || true

copy_first "$STAGE_DIR" "libmcl.so" \
  "lib/libmcl.so" \
  "_deps/mcl-build/libmcl.so" \
  "./libmcl.so" \
  "src/libmcl.so" && ((COPIED++)) || true

echo "Staged $COPIED file(s) to $STAGE_DIR"
ls -l "$STAGE_DIR" || true
