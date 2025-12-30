#!/usr/bin/env bash
#
# Build libdia native libraries for Android
#
# Usage:
#   ./build.sh [OPTIONS] [ABI]
#
# Options:
#   --all         Build for all supported ABIs
#   --clean       Clean build directory before building
#   --verbose     Enable verbose output
#   --help        Show this help message
#
# ABIs:
#   arm64-v8a     64-bit ARM (default, for phones)
#   x86_64        64-bit x86 (for emulators)
#   armeabi-v7a   32-bit ARM (legacy devices)
#
# Examples:
#   ./build.sh                    # Build for arm64-v8a
#   ./build.sh x86_64            # Build for x86_64
#   ./build.sh --all             # Build for all ABIs
#   ./build.sh --clean arm64-v8a # Clean and build for arm64-v8a
#

set -euo pipefail

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Supported ABIs
AllowedABIs=(arm64-v8a x86_64 armeabi-v7a)

# Default options
ABI=""
BUILD_ALL=0
CLEAN=0
VERBOSE=0

# Colors for output
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m' # No Color
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
fi

# Helper functions
error() {
    echo -e "${RED}Error:${NC} $*" >&2
    exit 1
}

success() {
    echo -e "${GREEN}✓${NC} $*"
}

info() {
    echo -e "${BLUE}➜${NC} $*"
}

warn() {
    echo -e "${YELLOW}⚠${NC} $*"
}

show_help() {
    sed -n '2,22p' "$0" | sed 's/^# //' | sed 's/^#//'
    exit 0
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --all)
            BUILD_ALL=1
            shift
            ;;
        --clean)
            CLEAN=1
            shift
            ;;
        --verbose)
            VERBOSE=1
            shift
            ;;
        --help|-h)
            show_help
            ;;
        -*)
            error "Unknown option: $1"
            ;;
        *)
            if [[ -z "$ABI" ]]; then
                ABI="$1"
            else
                error "Multiple ABIs specified. Use --all to build all ABIs."
            fi
            shift
            ;;
    esac
done

# Default to arm64-v8a if no ABI specified and not building all
if [[ $BUILD_ALL -eq 0 && -z "$ABI" ]]; then
    ABI="arm64-v8a"
    info "No ABI specified, defaulting to $ABI"
fi

# Validate ABI
if [[ -n "$ABI" && ! " ${AllowedABIs[*]} " =~ " ${ABI} " ]]; then
    error "ABI '$ABI' is not supported. Allowed ABIs: ${AllowedABIs[*]}"
fi

# Find NDK
if [[ -n "${ANDROID_NDK_ROOT:-}" ]]; then
    NDK_PATH="$ANDROID_NDK_ROOT"
elif [[ -n "${ANDROID_NDK_HOME:-}" ]]; then
    NDK_PATH="$ANDROID_NDK_HOME"
else
    error "ANDROID_NDK_ROOT or ANDROID_NDK_HOME must be set.\nExample: export ANDROID_NDK_ROOT=\$HOME/Android/Sdk/ndk/27.2.12479018"
fi

[[ -d "$NDK_PATH" ]] || error "NDK path does not exist: $NDK_PATH"

# Detect NDK version
if [[ -f "$NDK_PATH/source.properties" ]]; then
    NDK_VERSION=$(grep "Pkg.Revision" "$NDK_PATH/source.properties" | cut -d'=' -f2 | tr -d ' ')
    info "Using Android NDK version: $NDK_VERSION"
    
    # Warn if NDK version is too old
    NDK_MAJOR=$(echo "$NDK_VERSION" | cut -d'.' -f1)
    if [[ $NDK_MAJOR -lt 26 ]]; then
        warn "NDK version $NDK_VERSION is older than r26. Build may fail."
    fi
else
    warn "Could not detect NDK version"
fi

# Build function
build_abi() {
    local abi="$1"
    
    # Get absolute path to repo root (4 levels up from this script)
    local script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local repo_root="$(cd "$script_dir/../.." && pwd)"
    local build_dir="$script_dir/builds/$abi"
    
    info "Building for ABI: $abi"
    
    # Clean if requested
    if [[ $CLEAN -eq 1 && -d "$build_dir" ]]; then
        info "Cleaning $build_dir"
        rm -rf "$build_dir"
    fi
    
    # Create build directory
    mkdir -p "$build_dir"
    cd "$build_dir"
    
    # Configure CMake
    local cmake_args=(
        "-DCMAKE_TOOLCHAIN_FILE=$NDK_PATH/build/cmake/android.toolchain.cmake"
        "-DANDROID_ABI=$abi"
        "-DANDROID_PLATFORM=android-24"
        "-DCMAKE_BUILD_TYPE=Release"
        "-DBUILD_DIA_JNI=ON"
        "-DBUILD_DIA_TESTING=OFF"
        "-DBUILD_DIA_BENCHMARK=OFF"
        "-DMCL_TEST_WITH_GMP=OFF"
        "-DFORCE_BUNDLED_SODIUM=ON"
    )
    
    if [[ $VERBOSE -eq 1 ]]; then
        cmake_args+=("-DCMAKE_VERBOSE_MAKEFILE=ON")
    fi
    
    info "Configuring CMake..."
    if [[ $VERBOSE -eq 1 ]]; then
        cmake "${cmake_args[@]}" "$repo_root"
    else
        cmake "${cmake_args[@]}" "$repo_root" > /dev/null
    fi
    
    # Build
    info "Building native libraries..."
    if [[ $VERBOSE -eq 1 ]]; then
        cmake --build . --config Release -j
    else
        cmake --build . --config Release -j > /dev/null
    fi
    
    # Stage libraries
    local stage_dir="jniLibs/$abi"
    mkdir -p "$stage_dir"
    
    info "Staging libraries to $stage_dir..."
    
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
            cp -v "$found" "$outdir/" | sed 's/^/  /'
            return 0
        else
            warn "$name not found in expected locations"
            return 1
        fi
    }
    
    # Try common locations
    local copied=0
    copy_first "$stage_dir" "libdia_jni.so" \
        "src/libdia_jni.so" \
        "lib/libdia_jni.so" \
        "./libdia_jni.so" && ((copied++)) || true
    
    copy_first "$stage_dir" "libmcl.so" \
        "lib/libmcl.so" \
        "_deps/mcl-build/lib/libmcl.so" \
        "_deps/mcl-build/libmcl.so" \
        "./libmcl.so" \
        "src/libmcl.so" && ((copied++)) || true
    
    # Return to original directory
    cd "$OLDPWD" > /dev/null || cd "$repo_root"
    
    if [[ $copied -eq 2 ]]; then
        success "Build completed for $abi ($copied libraries staged)"
    else
        warn "Build completed for $abi but only $copied/2 libraries staged"
    fi
    
    echo ""
}

# Main execution
echo ""
info "=== libdia Android Build ==="
echo ""

if [[ $BUILD_ALL -eq 1 ]]; then
    info "Building for all ABIs: ${AllowedABIs[*]}"
    echo ""
    for abi in "${AllowedABIs[@]}"; do
        build_abi "$abi"
    done
    echo ""
    success "All ABIs built successfully!"
    echo ""
    info "Staged libraries:"
    for abi in "${AllowedABIs[@]}"; do
        local stage_dir="bindings/android/builds/$abi/jniLibs/$abi"
        if [[ -d "$stage_dir" ]]; then
            echo "  $abi:"
            ls -lh "$stage_dir" | tail -n +2 | awk '{print "    " $9 " (" $5 ")"}'
        fi
    done
else
    build_abi "$ABI"
    echo ""
    success "Build completed successfully!"
    echo ""
    info "Staged libraries:"
    stage_dir="$SCRIPT_DIR/builds/$ABI/jniLibs/$ABI"
    if [[ -d "$stage_dir" ]]; then
        ls -lh "$stage_dir" | tail -n +2 | awk '{print "  " $9 " (" $5 ")"}'
    fi
fi

echo ""
info "Next steps:"
echo "  1. Copy libraries to your Android project:"
echo "     cp $stage_dir/*.so app/src/main/jniLibs/$ABI/"
echo ""
echo "  2. Copy LibDia.kt to your project:"
echo "     cp bindings/android/LibDia.kt app/src/main/java/io/github/lokingdav/libdia/"
echo ""
echo "  3. Update app/build.gradle.kts with:"
echo "     android { defaultConfig { ndk { abiFilters += listOf(\"$ABI\") } } }"
echo ""
