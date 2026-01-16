#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./run.sh <command> [args...]

Commands:
  test           Run Go tests against installed libdia (pkg-config: dia)
  build          Build Go package against installed libdia (pkg-config: dia)

  test-dev       Run Go tests against the libdia build dir (pkg-config: dia-dev)
  build-dev      Build Go package against the libdia build dir (pkg-config: dia-dev)

  env-dev        Print the environment this script would use for *-dev commands

Environment overrides:
  BUILD_DIR       Path to libdia CMake build dir (default: <repo>/build)
  PKG_CONFIG_PATH If set, used as-is for *-dev commands (otherwise set to BUILD_DIR)

Examples:
  ./run.sh test
  ./run.sh build

  # Development build (no install):
  ./run.sh test-dev
  ./run.sh build-dev

  # Custom build dir:
  BUILD_DIR=/path/to/libdia/build ./run.sh test-dev
EOF
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"

default_build_dir="$repo_root/build"
build_dir="${BUILD_DIR:-$default_build_dir}"

cmd="${1:-}"
shift || true

run_go() {
  (cd "$script_dir" && "$@")
}

case "$cmd" in
  test)
    run_go go test ./... "$@"
    ;;
  build)
    run_go go build ./... "$@"
    ;;

  test-dev|build-dev|env-dev)
    pkg_path="${PKG_CONFIG_PATH:-$build_dir}"
    if [[ ! -f "$pkg_path/dia-dev.pc" ]]; then
      echo "error: dia-dev.pc not found at: $pkg_path/dia-dev.pc" >&2
      echo "hint: build libdia first (cmake -S . -B build && cmake --build build), or set BUILD_DIR/PKG_CONFIG_PATH" >&2
      exit 1
    fi

    if [[ "$cmd" == "env-dev" ]]; then
      echo "export PKG_CONFIG_PATH=\"$pkg_path\""
      echo "go <cmd> -tags dia_dev ./..."
      exit 0
    fi

    if [[ "$cmd" == "test-dev" ]]; then
      PKG_CONFIG_PATH="$pkg_path" run_go go test -tags dia_dev ./... "$@"
    else
      PKG_CONFIG_PATH="$pkg_path" run_go go build -tags dia_dev ./... "$@"
    fi
    ;;

  -h|--help|help|"")
    usage
    ;;

  *)
    echo "error: unknown command: $cmd" >&2
    usage
    exit 2
    ;;
esac
