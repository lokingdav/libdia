# Go bindings for `libdia`

This document explains how to **build** and **use** the Go bindings for `libdia`, plus how to run tests/benchmarks.

---

## Prerequisites

- **Go** 1.20+ (cgo enabled)
- **CMake** and a **C++17** compiler (Clang or GCC)
- **pkg-config** (used to locate headers/libs via `dia.pc`)

> cgo must be enabled (it is by default on Linux/macOS). For cross‑builds set `CGO_ENABLED=1` and ensure a working C/C++ toolchain for your target.

---

## Build & Install `libdia` (once)

From the repo root, run the installer (builds C/C++ and installs headers, libs, and `dia.pc`):

```bash
./bindings/install.sh
````

* Default install prefix is **`/usr`** (so headers go to `/usr/include/dia/…`, libs to `/usr/lib{,64}`, and `dia.pc` to `/usr/lib{,64}/pkgconfig`).
* To change the prefix, edit the CMake line in `bindings/install.sh` and add:

  ```
  -DCMAKE_INSTALL_PREFIX=/your/prefix
  ```

### Verify pkg-config

```bash
pkg-config --modversion dia
pkg-config --cflags --libs dia
```

* Expect a version (e.g. `1.0.0`) and valid flags.
* If `dia.pc` isn’t found, ensure `PKG_CONFIG_PATH` includes the install location, e.g.:

  * Linux: `export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:/usr/lib/pkgconfig`
  * macOS: `export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:/opt/homebrew/lib/pkgconfig`

> **Runtime note (shared linking):** If `libdia.so`/`libmcl.so` are installed to a non‑standard path, set:
>
> * Linux: `export LD_LIBRARY_PATH=/your/prefix/lib:$LD_LIBRARY_PATH`
> * macOS: `export DYLD_LIBRARY_PATH=/your/prefix/lib:$DYLD_LIBRARY_PATH`

---

## Using the Go bindings

The Go package relies on `pkg-config: dia` to provide include/lib paths—so no manual `CGO_CFLAGS`/`CGO_LDFLAGS` are needed if `dia.pc` is visible.

### Add the dependency

```bash
# from your module
go get github.com/lokingdav/libdia/bindings/go
```

> The package name is `dia`.

### Example

```go
package main

import (
	"fmt"
	"github.com/lokingdav/libdia/bindings/go"
)

func main() {
	sk, pk := libdia.DhKeygen()
	fmt.Printf("sk: %x\n", sk)
	fmt.Printf("pk: %x\n", pk)
}
```

Build/run:

```bash
go run .
```

---

## Running Tests and Benchmarks

From the Go bindings directory:

```bash
cd bindings/go

# Unit tests
go test ./...

# Benchmarks
go test -bench=. -benchmem
```

> These assume `pkg-config dia` resolves correctly and that the shared libs are on your runtime library path if you installed them outside system default locations.

---

## Tips & Troubleshooting

* **`pkg-config: exec: "pkg-config": executable file not found`**
  Install `pkg-config` and ensure it’s on your `PATH`.

* **`Package dia was not found in the pkg-config search path`**
  Set `PKG_CONFIG_PATH` to include your install prefix (where `dia.pc` lives).

* **`ld: cannot find -ldia` or runtime `…: cannot open shared object file`**
  Ensure you installed `libdia` and set `LD_LIBRARY_PATH`/`DYLD_LIBRARY_PATH` for non‑system locations.
  To prefer static linking with pkg-config:

  ```bash
  export PKG_CONFIG="pkg-config --static"
  ```

* **Cross‑compiling**
  You need a cross C/C++ toolchain that can build `libdia` for the target first, then point `pkg-config` to that sysroot/prefix when building your Go app with `GOOS/GOARCH` and `CGO_ENABLED=1`.

* **API surface**
  See `bindings/go/libdia.go` for exported functions. Extend it as needed by adding cgo wrappers.

---

## What gets installed

* Headers: `include/dia/*.h`
* Libraries: `lib/libdia.{a,so}` (and its deps, e.g., `libmcl`)
* pkg-config: `lib/pkgconfig/dia.pc`

With `dia.pc` in place, the Go bindings “just work” via cgo + pkg-config.

---