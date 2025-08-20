# `libdia`

`libdia` is a cryptographic library implementing primitives and protocols for **dynamic identity authentication** and related privacy-preserving identity mechanisms.  
It provides a C API, with bindings for Go and Android.

---

## Features

- **Diffie–Hellman (DH)** key generation and secret computation  
- **BBS+ signatures** (group / anonymous signatures)  
- **Verifiable Oblivious PRFs (VOPRFs)**  
- **Commitments, helpers, and serialization utilities**  
- **C API** suitable for FFI (Go, Kotlin/Java, etc.)  
- **Bindings**:
  - Go (`bindings/go/`)
  - Android JNI (`bindings/android/`)

---

## Prerequisites

- **CMake** 3.16+  
- **C++17 compiler** (Clang or GCC)  
- **pkg-config** (for downstream bindings)

---

## Building

Clone with submodules (for dependencies like MCL):

```bash
git clone https://github.com/lokingdav/libdia.git
cd libdia
````

### Build (default)

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

### Build + install

```bash
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=/usr/local

cmake --build build -j
cmake --install build
```

This installs:

* headers → `/usr/local/include/dia/`
* libraries → `/usr/local/lib/`
* pkg-config file → `/usr/local/lib/pkgconfig/dia.pc`

---

## Verify installation

```bash
pkg-config --modversion dia
pkg-config --cflags --libs dia
```

You should see a version number and proper compiler flags.

---

## Using `libdia` directly (C API)

Include headers:

```c
#include <dia/dia_c.h>
```

Link with:

```bash
gcc myapp.c $(pkg-config --cflags --libs dia) -o myapp
```

---

## Bindings

* [Go bindings](bindings/go/README.md) – idiomatic Go wrapper, tested with `go test` and `go bench`.
* [Android bindings](bindings/android/README.md) – JNI + `.so` build for `arm64-v8a` (phones) and `x86_64` (emulators).

See each binding’s README for details.

---

## Running tests

Build with testing enabled:

```bash
cmake -S . -B build -DBUILD_DIA_TESTING=ON
cmake --build build -j
./build/tests/run_dia_tests
```

---

## Benchmarks

Build with benchmarks enabled:

```bash
cmake -S . -B build -DBUILD_DIA_BENCHMARK=ON
cmake --build build -j
./build/benchmarks/run_dia_benchmarks
```

---

## Troubleshooting

* **`Package dia was not found in the pkg-config search path`**
  Ensure `PKG_CONFIG_PATH` includes the install location, e.g.:

  ```bash
  export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
  ```

* **Linker errors (`libmcl.so not found`)**
  Ensure you also ship/install `libmcl.so` if it was built shared. Add to `LD_LIBRARY_PATH` or use static linking.

* **Cross-compilation (Android/iOS)**
  Use the provided bindings or set a proper CMake toolchain.

---
