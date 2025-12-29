# libdia

`libdia` is a cryptographic library implementing the **DIA (Dynamic Identity Authentication)** protocol. It provides privacy-preserving identity authentication with enrollment, authenticated key exchange (AKE), right-to-use authentication (RUA), and secure messaging via Double Ratchet.

## Features

### Core Protocol
- **Enrollment**: Register users with cryptographic credentials
- **AKE (Authenticated Key Exchange)**: Establish shared secrets between authenticated parties
- **RUA (Right-To-Use Authentication)**: Exchange and verify identity information
- **Double Ratchet**: End-to-end encrypted messaging with forward secrecy

### Cryptographic Primitives
- **BBS+ Signatures**: Privacy-preserving credential issuance and verification
- **Verifiable Oblivious PRF (VOPRF)**: Access control with privacy
- **AMF (Asymmetric Message Franking)**: Designated verifier signature
- **Diffie-Hellman**: Elliptic curve key exchange on BN256
- **PKE (Public Key Encryption)**: X25519-based encryption
- **Hash functions**: SHA-256, HMAC, HKDF

### Language Support
- **C++ API**: Full protocol implementation
- **C API**: FFI-friendly interface for bindings
- **Go bindings**: Idiomatic Go wrapper with comprehensive tests
- **Android bindings**: JNI interface for Kotlin/Java

## Prerequisites

- **CMake 3.22+**
- **C++17 compiler** (GCC 9+ or Clang 10+)
- **pkg-config**
- **libsodium 1.0.18+** (auto-installed if not found)

## Quick Start

### Building from Source

```bash
# Clone the repository
git clone https://github.com/lokingdav/libdia.git
cd libdia

# Build (Release mode)
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)

# Run tests
./tests/run_dia_tests

# Install system-wide (optional)
sudo make install
sudo ldconfig  # Linux only
```

### Installation Locations

After `make install`:
- Headers: `/usr/local/include/dia/`
- Libraries: `/usr/local/lib/libdia.{a,so}`
- Dependencies: `/usr/local/lib/libmcl.so`, `/usr/local/lib/libecgroup.a`
- pkg-config: `/usr/local/lib/pkgconfig/dia.pc`

Verify installation:

```bash
pkg-config --modversion dia
pkg-config --cflags --libs dia
```

## Usage

### C++ API

```cpp
#include "dia/dia.hpp"
#include "protocol/enrollment.hpp"
#include "protocol/callstate.hpp"

using namespace protocol;

// Server: Generate enrollment keys
ServerConfig server_cfg = generate_server_config(30); // 30 days validity

// Client: Create enrollment request
EnrollmentKeys keys = create_enrollment_request("+1234567890", "Alice", "https://example.com/logo.png", 1);
auto request = keys.create_request();

// Server: Process enrollment
EnrollmentResponse response = process_enrollment(server_cfg, request);

// Client: Finalize enrollment
ClientConfig client_cfg = finalize_enrollment(keys, response, "+1234567890", "Alice", "https://example.com/logo.png");

// Use client_cfg for authenticated calls...
```

### C API

```c
#include <dia/dia_c.h>

int main() {
    // Initialize library
    dia_init();
    
    // Generate server config
    dia_server_config_t* server_cfg;
    dia_server_config_generate(30, &server_cfg);
    
    // Create enrollment request
    dia_enrollment_keys_t* keys;
    unsigned char* request;
    size_t request_len;
    dia_enrollment_create_request("+1234567890", "Alice", 
                                   "https://example.com/logo.png", 1,
                                   &keys, &request, &request_len);
    
    // Process enrollment
    unsigned char* response;
    size_t response_len;
    dia_enrollment_process(server_cfg, request, request_len, 
                           &response, &response_len);
    
    // Finalize enrollment
    dia_config_t* config;
    dia_enrollment_finalize(keys, response, response_len,
                           "+1234567890", "Alice", 
                           "https://example.com/logo.png", &config);
    
    // Cleanup
    dia_free_bytes(request);
    dia_free_bytes(response);
    dia_enrollment_keys_destroy(keys);
    dia_server_config_destroy(server_cfg);
    dia_config_destroy(config);
    
    return 0;
}
```

Compile:

```bash
gcc myapp.c $(pkg-config --cflags --libs dia) -o myapp
```

## Language Bindings

### Go

Full-featured Go bindings with idiomatic API:

```go
import "github.com/lokingdav/libdia/bindings/go"

// Generate server config
serverCfg, _ := dia.GenerateServerConfig(30)
defer serverCfg.Close()

// Enrollment flow
keys, request, _ := dia.CreateEnrollmentRequest("+1234567890", "Alice", "https://example.com/logo.png", 1)
defer keys.Close()

response, _ := serverCfg.ProcessEnrollment(request)
config, _ := dia.FinalizeEnrollment(keys, response, "+1234567890", "Alice", "https://example.com/logo.png")
defer config.Close()
```

See [Go bindings documentation](bindings/go/README.md) for complete API reference and examples.

### Android

Kotlin/Java bindings via JNI:

```kotlin
// Initialize
LibDia.init(context)

// Generate server config
val serverConfig = ServerConfig.generate(30)

// Enrollment
val (keys, request) = Enrollment.createRequest("+1234567890", "Alice", "https://example.com/logo.png", 1)
val response = serverConfig.processEnrollment(request)
val config = Enrollment.finalize(keys, response, "+1234567890", "Alice", "https://example.com/logo.png")
```

See [Android bindings documentation](bindings/android/README.md) for setup and usage.

## Protocol Overview

### 1. Enrollment Phase

Users register with the authentication system:

```
Client                                    Server
  |                                          |
  |  1. Generate keys                       |
  |  2. Create enrollment request ---------->|
  |                                          |  3. Verify request
  |                                          |  4. Issue credentials
  |<---------- 5. Send enrollment response --|
  |                                          |
  |  6. Finalize enrollment                 |
  |  7. Store credentials                   |
```

### 2. Call Authentication (AKE + RUA)

Establish authenticated, encrypted communication:

```
Caller                                  Recipient
  |                                          |
  |  AKE Phase (3-message exchange)         |
  |  1. AKE Init                            |  1. AKE Init
  |  2. AKE Request ----------------------->|
  |                                          |  3. Verify, create response
  |<----------------------- 4. AKE Response |
  |  5. Verify, create complete ----------->|
  |                                          |  6. Finalize
  |  Shared key K established                |  Shared key K established
  |                                          |
  |  RUA Phase (identity verification)      |
  |  7. RUA Request ----------------------->|
  |                                          |  8. Verify credentials
  |<----------------------- 9. RUA Response |
  |  10. Verify identity                    |
  |                                          |
  |  Both parties verified ✓                |  Both parties verified ✓
```

### 3. Secure Messaging

Double Ratchet encrypted communication:

```
Party A                                   Party B
  |                                          |
  |  Encrypt(msg) -------------------------→|  Decrypt(ct) → msg
  |←------------------------- Encrypt(reply)|  
  |  Decrypt(ct) → reply                    |
```

## Building and Testing

### Build Options

```bash
# Release build (optimized)
cmake -DCMAKE_BUILD_TYPE=Release ..

# Debug build (with symbols)
cmake -DCMAKE_BUILD_TYPE=Debug ..

# Enable tests
cmake -DBUILD_DIA_TESTING=ON ..

# Enable benchmarks
cmake -DBUILD_DIA_BENCHMARK=ON ..

# Force bundled libsodium (for Android)
cmake -DFORCE_BUNDLED_SODIUM=ON ..

# Custom install prefix
cmake -DCMAKE_INSTALL_PREFIX=/opt/libdia ..
```

### Running Tests

```bash
# C++ tests
cd build
./tests/run_dia_tests

# Go tests
cd bindings/go
PKG_CONFIG_PATH=../../build go test -v

# Benchmarks
cd build
./benchmarks/run_dia_benchmarks
```

All 558 C++ test assertions across 54 test cases should pass.

### Running Benchmarks

```bash
# C++ benchmarks
./build/benchmarks/run_dia_benchmarks

# Go benchmarks
cd bindings/go
PKG_CONFIG_PATH=../../build go test -bench=. -benchmem
```

## Performance

Representative benchmarks on Intel Xeon Gold 6130 @ 2.10GHz:

| Operation | Time (ns/op) | Allocs |
|-----------|--------------|--------|
| Enrollment Request | ~900,000 | 448 B |
| Full Enrollment | ~2,600,000 | 928 B |
| AKE Full Exchange | ~4,300,000 | 960 B |
| RUA Exchange | ~4,600,000 | 976 B |
| DR Encrypt | ~7,700 | 160 B |
| DR Decrypt | ~5,500 | 80 B |

## Architecture

```
libdia/
├── include/dia/          # Public C API headers
│   ├── dia_c.h          # Main C API
│   └── dia.hpp          # C++ API (internal)
├── src/
│   ├── crypto/          # Cryptographic primitives
│   │   ├── bbs.cpp     # BBS+ signatures
│   │   ├── voprf.cpp   # Verifiable OPRF
│   │   ├── amf.cpp     # AMF authentication
│   │   ├── dh.cpp      # Diffie-Hellman
│   │   ├── pke.cpp     # Public key encryption
│   │   └── doubleratchet.cpp  # Double Ratchet
│   ├── protocol/        # Protocol implementation
│   │   ├── enrollment.cpp
│   │   ├── ake.cpp
│   │   ├── rua.cpp
│   │   ├── callstate.cpp
│   │   └── messages.cpp
│   └── bindings/        # Language bindings
│       └── dia_c.cpp   # C API implementation
├── bindings/
│   ├── go/             # Go bindings
│   └── android/        # Android/JNI bindings
└── tests/              # Unit tests
```

## Platform Support

| Platform | Architecture | Status |
|----------|-------------|--------|
| Linux | x86_64 | ✅ Tested |
| Linux | aarch64 | ✅ Tested |
| macOS | x86_64 | ✅ Tested |
| macOS | arm64 (M1/M2) | ✅ Tested |
| Android | arm64-v8a | ✅ Supported |
| Android | x86_64 | ✅ Emulator |
| Windows | x86_64 | ⚠️ Experimental |

## Dependencies

### Required
- **MCL** (Multi-precision and Curve Library) - For BN256 pairing-based crypto
  - Automatically fetched via CMake FetchContent
- **libsodium** - For symmetric crypto and hashing
  - System library used if available, otherwise auto-downloaded

### Optional
- **Catch2** - For unit testing (auto-fetched if `BUILD_DIA_TESTING=ON`)

All dependencies are handled automatically by CMake.

## Troubleshooting

### pkg-config not found

```bash
# Ubuntu/Debian
sudo apt-get install pkg-config

# macOS
brew install pkg-config

# Fedora/RHEL
sudo dnf install pkgconfig
```

### libsodium not found

The build will automatically download and build libsodium if not found. To force bundled version:

```bash
cmake -DFORCE_BUNDLED_SODIUM=ON ..
```

### Library not found at runtime

```bash
# Linux: Add to library path
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

# macOS: Add to library path
export DYLD_LIBRARY_PATH=/usr/local/lib:$DYLD_LIBRARY_PATH

# Or update cache (Linux)
sudo ldconfig
```

### Cross-compilation

For Android:

```bash
cd bindings/android
./build.sh arm64-v8a  # or x86_64
```

For other platforms, use CMake toolchain files:

```bash
cmake -DCMAKE_TOOLCHAIN_FILE=/path/to/toolchain.cmake ..
```

## Security Considerations

- **Credential Storage**: Client credentials should be stored encrypted (use OS keychain/keystore)
- **Server Keys**: Server private keys must be protected and rotated periodically
- **Network Transport**: Protocol messages should be sent over TLS
- **Enrollment Duration**: Set appropriate validity periods for credentials
- **Key Material**: Use secure random number generators for all key generation

## Contributing

Contributions are welcome! Please ensure:

1. All tests pass: `./build/tests/run_dia_tests`
2. Code follows existing style (run `clang-format`)
3. Add tests for new features
4. Update documentation as needed

### Development Setup

```bash
# Install dependencies
sudo apt-get install cmake g++ pkg-config libsodium-dev  # Ubuntu/Debian
brew install cmake libsodium pkg-config  # macOS

# Build with tests and benchmarks
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Debug -DBUILD_DIA_TESTING=ON -DBUILD_DIA_BENCHMARK=ON ..
make -j$(nproc)

# Run tests
./tests/run_dia_tests
cd ../bindings/go && PKG_CONFIG_PATH=../../build go test -v
```

## License

[Specify your license here]

## Citation

If you use libdia in your research, please cite:

```bibtex
@software{libdia,
  title = {libdia: Dynamic Identity Authentication Protocol Library},
  author = {[Your Name/Organization]},
  year = {2024},
  url = {https://github.com/lokingdav/libdia}
}
```

## Related Projects

- [MCL Library](https://github.com/herumi/mcl) - Cryptographic pairing library
- [libsodium](https://libsodium.org) - Modern cryptographic library
- [Signal Protocol](https://signal.org/docs/) - Similar approach to Double Ratchet

## Support

- **Issues**: [GitHub Issues](https://github.com/lokingdav/libdia/issues)
- **Discussions**: [GitHub Discussions](https://github.com/lokingdav/libdia/discussions)
- **Documentation**: See `docs/` directory and binding-specific READMEs

## Acknowledgments

This library builds upon research in privacy-preserving authentication and uses established cryptographic primitives from the academic community.
