# Go Bindings for libdia

Go bindings for the **DIA (Dynamic Identity Authentication)** protocol library. This package provides idiomatic Go access to enrollment, authenticated key exchange (AKE), right-to-use authentication (RUA), and secure messaging via Double Ratchet.

## Features

- **Enrollment**: Register users with the authentication system
- **AKE Protocol**: Establish authenticated shared keys between parties
- **RUA Protocol**: Exchange verified identity information
- **Double Ratchet**: End-to-end encrypted messaging with forward secrecy
- **Zero-copy design**: Efficient C/Go interop via cgo

## Installation

### Prerequisites

- **Go 1.20+** with cgo enabled
- **CMake 3.22+**
- **C++17 compiler** (GCC 9+ or Clang 10+)
- **pkg-config**
- **libsodium** (auto-installed if not found)

### Option 1: Install from System Build

Build and install libdia system-wide:

```bash
# From the libdia repository root
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
sudo make install
sudo ldconfig  # Linux only
```

This installs:
- Headers to `/usr/local/include/dia/`
- Libraries to `/usr/local/lib/`
- pkg-config file to `/usr/local/lib/pkgconfig/dia.pc`

Verify installation:

```bash
pkg-config --modversion dia
pkg-config --cflags --libs dia
```

Then install the Go package:

```bash
go get github.com/lokingdav/libdia/bindings/go
```

### Option 2: Development Build (No Installation)

For development, you can use the build directory directly:

```bash
# Build libdia
cd /path/to/libdia
mkdir -p build && cd build
cmake ..
make -j$(nproc)

# Use with Go (from bindings/go directory)
cd ../bindings/go
PKG_CONFIG_PATH=/path/to/libdia/build go test
PKG_CONFIG_PATH=/path/to/libdia/build go build
```

## Quick Start

### Basic Enrollment Flow

```go
package main

import (
"fmt"
"log"

"github.com/lokingdav/libdia/bindings/go"
)

func main() {
// Server generates keys (in production, these are persisted)
serverCfg, err := dia.GenerateServerConfig(30) // 30 days validity
if err != nil {
log.Fatal(err)
}
defer serverCfg.Close()

// Client creates enrollment request
phone := "+1234567890"
name := "Alice"
logoURL := "https://example.com/logo.png"

keys, request, err := dia.CreateEnrollmentRequest(phone, name, logoURL, 1)
if err != nil {
log.Fatal(err)
}
defer keys.Close()

// Server processes enrollment request
response, err := serverCfg.ProcessEnrollment(request)
if err != nil {
log.Fatal(err)
}

// Client finalizes enrollment
config, err := dia.FinalizeEnrollment(keys, response, phone, name, logoURL)
if err != nil {
log.Fatal(err)
}
defer config.Close()

fmt.Println("Enrollment successful!")

// Save config for later use
envString, _ := config.ToEnv()
// Store envString securely (e.g., encrypted file, keychain)
_ = envString
}
```

### Authenticated Call Setup (AKE + RUA)

```go
package main

import (
"fmt"
"log"

"github.com/lokingdav/libdia/bindings/go"
)

func main() {
// Load configs (from enrollment)
aliceConfig, _ := dia.ConfigFromEnv(aliceEnvString)
defer aliceConfig.Close()
bobConfig, _ := dia.ConfigFromEnv(bobEnvString)
defer bobConfig.Close()

// Alice initiates call to Bob
alice, _ := dia.NewCallState(aliceConfig, "+1987654321", true)  // outgoing
defer alice.Close()

// Bob receives call from Alice
bob, _ := dia.NewCallState(bobConfig, "+1234567890", false)  // incoming
defer bob.Close()

// === AKE Phase ===
alice.AKEInit()
bob.AKEInit()

// 3-message AKE exchange
request, _ := alice.AKERequest()
response, _ := bob.AKEResponse(request)
complete, _ := alice.AKEComplete(response)
bob.AKEFinalize(complete)

// Verify shared key established
aliceKey, _ := alice.SharedKey()
bobKey, _ := bob.SharedKey()
fmt.Printf("Shared key established: %d bytes\n", len(aliceKey))

// === RUA Phase (identity verification) ===
alice.TransitionToRUA()
bob.TransitionToRUA()

alice.RUAInit()
bob.RUAInit()

ruaReq, _ := alice.RUARequest()
ruaResp, _ := bob.RUAResponse(ruaReq)
alice.RUAFinalize(ruaResp)

// Verify identities
aliceRemote, _ := alice.RemoteParty()
bobRemote, _ := bob.RemoteParty()

fmt.Printf("Alice verified Bob: %s (%s)\n", bobRemote.Name, bobRemote.Phone)
fmt.Printf("Bob verified Alice: %s (%s)\n", aliceRemote.Name, aliceRemote.Phone)
}
```

### Secure Messaging

```go
// After AKE + RUA setup (see above)

// Alice sends message to Bob
plaintext := []byte("Hello, Bob!")
ciphertext, err := alice.Encrypt(plaintext)
if err != nil {
log.Fatal(err)
}

// Bob receives and decrypts
decrypted, err := bob.Decrypt(ciphertext)
if err != nil {
log.Fatal(err)
}

fmt.Printf("Bob received: %s\n", decrypted)

// Bidirectional communication
response := []byte("Hi Alice!")
responseCt, _ := bob.Encrypt(response)
responseDecrypted, _ := alice.Decrypt(responseCt)
fmt.Printf("Alice received: %s\n", responseDecrypted)
```

## API Reference

### Configuration

```go
// Generate server config with fresh keys
serverCfg, err := dia.GenerateServerConfig(durationDays int) (*ServerConfig, error)

// Create enrollment request (client-side)
keys, request, err := dia.CreateEnrollmentRequest(phone, name, logoURL string, numTickets int) (*EnrollmentKeys, []byte, error)

// Process enrollment (server-side)
response, err := serverCfg.ProcessEnrollment(request []byte) ([]byte, error)

// Finalize enrollment (client-side)
config, err := dia.FinalizeEnrollment(keys *EnrollmentKeys, response []byte, phone, name, logoURL string) (*Config, error)

// Serialize/deserialize config
envString, err := config.ToEnv() (string, error)
config, err := dia.ConfigFromEnv(envString string) (*Config, error)
```

### Call State Management

```go
// Create call state
callState, err := dia.NewCallState(config *Config, otherPhone string, outgoing bool) (*CallState, error)

// Query state
isCaller := callState.IsCaller() bool
isRecipient := callState.IsRecipient() bool
isRUAActive := callState.IsRUAActive() bool
senderID, err := callState.SenderID() (string, error)
```

### AKE Protocol

```go
// Initialize AKE
err := callState.AKEInit() error

// Get AKE topic
topic, err := callState.AKETopic() (string, error)

// Caller side
request, err := callState.AKERequest() ([]byte, error)
complete, err := callState.AKEComplete(response []byte) ([]byte, error)

// Recipient side  
response, err := callState.AKEResponse(request []byte) ([]byte, error)
err := callState.AKEFinalize(complete []byte) error

// Access shared key
sharedKey, err := callState.SharedKey() ([]byte, error)
ticket, err := callState.Ticket() ([]byte, error)
```

### RUA Protocol

```go
// Transition to RUA phase
err := callState.TransitionToRUA() error

// Initialize RUA
err := callState.RUAInit() error

// Caller side
request, err := callState.RUARequest() ([]byte, error)
err := callState.RUAFinalize(response []byte) error

// Recipient side
response, err := callState.RUAResponse(request []byte) ([]byte, error)

// Get verified remote party info
remoteParty, err := callState.RemoteParty() (*RemoteParty, error)
// RemoteParty has: Phone, Name, Logo (string), Verified (bool)
```

### Secure Messaging (Double Ratchet)

```go
// Encrypt message
ciphertext, err := callState.Encrypt(plaintext []byte) ([]byte, error)

// Decrypt message
plaintext, err := callState.Decrypt(ciphertext []byte) ([]byte, error)
```

### Message Utilities

```go
// Parse received message
msg, err := dia.ParseMessage(data []byte) (*Message, error)

// Query message
msgType := msg.Type() int  // MsgAKERequest, MsgAKEResponse, etc.
senderID, err := msg.SenderID() (string, error)
topic, err := msg.Topic() (string, error)

// Create control messages
bye, err := callState.CreateByeMessage() ([]byte, error)
heartbeat, err := callState.CreateHeartbeatMessage() ([]byte, error)
```

### Error Handling

```go
var (
ErrInvalidArg  = errors.New("dia: invalid argument")
ErrVerifyFail  = errors.New("dia: verification failed")
ErrProtocol    = errors.New("dia: protocol error")
// ... other errors
)
```

## Building and Testing

### Run Tests

```bash
cd bindings/go

# All tests
go test -v

# Specific test
go test -v -run TestAKE_FullExchange

# With race detector
go test -race -v
```

### Run Benchmarks

```bash
# All benchmarks
go test -bench=. -benchmem

# Specific benchmark
go test -bench=BenchmarkAKE -benchmem

# Save results
go test -bench=. -benchmem > bench.txt
```

### Development Build

```bash
# Use local build directory
export PKG_CONFIG_PATH=/path/to/libdia/build
go test -v
go build
```

## Platform Support

| Platform | Arch | Status |
|----------|------|--------|
| Linux | amd64 | ✅ Tested |
| Linux | arm64 | ✅ Tested |
| macOS | amd64 | ✅ Tested |
| macOS | arm64 | ✅ Tested |
| Android | arm64-v8a | ✅ Supported (see android/) |
| Windows | amd64 | ⚠️ Experimental |

## Troubleshooting

### pkg-config not found

```bash
# Ubuntu/Debian
sudo apt-get install pkg-config

# macOS
brew install pkg-config
```

### dia.pc not found

Ensure `PKG_CONFIG_PATH` includes the directory containing `dia.pc`:

```bash
# System install
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH

# Development build
export PKG_CONFIG_PATH=/path/to/libdia/build:$PKG_CONFIG_PATH
```

### Linker errors

```bash
# Linux: Update library cache
sudo ldconfig

# Linux/macOS: Add to library path
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH        # Linux
export DYLD_LIBRARY_PATH=/usr/local/lib:$DYLD_LIBRARY_PATH    # macOS
```

### Cross-compilation

```bash
# Example: Building for arm64 on amd64
CGO_ENABLED=1 GOOS=linux GOARCH=arm64 \
  CC=aarch64-linux-gnu-gcc \
  PKG_CONFIG_PATH=/path/to/arm64/sysroot/lib/pkgconfig \
  go build
```

## Examples

See the test files for complete examples:
- `dia_test.go`: Unit tests demonstrating all features
- `dia_benchmark_test.go`: Performance benchmarks

## License

Same as libdia (see repository root).

## Contributing

Contributions welcome! Please ensure:
1. All tests pass: `go test -v`
2. Code is formatted: `go fmt`
3. No race conditions: `go test -race`

## Related

- [libdia C++ library](../../README.md)
- [Android bindings](../android/README.md)
- [DIA Protocol Specification](../../docs/protocol.md) (if available)
