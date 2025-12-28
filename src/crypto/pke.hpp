#ifndef DIA_CRYPTO_PKE_HPP
#define DIA_CRYPTO_PKE_HPP

#include "ecgroup.hpp"
#include <stdexcept>

namespace pke {

using Bytes = ecgroup::Bytes;

// Key sizes for X25519
constexpr size_t PRIVATE_KEY_SIZE = 32;
constexpr size_t PUBLIC_KEY_SIZE = 32;
constexpr size_t SEAL_OVERHEAD = 48;  // crypto_box_SEALBYTES

// -----------------------------------------------------------------------------
// KeyPair - X25519 key pair for PKE
// -----------------------------------------------------------------------------
struct KeyPair {
    Bytes private_key;  // 32 bytes
    Bytes public_key;   // 32 bytes
};

// Generate a new X25519 key pair
KeyPair keygen();

// Encrypt plaintext for a recipient's public key (anonymous authenticated encryption)
// Uses crypto_box_seal: ephemeral key + XSalsa20-Poly1305
// Output: sealed ciphertext (plaintext.size() + 48 bytes overhead)
Bytes encrypt(const Bytes& recipient_public_key, const Bytes& plaintext);

// Decrypt ciphertext using the recipient's key pair
// Throws on decryption failure (authentication failed or corrupted)
Bytes decrypt(const Bytes& private_key, const Bytes& public_key, const Bytes& ciphertext);

// Convenience overload using KeyPair
inline Bytes decrypt(const KeyPair& kp, const Bytes& ciphertext) {
    return decrypt(kp.private_key, kp.public_key, ciphertext);
}

} // namespace pke

#endif // DIA_CRYPTO_PKE_HPP
