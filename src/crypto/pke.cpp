#include "pke.hpp"
#include <sodium.h>
#include <stdexcept>

namespace pke {

// Ensure sodium is initialized (safe to call multiple times)
static void ensure_sodium_init() {
    static bool initialized = false;
    if (!initialized) {
        if (sodium_init() < 0) {
            throw std::runtime_error("Failed to initialize libsodium");
        }
        initialized = true;
    }
}

KeyPair keygen() {
    ensure_sodium_init();
    
    KeyPair kp;
    kp.public_key.resize(crypto_box_PUBLICKEYBYTES);
    kp.private_key.resize(crypto_box_SECRETKEYBYTES);
    
    if (crypto_box_keypair(kp.public_key.data(), kp.private_key.data()) != 0) {
        throw std::runtime_error("Failed to generate key pair");
    }
    
    return kp;
}

Bytes encrypt(const Bytes& recipient_public_key, const Bytes& plaintext) {
    ensure_sodium_init();
    
    if (recipient_public_key.size() != crypto_box_PUBLICKEYBYTES) {
        throw std::invalid_argument("Invalid public key size: expected " + 
            std::to_string(crypto_box_PUBLICKEYBYTES) + ", got " + 
            std::to_string(recipient_public_key.size()));
    }
    
    if (plaintext.empty()) {
        throw std::invalid_argument("Plaintext cannot be empty");
    }
    
    // crypto_box_seal: anonymous authenticated encryption
    // Output size: plaintext + crypto_box_SEALBYTES (48 bytes overhead)
    Bytes ciphertext(plaintext.size() + crypto_box_SEALBYTES);
    
    if (crypto_box_seal(ciphertext.data(), 
                        plaintext.data(), 
                        plaintext.size(),
                        recipient_public_key.data()) != 0) {
        throw std::runtime_error("Encryption failed");
    }
    
    return ciphertext;
}

Bytes decrypt(const Bytes& private_key, const Bytes& public_key, const Bytes& ciphertext) {
    ensure_sodium_init();
    
    if (private_key.size() != crypto_box_SECRETKEYBYTES) {
        throw std::invalid_argument("Invalid private key size: expected " + 
            std::to_string(crypto_box_SECRETKEYBYTES) + ", got " + 
            std::to_string(private_key.size()));
    }
    
    if (public_key.size() != crypto_box_PUBLICKEYBYTES) {
        throw std::invalid_argument("Invalid public key size: expected " + 
            std::to_string(crypto_box_PUBLICKEYBYTES) + ", got " + 
            std::to_string(public_key.size()));
    }
    
    if (ciphertext.size() < crypto_box_SEALBYTES) {
        throw std::invalid_argument("Ciphertext too short: minimum " + 
            std::to_string(crypto_box_SEALBYTES) + " bytes required");
    }
    
    // Output size: ciphertext - overhead
    Bytes plaintext(ciphertext.size() - crypto_box_SEALBYTES);
    
    if (crypto_box_seal_open(plaintext.data(),
                             ciphertext.data(),
                             ciphertext.size(),
                             public_key.data(),
                             private_key.data()) != 0) {
        throw std::runtime_error("Decryption failed: authentication failed or corrupted data");
    }
    
    return plaintext;
}

} // namespace pke
