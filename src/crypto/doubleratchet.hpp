#ifndef DIA_CRYPTO_DOUBLERATCHET_HPP
#define DIA_CRYPTO_DOUBLERATCHET_HPP

#include "ecgroup.hpp"
#include <mutex>
#include <map>
#include <memory>
#include <cstdint>

namespace doubleratchet {

using Bytes = ecgroup::Bytes;

// Key sizes
constexpr size_t KEY_SIZE = 32;
constexpr size_t NONCE_SIZE = 24;  // XChaCha20-Poly1305
constexpr size_t TAG_SIZE = 16;

// -----------------------------------------------------------------------------
// Key generation
// -----------------------------------------------------------------------------
struct DrKeyPair {
    Bytes public_key;   // 32 bytes
    Bytes private_key;  // 32 bytes
};

// Generate a new X25519 key pair for Double Ratchet
DrKeyPair keygen();

// -----------------------------------------------------------------------------
// DrHeader - Message header containing ratchet state
// -----------------------------------------------------------------------------
struct DrHeader {
    Bytes    dh;   // Current ratchet public key (32 bytes)
    uint32_t n;    // Message number in current sending chain
    uint32_t pn;   // Number of messages in previous sending chain
    
    Bytes serialize() const;
    static DrHeader deserialize(const Bytes& data);
};

// -----------------------------------------------------------------------------
// DrMessage - Encrypted message with header
// -----------------------------------------------------------------------------
struct DrMessage {
    DrHeader header;
    Bytes    ciphertext;
    
    Bytes serialize() const;
    static DrMessage deserialize(const Bytes& data);
};

// -----------------------------------------------------------------------------
// DrSession - Double Ratchet session state
// -----------------------------------------------------------------------------
class DrSession {
public:
    // Initialize as recipient (has their own DH key pair, will receive first message)
    // Called by the party that provided their DR public key during key exchange
    static std::unique_ptr<DrSession> init_as_recipient(
        const Bytes& shared_key,      // 32-byte shared secret from AKE
        const Bytes& our_private_key, // Our DR private key
        const Bytes& our_public_key   // Our DR public key
    );
    
    // Initialize as caller (only has remote's public key, will send first message)
    // Called by the party that received the counterpart's DR public key
    static std::unique_ptr<DrSession> init_as_caller(
        const Bytes& shared_key,      // 32-byte shared secret from AKE
        const Bytes& remote_public_key // Counterpart's DR public key
    );
    
    // Encrypt a message (returns serialized DrMessage)
    Bytes encrypt(const Bytes& plaintext, const Bytes& associated_data = {});
    
    // Decrypt a message (takes serialized DrMessage)
    Bytes decrypt(const Bytes& message, const Bytes& associated_data = {});

private:
    DrSession() = default;
    
    // Generate a new DH key pair
    void generate_dh_keypair();
    
    // Perform a DH ratchet step
    void dh_ratchet(const Bytes& remote_public_key);
    
    // Derive chain and message keys using KDF
    Bytes kdf_chain_key(Bytes& chain_key);
    
    // Encrypt with AEAD
    Bytes aead_encrypt(const Bytes& key, const Bytes& plaintext, 
                       const Bytes& associated_data, const Bytes& header_bytes);
    
    // Decrypt with AEAD
    Bytes aead_decrypt(const Bytes& key, const Bytes& ciphertext,
                       const Bytes& associated_data, const Bytes& header_bytes);

    std::mutex mu_;
    
    // DH ratchet state
    Bytes dh_private_key_;  // Our current DH private key
    Bytes dh_public_key_;   // Our current DH public key
    Bytes remote_dh_pk_;    // Remote party's current DH public key
    
    // Root chain
    Bytes root_key_;
    
    // Sending chain
    Bytes sending_chain_key_;
    uint32_t send_n_ = 0;
    
    // Receiving chain
    Bytes receiving_chain_key_;
    uint32_t recv_n_ = 0;
    
    // Previous sending chain message count (for header)
    uint32_t prev_send_n_ = 0;
    
    // Skipped message keys (for out-of-order messages)
    // Key: (dh_public_key || message_number) -> message_key
    std::map<Bytes, Bytes> skipped_keys_;
    static constexpr size_t MAX_SKIP = 100;
    
    bool initialized_ = false;
};

} // namespace doubleratchet

#endif // DIA_CRYPTO_DOUBLERATCHET_HPP
