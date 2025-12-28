#include "doubleratchet.hpp"
#include "../helpers.hpp"
#include <sodium.h>
#include <stdexcept>
#include <cstring>

namespace doubleratchet {

// -----------------------------------------------------------------------------
// Key generation
// -----------------------------------------------------------------------------

DrKeyPair keygen() {
    DrKeyPair kp;
    kp.public_key.resize(crypto_kx_PUBLICKEYBYTES);
    kp.private_key.resize(crypto_kx_SECRETKEYBYTES);
    crypto_kx_keypair(kp.public_key.data(), kp.private_key.data());
    return kp;
}

// -----------------------------------------------------------------------------
// DrHeader implementation
// -----------------------------------------------------------------------------

Bytes DrHeader::serialize() const {
    Bytes result;
    result.reserve(dh.size() + 8);
    
    // DH public key (32 bytes)
    result.insert(result.end(), dh.begin(), dh.end());
    
    // n (4 bytes, big-endian)
    dia::utils::append_u32_be(result, n);
    
    // pn (4 bytes, big-endian)
    dia::utils::append_u32_be(result, pn);
    
    return result;
}

DrHeader DrHeader::deserialize(const Bytes& data) {
    if (data.size() < KEY_SIZE + 8) {
        throw std::runtime_error("DrHeader: invalid data size");
    }
    
    DrHeader header;
    size_t offset = 0;
    
    // DH public key
    header.dh.assign(data.begin(), data.begin() + KEY_SIZE);
    offset += KEY_SIZE;
    
    // n
    header.n = dia::utils::read_u32_be(data, offset);
    
    // pn
    header.pn = dia::utils::read_u32_be(data, offset);
    
    return header;
}

// -----------------------------------------------------------------------------
// DrMessage implementation
// -----------------------------------------------------------------------------

Bytes DrMessage::serialize() const {
    Bytes result;
    Bytes header_bytes = header.serialize();
    
    dia::utils::append_lp(result, header_bytes);
    dia::utils::append_lp(result, ciphertext);
    
    return result;
}

DrMessage DrMessage::deserialize(const Bytes& data) {
    DrMessage msg;
    size_t offset = 0;
    
    Bytes header_bytes = dia::utils::read_lp(data, offset);
    msg.header = DrHeader::deserialize(header_bytes);
    
    msg.ciphertext = dia::utils::read_lp(data, offset);
    
    return msg;
}

// -----------------------------------------------------------------------------
// DrSession implementation
// -----------------------------------------------------------------------------

void DrSession::generate_dh_keypair() {
    dh_public_key_.resize(crypto_kx_PUBLICKEYBYTES);
    dh_private_key_.resize(crypto_kx_SECRETKEYBYTES);
    crypto_kx_keypair(dh_public_key_.data(), dh_private_key_.data());
}

std::unique_ptr<DrSession> DrSession::init_as_recipient(
    const Bytes& shared_key,
    const Bytes& our_private_key,
    const Bytes& our_public_key)
{
    if (shared_key.size() != KEY_SIZE) {
        throw std::runtime_error("DrSession: shared_key must be 32 bytes");
    }
    if (our_private_key.size() != crypto_kx_SECRETKEYBYTES) {
        throw std::runtime_error("DrSession: our_private_key must be 32 bytes");
    }
    if (our_public_key.size() != crypto_kx_PUBLICKEYBYTES) {
        throw std::runtime_error("DrSession: our_public_key must be 32 bytes");
    }
    
    auto session = std::unique_ptr<DrSession>(new DrSession());
    
    // Store our DH key pair
    session->dh_private_key_ = our_private_key;
    session->dh_public_key_ = our_public_key;
    
    // Initialize root key from shared secret
    session->root_key_ = shared_key;
    
    // Recipient doesn't know remote's DH public key yet
    // Will perform DH ratchet on first received message
    session->remote_dh_pk_.clear();
    
    // No sending chain until we receive first message and do DH ratchet
    session->sending_chain_key_.clear();
    session->receiving_chain_key_.clear();
    
    session->initialized_ = true;
    return session;
}

std::unique_ptr<DrSession> DrSession::init_as_caller(
    const Bytes& shared_key,
    const Bytes& remote_public_key)
{
    if (shared_key.size() != KEY_SIZE) {
        throw std::runtime_error("DrSession: shared_key must be 32 bytes");
    }
    if (remote_public_key.size() != crypto_kx_PUBLICKEYBYTES) {
        throw std::runtime_error("DrSession: remote_public_key must be 32 bytes");
    }
    
    auto session = std::unique_ptr<DrSession>(new DrSession());
    
    // Generate our DH key pair
    session->generate_dh_keypair();
    
    // Store remote's DH public key
    session->remote_dh_pk_ = remote_public_key;
    
    // Initialize root key from shared secret
    session->root_key_ = shared_key;
    
    // Perform initial DH to derive first sending chain
    // Use crypto_scalarmult for X25519 DH
    Bytes dh_output(crypto_scalarmult_BYTES);
    if (crypto_scalarmult(dh_output.data(), 
                          session->dh_private_key_.data(),
                          remote_public_key.data()) != 0) {
        throw std::runtime_error("DrSession: DH computation failed");
    }
    
    // KDF: derive new root key and sending chain key using HKDF-like construction
    // Input: root_key || dh_output
    Bytes kdf_input;
    kdf_input.insert(kdf_input.end(), session->root_key_.begin(), session->root_key_.end());
    kdf_input.insert(kdf_input.end(), dh_output.begin(), dh_output.end());
    
    // Use crypto_generichash (BLAKE2b) to derive keys
    Bytes kdf_output(64);
    crypto_generichash(kdf_output.data(), 64, kdf_input.data(), kdf_input.size(), 
                       nullptr, 0);
    
    session->root_key_.assign(kdf_output.begin(), kdf_output.begin() + KEY_SIZE);
    session->sending_chain_key_.assign(kdf_output.begin() + KEY_SIZE, kdf_output.end());
    
    // No receiving chain yet (will be set on first received message)
    session->receiving_chain_key_.clear();
    
    session->initialized_ = true;
    return session;
}

void DrSession::dh_ratchet(const Bytes& remote_public_key) {
    // Compute DH with our current private key and new remote public key
    Bytes dh_output(crypto_scalarmult_BYTES);
    if (crypto_scalarmult(dh_output.data(),
                          dh_private_key_.data(),
                          remote_public_key.data()) != 0) {
        throw std::runtime_error("DrSession: DH computation failed");
    }
    
    // KDF: derive new root key and receiving chain key
    Bytes kdf_input;
    kdf_input.insert(kdf_input.end(), root_key_.begin(), root_key_.end());
    kdf_input.insert(kdf_input.end(), dh_output.begin(), dh_output.end());
    
    Bytes kdf_output(64);
    crypto_generichash(kdf_output.data(), 64, kdf_input.data(), kdf_input.size(),
                       nullptr, 0);
    
    root_key_.assign(kdf_output.begin(), kdf_output.begin() + KEY_SIZE);
    receiving_chain_key_.assign(kdf_output.begin() + KEY_SIZE, kdf_output.end());
    
    // Update remote DH public key
    remote_dh_pk_ = remote_public_key;
    
    // Generate new DH key pair for next sending
    prev_send_n_ = send_n_;
    send_n_ = 0;
    generate_dh_keypair();
    
    // Compute new DH with new private key
    if (crypto_scalarmult(dh_output.data(),
                          dh_private_key_.data(),
                          remote_public_key.data()) != 0) {
        throw std::runtime_error("DrSession: DH computation failed");
    }
    
    // KDF: derive new root key and sending chain key
    kdf_input.clear();
    kdf_input.insert(kdf_input.end(), root_key_.begin(), root_key_.end());
    kdf_input.insert(kdf_input.end(), dh_output.begin(), dh_output.end());
    
    crypto_generichash(kdf_output.data(), 64, kdf_input.data(), kdf_input.size(),
                       nullptr, 0);
    
    root_key_.assign(kdf_output.begin(), kdf_output.begin() + KEY_SIZE);
    sending_chain_key_.assign(kdf_output.begin() + KEY_SIZE, kdf_output.end());
}

Bytes DrSession::kdf_chain_key(Bytes& chain_key) {
    // Derive message key and new chain key using BLAKE2b
    Bytes output(64);
    crypto_generichash(output.data(), 64, chain_key.data(), chain_key.size(),
                       nullptr, 0);
    
    // First 32 bytes: new chain key
    // Second 32 bytes: message key
    Bytes message_key(output.begin() + KEY_SIZE, output.end());
    chain_key.assign(output.begin(), output.begin() + KEY_SIZE);
    
    return message_key;
}

Bytes DrSession::aead_encrypt(const Bytes& key, const Bytes& plaintext,
                               const Bytes& associated_data, const Bytes& header_bytes) {
    // Combine header and AD for full associated data
    Bytes full_ad;
    full_ad.insert(full_ad.end(), header_bytes.begin(), header_bytes.end());
    full_ad.insert(full_ad.end(), associated_data.begin(), associated_data.end());
    
    Bytes ciphertext(plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    Bytes nonce(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    randombytes_buf(nonce.data(), nonce.size());
    
    unsigned long long ciphertext_len;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        ciphertext.data(), &ciphertext_len,
        plaintext.data(), plaintext.size(),
        full_ad.data(), full_ad.size(),
        nullptr,  // nsec
        nonce.data(),
        key.data()
    );
    
    ciphertext.resize(ciphertext_len);
    
    // Prepend nonce to ciphertext
    Bytes result;
    result.reserve(nonce.size() + ciphertext.size());
    result.insert(result.end(), nonce.begin(), nonce.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    
    return result;
}

Bytes DrSession::aead_decrypt(const Bytes& key, const Bytes& ciphertext,
                               const Bytes& associated_data, const Bytes& header_bytes) {
    if (ciphertext.size() < crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + 
                           crypto_aead_xchacha20poly1305_ietf_ABYTES) {
        throw std::runtime_error("DrSession: ciphertext too short");
    }
    
    // Extract nonce
    Bytes nonce(ciphertext.begin(), 
                ciphertext.begin() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    
    // Extract actual ciphertext
    Bytes ct(ciphertext.begin() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
             ciphertext.end());
    
    // Combine header and AD
    Bytes full_ad;
    full_ad.insert(full_ad.end(), header_bytes.begin(), header_bytes.end());
    full_ad.insert(full_ad.end(), associated_data.begin(), associated_data.end());
    
    Bytes plaintext(ct.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long plaintext_len;
    
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext.data(), &plaintext_len,
            nullptr,  // nsec
            ct.data(), ct.size(),
            full_ad.data(), full_ad.size(),
            nonce.data(),
            key.data()) != 0) {
        throw std::runtime_error("DrSession: decryption failed");
    }
    
    plaintext.resize(plaintext_len);
    return plaintext;
}

Bytes DrSession::encrypt(const Bytes& plaintext, const Bytes& associated_data) {
    std::lock_guard<std::mutex> lock(mu_);
    
    if (!initialized_) {
        throw std::runtime_error("DrSession: not initialized");
    }
    
    if (sending_chain_key_.empty()) {
        throw std::runtime_error("DrSession: no sending chain key");
    }
    
    // Get message key from chain
    Bytes message_key = kdf_chain_key(sending_chain_key_);
    
    // Create header
    DrHeader header;
    header.dh = dh_public_key_;
    header.n = send_n_;
    header.pn = prev_send_n_;
    
    Bytes header_bytes = header.serialize();
    
    // Encrypt
    Bytes ciphertext = aead_encrypt(message_key, plaintext, associated_data, header_bytes);
    
    send_n_++;
    
    DrMessage msg;
    msg.header = header;
    msg.ciphertext = ciphertext;
    
    return msg.serialize();
}

Bytes DrSession::decrypt(const Bytes& message_bytes, const Bytes& associated_data) {
    std::lock_guard<std::mutex> lock(mu_);
    
    if (!initialized_) {
        throw std::runtime_error("DrSession: not initialized");
    }
    
    DrMessage message = DrMessage::deserialize(message_bytes);
    const auto& header = message.header;
    Bytes header_bytes = header.serialize();
    
    // Check if this is from a new DH ratchet (remote changed their key)
    if (remote_dh_pk_.empty() || header.dh != remote_dh_pk_) {
        // Store skipped message keys from current receiving chain
        if (!receiving_chain_key_.empty()) {
            while (recv_n_ < header.pn && skipped_keys_.size() < MAX_SKIP) {
                Bytes mk = kdf_chain_key(receiving_chain_key_);
                Bytes skip_key;
                skip_key.insert(skip_key.end(), remote_dh_pk_.begin(), remote_dh_pk_.end());
                dia::utils::append_u32_be(skip_key, recv_n_);
                skipped_keys_[skip_key] = mk;
                recv_n_++;
            }
        }
        
        // Perform DH ratchet
        dh_ratchet(header.dh);
        recv_n_ = 0;
    }
    
    // Check for skipped key
    Bytes skip_key;
    skip_key.insert(skip_key.end(), header.dh.begin(), header.dh.end());
    dia::utils::append_u32_be(skip_key, header.n);
    
    auto it = skipped_keys_.find(skip_key);
    if (it != skipped_keys_.end()) {
        Bytes message_key = it->second;
        skipped_keys_.erase(it);
        return aead_decrypt(message_key, message.ciphertext, associated_data, header_bytes);
    }
    
    // Skip ahead if needed
    while (recv_n_ < header.n && skipped_keys_.size() < MAX_SKIP) {
        Bytes mk = kdf_chain_key(receiving_chain_key_);
        Bytes sk;
        sk.insert(sk.end(), header.dh.begin(), header.dh.end());
        dia::utils::append_u32_be(sk, recv_n_);
        skipped_keys_[sk] = mk;
        recv_n_++;
    }
    
    if (recv_n_ != header.n) {
        throw std::runtime_error("DrSession: too many skipped messages");
    }
    
    // Get message key
    Bytes message_key = kdf_chain_key(receiving_chain_key_);
    recv_n_++;
    
    return aead_decrypt(message_key, message.ciphertext, associated_data, header_bytes);
}

} // namespace doubleratchet
