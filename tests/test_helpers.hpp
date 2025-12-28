#ifndef DIA_TEST_HELPERS_HPP
#define DIA_TEST_HELPERS_HPP

#include "../src/crypto/ecgroup.hpp"
#include "../src/crypto/bbs.hpp"
#include "../src/crypto/amf.hpp"
#include "../src/crypto/voprf.hpp"
#include "../src/crypto/pke.hpp"
#include "../src/crypto/doubleratchet.hpp"
#include "../src/protocol/callstate.hpp"
#include "../src/helpers.hpp"
#include <sodium.h>
#include <string>

namespace test_helpers {

using Bytes = ecgroup::Bytes;

// -----------------------------------------------------------------------------
// One-time initialization
// -----------------------------------------------------------------------------

// Call once at the start of tests to initialize pairing and sodium
inline void init_crypto() {
    static bool initialized = false;
    if (!initialized) {
        ecgroup::init_pairing();
        if (sodium_init() < 0) {
            throw std::runtime_error("Failed to initialize libsodium");
        }
        initialized = true;
    }
}

// -----------------------------------------------------------------------------
// Random data generation
// -----------------------------------------------------------------------------

// Generate a random 32-byte key
inline Bytes random_bytes(size_t len = 32) {
    Bytes data(len);
    randombytes_buf(data.data(), data.size());
    return data;
}

// -----------------------------------------------------------------------------
// Server configuration for enrollment tests
// -----------------------------------------------------------------------------

struct TestServerConfig {
    // Credential Issuance (BBS)
    bbs::KeyPair ci_keypair;
    
    // Access Throttling (VOPRF)
    voprf::KeyPair at_keypair;
    
    // Moderator AMF (AMF)
    amf::KeyPair mod_keypair;
    
    // Derived bytes for ServerConfig
    Bytes ci_private_key;
    Bytes ci_public_key;
    Bytes at_private_key;
    Bytes at_public_key;
    Bytes mod_public_key;
};

inline TestServerConfig create_server_config() {
    init_crypto();
    
    TestServerConfig cfg;
    
    // Credential Issuance keypair (BBS)
    bbs::Params bbs_params = bbs::Params::Default();
    cfg.ci_keypair = bbs::keygen(bbs_params);
    cfg.ci_private_key = cfg.ci_keypair.sk.to_bytes();
    cfg.ci_public_key = cfg.ci_keypair.pk.to_bytes();
    
    // Access Throttling keypair (VOPRF)
    cfg.at_keypair = voprf::keygen();
    cfg.at_private_key = cfg.at_keypair.sk.to_bytes();
    cfg.at_public_key = cfg.at_keypair.pk.to_bytes();
    
    // Moderator AMF keypair (uses AMF keygen!)
    amf::Params amf_params = amf::Params::Default();
    cfg.mod_keypair = amf::KeyGen(amf_params);
    cfg.mod_public_key = cfg.mod_keypair.pk.to_bytes();
    
    return cfg;
}

// -----------------------------------------------------------------------------
// Client configuration for AKE/protocol tests
// -----------------------------------------------------------------------------

struct TestClientConfig {
    // BBS keypair for subscriber signing (used to sign requests)
    bbs::KeyPair sub_keypair;
    
    // AMF keypair for accountability
    amf::KeyPair amf_keypair;
    
    // PKE keypair for encryption
    pke::KeyPair pke_keypair;
    
    // DR keypair for double ratchet
    doubleratchet::DrKeyPair dr_keypair;
    
    // RA (Registration Authority) - simulated for tests
    bbs::KeyPair ra_keypair;
    
    // The complete ClientConfig for protocol use
    protocol::ClientConfig config;
};

// Create a test client config with valid enrollment credentials
inline TestClientConfig create_client_config(
    const std::string& phone,
    const std::string& name,
    const bbs::KeyPair* shared_ra = nullptr)
{
    init_crypto();
    
    TestClientConfig tc;
    bbs::Params bbs_params = bbs::Params::Default();
    amf::Params amf_params = amf::Params::Default();
    
    // Use shared RA if provided, otherwise create new one
    if (shared_ra) {
        tc.ra_keypair = *shared_ra;
    } else {
        tc.ra_keypair = bbs::keygen(bbs_params);
    }
    
    // Generate subscriber signing keys (BBS)
    tc.sub_keypair = bbs::keygen(bbs_params);
    
    // Generate AMF keys (AMF keygen - NOT BBS!)
    tc.amf_keypair = amf::KeyGen(amf_params);
    
    // Generate PKE keys
    tc.pke_keypair = pke::keygen();
    
    // Generate DR keys
    tc.dr_keypair = doubleratchet::keygen();
    
    // Build ClientConfig
    tc.config.my_phone = phone;
    tc.config.my_name = name;
    tc.config.my_logo = "";
    
    tc.config.ra_public_key = tc.ra_keypair.pk.to_bytes();
    tc.config.amf_private_key = tc.amf_keypair.sk.to_bytes();
    tc.config.amf_public_key = tc.amf_keypair.pk.to_bytes();
    tc.config.pke_private_key = tc.pke_keypair.private_key;
    tc.config.pke_public_key = tc.pke_keypair.public_key;
    tc.config.dr_private_key = tc.dr_keypair.private_key;
    tc.config.dr_public_key = tc.dr_keypair.public_key;
    tc.config.en_expiration = Bytes(8, 0xFF);  // Far future
    
    // Create BBS credential: message1 = hash(amf_pk, pke_pk, dr_pk, expiration, phone)
    Bytes tn_bytes(phone.begin(), phone.end());
    Bytes message1 = dia::utils::hash_all({
        tc.config.amf_public_key,
        tc.config.pke_public_key,
        tc.config.dr_public_key,
        tc.config.en_expiration,
        tn_bytes
    });
    Bytes message2(name.begin(), name.end());
    
    ecgroup::Scalar m1 = ecgroup::Scalar::hash_to_scalar(message1);
    ecgroup::Scalar m2 = ecgroup::Scalar::hash_to_scalar(message2);
    std::vector<ecgroup::Scalar> msgs = {m1, m2};
    
    // Sign with RA key
    bbs::Signature sig = bbs::sign(bbs_params, tc.ra_keypair.sk, msgs);
    tc.config.ra_signature = sig.to_bytes();
    
    return tc;
}

// Create paired client configs with shared RA (for AKE tests)
inline std::pair<TestClientConfig, TestClientConfig> create_paired_configs(
    const std::string& caller_phone,
    const std::string& caller_name,
    const std::string& recipient_phone,
    const std::string& recipient_name)
{
    init_crypto();
    
    // Create shared RA keypair
    bbs::Params params = bbs::Params::Default();
    bbs::KeyPair ra_kp = bbs::keygen(params);
    
    auto caller_cfg = create_client_config(caller_phone, caller_name, &ra_kp);
    auto recipient_cfg = create_client_config(recipient_phone, recipient_name, &ra_kp);
    
    return {caller_cfg, recipient_cfg};
}

} // namespace test_helpers

#endif // DIA_TEST_HELPERS_HPP
