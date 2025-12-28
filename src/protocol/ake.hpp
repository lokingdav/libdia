#ifndef DIA_PROTOCOL_AKE_HPP
#define DIA_PROTOCOL_AKE_HPP

#include "callstate.hpp"
#include "messages.hpp"
#include "../crypto/bbs.hpp"
#include "../crypto/dh.hpp"
#include "../crypto/pke.hpp"
#include "../crypto/doubleratchet.hpp"

#include <memory>
#include <stdexcept>

namespace protocol {

// -----------------------------------------------------------------------------
// AKE Error types
// -----------------------------------------------------------------------------
class AkeError : public std::runtime_error {
public:
    explicit AkeError(const std::string& msg) : std::runtime_error(msg) {}
};

class AuthenticationError : public AkeError {
public:
    explicit AuthenticationError(const std::string& msg) : AkeError(msg) {}
};

// -----------------------------------------------------------------------------
// ZK Proof parameters for AKE
// -----------------------------------------------------------------------------
struct AkeZkProofParams {
    std::string telephone_number;
    std::string name;
    Bytes       amf_public_key;
    Bytes       pke_public_key;
    Bytes       dr_public_key;
    Bytes       expiration;
    Bytes       nonce;            // challenge
    Bytes       ra_public_key;
    Bytes       ra_signature;
};

// -----------------------------------------------------------------------------
// AKE Protocol Functions
// -----------------------------------------------------------------------------

// Initialize AKE state for a call
// Generates ephemeral DH key pair and computes AKE topic
void init_ake(CallState& call_state);

// Step 1: Caller creates AkeRequest (unencrypted)
// - Creates ZK proof of enrollment
// - Sends AMF, PKE, DR public keys + proof
// Returns serialized ProtocolMessage
Bytes ake_request(CallState& caller);

// Step 2: Recipient processes AkeRequest and creates AkeResponse
// - Verifies caller's ZK proof
// - Creates own ZK proof
// - Sends DH public key + AMF, PKE, DR keys + proof (encrypted with caller's PKE key)
// Returns serialized ProtocolMessage
Bytes ake_response(CallState& recipient, const ProtocolMessage& caller_msg);

// Step 3: Caller processes AkeResponse and creates AkeComplete
// - Verifies recipient's ZK proof
// - Computes shared key from DH
// - Initializes Double Ratchet session
// - Sends concatenated DH public keys (encrypted with recipient's PKE key)
// Returns serialized ProtocolMessage
Bytes ake_complete(CallState& caller, const ProtocolMessage& recipient_msg);

// Step 4: Recipient processes AkeComplete and finalizes
// - Verifies DH public keys match
// - Computes shared key from DH
// - Initializes Double Ratchet session
void ake_finalize(CallState& recipient, const ProtocolMessage& caller_msg);

// -----------------------------------------------------------------------------
// Helper functions
// -----------------------------------------------------------------------------

// Hash multiple byte vectors together (SHA-256)
Bytes hash_all(std::initializer_list<Bytes> inputs);
Bytes hash_all(const std::vector<Bytes>& inputs);

// Concatenate bytes
Bytes concat_bytes(const Bytes& a, const Bytes& b);

// Compute shared key from AKE parameters
Bytes compute_shared_key(
    const Bytes& topic,
    const Bytes& caller_proof,
    const Bytes& recipient_proof,
    const Bytes& caller_dh_pk,
    const Bytes& recipient_dh_pk,
    const Bytes& dh_secret
);

// Create ZK proof for AKE
Bytes create_zk_proof(const CallState& prover, const Bytes& challenge);

// Verify ZK proof for AKE
bool verify_zk_proof(
    const AkeMessage& prover_msg,
    const std::string& telephone_number,
    const Bytes& challenge,
    const Bytes& ra_public_key
);

// Create AKE message wrapped in ProtocolMessage
// If recipient_pke_pk is provided, payload is encrypted
Bytes create_ake_message(
    const std::string& sender_id,
    const std::string& topic,
    MessageType msg_type,
    const AkeMessage& ake_msg,
    const Bytes& recipient_pke_pk = {}
);

// Decode AKE payload from ProtocolMessage
// If pke_private_key is provided, payload is decrypted first
AkeMessage decode_ake_payload(
    const ProtocolMessage& msg,
    const Bytes& pke_private_key = {},
    const Bytes& pke_public_key = {}
);

} // namespace protocol

#endif // DIA_PROTOCOL_AKE_HPP
