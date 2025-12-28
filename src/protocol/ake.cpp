#include "ake.hpp"
#include "../helpers.hpp"
#include <sodium.h>
#include <cstring>

namespace protocol {

using namespace dia::utils;

// -----------------------------------------------------------------------------
// ZK Proof functions
// -----------------------------------------------------------------------------

Bytes create_zk_proof(const CallState& prover, const Bytes& challenge) {
    // Determine telephone number based on role
    std::string telephone_number;
    if (prover.iam_caller()) {
        telephone_number = prover.src;
    } else {
        telephone_number = prover.dst;
    }
    
    // Create message1: hash of (amf_pk, pke_pk, dr_pk, expiration, telephone_number)
    Bytes tn_bytes(telephone_number.begin(), telephone_number.end());
    Bytes message1 = hash_all({
        prover.config.amf_public_key,
        prover.config.pke_public_key,
        prover.config.dr_public_key,
        prover.config.en_expiration,
        tn_bytes
    });
    
    // message2: name
    Bytes message2(prover.config.my_name.begin(), prover.config.my_name.end());
    
    // Convert RA public key to G2Point
    ecgroup::G2Point ra_pk = ecgroup::G2Point::from_bytes(prover.config.ra_public_key);
    
    // Convert signature from bytes
    bbs::Signature sig = bbs::Signature::from_bytes(prover.config.ra_signature);
    
    // Create messages as scalars using hash_to_scalar
    ecgroup::Scalar m1 = ecgroup::Scalar::hash_to_scalar(message1);
    ecgroup::Scalar m2 = ecgroup::Scalar::hash_to_scalar(message2);
    
    std::vector<ecgroup::Scalar> msgs = {m1, m2};
    
    // Create selective disclosure proof (disclose message1, hide message2 which is the name)
    bbs::Params params = bbs::Params::Default();
    std::vector<std::size_t> disclosed_indices = {1};  // Only disclose first message
    std::string nonce_str(challenge.begin(), challenge.end());
    
    bbs::SDProof proof = bbs::create_proof(params, ra_pk, sig, msgs, disclosed_indices, nonce_str);
    
    return proof.to_bytes();
}

bool verify_zk_proof(
    const AkeMessage& prover_msg,
    const std::string& telephone_number,
    const Bytes& challenge,
    const Bytes& ra_public_key)
{
    // Reconstruct message1 from the AkeMessage fields
    Bytes tn_bytes(telephone_number.begin(), telephone_number.end());
    Bytes message1 = hash_all({
        prover_msg.amf_pk,
        prover_msg.pke_pk,
        prover_msg.dr_pk,
        prover_msg.expiration,
        tn_bytes
    });
    
    // Convert to scalar using hash_to_scalar
    ecgroup::Scalar m1 = ecgroup::Scalar::hash_to_scalar(message1);
    
    // Parse the proof
    bbs::SDProof proof = bbs::SDProof::from_bytes(prover_msg.proof);
    
    // Convert RA public key to G2Point
    ecgroup::G2Point ra_pk = ecgroup::G2Point::from_bytes(ra_public_key);
    
    // Verify with disclosed message at index 1
    bbs::Params params = bbs::Params::Default();
    std::vector<std::pair<std::size_t, ecgroup::Scalar>> disclosed = {{1, m1}};
    
    return bbs::verify_proof(params, ra_pk, proof, disclosed, 2);  // 2 total messages
}

// -----------------------------------------------------------------------------
// Shared key computation
// -----------------------------------------------------------------------------

Bytes compute_shared_key(
    const Bytes& topic,
    const Bytes& caller_proof,
    const Bytes& recipient_proof,
    const Bytes& caller_dh_pk,
    const Bytes& recipient_dh_pk,
    const Bytes& dh_secret)
{
    return hash_all({topic, caller_proof, recipient_proof, caller_dh_pk, recipient_dh_pk, dh_secret});
}

// -----------------------------------------------------------------------------
// Message creation helpers
// -----------------------------------------------------------------------------

Bytes create_ake_message(
    const std::string& sender_id,
    const std::string& topic,
    MessageType msg_type,
    const AkeMessage& ake_msg,
    const Bytes& recipient_pke_pk)
{
    // Serialize AKE message
    Bytes payload = ake_msg.serialize();
    
    // Encrypt if recipient's PKE public key is provided
    if (!recipient_pke_pk.empty()) {
        payload = pke::encrypt(recipient_pke_pk, payload);
    }
    
    // Create protocol message
    ProtocolMessage msg;
    msg.type = msg_type;
    msg.sender_id = sender_id;
    msg.topic = topic;
    msg.payload = payload;
    
    return msg.serialize();
}

AkeMessage decode_ake_payload(
    const ProtocolMessage& msg,
    const Bytes& pke_private_key,
    const Bytes& pke_public_key)
{
    Bytes payload = msg.payload;
    
    // Decrypt if PKE key is provided
    if (!pke_private_key.empty() && !pke_public_key.empty()) {
        payload = pke::decrypt(pke_private_key, pke_public_key, payload);
    }
    
    return AkeMessage::deserialize(payload);
}

// -----------------------------------------------------------------------------
// AKE Protocol implementation
// -----------------------------------------------------------------------------

void init_ake(CallState& call_state) {
    // Compute AKE topic: hash(src, ts)
    Bytes src_bytes(call_state.src.begin(), call_state.src.end());
    Bytes ts_bytes(call_state.ts.begin(), call_state.ts.end());
    Bytes ake_topic = hash_all({src_bytes, ts_bytes});
    
    // Generate ephemeral DH key pair
    dh::KeyPair dh_kp = dh::keygen();
    
    // Serialize DH keys
    Bytes dh_sk_bytes = dh_kp.sk.to_bytes();
    Bytes dh_pk_bytes = dh_kp.pk.to_bytes();
    
    call_state.init_ake(dh_sk_bytes, dh_pk_bytes, ake_topic);
}

Bytes ake_request(CallState& caller) {
    if (caller.ake.dh_pk.empty()) {
        throw AkeError("AKE not initialized: DhPk is empty");
    }
    
    // Create challenge: hash(topic)
    Bytes challenge = hash_all({caller.ake.topic});
    
    // Create ZK proof
    Bytes proof = create_zk_proof(caller, challenge);
    
    // Create AKE message (no DH public key in request - it's sent in response/complete)
    AkeMessage ake_msg;
    ake_msg.amf_pk = caller.config.amf_public_key;
    ake_msg.pke_pk = caller.config.pke_public_key;
    ake_msg.dr_pk = caller.config.dr_public_key;
    ake_msg.expiration = caller.config.en_expiration;
    ake_msg.proof = proof;
    
    // Create unencrypted message
    Bytes msg = create_ake_message(
        caller.sender_id,
        caller.get_ake_topic(),
        MessageType::AkeRequest,
        ake_msg,
        {}  // No encryption for AkeRequest
    );
    
    // Update caller state
    caller.update_caller(challenge, proof);
    
    return msg;
}

Bytes ake_response(CallState& recipient, const ProtocolMessage& caller_msg) {
    if (!caller_msg.is_ake_request()) {
        throw AkeError("AkeResponse can only be called on AkeRequest message");
    }
    
    // Decode caller's AKE message (unencrypted)
    AkeMessage caller_ake = decode_ake_payload(caller_msg, {}, {});
    
    // Verify caller's ZK proof
    Bytes challenge0 = hash_all({recipient.ake.topic});
    if (!verify_zk_proof(caller_ake, recipient.src, challenge0, recipient.config.ra_public_key)) {
        throw AuthenticationError("Failed to verify caller's ZK proof");
    }
    
    // Create our challenge: hash(caller_proof, our_dh_pk, challenge0)
    Bytes challenge1 = hash_all({caller_ake.proof, recipient.ake.dh_pk, challenge0});
    
    // Create our ZK proof
    Bytes proof = create_zk_proof(recipient, challenge1);
    
    // Create AKE message with our DH public key
    AkeMessage ake_msg;
    ake_msg.dh_pk = recipient.ake.dh_pk;
    ake_msg.amf_pk = recipient.config.amf_public_key;
    ake_msg.pke_pk = recipient.config.pke_public_key;
    ake_msg.dr_pk = recipient.config.dr_public_key;
    ake_msg.expiration = recipient.config.en_expiration;
    ake_msg.proof = proof;
    
    // Store caller's info for later use in finalize
    recipient.ake.caller_proof = caller_ake.proof;
    recipient.ake.recipient_proof = proof;
    recipient.counterpart_amf_pk = caller_ake.amf_pk;
    recipient.counterpart_pke_pk = caller_ake.pke_pk;
    recipient.counterpart_dr_pk = caller_ake.dr_pk;
    
    // Create encrypted message (encrypted with caller's PKE public key)
    Bytes msg = create_ake_message(
        recipient.sender_id,
        recipient.get_ake_topic(),
        MessageType::AkeResponse,
        ake_msg,
        caller_ake.pke_pk
    );
    
    return msg;
}

Bytes ake_complete(CallState& caller, const ProtocolMessage& recipient_msg) {
    if (!recipient_msg.is_ake_response()) {
        throw AkeError("AkeComplete can only be called on AkeResponse message");
    }
    
    // Decode recipient's AKE message (decrypt with caller's PKE key)
    AkeMessage recipient_ake = decode_ake_payload(
        recipient_msg,
        caller.config.pke_private_key,
        caller.config.pke_public_key
    );
    
    if (recipient_ake.dh_pk.empty() || recipient_ake.proof.empty()) {
        throw AkeError("Missing DhPk or Proof in AkeResponse");
    }
    
    // Verify recipient's ZK proof
    Bytes challenge = hash_all({caller.ake.caller_proof, recipient_ake.dh_pk, caller.ake.chal0});
    if (!verify_zk_proof(recipient_ake, caller.dst, challenge, caller.config.ra_public_key)) {
        throw AuthenticationError("Failed to verify recipient's ZK proof");
    }
    
    // Store recipient's info
    caller.counterpart_amf_pk = recipient_ake.amf_pk;
    caller.counterpart_pke_pk = recipient_ake.pke_pk;
    caller.counterpart_dr_pk = recipient_ake.dr_pk;
    
    // Compute DH shared secret
    ecgroup::Scalar dh_sk = ecgroup::Scalar::from_bytes(caller.ake.dh_sk);
    ecgroup::G1Point recipient_dh_pk = ecgroup::G1Point::from_bytes(recipient_ake.dh_pk);
    
    ecgroup::G1Point dh_secret_point = dh::compute_secret(dh_sk, recipient_dh_pk);
    Bytes dh_secret = dh_secret_point.to_bytes();
    
    // Compute shared key
    Bytes shared_key = compute_shared_key(
        caller.ake.topic,
        caller.ake.caller_proof,
        recipient_ake.proof,
        caller.ake.dh_pk,
        recipient_ake.dh_pk,
        dh_secret
    );
    caller.set_shared_key(shared_key);
    
    // Initialize Double Ratchet session as caller
    // Caller uses recipient's DR public key
    caller.dr_session = doubleratchet::DrSession::init_as_caller(
        shared_key,
        caller.counterpart_dr_pk
    );
    
    // Create AkeComplete message with concatenated DH public keys
    AkeMessage ake_msg;
    ake_msg.dh_pk = concat_bytes(caller.ake.dh_pk, recipient_ake.dh_pk);
    
    // Encrypt with recipient's PKE public key
    Bytes msg = create_ake_message(
        caller.sender_id,
        caller.get_ake_topic(),
        MessageType::AkeComplete,
        ake_msg,
        recipient_ake.pke_pk
    );
    
    return msg;
}

void ake_finalize(CallState& recipient, const ProtocolMessage& caller_msg) {
    if (!caller_msg.is_ake_complete()) {
        throw AkeError("AkeFinalize can only be called on AkeComplete message");
    }
    
    // Decode caller's AKE message (decrypt with recipient's PKE key)
    AkeMessage caller_ake = decode_ake_payload(
        caller_msg,
        recipient.config.pke_private_key,
        recipient.config.pke_public_key
    );
    
    // Verify DH public keys
    if (caller_ake.dh_pk.size() < 64) {
        throw AkeError("Invalid DhPk length in AkeComplete");
    }
    
    // Extract caller's and recipient's DH public keys
    Bytes caller_dh_pk(caller_ake.dh_pk.begin(), caller_ake.dh_pk.begin() + 32);
    Bytes recipient_dh_pk(caller_ake.dh_pk.begin() + 32, caller_ake.dh_pk.end());
    
    // Verify our DH public key matches
    if (recipient_dh_pk != recipient.ake.dh_pk) {
        throw AkeError("Recipient DH public key mismatch");
    }
    
    // Compute DH shared secret
    ecgroup::Scalar dh_sk = ecgroup::Scalar::from_bytes(recipient.ake.dh_sk);
    ecgroup::G1Point caller_dh_pk_point = ecgroup::G1Point::from_bytes(caller_dh_pk);
    
    ecgroup::G1Point dh_secret_point = dh::compute_secret(dh_sk, caller_dh_pk_point);
    Bytes dh_secret = dh_secret_point.to_bytes();
    
    // Compute shared key
    Bytes shared_key = compute_shared_key(
        recipient.ake.topic,
        recipient.ake.caller_proof,
        recipient.ake.recipient_proof,
        caller_dh_pk,
        recipient.ake.dh_pk,
        dh_secret
    );
    recipient.set_shared_key(shared_key);
    
    // Initialize Double Ratchet session as recipient
    // Recipient uses their own DR key pair
    recipient.dr_session = doubleratchet::DrSession::init_as_recipient(
        shared_key,
        recipient.config.dr_private_key,
        recipient.config.dr_public_key
    );
}

} // namespace protocol
