#include "rua.hpp"
#include "enrollment.hpp"
#include "../helpers.hpp"
#include <sodium.h>

namespace protocol {

using namespace dia::utils;

// -----------------------------------------------------------------------------
// RTU creation from config
// -----------------------------------------------------------------------------

Rtu create_rtu_from_config(const ClientConfig& cfg) {
    Rtu rtu;
    rtu.amf_pk = cfg.amf_public_key;
    rtu.pke_pk = cfg.pke_public_key;
    rtu.dr_pk = cfg.dr_public_key;
    rtu.expiration = cfg.en_expiration;
    rtu.signature = cfg.ra_signature;
    rtu.name = cfg.my_name;
    return rtu;
}

// -----------------------------------------------------------------------------
// RUA Topic derivation
// -----------------------------------------------------------------------------

Bytes derive_rua_topic(const CallState& call_state) {
    Bytes src_bytes(call_state.src.begin(), call_state.src.end());
    Bytes dst_bytes(call_state.dst.begin(), call_state.dst.end());
    Bytes ts_bytes(call_state.ts.begin(), call_state.ts.end());
    
    return hash_all({
        call_state.shared_key,
        src_bytes,
        dst_bytes,
        ts_bytes
    });
}

// -----------------------------------------------------------------------------
// Initialize RUA state
// -----------------------------------------------------------------------------

void init_rtu(CallState& party) {
    // Derive RUA topic from shared key
    Bytes rua_topic = derive_rua_topic(party);
    
    // Create RTU from config
    Rtu rtu = create_rtu_from_config(party.config);
    
    // Generate ephemeral DH key pair for RUA
    dh::KeyPair dh_kp = dh::keygen();
    
    // Initialize RUA state
    party.rua.topic = rua_topic;
    party.rua.dh_sk = dh_kp.sk.to_bytes();
    party.rua.dh_pk = dh_kp.pk.to_bytes();
    party.rua.rtu = rtu;
}

// -----------------------------------------------------------------------------
// RTU Verification
// -----------------------------------------------------------------------------

void verify_rtu(
    const CallState& verifier,
    const std::string& telephone_number,
    const RuaMessage& msg)
{
    // Check expiration
    if (!check_expiry(msg.rtu.expiration)) {
        throw RtuVerificationError("RTU has expired");
    }
    
    // Validate RA's BBS signature on RTU
    // message1 = hash(amf_pk, pke_pk, dr_pk, expiration, telephone_number)
    Bytes tn_bytes(telephone_number.begin(), telephone_number.end());
    Bytes message1 = hash_all({
        msg.rtu.amf_pk,
        msg.rtu.pke_pk,
        msg.rtu.dr_pk,
        msg.rtu.expiration,
        tn_bytes
    });
    
    // message2 = name
    Bytes message2(msg.rtu.name.begin(), msg.rtu.name.end());
    
    // Convert to scalars
    ecgroup::Scalar m1 = ecgroup::Scalar::hash_to_scalar(message1);
    ecgroup::Scalar m2 = ecgroup::Scalar::hash_to_scalar(message2);
    std::vector<ecgroup::Scalar> msgs = {m1, m2};
    
    // Parse RA public key and signature
    ecgroup::G2Point ra_pk = ecgroup::G2Point::from_bytes(verifier.config.ra_public_key);
    bbs::Signature sig = bbs::Signature::from_bytes(msg.rtu.signature);
    
    // Verify BBS signature
    bbs::Params params = bbs::Params::Default();
    if (!bbs::verify(params, ra_pk, msgs, sig)) {
        throw RtuVerificationError("Invalid RTU signature from RA");
    }
}

// -----------------------------------------------------------------------------
// AMF Signature verification
// -----------------------------------------------------------------------------

void verify_amf_signature(
    const CallState& verifier,
    const RuaMessage& msg,
    const Bytes& data_to_verify)
{
    // Parse keys
    amf::Params params = amf::Params::Default();
    ecgroup::G1Point sender_pk = ecgroup::G1Point::from_bytes(msg.rtu.amf_pk);
    ecgroup::Scalar receiver_sk = ecgroup::Scalar::from_bytes(verifier.config.amf_private_key);
    ecgroup::G1Point moderator_pk = ecgroup::G1Point::from_bytes(verifier.config.moderator_public_key);
    
    // Parse signature
    amf::Signature amf_sig = amf::Signature::from_bytes(msg.sigma);
    
    // Convert data to string for AMF verify
    std::string msg_str(data_to_verify.begin(), data_to_verify.end());
    
    // Verify AMF signature
    if (!amf::Verify(sender_pk, receiver_sk, moderator_pk, msg_str, amf_sig, params)) {
        throw AmfVerificationError("Invalid AMF signature");
    }
}

// -----------------------------------------------------------------------------
// DR Message helpers for RUA
// -----------------------------------------------------------------------------

Bytes create_dr_rua_message(
    const std::string& sender_id,
    const std::string& topic,
    MessageType msg_type,
    const RuaMessage& payload,
    doubleratchet::DrSession& dr_session)
{
    // Serialize RUA payload
    Bytes payload_bytes = payload.serialize();
    
    // Encrypt using Double Ratchet
    Bytes encrypted = dr_session.encrypt(payload_bytes);
    
    // Create protocol message
    ProtocolMessage msg;
    msg.type = msg_type;
    msg.sender_id = sender_id;
    msg.topic = topic;
    msg.payload = encrypted;
    
    return msg.serialize();
}

RuaMessage decode_dr_rua_payload(
    const ProtocolMessage& msg,
    doubleratchet::DrSession& dr_session)
{
    // Decrypt using Double Ratchet
    Bytes decrypted = dr_session.decrypt(msg.payload);
    
    // Deserialize RuaMessage
    return RuaMessage::deserialize(decrypted);
}

// -----------------------------------------------------------------------------
// RUA Protocol Implementation
// -----------------------------------------------------------------------------

Bytes rua_request(CallState& caller) {
    if (!caller.dr_session) {
        throw RuaError("DR session not initialized - AKE must complete first");
    }
    
    // Initialize RUA if not already done
    if (caller.rua.topic.empty()) {
        init_rtu(caller);
    }
    
    std::string topic = bytes_to_hex(caller.rua.topic);
    
    // Create RUA message
    RuaMessage rua_msg;
    rua_msg.dh_pk = caller.rua.dh_pk;
    rua_msg.tpc = topic;
    rua_msg.reason = caller.call_reason;
    rua_msg.rtu = *caller.rua.rtu;
    
    // Serialize for signing (DDA = Data to be signed)
    Bytes dda = rua_msg.serialize_for_signing();
    
    // Sign with AMF
    amf::Params params = amf::Params::Default();
    ecgroup::Scalar sender_sk = ecgroup::Scalar::from_bytes(caller.config.amf_private_key);
    ecgroup::G1Point receiver_pk = ecgroup::G1Point::from_bytes(caller.counterpart_amf_pk);
    ecgroup::G1Point moderator_pk = ecgroup::G1Point::from_bytes(caller.config.moderator_public_key);
    
    std::string msg_str(dda.begin(), dda.end());
    amf::Signature sigma = amf::Frank(sender_sk, receiver_pk, moderator_pk, msg_str, params);
    rua_msg.sigma = sigma.to_bytes();
    
    // Store request for later verification
    caller.rua.req = rua_msg;
    
    // Create encrypted message using DR session
    return create_dr_rua_message(
        caller.sender_id,
        topic,
        MessageType::RuaRequest,
        rua_msg,
        *caller.dr_session
    );
}

Bytes rua_response(CallState& recipient, const ProtocolMessage& caller_msg) {
    if (!recipient.dr_session) {
        throw RuaError("DR session not initialized - AKE must complete first");
    }
    
    if (!caller_msg.is_rua_request()) {
        throw RuaError("RuaResponse can only be called on RuaRequest message");
    }
    
    // Decode the message using DR decryption
    RuaMessage caller_rua = decode_dr_rua_payload(caller_msg, *recipient.dr_session);
    
    // Verify RTU (caller's phone number is recipient.src since caller is the source)
    verify_rtu(recipient, recipient.src, caller_rua);
    
    // Verify AMF signature
    Bytes caller_dda = caller_rua.serialize_for_signing();
    verify_amf_signature(recipient, caller_rua, caller_dda);
    
    // Initialize RUA if not already done
    if (recipient.rua.topic.empty()) {
        init_rtu(recipient);
    }
    
    // Create reply
    RuaMessage reply;
    reply.dh_pk = recipient.rua.dh_pk;
    reply.rtu = *recipient.rua.rtu;
    reply.misc = caller_dda;  // Include caller's DDA for signature
    
    // Serialize reply (with misc) for signing
    Bytes reply_data = reply.serialize();
    
    // Sign with AMF
    amf::Params params = amf::Params::Default();
    ecgroup::Scalar sender_sk = ecgroup::Scalar::from_bytes(recipient.config.amf_private_key);
    ecgroup::G1Point receiver_pk = ecgroup::G1Point::from_bytes(caller_rua.rtu.amf_pk);
    ecgroup::G1Point moderator_pk = ecgroup::G1Point::from_bytes(recipient.config.moderator_public_key);
    
    std::string msg_str(reply_data.begin(), reply_data.end());
    amf::Signature sigma = amf::Frank(sender_sk, receiver_pk, moderator_pk, msg_str, params);
    
    // Compute new shared key
    ecgroup::Scalar dh_sk = ecgroup::Scalar::from_bytes(recipient.rua.dh_sk);
    ecgroup::G1Point caller_dh_pk = ecgroup::G1Point::from_bytes(caller_rua.dh_pk);
    ecgroup::G1Point secret_point = dh::compute_secret(dh_sk, caller_dh_pk);
    Bytes secret = secret_point.to_bytes();
    
    // Serialize caller's RTU for shared key computation
    Bytes rtu_bytes = caller_rua.rtu.serialize();
    
    Bytes shared_key = hash_all({
        caller_dda,
        reply.dh_pk,
        rtu_bytes,
        caller_rua.sigma,
        sigma.to_bytes(),
        secret
    });
    recipient.set_shared_key(shared_key);
    
    // Store counterpart info
    recipient.counterpart_amf_pk = caller_rua.rtu.amf_pk;
    recipient.counterpart_pke_pk = caller_rua.rtu.pke_pk;
    recipient.counterpart_dr_pk = caller_rua.rtu.dr_pk;
    
    // Finalize reply (remove misc, add sigma)
    reply.sigma = sigma.to_bytes();
    reply.misc.clear();
    
    std::string topic = bytes_to_hex(recipient.rua.topic);
    
    // Transition to RUA phase
    recipient.transition_to_rua(recipient.rua.topic);
    
    // Create encrypted message using DR session
    return create_dr_rua_message(
        recipient.sender_id,
        topic,
        MessageType::RuaResponse,
        reply,
        *recipient.dr_session
    );
}

void rua_finalize(CallState& caller, const ProtocolMessage& recipient_msg) {
    if (!caller.dr_session) {
        throw RuaError("DR session not initialized - AKE must complete first");
    }
    
    if (!recipient_msg.is_rua_response()) {
        throw RuaError("RuaFinalize can only be called on RuaResponse message");
    }
    
    if (!caller.rua.req.has_value()) {
        throw RuaError("RuaRequest was not stored - call rua_request first");
    }
    
    // Decode the RUA message using DR decryption
    RuaMessage recipient_rua = decode_dr_rua_payload(recipient_msg, *caller.dr_session);
    
    // Verify RTU (recipient's phone number is caller.dst)
    verify_rtu(caller, caller.dst, recipient_rua);
    
    // Verify AMF signature on RuaResponse
    // RuaResponse was signed with {DhPk, Rtu, Misc=caller_dda}
    Bytes caller_dda = caller.rua.req->serialize_for_signing();
    
    // Reconstruct what was signed
    RuaMessage signed_msg;
    signed_msg.dh_pk = recipient_rua.dh_pk;
    signed_msg.rtu = recipient_rua.rtu;
    signed_msg.misc = caller_dda;
    
    Bytes signed_data = signed_msg.serialize();
    
    // Parse keys for verification
    amf::Params params = amf::Params::Default();
    ecgroup::G1Point sender_pk = ecgroup::G1Point::from_bytes(recipient_rua.rtu.amf_pk);
    ecgroup::Scalar receiver_sk = ecgroup::Scalar::from_bytes(caller.config.amf_private_key);
    ecgroup::G1Point moderator_pk = ecgroup::G1Point::from_bytes(caller.config.moderator_public_key);
    
    // Parse signature
    amf::Signature amf_sig = amf::Signature::from_bytes(recipient_rua.sigma);
    
    // Verify AMF signature
    std::string msg_str(signed_data.begin(), signed_data.end());
    if (!amf::Verify(sender_pk, receiver_sk, moderator_pk, msg_str, amf_sig, params)) {
        throw AmfVerificationError("Invalid AMF signature on RuaResponse");
    }
    
    // Compute shared key
    ecgroup::Scalar dh_sk = ecgroup::Scalar::from_bytes(caller.rua.dh_sk);
    ecgroup::G1Point recipient_dh_pk = ecgroup::G1Point::from_bytes(recipient_rua.dh_pk);
    ecgroup::G1Point secret_point = dh::compute_secret(dh_sk, recipient_dh_pk);
    Bytes secret = secret_point.to_bytes();
    
    // Use caller's RTU to match RuaResponse's shared key derivation
    Bytes rtu_bytes = caller.rua.req->rtu.serialize();
    
    Bytes shared_key = hash_all({
        caller_dda,
        recipient_rua.dh_pk,
        rtu_bytes,
        caller.rua.req->sigma,
        recipient_rua.sigma,
        secret
    });
    caller.set_shared_key(shared_key);
    
    // Store counterpart info
    caller.counterpart_amf_pk = recipient_rua.rtu.amf_pk;
    caller.counterpart_pke_pk = recipient_rua.rtu.pke_pk;
    caller.counterpart_dr_pk = recipient_rua.rtu.dr_pk;
    
    // Transition to RUA phase
    caller.transition_to_rua(caller.rua.topic);
}

} // namespace protocol
