#ifndef DIA_PROTOCOL_RUA_HPP
#define DIA_PROTOCOL_RUA_HPP

#include "callstate.hpp"
#include "messages.hpp"
#include "../crypto/amf.hpp"
#include "../crypto/bbs.hpp"
#include "../crypto/dh.hpp"
#include "../crypto/doubleratchet.hpp"

#include <memory>
#include <stdexcept>

namespace protocol {

// -----------------------------------------------------------------------------
// RUA Error types
// -----------------------------------------------------------------------------
class RuaError : public std::runtime_error {
public:
    explicit RuaError(const std::string& msg) : std::runtime_error(msg) {}
};

class RtuVerificationError : public RuaError {
public:
    explicit RtuVerificationError(const std::string& msg) : RuaError(msg) {}
};

class AmfVerificationError : public RuaError {
public:
    explicit AmfVerificationError(const std::string& msg) : RuaError(msg) {}
};

// -----------------------------------------------------------------------------
// RUA Protocol Functions
// -----------------------------------------------------------------------------

// Create Rtu from client config
Rtu create_rtu_from_config(const ClientConfig& cfg);

// Derive RUA topic from shared key and call state
Bytes derive_rua_topic(const CallState& call_state);

// Initialize RUA state for a call party
// Generates ephemeral DH key pair and creates RTU from config
void init_rtu(CallState& party);

// Verify RTU validity (expiration and BBS signature from RA)
void verify_rtu(
    const CallState& verifier,
    const std::string& telephone_number,
    const RuaMessage& msg
);

// Verify AMF signature on RuaMessage
void verify_amf_signature(
    const CallState& verifier,
    const RuaMessage& msg,
    const Bytes& data_to_verify
);

// Step 1: Caller creates RuaRequest
// - Uses DR session for encryption
// - Signs with AMF
// Returns serialized ProtocolMessage
Bytes rua_request(CallState& caller);

// Step 2: Recipient processes RuaRequest and creates RuaResponse
// - Decrypts using DR session
// - Verifies RTU and AMF signature
// - Signs response with AMF
// - Computes new shared key
// Returns serialized ProtocolMessage
Bytes rua_response(CallState& recipient, const ProtocolMessage& caller_msg);

// Step 3: Caller processes RuaResponse and finalizes
// - Decrypts using DR session
// - Verifies RTU and AMF signature
// - Computes new shared key (should match recipient's)
void rua_finalize(CallState& caller, const ProtocolMessage& recipient_msg);

// -----------------------------------------------------------------------------
// DR Message helpers for RUA
// -----------------------------------------------------------------------------

// Create RUA message with DR encryption
Bytes create_dr_rua_message(
    const std::string& sender_id,
    const std::string& topic,
    MessageType msg_type,
    const RuaMessage& payload,
    doubleratchet::DrSession& dr_session
);

// Decode RUA message with DR decryption
RuaMessage decode_dr_rua_payload(
    const ProtocolMessage& msg,
    doubleratchet::DrSession& dr_session
);

} // namespace protocol

#endif // DIA_PROTOCOL_RUA_HPP
