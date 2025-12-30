#include "oda.hpp"
#include "../helpers.hpp"
#include <sodium.h>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace protocol {

using crypto::BasicWallet;
using crypto::VerificationResult;

// Helper to get current timestamp as string
static std::string get_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto tm = *std::localtime(&time_t);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

// -----------------------------------------------------------------------------
// ODA Request - Verifier creates request
// -----------------------------------------------------------------------------

Bytes oda_request(CallState& verifier, const std::vector<std::string>& requested_attributes) {
    if (!verifier.rua_active) {
        throw std::runtime_error("ODA requires RUA to be active");
    }
    
    if (!verifier.dr_session) {
        throw std::runtime_error("ODA requires Double Ratchet session");
    }
    
    // Generate random nonce (32 bytes)
    Bytes nonce(32);
    randombytes_buf(nonce.data(), nonce.size());
    
    // Create ODA request message
    OdaMessage oda_msg;
    oda_msg.nonce = nonce;
    oda_msg.requested_attributes = requested_attributes;
    oda_msg.presentation = {}; // Empty for request
    
    // Store pending request for later verification
    verifier.pending_oda_request = oda_msg;
    
    // Create protocol message
    ProtocolMessage proto_msg;
    proto_msg.type = MessageType::OdaRequest;
    proto_msg.sender_id = verifier.sender_id;
    proto_msg.topic = verifier.get_current_topic();
    proto_msg.payload = oda_msg.serialize();
    
    // Encrypt with Double Ratchet
    Bytes plaintext = proto_msg.serialize();
    Bytes ciphertext = verifier.dr_session->encrypt(plaintext);
    
    return ciphertext;
}

// -----------------------------------------------------------------------------
// ODA Response - Prover creates response with presentation
// -----------------------------------------------------------------------------

Bytes oda_response(CallState& prover, const ProtocolMessage& request_msg) {
    if (!prover.rua_active) {
        throw std::runtime_error("ODA requires RUA to be active");
    }
    
    if (!prover.dr_session) {
        throw std::runtime_error("ODA requires Double Ratchet session");
    }
    
    if (request_msg.type != MessageType::OdaRequest) {
        throw std::runtime_error("Expected OdaRequest message");
    }
    
    // Deserialize ODA request
    OdaMessage request = OdaMessage::deserialize(request_msg.payload);
    
    // Use BasicWallet to create presentation
    BasicWallet wallet;
    Bytes presentation = wallet.present(request.nonce, request.requested_attributes);
    
    // Create ODA response message
    OdaMessage response;
    response.nonce = request.nonce; // Echo back the nonce
    response.requested_attributes = request.requested_attributes; // Echo back attributes
    response.presentation = presentation;
    
    // Create protocol message
    ProtocolMessage proto_msg;
    proto_msg.type = MessageType::OdaResponse;
    proto_msg.sender_id = prover.sender_id;
    proto_msg.topic = prover.get_current_topic();
    proto_msg.payload = response.serialize();
    
    // Encrypt with Double Ratchet
    Bytes plaintext = proto_msg.serialize();
    Bytes ciphertext = prover.dr_session->encrypt(plaintext);
    
    return ciphertext;
}

// -----------------------------------------------------------------------------
// ODA Verify - Verifier verifies presentation
// -----------------------------------------------------------------------------

VerificationResult oda_verify(CallState& verifier, const ProtocolMessage& response_msg) {
    VerificationResult result;
    result.verified = false;
    
    if (!verifier.rua_active) {
        throw std::runtime_error("ODA requires RUA to be active");
    }
    
    if (response_msg.type != MessageType::OdaResponse) {
        throw std::runtime_error("Expected OdaResponse message");
    }
    
    if (!verifier.pending_oda_request.has_value()) {
        throw std::runtime_error("No pending ODA request found");
    }
    
    // Deserialize ODA response
    OdaMessage response = OdaMessage::deserialize(response_msg.payload);
    
    // Get the original request
    OdaMessage& request = verifier.pending_oda_request.value();
    
    // Verify nonce matches
    if (response.nonce != request.nonce) {
        throw std::runtime_error("Nonce mismatch in ODA response");
    }
    
    // Verify attributes match
    if (response.requested_attributes != request.requested_attributes) {
        throw std::runtime_error("Requested attributes mismatch in ODA response");
    }
    
    // Use BasicWallet to verify presentation
    BasicWallet wallet;
    result = wallet.verify(response.presentation, response.nonce, response.requested_attributes);
    
    // Store verification result in CallState
    OdaVerificationInfo info;
    info.timestamp = get_timestamp();
    info.verified = result.verified;
    info.disclosed_attributes = result.disclosed_attributes;
    info.issuer = result.issuer;
    info.credential_type = result.credential_type;
    info.issuance_date = result.issuance_date;
    info.expiration_date = result.expiration_date;
    info.requested_attributes = request.requested_attributes;
    
    verifier.oda_verifications.push_back(info);
    
    // Clear pending request
    verifier.pending_oda_request.reset();
    
    return result;
}

} // namespace protocol
