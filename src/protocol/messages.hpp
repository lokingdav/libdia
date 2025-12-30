#ifndef DIA_PROTOCOL_MESSAGES_HPP
#define DIA_PROTOCOL_MESSAGES_HPP

#include "../crypto/ecgroup.hpp"
#include "../helpers.hpp"

#include <string>
#include <cstdint>
#include <stdexcept>

namespace protocol {

using Bytes = ecgroup::Bytes;

// -----------------------------------------------------------------------------
// MessageType - Protocol message types
// -----------------------------------------------------------------------------
enum class MessageType : uint8_t {
    Unspecified = 0,
    AkeRequest  = 1,
    AkeResponse = 2,
    AkeComplete = 3,
    RuaRequest  = 4,
    RuaResponse = 5,
    Heartbeat   = 6,
    Bye         = 7,
    OdaRequest  = 8,
    OdaResponse = 9
};

// -----------------------------------------------------------------------------
// Rtu - Right To Use credential
// -----------------------------------------------------------------------------
struct Rtu {
    Bytes       amf_pk;      // AMF public key
    Bytes       expiration;  // RTU expiration
    Bytes       signature;   // Enrollment signature from RA
    std::string name;        // Display name
    std::string logo;        // Display logo (URL or base64 encoded)
    Bytes       pke_pk;      // PKE public key for encryption
    Bytes       dr_pk;       // Double Ratchet public key

    // Serialize to bytes
    Bytes serialize() const;
    
    // Deserialize from bytes
    static Rtu deserialize(const Bytes& data);
};

// -----------------------------------------------------------------------------
// AkeMessage - Authenticated Key Exchange message
// -----------------------------------------------------------------------------
struct AkeMessage {
    Bytes dh_pk;       // DH public key
    Bytes amf_pk;      // AMF public key
    Bytes expiration;  // Credential expiration
    Bytes proof;       // ZK proof of enrollment
    Bytes pke_pk;      // PKE public key for encryption
    Bytes dr_pk;       // Double Ratchet public key

    Bytes serialize() const;
    static AkeMessage deserialize(const Bytes& data);
};

// -----------------------------------------------------------------------------
// RuaMessage - Right-To-Use Authentication message
// -----------------------------------------------------------------------------
struct RuaMessage {
    Bytes       dh_pk;   // DH public key for RUA phase
    std::string reason;  // Call reason
    Rtu         rtu;     // RTU info
    std::string tpc;     // Topic
    Bytes       misc;    // Misc data
    Bytes       sigma;   // AMF signature

    Bytes serialize() const;
    static RuaMessage deserialize(const Bytes& data);
    
    // Serialize without sigma for signing (DDA = Data to be signed)
    Bytes serialize_for_signing() const;
};

// -----------------------------------------------------------------------------
// OdaMessage - On-Demand Authentication message
// -----------------------------------------------------------------------------
struct OdaMessage {
    Bytes                    nonce;                 // Challenge nonce for freshness
    std::vector<std::string> requested_attributes;  // Attributes to selectively disclose
    Bytes                    presentation;          // Wallet presentation (signed by prover)

    Bytes serialize() const;
    static OdaMessage deserialize(const Bytes& data);
};

// -----------------------------------------------------------------------------
// ProtocolMessage - Envelope for all protocol messages
// -----------------------------------------------------------------------------
struct ProtocolMessage {
    MessageType type = MessageType::Unspecified;
    std::string sender_id;
    std::string topic;
    Bytes       payload;  // Serialized AkeMessage or RuaMessage

    Bytes serialize() const;
    static ProtocolMessage deserialize(const Bytes& data);

    // Type check helpers
    bool is_ake_request() const  { return type == MessageType::AkeRequest; }
    bool is_ake_response() const { return type == MessageType::AkeResponse; }
    bool is_ake_complete() const { return type == MessageType::AkeComplete; }
    bool is_rua_request() const  { return type == MessageType::RuaRequest; }
    bool is_rua_response() const { return type == MessageType::RuaResponse; }
    bool is_heartbeat() const    { return type == MessageType::Heartbeat; }
    bool is_bye() const          { return type == MessageType::Bye; }
    bool is_oda_request() const  { return type == MessageType::OdaRequest; }
    bool is_oda_response() const { return type == MessageType::OdaResponse; }
};

// -----------------------------------------------------------------------------
// Message creation helpers
// -----------------------------------------------------------------------------

// Create a bye message
ProtocolMessage create_bye_message(const std::string& sender_id, const std::string& topic);

// Create a heartbeat message
ProtocolMessage create_heartbeat_message(const std::string& sender_id, const std::string& topic);

} // namespace protocol

#endif // DIA_PROTOCOL_MESSAGES_HPP
