#include "messages.hpp"

namespace protocol {

using dia::utils::append_u32_be;
using dia::utils::read_u32_be;
using dia::utils::append_lp;
using dia::utils::read_lp;
using dia::utils::to_bytes;
using dia::utils::read_string;

// -----------------------------------------------------------------------------
// Rtu serialization
// -----------------------------------------------------------------------------

Bytes Rtu::serialize() const {
    Bytes out;
    append_lp(out, amf_pk);
    append_lp(out, expiration);
    append_lp(out, signature);
    append_lp(out, to_bytes(name));
    append_lp(out, to_bytes(logo));
    append_lp(out, pke_pk);
    append_lp(out, dr_pk);
    return out;
}

Rtu Rtu::deserialize(const Bytes& data) {
    Rtu rtu;
    size_t off = 0;
    rtu.amf_pk     = read_lp(data, off);
    rtu.expiration = read_lp(data, off);
    rtu.signature  = read_lp(data, off);
    rtu.name       = read_string(data, off);
    rtu.logo       = read_string(data, off);
    rtu.pke_pk     = read_lp(data, off);
    rtu.dr_pk      = read_lp(data, off);
    return rtu;
}

// -----------------------------------------------------------------------------
// AkeMessage serialization
// -----------------------------------------------------------------------------

Bytes AkeMessage::serialize() const {
    Bytes out;
    append_lp(out, dh_pk);
    append_lp(out, amf_pk);
    append_lp(out, expiration);
    append_lp(out, proof);
    append_lp(out, pke_pk);
    append_lp(out, dr_pk);
    return out;
}

AkeMessage AkeMessage::deserialize(const Bytes& data) {
    AkeMessage msg;
    size_t off = 0;
    msg.dh_pk      = read_lp(data, off);
    msg.amf_pk     = read_lp(data, off);
    msg.expiration = read_lp(data, off);
    msg.proof      = read_lp(data, off);
    msg.pke_pk     = read_lp(data, off);
    msg.dr_pk      = read_lp(data, off);
    return msg;
}

// -----------------------------------------------------------------------------
// RuaMessage serialization
// -----------------------------------------------------------------------------

Bytes RuaMessage::serialize() const {
    Bytes out;
    append_lp(out, dh_pk);
    append_lp(out, to_bytes(reason));
    append_lp(out, rtu.serialize());
    append_lp(out, to_bytes(tpc));
    append_lp(out, misc);
    append_lp(out, sigma);
    return out;
}

RuaMessage RuaMessage::deserialize(const Bytes& data) {
    RuaMessage msg;
    size_t off = 0;
    msg.dh_pk  = read_lp(data, off);
    msg.reason = read_string(data, off);
    Bytes rtu_bytes = read_lp(data, off);
    msg.rtu    = Rtu::deserialize(rtu_bytes);
    msg.tpc    = read_string(data, off);
    msg.misc   = read_lp(data, off);
    msg.sigma  = read_lp(data, off);
    return msg;
}

Bytes RuaMessage::serialize_for_signing() const {
    // Serialize without sigma for AMF signing
    Bytes out;
    append_lp(out, dh_pk);
    append_lp(out, to_bytes(reason));
    append_lp(out, rtu.serialize());
    append_lp(out, to_bytes(tpc));
    // misc and sigma excluded for signing
    return out;
}

// -----------------------------------------------------------------------------
// ProtocolMessage serialization
// -----------------------------------------------------------------------------

Bytes ProtocolMessage::serialize() const {
    if (type == MessageType::Unspecified) {
        throw std::runtime_error("ProtocolMessage type is unspecified");
    }
    
    Bytes out;
    out.push_back(static_cast<uint8_t>(type));
    append_lp(out, to_bytes(sender_id));
    append_lp(out, to_bytes(topic));
    append_lp(out, payload);
    return out;
}

ProtocolMessage ProtocolMessage::deserialize(const Bytes& data) {
    if (data.empty()) {
        throw std::runtime_error("Empty data for ProtocolMessage");
    }
    
    ProtocolMessage msg;
    size_t off = 0;
    msg.type = static_cast<MessageType>(data[off++]);
    msg.sender_id = read_string(data, off);
    msg.topic     = read_string(data, off);
    msg.payload   = read_lp(data, off);
    return msg;
}

// -----------------------------------------------------------------------------
// Message creation helpers
// -----------------------------------------------------------------------------

ProtocolMessage create_bye_message(const std::string& sender_id, const std::string& topic) {
    ProtocolMessage msg;
    msg.type = MessageType::Bye;
    msg.sender_id = sender_id;
    msg.topic = topic;
    return msg;
}

ProtocolMessage create_heartbeat_message(const std::string& sender_id, const std::string& topic) {
    ProtocolMessage msg;
    msg.type = MessageType::Heartbeat;
    msg.sender_id = sender_id;
    msg.topic = topic;
    return msg;
}

} // namespace protocol
