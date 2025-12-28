#ifndef DIA_PROTOCOL_CALLSTATE_HPP
#define DIA_PROTOCOL_CALLSTATE_HPP

#include "messages.hpp"

#include <string>
#include <mutex>
#include <optional>

namespace protocol {

// -----------------------------------------------------------------------------
// ClientConfig - Configuration containing client keys and credentials
// -----------------------------------------------------------------------------
struct ClientConfig {
    // Personal details
    std::string my_phone;
    std::string my_name;
    std::string my_logo;

    // Credential verification
    Bytes en_expiration;
    Bytes ra_public_key;
    Bytes ra_signature;

    // AMF keys for RUA
    Bytes amf_private_key;
    Bytes amf_public_key;

    // PKE keys for encryption
    Bytes pke_private_key;
    Bytes pke_public_key;

    // DR keys for Double Ratchet messaging
    Bytes dr_private_key;
    Bytes dr_public_key;

    // Access Ticket
    Bytes access_ticket_vk;
    Bytes sample_ticket;

    // Moderation public key
    Bytes moderator_public_key;
};

// -----------------------------------------------------------------------------
// AkeState - State for Authenticated Key Exchange phase
// -----------------------------------------------------------------------------
struct AkeState {
    Bytes topic;
    Bytes dh_sk;
    Bytes dh_pk;
    Bytes chal0;
    Bytes caller_proof;
    Bytes recipient_proof;
};

// -----------------------------------------------------------------------------
// RuaState - State for Rich User Authentication phase
// -----------------------------------------------------------------------------
struct RuaState {
    Bytes                     topic;
    Bytes                     dh_sk;
    Bytes                     dh_pk;
    std::optional<Rtu>        rtu;
    std::optional<RuaMessage> req;
};

// -----------------------------------------------------------------------------
// CallState - Main state container for a call session
// -----------------------------------------------------------------------------
class CallState {
public:
    // Constructor for creating a new call state
    CallState(const ClientConfig& config, const std::string& phone_number, bool outgoing);

    // Getters
    Bytes get_ake_label() const;
    std::string get_ake_topic() const;
    std::string get_current_topic();
    bool iam_caller() const;
    bool iam_recipient() const;
    bool is_rua_active();

    // State transitions
    void init_ake(const Bytes& dh_sk, const Bytes& dh_pk, const Bytes& ake_topic);
    void transition_to_rua(const Bytes& rua_topic);

    // Setters
    void set_shared_key(const Bytes& key);
    void update_caller(const Bytes& chal, const Bytes& proof);

    // Public fields (matching Go struct - could be made private with getters if preferred)
    bool        is_outgoing;
    std::string src;
    std::string dst;
    std::string ts;
    std::string sender_id;
    std::string call_reason;
    Bytes       current_topic;
    bool        rua_active;
    Bytes       ticket;
    Bytes       shared_key;
    Bytes       counterpart_amf_pk;
    Bytes       counterpart_pke_pk;
    Bytes       counterpart_dr_pk;
    AkeState    ake;
    RuaState    rua;
    ClientConfig config;

private:
    mutable std::mutex mu_;
};

// -----------------------------------------------------------------------------
// Utility functions
// -----------------------------------------------------------------------------

// Get normalized timestamp (YYYY-MM-DD format)
std::string get_normalized_ts();

// Generate a random sender ID (16 random bytes as hex string)
std::string generate_sender_id();

} // namespace protocol

#endif // DIA_PROTOCOL_CALLSTATE_HPP
