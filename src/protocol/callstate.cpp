#include "callstate.hpp"
#include "../helpers.hpp"

#include <chrono>
#include <iomanip>
#include <sstream>
#include <random>
#include <stdexcept>
#include <array>

namespace protocol {

using dia::utils::bytes_to_hex;

// -----------------------------------------------------------------------------
// Utility function implementations
// -----------------------------------------------------------------------------

std::string get_normalized_ts() {
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    std::tm tm_utc{};
    
#ifdef _WIN32
    gmtime_s(&tm_utc, &time_t_now);
#else
    gmtime_r(&time_t_now, &tm_utc);
#endif
    
    std::ostringstream oss;
    oss << std::setfill('0') 
        << std::setw(4) << (tm_utc.tm_year + 1900) << "-"
        << std::setw(2) << (tm_utc.tm_mon + 1) << "-"
        << std::setw(2) << tm_utc.tm_mday;
    return oss.str();
}

std::string generate_sender_id() {
    // Generate 16 random bytes and encode as hex (32 chars, UUID-like)
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    Bytes random_bytes(16);
    for (auto& b : random_bytes) {
        b = static_cast<uint8_t>(dis(gen));
    }
    
    return bytes_to_hex(random_bytes);
}

// -----------------------------------------------------------------------------
// CallState implementation
// -----------------------------------------------------------------------------

CallState::CallState(const ClientConfig& cfg, const std::string& phone_number, bool outgoing)
    : is_outgoing(outgoing)
    , rua_active(false)
    , config(cfg)
{
    if (outgoing) {
        src = config.my_phone;
        dst = phone_number;
    } else {
        src = phone_number;
        dst = config.my_phone;
    }
    
    ts = get_normalized_ts();
    sender_id = generate_sender_id();
    ticket = config.sample_ticket;
}

Bytes CallState::get_ake_label() const {
    std::string label = src + ts;
    return Bytes(label.begin(), label.end());
}

std::string CallState::get_ake_topic() const {
    return bytes_to_hex(ake.topic);
}

std::string CallState::get_current_topic() {
    std::lock_guard<std::mutex> lock(mu_);
    return bytes_to_hex(current_topic);
}

bool CallState::iam_caller() const {
    return is_outgoing;
}

bool CallState::iam_recipient() const {
    return !is_outgoing;
}

bool CallState::is_rua_active() {
    std::lock_guard<std::mutex> lock(mu_);
    return rua_active;
}

void CallState::init_ake(const Bytes& dh_sk, const Bytes& dh_pk, const Bytes& ake_topic) {
    std::lock_guard<std::mutex> lock(mu_);
    ake.dh_sk = dh_sk;
    ake.dh_pk = dh_pk;
    ake.topic = ake_topic;
    current_topic = ake_topic;  // start on AKE topic
    rua_active = false;
}

void CallState::transition_to_rua(const Bytes& rua_topic) {
    std::lock_guard<std::mutex> lock(mu_);
    rua.topic = rua_topic;
    current_topic = rua_topic;
    rua_active = true;
}

void CallState::set_shared_key(const Bytes& key) {
    std::lock_guard<std::mutex> lock(mu_);
    shared_key = key;
}

void CallState::update_caller(const Bytes& chal, const Bytes& proof) {
    std::lock_guard<std::mutex> lock(mu_);
    ake.chal0 = chal;
    ake.caller_proof = proof;
}

PeerSessionState CallState::export_peer_session() const {
    std::lock_guard<std::mutex> lock(mu_);
    PeerSessionState out;
    out.shared_key = shared_key;
    out.counterpart_amf_pk = counterpart_amf_pk;
    out.counterpart_pke_pk = counterpart_pke_pk;
    out.counterpart_dr_pk = counterpart_dr_pk;
    return out;
}

void CallState::apply_peer_session(const PeerSessionState& peer) {
    std::lock_guard<std::mutex> lock(mu_);
    shared_key = peer.shared_key;
    counterpart_amf_pk = peer.counterpart_amf_pk;
    counterpart_pke_pk = peer.counterpart_pke_pk;
    counterpart_dr_pk = peer.counterpart_dr_pk;

    // Any existing DR session (if present) is tied to the old shared key.
    dr_session.reset();
}

Bytes PeerSessionState::serialize() const {
    using dia::utils::append_lp;
    using dia::utils::append_u32_be;

    Bytes out;

    // Header: magic + version
    static constexpr std::array<uint8_t, 4> kMagic{{'D','I','A','P'}};
    out.insert(out.end(), kMagic.begin(), kMagic.end());
    append_u32_be(out, 1);

    append_lp(out, shared_key);
    append_lp(out, counterpart_amf_pk);
    append_lp(out, counterpart_pke_pk);
    append_lp(out, counterpart_dr_pk);

    return out;
}

PeerSessionState PeerSessionState::deserialize(const Bytes& data) {
    using dia::utils::read_lp;
    using dia::utils::read_u32_be;

    if (data.size() < 8) {
        throw std::runtime_error("PeerSessionState: data too short");
    }

    size_t off = 0;
    if (!(data[0] == 'D' && data[1] == 'I' && data[2] == 'A' && data[3] == 'P')) {
        throw std::runtime_error("PeerSessionState: bad magic");
    }
    off += 4;

    uint32_t version = read_u32_be(data, off);
    if (version != 1) {
        throw std::runtime_error("PeerSessionState: unsupported version");
    }

    PeerSessionState out;
    out.shared_key = read_lp(data, off);
    out.counterpart_amf_pk = read_lp(data, off);
    out.counterpart_pke_pk = read_lp(data, off);
    out.counterpart_dr_pk = read_lp(data, off);

    return out;
}

// -----------------------------------------------------------------------------
// ClientConfig environment string serialization
// -----------------------------------------------------------------------------

std::string ClientConfig::to_env_string() const {
    using dia::utils::bytes_to_hex;
    
    std::ostringstream oss;
    
    // Personal details
    oss << "MY_PHONE=" << my_phone << "\n";
    oss << "MY_NAME=" << my_name << "\n";
    oss << "MY_LOGO=" << my_logo << "\n";
    
    // Credential verification
    oss << "ENROLLMENT_EXPIRATION=" << bytes_to_hex(en_expiration) << "\n";
    oss << "RA_PUBLIC_KEY=" << bytes_to_hex(ra_public_key) << "\n";
    oss << "RA_SIGNATURE=" << bytes_to_hex(ra_signature) << "\n";
    
    // AMF keys
    oss << "AMF_PRIVATE_KEY=" << bytes_to_hex(amf_private_key) << "\n";
    oss << "AMF_PUBLIC_KEY=" << bytes_to_hex(amf_public_key) << "\n";
    
    // PKE keys
    oss << "PKE_PRIVATE_KEY=" << bytes_to_hex(pke_private_key) << "\n";
    oss << "PKE_PUBLIC_KEY=" << bytes_to_hex(pke_public_key) << "\n";
    
    // DR keys
    oss << "DR_PRIVATE_KEY=" << bytes_to_hex(dr_private_key) << "\n";
    oss << "DR_PUBLIC_KEY=" << bytes_to_hex(dr_public_key) << "\n";
    
    // Access ticket
    oss << "ACCESS_TICKET_VK=" << bytes_to_hex(access_ticket_vk) << "\n";
    oss << "SAMPLE_TICKET=" << bytes_to_hex(sample_ticket) << "\n";
    
    // Moderator
    oss << "MODERATOR_PUBLIC_KEY=" << bytes_to_hex(moderator_public_key) << "\n";
    
    return oss.str();
}

ClientConfig ClientConfig::from_env_string(const std::string& env_content) {
    using dia::utils::hex_to_bytes;
    
    ClientConfig config;
    std::istringstream iss(env_content);
    std::string line;
    
    while (std::getline(iss, line)) {
        // Skip empty lines and comments
        if (line.empty() || line[0] == '#') {
            continue;
        }
        
        // Find the '=' separator
        auto eq_pos = line.find('=');
        if (eq_pos == std::string::npos) {
            continue;
        }
        
        std::string key = line.substr(0, eq_pos);
        std::string value = line.substr(eq_pos + 1);
        
        // Remove trailing whitespace/newline
        while (!value.empty() && (value.back() == '\r' || value.back() == '\n' || value.back() == ' ')) {
            value.pop_back();
        }
        
        // Parse based on key
        if (key == "MY_PHONE") {
            config.my_phone = value;
        } else if (key == "MY_NAME") {
            config.my_name = value;
        } else if (key == "MY_LOGO") {
            config.my_logo = value;
        } else if (key == "ENROLLMENT_EXPIRATION") {
            config.en_expiration = hex_to_bytes(value);
        } else if (key == "RA_PUBLIC_KEY") {
            config.ra_public_key = hex_to_bytes(value);
        } else if (key == "RA_SIGNATURE") {
            config.ra_signature = hex_to_bytes(value);
        } else if (key == "AMF_PRIVATE_KEY") {
            config.amf_private_key = hex_to_bytes(value);
        } else if (key == "AMF_PUBLIC_KEY") {
            config.amf_public_key = hex_to_bytes(value);
        } else if (key == "PKE_PRIVATE_KEY") {
            config.pke_private_key = hex_to_bytes(value);
        } else if (key == "PKE_PUBLIC_KEY") {
            config.pke_public_key = hex_to_bytes(value);
        } else if (key == "DR_PRIVATE_KEY") {
            config.dr_private_key = hex_to_bytes(value);
        } else if (key == "DR_PUBLIC_KEY") {
            config.dr_public_key = hex_to_bytes(value);
        } else if (key == "ACCESS_TICKET_VK") {
            config.access_ticket_vk = hex_to_bytes(value);
        } else if (key == "SAMPLE_TICKET") {
            config.sample_ticket = hex_to_bytes(value);
        } else if (key == "MODERATOR_PUBLIC_KEY") {
            config.moderator_public_key = hex_to_bytes(value);
        }
        // Unknown keys are silently ignored
    }
    
    return config;
}

} // namespace protocol
