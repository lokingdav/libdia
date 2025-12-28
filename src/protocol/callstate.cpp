#include "callstate.hpp"
#include "../helpers.hpp"

#include <chrono>
#include <iomanip>
#include <sstream>
#include <random>

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

} // namespace protocol
