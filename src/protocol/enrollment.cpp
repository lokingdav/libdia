#include "enrollment.hpp"
#include "../helpers.hpp"
#include "../crypto/voprf.hpp"
#include "../crypto/bbs.hpp"
#include "../crypto/amf.hpp"

#include <sodium.h>
#include <chrono>
#include <random>
#include <cstring>

namespace protocol {

using namespace dia::utils;
using ecgroup::Bytes;
using ecgroup::Scalar;
using ecgroup::G1Point;
using ecgroup::G2Point;

// -----------------------------------------------------------------------------
// Ticket implementation
// -----------------------------------------------------------------------------

Bytes Ticket::to_bytes() const {
    Bytes result;
    result.reserve(t1.size() + t2.size());
    result.insert(result.end(), t1.begin(), t1.end());
    result.insert(result.end(), t2.begin(), t2.end());
    return result;
}

Ticket Ticket::from_bytes(const Bytes& data) {
    if (data.size() < 32) {
        throw EnrollmentError("Invalid ticket data: too short");
    }
    Ticket t;
    t.t1 = Bytes(data.begin(), data.begin() + 32);
    t.t2 = Bytes(data.begin() + 32, data.end());
    return t;
}

// -----------------------------------------------------------------------------
// EnrollmentRequest serialization
// -----------------------------------------------------------------------------

Bytes EnrollmentRequest::serialize() const {
    Bytes out;
    
    append_lp(out, to_bytes(telephone_number));
    append_lp(out, to_bytes(name));
    append_lp(out, to_bytes(logo_url));
    append_lp(out, nonce);
    append_lp(out, subscriber_public_key);
    append_lp(out, amf_public_key);
    append_lp(out, pke_public_key);
    append_lp(out, dr_public_key);
    
    // Blinded tickets
    append_u32_be(out, static_cast<uint32_t>(blinded_tickets.size()));
    for (const auto& ticket : blinded_tickets) {
        append_lp(out, ticket);
    }
    
    append_lp(out, signature);
    
    return out;
}

EnrollmentRequest EnrollmentRequest::deserialize(const Bytes& data) {
    EnrollmentRequest req;
    std::size_t off = 0;
    
    req.telephone_number = read_string(data, off);
    req.name = read_string(data, off);
    req.logo_url = read_string(data, off);
    req.nonce = read_lp(data, off);
    req.subscriber_public_key = read_lp(data, off);
    req.amf_public_key = read_lp(data, off);
    req.pke_public_key = read_lp(data, off);
    req.dr_public_key = read_lp(data, off);
    
    uint32_t num_tickets = read_u32_be(data, off);
    req.blinded_tickets.resize(num_tickets);
    for (uint32_t i = 0; i < num_tickets; ++i) {
        req.blinded_tickets[i] = read_lp(data, off);
    }
    
    req.signature = read_lp(data, off);
    
    return req;
}

// -----------------------------------------------------------------------------
// EnrollmentResponse serialization
// -----------------------------------------------------------------------------

Bytes EnrollmentResponse::serialize() const {
    Bytes out;
    
    append_lp(out, to_bytes(enrollment_id));
    append_lp(out, expiration);
    append_lp(out, ra_public_key);
    append_lp(out, ra_signature);
    append_lp(out, amf_moderator_pk);
    append_lp(out, ticket_verify_key);
    
    // Evaluated tickets
    append_u32_be(out, static_cast<uint32_t>(evaluated_tickets.size()));
    for (const auto& ticket : evaluated_tickets) {
        append_lp(out, ticket);
    }
    
    return out;
}

EnrollmentResponse EnrollmentResponse::deserialize(const Bytes& data) {
    EnrollmentResponse resp;
    std::size_t off = 0;
    
    resp.enrollment_id = read_string(data, off);
    resp.expiration = read_lp(data, off);
    resp.ra_public_key = read_lp(data, off);
    resp.ra_signature = read_lp(data, off);
    resp.amf_moderator_pk = read_lp(data, off);
    resp.ticket_verify_key = read_lp(data, off);
    
    uint32_t num_tickets = read_u32_be(data, off);
    resp.evaluated_tickets.resize(num_tickets);
    for (uint32_t i = 0; i < num_tickets; ++i) {
        resp.evaluated_tickets[i] = read_lp(data, off);
    }
    
    return resp;
}

// -----------------------------------------------------------------------------
// Expiration utilities
// -----------------------------------------------------------------------------

Bytes make_expiration(int days) {
    // Get current time and add days
    auto now = std::chrono::system_clock::now();
    
    // Floor to midnight UTC (C++17 compatible)
    auto now_secs = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()
    ).count();
    constexpr int64_t secs_per_day = 24 * 60 * 60;
    auto today_secs = (now_secs / secs_per_day) * secs_per_day;
    auto expiry_secs = today_secs + (static_cast<int64_t>(days) * secs_per_day);
    
    // Convert to seconds since epoch
    auto epoch_seconds = expiry_secs;
    
    // Serialize as 8-byte big-endian timestamp
    Bytes result(8);
    for (int i = 7; i >= 0; --i) {
        result[i] = static_cast<uint8_t>(epoch_seconds & 0xFF);
        epoch_seconds >>= 8;
    }
    
    return result;
}

bool check_expiry(const Bytes& expiration) {
    if (expiration.size() != 8) {
        return false;
    }
    
    // Parse 8-byte big-endian timestamp
    int64_t epoch_seconds = 0;
    for (int i = 0; i < 8; ++i) {
        epoch_seconds = (epoch_seconds << 8) | expiration[i];
    }
    
    auto expiry_time = std::chrono::system_clock::time_point(
        std::chrono::seconds(epoch_seconds)
    );
    auto now = std::chrono::system_clock::now();
    
    return now < expiry_time;
}

// -----------------------------------------------------------------------------
// Ticket generation
// -----------------------------------------------------------------------------

std::vector<BlindedTicket> generate_blinded_tickets(std::size_t count) {
    std::vector<BlindedTicket> tickets;
    tickets.reserve(count);
    
    for (std::size_t i = 0; i < count; ++i) {
        // Generate random input (use VOPRF keygen to get random scalar as input)
        voprf::KeyPair temp_kp = voprf::keygen();
        Bytes input = temp_kp.sk.to_bytes();
        
        // Convert input to string for blind function
        std::string input_str(input.begin(), input.end());
        
        // Blind the input
        auto [blinded_point, blind] = voprf::blind(input_str);
        
        BlindedTicket ticket;
        ticket.input = input;
        ticket.blinded = blinded_point.to_bytes();
        ticket.blind = blind.to_bytes();
        
        tickets.push_back(std::move(ticket));
    }
    
    return tickets;
}

std::vector<Ticket> finalize_tickets(
    const std::vector<BlindedTicket>& blinded,
    const std::vector<Bytes>& evaluated)
{
    if (blinded.size() != evaluated.size()) {
        throw EnrollmentError("Mismatched blinded and evaluated ticket counts");
    }
    
    std::vector<Ticket> tickets;
    tickets.reserve(blinded.size());
    
    for (std::size_t i = 0; i < blinded.size(); ++i) {
        // Parse evaluated point
        G1Point eval_point = G1Point::from_bytes(evaluated[i]);
        
        // Parse blind
        Scalar blind = Scalar::from_bytes(blinded[i].blind);
        
        // Unblind
        G1Point output = voprf::unblind(eval_point, blind);
        
        Ticket ticket;
        ticket.t1 = blinded[i].input;
        ticket.t2 = output.to_bytes();
        
        tickets.push_back(std::move(ticket));
    }
    
    return tickets;
}

// -----------------------------------------------------------------------------
// Client-side: create enrollment request
// -----------------------------------------------------------------------------

std::pair<EnrollmentKeys, EnrollmentRequest> create_enrollment_request(
    const std::string& telephone_number,
    const std::string& name,
    const std::string& logo_url,
    std::size_t num_tickets)
{
    EnrollmentKeys keys;
    EnrollmentRequest request;
    
    // Generate subscriber signing keys (BBS)
    bbs::Params bbs_params = bbs::Params::Default();
    bbs::KeyPair sub_kp = bbs::keygen(bbs_params);
    keys.subscriber_private_key = sub_kp.sk.to_bytes();
    keys.subscriber_public_key = sub_kp.pk.to_bytes();
    
    // Generate AMF keys (AMF keygen)
    amf::Params amf_params = amf::Params::Default();
    amf::KeyPair amf_kp = amf::KeyGen(amf_params);
    keys.amf_private_key = amf_kp.sk.to_bytes();
    keys.amf_public_key = amf_kp.pk.to_bytes();
    
    // Generate PKE keys (libsodium sealed box)
    pke::KeyPair pke_kp = pke::keygen();
    keys.pke_private_key = pke_kp.private_key;
    keys.pke_public_key = pke_kp.public_key;
    
    // Generate Double Ratchet keys (X25519)
    doubleratchet::DrKeyPair dr_kp = doubleratchet::keygen();
    keys.dr_private_key = dr_kp.private_key;
    keys.dr_public_key = dr_kp.public_key;
    
    // Generate blinded tickets
    keys.blinded_tickets = generate_blinded_tickets(num_tickets);
    
    // Generate random nonce
    Bytes nonce(32);
    randombytes_buf(nonce.data(), nonce.size());
    
    // Build request (without signature first)
    request.telephone_number = telephone_number;
    request.name = name;
    request.logo_url = logo_url;
    request.nonce = nonce;
    request.subscriber_public_key = keys.subscriber_public_key;
    request.amf_public_key = keys.amf_public_key;
    request.pke_public_key = keys.pke_public_key;
    request.dr_public_key = keys.dr_public_key;
    
    for (const auto& bt : keys.blinded_tickets) {
        request.blinded_tickets.push_back(bt.blinded);
    }
    
    // Serialize request (without signature) for signing
    Bytes to_sign = request.serialize();
    
    // Sign request using BBS (hash the request bytes to a scalar)
    Scalar msg_scalar = Scalar::hash_to_scalar(to_sign);
    std::vector<Scalar> msgs = {msg_scalar};
    bbs::Signature sig = bbs::sign(bbs_params, sub_kp.sk, msgs);
    request.signature = sig.to_bytes();
    
    return {keys, request};
}

// -----------------------------------------------------------------------------
// Client-side: finalize enrollment
// -----------------------------------------------------------------------------

ClientConfig finalize_enrollment(
    const EnrollmentKeys& keys,
    const EnrollmentResponse& response,
    const std::string& telephone_number,
    const std::string& name,
    const std::string& logo_url)
{
    // Finalize tickets
    std::vector<Ticket> tickets = finalize_tickets(
        keys.blinded_tickets,
        response.evaluated_tickets
    );
    
    ClientConfig config;
    
    // Personal info
    config.my_phone = telephone_number;
    config.my_name = name;
    config.my_logo = logo_url;
    
    // Enrollment credentials
    config.en_expiration = response.expiration;
    config.ra_public_key = response.ra_public_key;
    config.ra_signature = response.ra_signature;
    
    // AMF keys
    config.amf_private_key = keys.amf_private_key;
    config.amf_public_key = keys.amf_public_key;
    
    // PKE keys
    config.pke_private_key = keys.pke_private_key;
    config.pke_public_key = keys.pke_public_key;
    
    // Double Ratchet keys
    config.dr_private_key = keys.dr_private_key;
    config.dr_public_key = keys.dr_public_key;
    
    // Ticket
    if (!tickets.empty()) {
        config.sample_ticket = tickets[0].to_bytes();
    }
    
    // Ticket verification key
    config.access_ticket_vk = response.ticket_verify_key;
    
    // Moderator key
    config.moderator_public_key = response.amf_moderator_pk;
    
    return config;
}

// -----------------------------------------------------------------------------
// Server-side: process enrollment
// -----------------------------------------------------------------------------

EnrollmentResponse process_enrollment(
    const ServerConfig& config,
    const EnrollmentRequest& request)
{
    // Verify request signature using BBS
    // First, serialize request without signature
    EnrollmentRequest req_copy = request;
    req_copy.signature = {};
    Bytes to_verify = req_copy.serialize();
    
    // Parse client's BBS public key
    G2Point client_pk = G2Point::from_bytes(request.subscriber_public_key);
    
    // Parse the signature
    bbs::Signature sig = bbs::Signature::from_bytes(request.signature);
    
    // Hash the request to a scalar and verify
    bbs::Params bbs_params = bbs::Params::Default();
    Scalar msg_scalar = Scalar::hash_to_scalar(to_verify);
    std::vector<Scalar> msgs = {msg_scalar};
    
    if (!bbs::verify(bbs_params, client_pk, msgs, sig)) {
        throw EnrollmentError("Request signature verification failed");
    }
    
    EnrollmentResponse response;
    
    // Generate enrollment ID (32 random bytes, hex-encoded)
    Bytes eid_bytes(32);
    randombytes_buf(eid_bytes.data(), eid_bytes.size());
    response.enrollment_id = bytes_to_hex(eid_bytes);
    
    // Generate expiration
    response.expiration = make_expiration(config.enrollment_duration_days);
    
    // Create BBS signature over enrollment
    // message1 = hash(amf_pk, pke_pk, dr_pk, expiration, telephone_number)
    Bytes tn_bytes = to_bytes(request.telephone_number);
    Bytes message1 = hash_all({
        request.amf_public_key,
        request.pke_public_key,
        request.dr_public_key,
        response.expiration,
        tn_bytes
    });
    
    // message2 = name
    Bytes message2 = to_bytes(request.name);
    
    // Create scalars and sign
    Scalar m1 = Scalar::hash_to_scalar(message1);
    Scalar m2 = Scalar::hash_to_scalar(message2);
    std::vector<Scalar> cred_msgs = {m1, m2};
    
    Scalar ci_sk = Scalar::from_bytes(config.ci_private_key);
    bbs::Signature cred_sig = bbs::sign(bbs_params, ci_sk, cred_msgs);
    
    response.ra_signature = cred_sig.to_bytes();
    response.ra_public_key = config.ci_public_key;
    response.amf_moderator_pk = config.amf_public_key;
    response.ticket_verify_key = config.at_public_key;
    
    // Evaluate tickets
    Scalar at_sk = Scalar::from_bytes(config.at_private_key);
    for (const auto& blinded : request.blinded_tickets) {
        // Parse blinded point
        G1Point blinded_point = G1Point::from_bytes(blinded);
        
        // Evaluate: multiply by private key
        G1Point evaluated = G1Point::mul(blinded_point, at_sk);
        
        response.evaluated_tickets.push_back(evaluated.to_bytes());
    }
    
    return response;
}

} // namespace protocol
