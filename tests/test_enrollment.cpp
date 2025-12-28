#include <catch2/catch_test_macros.hpp>
#include "test_helpers.hpp"
#include "../src/protocol/enrollment.hpp"

using namespace protocol;
using namespace test_helpers;
using ecgroup::Bytes;
using dia::utils::hash_all;

// Helper to create a valid server config for testing
static ServerConfig create_test_server_config() {
    auto ts = create_server_config();
    
    ServerConfig config;
    config.ci_private_key = ts.ci_private_key;
    config.ci_public_key = ts.ci_public_key;
    config.at_private_key = ts.at_private_key;
    config.at_public_key = ts.at_public_key;
    config.amf_public_key = ts.mod_public_key;  // Using AMF keygen!
    config.enrollment_duration_days = 30;
    
    return config;
}

TEST_CASE("make_expiration creates valid timestamp", "[enrollment]") {
    Bytes expiration = make_expiration(30);
    
    REQUIRE(expiration.size() == 8);
    REQUIRE(check_expiry(expiration));  // Should not be expired
}

TEST_CASE("check_expiry returns false for expired timestamp", "[enrollment]") {
    // Create expiration for -1 days (yesterday)
    Bytes expired = make_expiration(-1);
    
    REQUIRE_FALSE(check_expiry(expired));
}

TEST_CASE("generate_blinded_tickets creates valid tickets", "[enrollment]") {
    init_crypto();
    
    auto tickets = generate_blinded_tickets(3);
    
    REQUIRE(tickets.size() == 3);
    for (const auto& t : tickets) {
        REQUIRE(!t.input.empty());
        REQUIRE(!t.blinded.empty());
        REQUIRE(!t.blind.empty());
    }
}

TEST_CASE("Ticket serialization round trip", "[enrollment]") {
    Ticket ticket;
    ticket.t1 = Bytes(32, 0xAA);
    ticket.t2 = Bytes(48, 0xBB);
    
    Bytes serialized = ticket.to_bytes();
    REQUIRE(serialized.size() == 80);
    
    Ticket restored = Ticket::from_bytes(serialized);
    REQUIRE(restored.t1 == ticket.t1);
    REQUIRE(restored.t2 == ticket.t2);
}

TEST_CASE("EnrollmentRequest serialization round trip", "[enrollment]") {
    EnrollmentRequest req;
    req.telephone_number = "+1234567890";
    req.name = "Alice";
    req.logo_url = "https://example.com/logo.png";
    req.nonce = Bytes(32, 0x11);
    req.subscriber_public_key = Bytes(44, 0x22);
    req.amf_public_key = Bytes(96, 0x33);
    req.pke_public_key = Bytes(32, 0x44);
    req.dr_public_key = Bytes(32, 0x55);
    req.blinded_tickets = {Bytes(48, 0x66), Bytes(48, 0x77)};
    req.signature = Bytes(64, 0x88);
    
    Bytes serialized = req.serialize();
    REQUIRE(!serialized.empty());
    
    EnrollmentRequest restored = EnrollmentRequest::deserialize(serialized);
    REQUIRE(restored.telephone_number == req.telephone_number);
    REQUIRE(restored.name == req.name);
    REQUIRE(restored.logo_url == req.logo_url);
    REQUIRE(restored.nonce == req.nonce);
    REQUIRE(restored.subscriber_public_key == req.subscriber_public_key);
    REQUIRE(restored.amf_public_key == req.amf_public_key);
    REQUIRE(restored.pke_public_key == req.pke_public_key);
    REQUIRE(restored.dr_public_key == req.dr_public_key);
    REQUIRE(restored.blinded_tickets.size() == req.blinded_tickets.size());
    REQUIRE(restored.signature == req.signature);
}

TEST_CASE("EnrollmentResponse serialization round trip", "[enrollment]") {
    EnrollmentResponse resp;
    resp.enrollment_id = "abc123";
    resp.expiration = Bytes(8, 0x11);
    resp.ra_public_key = Bytes(96, 0x22);
    resp.ra_signature = Bytes(128, 0x33);
    resp.amf_moderator_pk = Bytes(96, 0x44);
    resp.ticket_verify_key = Bytes(96, 0x55);
    resp.evaluated_tickets = {Bytes(48, 0x66), Bytes(48, 0x77)};
    
    Bytes serialized = resp.serialize();
    REQUIRE(!serialized.empty());
    
    EnrollmentResponse restored = EnrollmentResponse::deserialize(serialized);
    REQUIRE(restored.enrollment_id == resp.enrollment_id);
    REQUIRE(restored.expiration == resp.expiration);
    REQUIRE(restored.ra_public_key == resp.ra_public_key);
    REQUIRE(restored.ra_signature == resp.ra_signature);
    REQUIRE(restored.amf_moderator_pk == resp.amf_moderator_pk);
    REQUIRE(restored.ticket_verify_key == resp.ticket_verify_key);
    REQUIRE(restored.evaluated_tickets.size() == resp.evaluated_tickets.size());
}

TEST_CASE("create_enrollment_request generates all keys", "[enrollment]") {
    init_crypto();
    
    auto [keys, request] = create_enrollment_request(
        "+1234567890",
        "Alice",
        "https://example.com/logo.png",
        2
    );
    
    // Check keys were generated
    REQUIRE(!keys.subscriber_private_key.empty());
    REQUIRE(!keys.subscriber_public_key.empty());
    REQUIRE(!keys.subscriber_public_key.empty());
    REQUIRE(!keys.amf_private_key.empty());
    REQUIRE(!keys.amf_public_key.empty());
    REQUIRE(!keys.pke_private_key.empty());
    REQUIRE(!keys.pke_public_key.empty());
    REQUIRE(!keys.dr_private_key.empty());
    REQUIRE(!keys.dr_public_key.empty());
    REQUIRE(keys.blinded_tickets.size() == 2);
    
    // Check request fields
    REQUIRE(request.telephone_number == "+1234567890");
    REQUIRE(request.name == "Alice");
    REQUIRE(request.logo_url == "https://example.com/logo.png");
    REQUIRE(!request.nonce.empty());
    REQUIRE(!request.signature.empty());
    REQUIRE(request.blinded_tickets.size() == 2);
    
    // Verify BBS signature is valid
    EnrollmentRequest req_copy = request;
    req_copy.signature = {};
    Bytes to_verify = req_copy.serialize();
    ecgroup::G2Point pk = ecgroup::G2Point::from_bytes(request.subscriber_public_key);
    bbs::Signature sig = bbs::Signature::from_bytes(request.signature);
    ecgroup::Scalar msg_scalar = ecgroup::Scalar::hash_to_scalar(to_verify);
    std::vector<ecgroup::Scalar> msgs = {msg_scalar};
    bbs::Params params = bbs::Params::Default();
    REQUIRE(bbs::verify(params, pk, msgs, sig));
}

TEST_CASE("process_enrollment validates signature", "[enrollment]") {
    init_crypto();
    
    ServerConfig server_config = create_test_server_config();
    
    auto [keys, request] = create_enrollment_request(
        "+1234567890",
        "Alice",
        "https://example.com/logo.png"
    );
    
    // Should succeed with valid signature
    REQUIRE_NOTHROW(process_enrollment(server_config, request));
    
    // Should fail with tampered signature (either parse error or verification failure)
    EnrollmentRequest tampered = request;
    // Tamper with a byte in the middle of the signature to corrupt it
    if (tampered.signature.size() > 10) {
        tampered.signature[10] ^= 0xFF;
    }
    REQUIRE_THROWS(process_enrollment(server_config, tampered));
}

TEST_CASE("Complete enrollment flow", "[enrollment]") {
    init_crypto();
    
    // Setup server
    ServerConfig server_config = create_test_server_config();
    
    // Client creates enrollment request
    auto [keys, request] = create_enrollment_request(
        "+1234567890",
        "Alice",
        "https://example.com/logo.png",
        1
    );
    
    // Server processes enrollment
    EnrollmentResponse response = process_enrollment(server_config, request);
    
    // Verify response
    REQUIRE(!response.enrollment_id.empty());
    REQUIRE(!response.expiration.empty());
    REQUIRE(!response.ra_public_key.empty());
    REQUIRE(!response.ra_signature.empty());
    REQUIRE(!response.amf_moderator_pk.empty());
    REQUIRE(!response.ticket_verify_key.empty());
    REQUIRE(response.evaluated_tickets.size() == 1);
    REQUIRE(check_expiry(response.expiration));
    
    // Client finalizes enrollment
    ClientConfig config = finalize_enrollment(
        keys,
        response,
        "+1234567890",
        "Alice",
        "https://example.com/logo.png"
    );
    
    // Verify ClientConfig
    REQUIRE(config.my_phone == "+1234567890");
    REQUIRE(config.my_name == "Alice");
    REQUIRE(config.my_logo == "https://example.com/logo.png");
    REQUIRE(!config.en_expiration.empty());
    REQUIRE(!config.ra_public_key.empty());
    REQUIRE(!config.ra_signature.empty());
    REQUIRE(!config.amf_private_key.empty());
    REQUIRE(!config.amf_public_key.empty());
    REQUIRE(!config.pke_private_key.empty());
    REQUIRE(!config.pke_public_key.empty());
    REQUIRE(!config.dr_private_key.empty());
    REQUIRE(!config.dr_public_key.empty());
    REQUIRE(!config.sample_ticket.empty());
    REQUIRE(!config.access_ticket_vk.empty());
    REQUIRE(!config.moderator_public_key.empty());
}

TEST_CASE("Enrolled credential can be used for ZK proof", "[enrollment]") {
    init_crypto();
    
    // Setup server
    ServerConfig server_config = create_test_server_config();
    
    // Client creates enrollment request
    auto [keys, request] = create_enrollment_request(
        "+1234567890",
        "Alice",
        "https://example.com/logo.png"
    );
    
    // Server processes enrollment
    EnrollmentResponse response = process_enrollment(server_config, request);
    
    // Client finalizes enrollment
    ClientConfig config = finalize_enrollment(
        keys,
        response,
        "+1234567890",
        "Alice",
        "https://example.com/logo.png"
    );
    
    // Verify the BBS signature on the credential
    bbs::Params params = bbs::Params::Default();
    ecgroup::G2Point ra_pk = ecgroup::G2Point::from_bytes(config.ra_public_key);
    bbs::Signature sig = bbs::Signature::from_bytes(config.ra_signature);
    
    // Reconstruct messages
    Bytes tn_bytes(config.my_phone.begin(), config.my_phone.end());
    Bytes message1 = hash_all({
        config.amf_public_key,
        config.pke_public_key,
        config.dr_public_key,
        config.en_expiration,
        tn_bytes
    });
    // message2 = hash(name, logo)
    Bytes message2 = hash_all({
        Bytes(config.my_name.begin(), config.my_name.end()),
        Bytes(config.my_logo.begin(), config.my_logo.end())
    });
    
    ecgroup::Scalar m1 = ecgroup::Scalar::hash_to_scalar(message1);
    ecgroup::Scalar m2 = ecgroup::Scalar::hash_to_scalar(message2);
    std::vector<ecgroup::Scalar> msgs = {m1, m2};
    
    // Verify signature
    REQUIRE(bbs::verify(params, ra_pk, msgs, sig));
    
    // Create and verify a selective disclosure proof
    std::vector<std::size_t> disclosed_indices = {1};  // Disclose message1 only
    std::string nonce = "test-nonce";
    
    bbs::SDProof proof = bbs::create_proof(params, ra_pk, sig, msgs, disclosed_indices, nonce);
    
    std::vector<std::pair<std::size_t, ecgroup::Scalar>> disclosed = {{1, m1}};
    REQUIRE(bbs::verify_proof(params, ra_pk, proof, disclosed, 2));
}

TEST_CASE("Finalized ticket can be verified", "[enrollment]") {
    init_crypto();
    
    // Setup server
    ServerConfig server_config = create_test_server_config();
    
    // Client creates enrollment request
    auto [keys, request] = create_enrollment_request(
        "+1234567890",
        "Alice",
        "https://example.com/logo.png",
        1
    );
    
    // Server processes enrollment
    EnrollmentResponse response = process_enrollment(server_config, request);
    
    // Finalize tickets
    std::vector<Ticket> tickets = finalize_tickets(
        keys.blinded_tickets,
        response.evaluated_tickets
    );
    
    REQUIRE(tickets.size() == 1);
    
    // Verify the ticket
    Ticket& ticket = tickets[0];
    std::string input_str(ticket.t1.begin(), ticket.t1.end());
    ecgroup::G1Point output = ecgroup::G1Point::from_bytes(ticket.t2);
    ecgroup::G2Point vk = ecgroup::G2Point::from_bytes(response.ticket_verify_key);
    
    REQUIRE(voprf::verify(input_str, output, vk));
}
