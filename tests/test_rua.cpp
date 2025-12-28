#include <catch2/catch_test_macros.hpp>
#include "test_helpers.hpp"
#include "../src/protocol/rua.hpp"
#include "../src/protocol/ake.hpp"
#include "../src/protocol/enrollment.hpp"
#include <memory>

using namespace protocol;
using namespace test_helpers;
using dia::utils::hash_all;

// Helper to setup a complete AKE session between two parties
struct AkeSessionPair {
    std::unique_ptr<CallState> alice;
    std::unique_ptr<CallState> bob;
};

static AkeSessionPair setup_ake_session() {
    init_crypto();
    
    // Create paired configs with shared RA
    auto [alice_tc, bob_tc] = create_paired_configs(
        "+1234567890", "Alice",
        "+1987654321", "Bob"
    );
    
    // Add moderator public key (using AMF keygen)
    amf::Params amf_params = amf::Params::Default();
    amf::KeyPair mod_kp = amf::KeyGen(amf_params);
    alice_tc.config.moderator_public_key = mod_kp.pk.to_bytes();
    bob_tc.config.moderator_public_key = mod_kp.pk.to_bytes();
    
    // Create CallStates - Alice is caller, Bob is recipient
    auto alice = std::make_unique<CallState>(alice_tc.config, "+1987654321", true);
    alice->src = "+1234567890";
    alice->dst = "+1987654321";
    alice->ts = get_normalized_ts();
    alice->call_reason = "Business Call";
    
    auto bob = std::make_unique<CallState>(bob_tc.config, "+1234567890", false);
    bob->src = "+1234567890";  // src is caller's number
    bob->dst = "+1987654321";  // dst is recipient's number
    bob->ts = alice->ts;
    
    // Complete AKE handshake
    init_ake(*alice);
    init_ake(*bob);
    
    Bytes request_bytes = ake_request(*alice);
    ProtocolMessage request_msg = ProtocolMessage::deserialize(request_bytes);
    
    Bytes response_bytes = ake_response(*bob, request_msg);
    ProtocolMessage response_msg = ProtocolMessage::deserialize(response_bytes);
    
    Bytes complete_bytes = ake_complete(*alice, response_msg);
    ProtocolMessage complete_msg = ProtocolMessage::deserialize(complete_bytes);
    
    ake_finalize(*bob, complete_msg);
    
    // Both parties now have DR sessions and shared key
    return {std::move(alice), std::move(bob)};
}

TEST_CASE("create_rtu_from_config creates valid RTU", "[rua]") {
    init_crypto();
    
    auto tc = create_client_config("+1234567890", "Alice");
    
    Rtu rtu = create_rtu_from_config(tc.config);
    
    REQUIRE(rtu.amf_pk == tc.config.amf_public_key);
    REQUIRE(rtu.pke_pk == tc.config.pke_public_key);
    REQUIRE(rtu.dr_pk == tc.config.dr_public_key);
    REQUIRE(rtu.expiration == tc.config.en_expiration);
    REQUIRE(rtu.signature == tc.config.ra_signature);
    REQUIRE(rtu.name == tc.config.my_name);
    REQUIRE(rtu.logo == tc.config.my_logo);
}

TEST_CASE("derive_rua_topic produces consistent output", "[rua]") {
    init_crypto();
    
    auto tc = create_client_config("+1234567890", "Alice");
    CallState state(tc.config, "+1987654321", true);
    state.set_shared_key(random_bytes(32));
    
    Bytes topic1 = derive_rua_topic(state);
    Bytes topic2 = derive_rua_topic(state);
    
    REQUIRE(topic1.size() == 32);  // SHA-256
    REQUIRE(topic1 == topic2);
    
    // Different shared key should produce different topic
    state.set_shared_key(random_bytes(32));
    Bytes topic3 = derive_rua_topic(state);
    REQUIRE(topic1 != topic3);
}

TEST_CASE("init_rtu initializes RUA state", "[rua]") {
    init_crypto();
    
    auto tc = create_client_config("+1234567890", "Alice");
    CallState state(tc.config, "+1987654321", true);
    state.set_shared_key(random_bytes(32));
    
    // Before init_rtu
    REQUIRE(state.rua.topic.empty());
    REQUIRE(state.rua.dh_pk.empty());
    REQUIRE(!state.rua.rtu.has_value());
    
    init_rtu(state);
    
    // After init_rtu
    REQUIRE(!state.rua.topic.empty());
    REQUIRE(!state.rua.dh_pk.empty());
    REQUIRE(!state.rua.dh_sk.empty());
    REQUIRE(state.rua.rtu.has_value());
    REQUIRE(state.rua.rtu->name == "Alice");
}

TEST_CASE("rua_request without DR session throws", "[rua]") {
    init_crypto();
    
    auto tc = create_client_config("+1234567890", "Alice");
    CallState caller(tc.config, "+1987654321", true);
    
    // No DR session
    REQUIRE_THROWS_AS(rua_request(caller), RuaError);
}

TEST_CASE("Complete RUA flow", "[rua]") {
    auto session = setup_ake_session();
    auto& alice = *session.alice;
    auto& bob = *session.bob;
    
    // Verify AKE completed successfully
    REQUIRE(!alice.shared_key.empty());
    REQUIRE(!bob.shared_key.empty());
    REQUIRE(alice.shared_key == bob.shared_key);
    REQUIRE(alice.dr_session != nullptr);
    REQUIRE(bob.dr_session != nullptr);
    
    // Step 1: Alice creates RuaRequest
    Bytes request_bytes = rua_request(alice);
    REQUIRE(!request_bytes.empty());
    
    ProtocolMessage request_msg = ProtocolMessage::deserialize(request_bytes);
    REQUIRE(request_msg.is_rua_request());
    
    // Verify Alice stored the request
    REQUIRE(alice.rua.req.has_value());
    REQUIRE(!alice.rua.req->sigma.empty());
    
    // Step 2: Bob processes RuaRequest and creates RuaResponse
    Bytes response_bytes = rua_response(bob, request_msg);
    REQUIRE(!response_bytes.empty());
    
    ProtocolMessage response_msg = ProtocolMessage::deserialize(response_bytes);
    REQUIRE(response_msg.is_rua_response());
    
    // Verify Bob transitioned to RUA
    REQUIRE(bob.is_rua_active());
    
    // Save Bob's new shared key for comparison
    Bytes bob_new_shared_key = bob.shared_key;
    REQUIRE(!bob_new_shared_key.empty());
    
    // Step 3: Alice processes RuaResponse and finalizes
    REQUIRE_NOTHROW(rua_finalize(alice, response_msg));
    
    // Verify Alice transitioned to RUA
    REQUIRE(alice.is_rua_active());
    
    // Both should have the same new shared key (different from AKE shared key)
    REQUIRE(alice.shared_key == bob_new_shared_key);
}

TEST_CASE("RUA fails with wrong message type", "[rua]") {
    auto session = setup_ake_session();
    auto& alice = *session.alice;
    auto& bob = *session.bob;
    
    // Create RuaRequest
    Bytes request_bytes = rua_request(alice);
    ProtocolMessage request_msg = ProtocolMessage::deserialize(request_bytes);
    
    // Try to finalize with request (wrong type)
    REQUIRE_THROWS_AS(rua_finalize(alice, request_msg), RuaError);
    
    // Create response
    Bytes response_bytes = rua_response(bob, request_msg);
    ProtocolMessage response_msg = ProtocolMessage::deserialize(response_bytes);
    
    // Try to call rua_response with response (wrong type)
    REQUIRE_THROWS_AS(rua_response(alice, response_msg), RuaError);
}

TEST_CASE("RUA request includes call reason", "[rua]") {
    auto session = setup_ake_session();
    auto& alice = *session.alice;
    auto& bob = *session.bob;
    
    alice.call_reason = "Test Call Reason";
    
    Bytes request_bytes = rua_request(alice);
    ProtocolMessage request_msg = ProtocolMessage::deserialize(request_bytes);
    
    // Decode and check reason
    RuaMessage rua_msg = decode_dr_rua_payload(request_msg, *bob.dr_session);
    REQUIRE(rua_msg.reason == "Test Call Reason");
}

TEST_CASE("RUA DR encryption works correctly", "[rua]") {
    auto session = setup_ake_session();
    auto& alice = *session.alice;
    auto& bob = *session.bob;
    
    // Complete RUA handshake
    Bytes request_bytes = rua_request(alice);
    ProtocolMessage request_msg = ProtocolMessage::deserialize(request_bytes);
    
    Bytes response_bytes = rua_response(bob, request_msg);
    ProtocolMessage response_msg = ProtocolMessage::deserialize(response_bytes);
    
    rua_finalize(alice, response_msg);
    
    // After RUA, DR sessions should still work for additional messages
    std::string test_msg = "Post-RUA message";
    Bytes plaintext(test_msg.begin(), test_msg.end());
    
    Bytes ciphertext = alice.dr_session->encrypt(plaintext);
    Bytes decrypted = bob.dr_session->decrypt(ciphertext);
    
    REQUIRE(decrypted == plaintext);
}

TEST_CASE("RUA populates remote_party info after completion", "[rua]") {
    auto session = setup_ake_session();
    auto& alice = *session.alice;
    auto& bob = *session.bob;
    
    // Before RUA, remote_party should not be verified
    REQUIRE_FALSE(alice.remote_party.verified);
    REQUIRE_FALSE(bob.remote_party.verified);
    
    // Complete RUA handshake
    Bytes request_bytes = rua_request(alice);
    ProtocolMessage request_msg = ProtocolMessage::deserialize(request_bytes);
    
    Bytes response_bytes = rua_response(bob, request_msg);
    ProtocolMessage response_msg = ProtocolMessage::deserialize(response_bytes);
    
    rua_finalize(alice, response_msg);
    
    // Bob (recipient) should see Alice's info
    REQUIRE(bob.remote_party.verified);
    REQUIRE(bob.remote_party.phone == "+1234567890");
    REQUIRE(bob.remote_party.name == "Alice");
    REQUIRE_FALSE(bob.remote_party.logo.empty());
    
    // Alice (caller) should see Bob's info
    REQUIRE(alice.remote_party.verified);
    REQUIRE(alice.remote_party.phone == "+1987654321");
    REQUIRE(alice.remote_party.name == "Bob");
    REQUIRE_FALSE(alice.remote_party.logo.empty());
}
