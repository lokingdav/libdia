#include <catch2/catch_test_macros.hpp>
#include "test_helpers.hpp"
#include "../src/protocol/ake.hpp"
#include "../src/helpers.hpp"
#include <memory>

using namespace protocol;
using namespace test_helpers;
using dia::utils::hash_all;
using dia::utils::concat_bytes;

TEST_CASE("hash_all produces consistent output", "[ake]") {
    init_crypto();
    
    Bytes a = {0x01, 0x02, 0x03};
    Bytes b = {0x04, 0x05, 0x06};
    
    Bytes hash1 = hash_all({a, b});
    Bytes hash2 = hash_all({a, b});
    
    REQUIRE(hash1.size() == 32);  // SHA-256
    REQUIRE(hash1 == hash2);
    
    // Different input should produce different hash
    Bytes hash3 = hash_all({b, a});
    REQUIRE(hash1 != hash3);
}

TEST_CASE("concat_bytes works correctly", "[ake]") {
    init_crypto();
    
    Bytes a = {0x01, 0x02};
    Bytes b = {0x03, 0x04, 0x05};
    
    Bytes result = concat_bytes(a, b);
    
    REQUIRE(result.size() == 5);
    REQUIRE(result == Bytes({0x01, 0x02, 0x03, 0x04, 0x05}));
}

TEST_CASE("init_ake initializes AKE state", "[ake]") {
    init_crypto();
    
    auto tc = create_client_config("+1234567890", "Alice");
    CallState caller(tc.config, "+1987654321", true);
    
    // Before init_ake, DH keys should be empty
    REQUIRE(caller.ake.dh_pk.empty());
    REQUIRE(caller.ake.dh_sk.empty());
    
    init_ake(caller);
    
    // After init_ake, DH keys and topic should be set
    REQUIRE(!caller.ake.dh_pk.empty());
    REQUIRE(!caller.ake.dh_sk.empty());
    REQUIRE(!caller.ake.topic.empty());
}

TEST_CASE("create_zk_proof and verify_zk_proof round trip", "[ake]") {
    init_crypto();
    
    // Create a config with valid enrollment credentials
    auto tc = create_client_config("+1234567890", "Alice");
    
    // Create call state as caller
    CallState prover(tc.config, "+1987654321", true);
    init_ake(prover);
    
    // Create a challenge
    Bytes challenge = hash_all({prover.ake.topic});
    
    // Create proof
    Bytes proof = create_zk_proof(prover, challenge);
    REQUIRE(!proof.empty());
    
    // Create an AkeMessage containing the proof and public keys
    AkeMessage ake_msg;
    ake_msg.amf_pk = prover.config.amf_public_key;
    ake_msg.pke_pk = prover.config.pke_public_key;
    ake_msg.dr_pk = prover.config.dr_public_key;
    ake_msg.expiration = prover.config.en_expiration;
    ake_msg.proof = proof;
    
    // Verify the proof using the same challenge and the prover's phone number
    bool valid = verify_zk_proof(ake_msg, prover.src, challenge, prover.config.ra_public_key);
    REQUIRE(valid);
}

TEST_CASE("ake_request creates valid request message", "[ake]") {
    init_crypto();
    
    auto tc = create_client_config("+1234567890", "Alice");
    CallState caller(tc.config, "+1987654321", true);
    
    init_ake(caller);
    
    Bytes msg_bytes = ake_request(caller);
    
    // Should produce a non-empty message
    REQUIRE(!msg_bytes.empty());
    
    // Should be deserializable as ProtocolMessage
    ProtocolMessage msg = ProtocolMessage::deserialize(msg_bytes);
    REQUIRE(msg.is_ake_request());
    REQUIRE(!msg.sender_id.empty());
    
    // Payload should be deserializable as AkeMessage (unencrypted)
    AkeMessage ake_msg = decode_ake_payload(msg, {}, {});
    REQUIRE(!ake_msg.amf_pk.empty());
    REQUIRE(!ake_msg.pke_pk.empty());
    REQUIRE(!ake_msg.dr_pk.empty());
    REQUIRE(!ake_msg.proof.empty());
    // DH public key is NOT included in AkeRequest
    REQUIRE(ake_msg.dh_pk.empty());
}

TEST_CASE("ake_request without init throws", "[ake]") {
    init_crypto();
    
    auto tc = create_client_config("+1234567890", "Alice");
    CallState caller(tc.config, "+1987654321", true);
    
    // Don't call init_ake
    REQUIRE_THROWS_AS(ake_request(caller), AkeError);
}

TEST_CASE("Complete AKE flow", "[ake]") {
    init_crypto();
    
    // Create paired configs with shared RA
    auto [alice_tc, bob_tc] = create_paired_configs(
        "+1234567890", "Alice",
        "+1987654321", "Bob"
    );
    
    // Create CallStates - Alice is caller, calling Bob
    CallState alice(alice_tc.config, "+1987654321", true);
    alice.src = "+1234567890";
    alice.dst = "+1987654321";
    alice.ts = get_normalized_ts();
    
    // Bob is recipient
    CallState bob(bob_tc.config, "+1234567890", false);
    bob.src = "+1234567890";  // src is caller's number
    bob.dst = "+1987654321";  // dst is recipient's number
    bob.ts = alice.ts;  // Same timestamp
    
    // Initialize AKE for both parties
    init_ake(alice);
    init_ake(bob);
    
    // Step 1: Alice creates AkeRequest
    Bytes request_bytes = ake_request(alice);
    ProtocolMessage request_msg = ProtocolMessage::deserialize(request_bytes);
    REQUIRE(request_msg.is_ake_request());
    
    // Step 2: Bob processes AkeRequest and creates AkeResponse
    Bytes response_bytes = ake_response(bob, request_msg);
    ProtocolMessage response_msg = ProtocolMessage::deserialize(response_bytes);
    REQUIRE(response_msg.is_ake_response());
    
    // Verify Bob stored Alice's info
    REQUIRE(!bob.counterpart_amf_pk.empty());
    REQUIRE(!bob.counterpart_pke_pk.empty());
    REQUIRE(!bob.counterpart_dr_pk.empty());
    
    // Step 3: Alice processes AkeResponse and creates AkeComplete
    Bytes complete_bytes = ake_complete(alice, response_msg);
    ProtocolMessage complete_msg = ProtocolMessage::deserialize(complete_bytes);
    REQUIRE(complete_msg.is_ake_complete());
    
    // Verify Alice has shared key and DR session
    REQUIRE(!alice.shared_key.empty());
    REQUIRE(alice.dr_session != nullptr);
    REQUIRE(!alice.counterpart_amf_pk.empty());
    
    // Step 4: Bob processes AkeComplete (finalize)
    REQUIRE_NOTHROW(ake_finalize(bob, complete_msg));
    
    // Verify Bob has shared key and DR session
    REQUIRE(!bob.shared_key.empty());
    REQUIRE(bob.dr_session != nullptr);
    
    // Both should have the same shared key
    REQUIRE(alice.shared_key == bob.shared_key);
    
    // Test DR session works
    std::string test_msg = "Hello, Bob!";
    Bytes plaintext(test_msg.begin(), test_msg.end());
    
    Bytes ciphertext = alice.dr_session->encrypt(plaintext);
    Bytes decrypted = bob.dr_session->decrypt(ciphertext);
    
    REQUIRE(decrypted == plaintext);
    
    // Test bidirectional
    std::string reply = "Hello, Alice!";
    Bytes reply_pt(reply.begin(), reply.end());
    
    Bytes reply_ct = bob.dr_session->encrypt(reply_pt);
    Bytes reply_dec = alice.dr_session->decrypt(reply_ct);
    
    REQUIRE(reply_dec == reply_pt);
}

TEST_CASE("AKE fails with wrong message type", "[ake]") {
    init_crypto();
    
    auto tc = create_client_config("+1234567890", "Alice");
    CallState state(tc.config, "+1987654321", false);
    init_ake(state);
    
    // Create a wrong message type
    ProtocolMessage wrong_msg;
    wrong_msg.type = MessageType::AkeComplete;  // Wrong type for ake_response
    wrong_msg.sender_id = "test";
    wrong_msg.topic = "test";
    
    REQUIRE_THROWS_AS(ake_response(state, wrong_msg), AkeError);
}
