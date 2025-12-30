#include <catch2/catch_test_macros.hpp>
#include "../src/protocol/oda.hpp"
#include "../src/protocol/ake.hpp"
#include "../src/protocol/rua.hpp"
#include "../src/protocol/enrollment.hpp"
#include "test_helpers.hpp"

using namespace protocol;
using namespace test_helpers;

// Helper to setup a complete AKE and RUA session
struct OdaSessionPair {
    std::unique_ptr<CallState> alice;
    std::unique_ptr<CallState> bob;
};

static OdaSessionPair setup_oda_session() {
    init_crypto();
    
    // Create paired configs with shared RA
    auto [alice_tc, bob_tc] = create_paired_configs(
        "+1111111111", "Alice",
        "+2222222222", "Bob"
    );
    
    // Add moderator public key
    amf::Params amf_params = amf::Params::Default();
    amf::KeyPair mod_kp = amf::KeyGen(amf_params);
    alice_tc.config.moderator_public_key = mod_kp.pk.to_bytes();
    bob_tc.config.moderator_public_key = mod_kp.pk.to_bytes();
    
    // Create CallStates
    auto alice = std::make_unique<CallState>(alice_tc.config, "+2222222222", true);
    alice->src = "+1111111111";
    alice->dst = "+2222222222";
    alice->ts = get_normalized_ts();
    alice->call_reason = "Test Call";
    
    auto bob = std::make_unique<CallState>(bob_tc.config, "+1111111111", false);
    bob->src = "+1111111111";
    bob->dst = "+2222222222";
    bob->ts = alice->ts;
    
    // Complete AKE
    init_ake(*alice);
    init_ake(*bob);
    
    Bytes ake_req = ake_request(*alice);
    ProtocolMessage ake_req_msg = ProtocolMessage::deserialize(ake_req);
    
    Bytes ake_resp = ake_response(*bob, ake_req_msg);
    ProtocolMessage ake_resp_msg = ProtocolMessage::deserialize(ake_resp);
    
    Bytes ake_comp = ake_complete(*alice, ake_resp_msg);
    ProtocolMessage ake_comp_msg = ProtocolMessage::deserialize(ake_comp);
    
    ake_finalize(*bob, ake_comp_msg);
    
    // Complete RUA
    Bytes rua_topic = derive_rua_topic(*alice);
    alice->transition_to_rua(rua_topic);
    bob->transition_to_rua(rua_topic);
    
    init_rtu(*alice);
    init_rtu(*bob);
    
    Bytes rua_req = rua_request(*alice);
    ProtocolMessage rua_req_msg = ProtocolMessage::deserialize(rua_req);
    
    Bytes rua_resp = rua_response(*bob, rua_req_msg);
    ProtocolMessage rua_resp_msg = ProtocolMessage::deserialize(rua_resp);
    
    rua_finalize(*alice, rua_resp_msg);
    
    return {std::move(alice), std::move(bob)};
}

TEST_CASE("ODA: Complete ODA protocol flow", "[oda]") {
    auto session = setup_oda_session();
    auto& alice = *session.alice;
    auto& bob = *session.bob;
    
    REQUIRE(alice.rua_active);
    REQUIRE(bob.rua_active);
    REQUIRE(alice.remote_party.verified);
    REQUIRE(bob.remote_party.verified);
    
    SECTION("Alice verifies Bob with ODA") {
        // Alice requests Bob's age verification
        std::vector<std::string> requested_attrs = {"age_over_21", "nationality"};
        
        // Alice creates ODA request
        Bytes oda_request_encrypted = oda_request(alice, requested_attrs);
        REQUIRE(!oda_request_encrypted.empty());
        REQUIRE(alice.pending_oda_request.has_value());
        REQUIRE(alice.pending_oda_request->requested_attributes == requested_attrs);
        
        // Bob receives and decrypts the request
        Bytes oda_request_plaintext = bob.dr_session->decrypt(oda_request_encrypted);
        ProtocolMessage oda_request_msg = ProtocolMessage::deserialize(oda_request_plaintext);
        
        REQUIRE(oda_request_msg.type == MessageType::OdaRequest);
        
        // Bob creates ODA response with presentation
        Bytes oda_response_encrypted = oda_response(bob, oda_request_msg);
        REQUIRE(!oda_response_encrypted.empty());
        
        // Alice receives and decrypts the response
        Bytes oda_response_plaintext = alice.dr_session->decrypt(oda_response_encrypted);
        ProtocolMessage oda_response_msg = ProtocolMessage::deserialize(oda_response_plaintext);
        
        REQUIRE(oda_response_msg.type == MessageType::OdaResponse);
        
        // Alice verifies the presentation
        auto verification = oda_verify(alice, oda_response_msg);
        
        REQUIRE(verification.verified);
        REQUIRE(verification.issuer == "MockIssuer");
        REQUIRE(verification.credential_type == "VerifiableCredential");
        REQUIRE(!verification.issuance_date.empty());
        REQUIRE(!verification.expiration_date.empty());
        REQUIRE(verification.disclosed_attributes.count("age_over_21") > 0);
        REQUIRE(verification.disclosed_attributes["age_over_21"] == "true");
        REQUIRE(verification.disclosed_attributes.count("nationality") > 0);
        REQUIRE(verification.disclosed_attributes["nationality"] == "US");
        
        // Verify Alice's state was updated
        REQUIRE(alice.oda_verifications.size() == 1);
        REQUIRE(alice.oda_verifications[0].verified);
        REQUIRE(alice.oda_verifications[0].requested_attributes == requested_attrs);
        REQUIRE(!alice.pending_oda_request.has_value()); // Should be cleared
    }
    
    SECTION("Bob verifies Alice with ODA") {
        // Bob can also verify Alice (bidirectional)
        std::vector<std::string> requested_attrs = {"name", "driver_license_number"};
        
        Bytes oda_request_encrypted = oda_request(bob, requested_attrs);
        REQUIRE(!oda_request_encrypted.empty());
        
        Bytes oda_request_plaintext = alice.dr_session->decrypt(oda_request_encrypted);
        ProtocolMessage oda_request_msg = ProtocolMessage::deserialize(oda_request_plaintext);
        
        Bytes oda_response_encrypted = oda_response(alice, oda_request_msg);
        Bytes oda_response_plaintext = bob.dr_session->decrypt(oda_response_encrypted);
        ProtocolMessage oda_response_msg = ProtocolMessage::deserialize(oda_response_plaintext);
        
        auto verification = oda_verify(bob, oda_response_msg);
        
        REQUIRE(verification.verified);
        REQUIRE(verification.disclosed_attributes["name"] == "John Doe");
        REQUIRE(verification.disclosed_attributes["driver_license_number"] == "D1234567");
        REQUIRE(bob.oda_verifications.size() == 1);
    }
    
    SECTION("Multiple ODA rounds") {
        // Alice verifies Bob multiple times
        std::vector<std::string> attrs1 = {"age_over_18"};
        std::vector<std::string> attrs2 = {"nationality", "birth_date"};
        std::vector<std::string> attrs3 = {"name"};
        
        // First verification
        {
            Bytes req = oda_request(alice, attrs1);
            Bytes req_plain = bob.dr_session->decrypt(req);
            ProtocolMessage req_msg = ProtocolMessage::deserialize(req_plain);
            Bytes resp = oda_response(bob, req_msg);
            Bytes resp_plain = alice.dr_session->decrypt(resp);
            ProtocolMessage resp_msg = ProtocolMessage::deserialize(resp_plain);
            auto result = oda_verify(alice, resp_msg);
            REQUIRE(result.verified);
        }
        
        // Second verification
        {
            Bytes req = oda_request(alice, attrs2);
            Bytes req_plain = bob.dr_session->decrypt(req);
            ProtocolMessage req_msg = ProtocolMessage::deserialize(req_plain);
            Bytes resp = oda_response(bob, req_msg);
            Bytes resp_plain = alice.dr_session->decrypt(resp);
            ProtocolMessage resp_msg = ProtocolMessage::deserialize(resp_plain);
            auto result = oda_verify(alice, resp_msg);
            REQUIRE(result.verified);
        }
        
        // Third verification
        {
            Bytes req = oda_request(alice, attrs3);
            Bytes req_plain = bob.dr_session->decrypt(req);
            ProtocolMessage req_msg = ProtocolMessage::deserialize(req_plain);
            Bytes resp = oda_response(bob, req_msg);
            Bytes resp_plain = alice.dr_session->decrypt(resp);
            ProtocolMessage resp_msg = ProtocolMessage::deserialize(resp_plain);
            auto result = oda_verify(alice, resp_msg);
            REQUIRE(result.verified);
        }
        
        // Alice should have 3 verifications in history
        REQUIRE(alice.oda_verifications.size() == 3);
        REQUIRE(alice.oda_verifications[0].requested_attributes == attrs1);
        REQUIRE(alice.oda_verifications[1].requested_attributes == attrs2);
        REQUIRE(alice.oda_verifications[2].requested_attributes == attrs3);
    }
}

TEST_CASE("ODA: Error handling", "[oda]") {
    auto session = setup_oda_session();
    auto& alice = *session.alice;
    auto& bob = *session.bob;
    
    SECTION("Cannot call ODA without RUA active") {
        init_crypto();
        auto [new_tc, _] = create_paired_configs("+9999999999", "New", "+8888888888", "Other");
        CallState new_caller(new_tc.config, "+8888888888", true);
        std::vector<std::string> attrs = {"age"};
        
        REQUIRE_THROWS(oda_request(new_caller, attrs));
    }
    
    SECTION("Verify requires pending request") {
        // Try to verify without creating a request first
        std::vector<std::string> attrs = {"age"};
        
        // Bob creates a request
        Bytes req = oda_request(bob, attrs);
        Bytes req_plain = alice.dr_session->decrypt(req);
        ProtocolMessage req_msg = ProtocolMessage::deserialize(req_plain);
        
        // Alice creates response  
        Bytes resp = oda_response(alice, req_msg);
        Bytes resp_plain = bob.dr_session->decrypt(resp);
        ProtocolMessage resp_msg = ProtocolMessage::deserialize(resp_plain);
        
        // But if Alice (who didn't initiate) tries to verify, it should fail
        REQUIRE_THROWS(oda_verify(alice, resp_msg));
    }
}
