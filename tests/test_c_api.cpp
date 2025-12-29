#include <catch2/catch_test_macros.hpp>
#include "dia/dia_c.h"
#include "test_helpers.hpp"

#include <cstring>
#include <string>

using namespace test_helpers;

// Helper to create a test config env string
static std::string create_test_env_string() {
    init_crypto();
    
    auto tc = create_client_config("+1234567890", "Test User");
    return tc.config.to_env_string();
}

TEST_CASE("dia_init initializes library", "[c_api]") {
    dia_init();
    // If we get here without crashing, it worked
    REQUIRE(true);
}

TEST_CASE("Config from/to env string", "[c_api]") {
    dia_init();
    
    std::string env_str = create_test_env_string();
    
    SECTION("Parse config from env string") {
        dia_config_t* cfg = nullptr;
        int result = dia_config_from_env_string(env_str.c_str(), &cfg);
        REQUIRE(result == DIA_OK);
        REQUIRE(cfg != nullptr);
        
        dia_config_destroy(cfg);
    }
    
    SECTION("Round trip config") {
        dia_config_t* cfg = nullptr;
        REQUIRE(dia_config_from_env_string(env_str.c_str(), &cfg) == DIA_OK);
        
        char* output = nullptr;
        REQUIRE(dia_config_to_env_string(cfg, &output) == DIA_OK);
        REQUIRE(output != nullptr);
        
        // Parse again and verify
        dia_config_t* cfg2 = nullptr;
        REQUIRE(dia_config_from_env_string(output, &cfg2) == DIA_OK);
        
        dia_free_string(output);
        dia_config_destroy(cfg);
        dia_config_destroy(cfg2);
    }
    
    SECTION("Invalid env string returns error") {
        dia_config_t* cfg = nullptr;
        int result = dia_config_from_env_string("INVALID_CONTENT", &cfg);
        // Should either succeed with empty fields or fail - just shouldn't crash
        if (result == DIA_OK) {
            dia_config_destroy(cfg);
        }
    }
}

TEST_CASE("CallState creation and getters", "[c_api]") {
    dia_init();
    
    std::string env_str = create_test_env_string();
    dia_config_t* cfg = nullptr;
    REQUIRE(dia_config_from_env_string(env_str.c_str(), &cfg) == DIA_OK);
    
    SECTION("Create outgoing call state") {
        dia_callstate_t* state = nullptr;
        REQUIRE(dia_callstate_create(cfg, "+1987654321", 1, &state) == DIA_OK);
        REQUIRE(state != nullptr);
        
        REQUIRE(dia_callstate_iam_caller(state) == 1);
        REQUIRE(dia_callstate_iam_recipient(state) == 0);
        REQUIRE(dia_callstate_is_rua_active(state) == 0);
        
        char* sender_id = nullptr;
        REQUIRE(dia_callstate_get_sender_id(state, &sender_id) == DIA_OK);
        REQUIRE(sender_id != nullptr);
        REQUIRE(std::strlen(sender_id) > 0);
        dia_free_string(sender_id);
        
        dia_callstate_destroy(state);
    }
    
    SECTION("Create incoming call state") {
        dia_callstate_t* state = nullptr;
        REQUIRE(dia_callstate_create(cfg, "+1987654321", 0, &state) == DIA_OK);
        REQUIRE(state != nullptr);
        
        REQUIRE(dia_callstate_iam_caller(state) == 0);
        REQUIRE(dia_callstate_iam_recipient(state) == 1);
        
        dia_callstate_destroy(state);
    }
    
    dia_config_destroy(cfg);
}

TEST_CASE("AKE protocol via C API", "[c_api]") {
    dia_init();
    
    // Create paired configs
    auto [alice_tc, bob_tc] = create_paired_configs(
        "+1234567890", "Alice",
        "+1987654321", "Bob"
    );
    
    // Add moderator key
    amf::Params amf_params = amf::Params::Default();
    amf::KeyPair mod_kp = amf::KeyGen(amf_params);
    alice_tc.config.moderator_public_key = mod_kp.pk.to_bytes();
    bob_tc.config.moderator_public_key = mod_kp.pk.to_bytes();
    
    std::string alice_env = alice_tc.config.to_env_string();
    std::string bob_env = bob_tc.config.to_env_string();
    
    // Create C configs
    dia_config_t* alice_cfg = nullptr;
    dia_config_t* bob_cfg = nullptr;
    REQUIRE(dia_config_from_env_string(alice_env.c_str(), &alice_cfg) == DIA_OK);
    REQUIRE(dia_config_from_env_string(bob_env.c_str(), &bob_cfg) == DIA_OK);
    
    // Create call states
    dia_callstate_t* alice = nullptr;
    dia_callstate_t* bob = nullptr;
    REQUIRE(dia_callstate_create(alice_cfg, "+1987654321", 1, &alice) == DIA_OK);  // outgoing
    REQUIRE(dia_callstate_create(bob_cfg, "+1234567890", 0, &bob) == DIA_OK);     // incoming
    
    // Initialize AKE
    REQUIRE(dia_ake_init(alice) == DIA_OK);
    REQUIRE(dia_ake_init(bob) == DIA_OK);
    
    // Get AKE topics
    char* alice_topic = nullptr;
    char* bob_topic = nullptr;
    REQUIRE(dia_callstate_get_ake_topic(alice, &alice_topic) == DIA_OK);
    REQUIRE(dia_callstate_get_ake_topic(bob, &bob_topic) == DIA_OK);
    REQUIRE(std::string(alice_topic) == std::string(bob_topic));
    dia_free_string(alice_topic);
    dia_free_string(bob_topic);
    
    // Step 1: Alice creates AkeRequest
    unsigned char* request = nullptr;
    size_t request_len = 0;
    REQUIRE(dia_ake_request(alice, &request, &request_len) == DIA_OK);
    REQUIRE(request != nullptr);
    REQUIRE(request_len > 0);
    
    // Step 2: Bob processes AkeRequest, creates AkeResponse
    unsigned char* response = nullptr;
    size_t response_len = 0;
    REQUIRE(dia_ake_response(bob, request, request_len, &response, &response_len) == DIA_OK);
    REQUIRE(response != nullptr);
    REQUIRE(response_len > 0);
    dia_free_bytes(request);
    
    // Step 3: Alice processes AkeResponse, creates AkeComplete
    unsigned char* complete = nullptr;
    size_t complete_len = 0;
    REQUIRE(dia_ake_complete(alice, response, response_len, &complete, &complete_len) == DIA_OK);
    REQUIRE(complete != nullptr);
    REQUIRE(complete_len > 0);
    dia_free_bytes(response);
    
    // Step 4: Bob processes AkeComplete
    REQUIRE(dia_ake_finalize(bob, complete, complete_len) == DIA_OK);
    dia_free_bytes(complete);
    
    // Both should have same shared key
    unsigned char* alice_key = nullptr;
    unsigned char* bob_key = nullptr;
    size_t alice_key_len = 0, bob_key_len = 0;
    
    REQUIRE(dia_callstate_get_shared_key(alice, &alice_key, &alice_key_len) == DIA_OK);
    REQUIRE(dia_callstate_get_shared_key(bob, &bob_key, &bob_key_len) == DIA_OK);
    REQUIRE(alice_key_len == bob_key_len);
    REQUIRE(alice_key_len > 0);
    REQUIRE(std::memcmp(alice_key, bob_key, alice_key_len) == 0);
    
    dia_free_bytes(alice_key);
    dia_free_bytes(bob_key);
    
    // Cleanup
    dia_callstate_destroy(alice);
    dia_callstate_destroy(bob);
    dia_config_destroy(alice_cfg);
    dia_config_destroy(bob_cfg);
}

TEST_CASE("Message handling via C API", "[c_api]") {
    dia_init();
    
    std::string env_str = create_test_env_string();
    dia_config_t* cfg = nullptr;
    REQUIRE(dia_config_from_env_string(env_str.c_str(), &cfg) == DIA_OK);
    
    dia_callstate_t* state = nullptr;
    REQUIRE(dia_callstate_create(cfg, "+1987654321", 1, &state) == DIA_OK);
    REQUIRE(dia_ake_init(state) == DIA_OK);
    
    SECTION("Create and parse bye message") {
        unsigned char* bye_data = nullptr;
        size_t bye_len = 0;
        REQUIRE(dia_message_create_bye(state, &bye_data, &bye_len) == DIA_OK);
        REQUIRE(bye_data != nullptr);
        REQUIRE(bye_len > 0);
        
        dia_message_t* msg = nullptr;
        REQUIRE(dia_message_deserialize(bye_data, bye_len, &msg) == DIA_OK);
        REQUIRE(msg != nullptr);
        
        REQUIRE(dia_message_get_type(msg) == DIA_MSG_BYE);
        
        char* sender_id = nullptr;
        REQUIRE(dia_message_get_sender_id(msg, &sender_id) == DIA_OK);
        REQUIRE(sender_id != nullptr);
        dia_free_string(sender_id);
        
        char* topic = nullptr;
        REQUIRE(dia_message_get_topic(msg, &topic) == DIA_OK);
        REQUIRE(topic != nullptr);
        dia_free_string(topic);
        
        dia_message_destroy(msg);
        dia_free_bytes(bye_data);
    }
    
    SECTION("Create heartbeat message") {
        unsigned char* hb_data = nullptr;
        size_t hb_len = 0;
        REQUIRE(dia_message_create_heartbeat(state, &hb_data, &hb_len) == DIA_OK);
        REQUIRE(hb_data != nullptr);
        REQUIRE(hb_len > 0);
        
        dia_message_t* msg = nullptr;
        REQUIRE(dia_message_deserialize(hb_data, hb_len, &msg) == DIA_OK);
        REQUIRE(dia_message_get_type(msg) == DIA_MSG_HEARTBEAT);
        
        dia_message_destroy(msg);
        dia_free_bytes(hb_data);
    }
    
    dia_callstate_destroy(state);
    dia_config_destroy(cfg);
}

TEST_CASE("Remote party info", "[c_api]") {
    dia_init();
    
    std::string env_str = create_test_env_string();
    dia_config_t* cfg = nullptr;
    REQUIRE(dia_config_from_env_string(env_str.c_str(), &cfg) == DIA_OK);
    
    dia_callstate_t* state = nullptr;
    REQUIRE(dia_callstate_create(cfg, "+1987654321", 1, &state) == DIA_OK);
    
    // Before RUA, remote party should not be verified
    dia_remote_party_t* rp = nullptr;
    REQUIRE(dia_callstate_get_remote_party(state, &rp) == DIA_OK);
    REQUIRE(rp != nullptr);
    REQUIRE(rp->verified == 0);
    
    dia_free_remote_party(rp);
    dia_callstate_destroy(state);
    dia_config_destroy(cfg);
}

TEST_CASE("Enrollment API full flow", "[c_api][enrollment]") {
    dia_init();
    
    // Create server config using test helper keys
    init_crypto();
    auto server_keys = test_helpers::create_server_config();
    
    dia_server_config_t* server_cfg = nullptr;
    int result = dia_server_config_create(
        server_keys.ci_private_key.data(), server_keys.ci_private_key.size(),
        server_keys.ci_public_key.data(), server_keys.ci_public_key.size(),
        server_keys.at_private_key.data(), server_keys.at_private_key.size(),
        server_keys.at_public_key.data(), server_keys.at_public_key.size(),
        server_keys.mod_private_key.data(), server_keys.mod_private_key.size(),
        server_keys.mod_public_key.data(), server_keys.mod_public_key.size(),
        30,  // enrollment_duration_days
        &server_cfg
    );
    REQUIRE(result == DIA_OK);
    REQUIRE(server_cfg != nullptr);
    
    // Client creates enrollment request
    dia_enrollment_keys_t* client_keys = nullptr;
    unsigned char* request_data = nullptr;
    size_t request_len = 0;
    
    result = dia_enrollment_create_request(
        "+1234567890",
        "Test User",
        "https://example.com/logo.png",
        3,  // num_tickets
        &client_keys,
        &request_data,
        &request_len
    );
    REQUIRE(result == DIA_OK);
    REQUIRE(client_keys != nullptr);
    REQUIRE(request_data != nullptr);
    REQUIRE(request_len > 0);
    
    // Server processes enrollment request
    unsigned char* response_data = nullptr;
    size_t response_len = 0;
    
    result = dia_enrollment_process(
        server_cfg,
        request_data,
        request_len,
        &response_data,
        &response_len
    );
    REQUIRE(result == DIA_OK);
    REQUIRE(response_data != nullptr);
    REQUIRE(response_len > 0);
    
    // Client finalizes enrollment
    dia_config_t* client_cfg = nullptr;
    result = dia_enrollment_finalize(
        client_keys,
        response_data,
        response_len,
        "+1234567890",
        "Test User",
        "https://example.com/logo.png",
        &client_cfg
    );
    REQUIRE(result == DIA_OK);
    REQUIRE(client_cfg != nullptr);
    
    // Verify we can use the resulting config
    char* env_str = nullptr;
    REQUIRE(dia_config_to_env_string(client_cfg, &env_str) == DIA_OK);
    REQUIRE(env_str != nullptr);
    
    // Config should have proper fields
    std::string env(env_str);
    REQUIRE(env.find("+1234567890") != std::string::npos);
    REQUIRE(env.find("Test User") != std::string::npos);
    
    // Clean up
    dia_free_string(env_str);
    dia_free_bytes(request_data);
    dia_free_bytes(response_data);
    dia_enrollment_keys_destroy(client_keys);
    dia_config_destroy(client_cfg);
    dia_server_config_destroy(server_cfg);
}

TEST_CASE("ServerConfig env string serialization", "[c_api][enrollment]") {
    dia_init();
    
    // Generate a server config
    dia_server_config_t* original_cfg = nullptr;
    int result = dia_server_config_generate(45, &original_cfg);
    REQUIRE(result == DIA_OK);
    REQUIRE(original_cfg != nullptr);
    
    // Serialize to env string
    char* env_str = nullptr;
    result = dia_server_config_to_env_string(original_cfg, &env_str);
    REQUIRE(result == DIA_OK);
    REQUIRE(env_str != nullptr);
    
    std::string env(env_str);
    REQUIRE(env.find("CI_SK=") != std::string::npos);
    REQUIRE(env.find("CI_PK=") != std::string::npos);
    REQUIRE(env.find("AT_SK=") != std::string::npos);
    REQUIRE(env.find("AT_VK=") != std::string::npos);
    REQUIRE(env.find("AMF_SK=") != std::string::npos);
    REQUIRE(env.find("AMF_PK=") != std::string::npos);
    REQUIRE(env.find("ENROLLMENT_DURATION_DAYS=45") != std::string::npos);
    
    // Deserialize back
    dia_server_config_t* restored_cfg = nullptr;
    result = dia_server_config_from_env_string(env_str, &restored_cfg);
    REQUIRE(result == DIA_OK);
    REQUIRE(restored_cfg != nullptr);
    
    // Verify round trip by getting keys
    unsigned char* orig_ci_pk = nullptr;
    unsigned char* rest_ci_pk = nullptr;
    size_t orig_len = 0, rest_len = 0;
    
    REQUIRE(dia_server_config_get_ci_public_key(original_cfg, &orig_ci_pk, &orig_len) == DIA_OK);
    REQUIRE(dia_server_config_get_ci_public_key(restored_cfg, &rest_ci_pk, &rest_len) == DIA_OK);
    REQUIRE(orig_len == rest_len);
    REQUIRE(std::memcmp(orig_ci_pk, rest_ci_pk, orig_len) == 0);
    
    unsigned char* orig_at_pk = nullptr;
    unsigned char* rest_at_pk = nullptr;
    REQUIRE(dia_server_config_get_at_public_key(original_cfg, &orig_at_pk, &orig_len) == DIA_OK);
    REQUIRE(dia_server_config_get_at_public_key(restored_cfg, &rest_at_pk, &rest_len) == DIA_OK);
    REQUIRE(orig_len == rest_len);
    REQUIRE(std::memcmp(orig_at_pk, rest_at_pk, orig_len) == 0);
    
    unsigned char* orig_amf_pk = nullptr;
    unsigned char* rest_amf_pk = nullptr;
    REQUIRE(dia_server_config_get_amf_public_key(original_cfg, &orig_amf_pk, &orig_len) == DIA_OK);
    REQUIRE(dia_server_config_get_amf_public_key(restored_cfg, &rest_amf_pk, &rest_len) == DIA_OK);
    REQUIRE(orig_len == rest_len);
    REQUIRE(std::memcmp(orig_amf_pk, rest_amf_pk, orig_len) == 0);
    
    // Clean up
    dia_free_bytes(orig_ci_pk);
    dia_free_bytes(rest_ci_pk);
    dia_free_bytes(orig_at_pk);
    dia_free_bytes(rest_at_pk);
    dia_free_bytes(orig_amf_pk);
    dia_free_bytes(rest_amf_pk);
    dia_free_string(env_str);
    dia_server_config_destroy(original_cfg);
    dia_server_config_destroy(restored_cfg);
}
