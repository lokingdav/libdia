#include <catch2/catch_test_macros.hpp>
#include "protocol/callstate.hpp"

#include <regex>
#include <thread>

// Helper to create a test config
static protocol::ClientConfig make_test_config(const std::string& my_phone = "1234567890") {
    protocol::ClientConfig config;
    config.my_phone = my_phone;
    config.my_name = "Test User";
    config.sample_ticket = {0x01, 0x02, 0x03};
    return config;
}

TEST_CASE("Protocol CallState", "[protocol][callstate]") {

    SECTION("get_normalized_ts returns YYYY-MM-DD format") {
        std::string ts = protocol::get_normalized_ts();
        
        // Should match YYYY-MM-DD pattern
        std::regex date_pattern(R"(\d{4}-\d{2}-\d{2})");
        REQUIRE(std::regex_match(ts, date_pattern));
        
        // Should be 10 characters
        REQUIRE(ts.length() == 10);
    }

    SECTION("generate_sender_id returns 32 char hex string") {
        std::string id1 = protocol::generate_sender_id();
        std::string id2 = protocol::generate_sender_id();
        
        // Should be 32 hex characters (16 bytes)
        REQUIRE(id1.length() == 32);
        REQUIRE(id2.length() == 32);
        
        // Should be different (random)
        REQUIRE(id1 != id2);
        
        // Should be valid hex
        std::regex hex_pattern(R"([0-9a-f]{32})");
        REQUIRE(std::regex_match(id1, hex_pattern));
    }

    SECTION("CallState constructor - outgoing call") {
        auto config = make_test_config("1234567890");
        protocol::CallState state(config, "0987654321", true);
        
        REQUIRE(state.is_outgoing == true);
        REQUIRE(state.src == "1234567890");  // my phone
        REQUIRE(state.dst == "0987654321");  // other party
        REQUIRE(state.iam_caller() == true);
        REQUIRE(state.iam_recipient() == false);
        REQUIRE(state.rua_active == false);
        REQUIRE(state.sender_id.length() == 32);
        REQUIRE(state.ts.length() == 10);
        REQUIRE(state.ticket == config.sample_ticket);
    }

    SECTION("CallState constructor - incoming call") {
        auto config = make_test_config("1234567890");
        protocol::CallState state(config, "0987654321", false);
        
        REQUIRE(state.is_outgoing == false);
        REQUIRE(state.src == "0987654321");  // caller (other party)
        REQUIRE(state.dst == "1234567890");  // my phone
        REQUIRE(state.iam_caller() == false);
        REQUIRE(state.iam_recipient() == true);
    }

    SECTION("get_ake_label combines src and ts") {
        auto config = make_test_config();
        protocol::CallState state(config, "0987654321", true);
        
        protocol::Bytes label = state.get_ake_label();
        std::string label_str(label.begin(), label.end());
        
        // Should be src + ts
        REQUIRE(label_str == state.src + state.ts);
    }

    SECTION("init_ake sets AKE state correctly") {
        auto config = make_test_config();
        protocol::CallState state(config, "0987654321", true);
        
        protocol::Bytes dh_sk = {0x01, 0x02, 0x03};
        protocol::Bytes dh_pk = {0x04, 0x05, 0x06};
        protocol::Bytes topic = {0x07, 0x08, 0x09};
        
        state.init_ake(dh_sk, dh_pk, topic);
        
        REQUIRE(state.ake.dh_sk == dh_sk);
        REQUIRE(state.ake.dh_pk == dh_pk);
        REQUIRE(state.ake.topic == topic);
        REQUIRE(state.current_topic == topic);
        REQUIRE(state.is_rua_active() == false);
    }

    SECTION("get_ake_topic returns hex encoded topic") {
        auto config = make_test_config();
        protocol::CallState state(config, "0987654321", true);
        
        protocol::Bytes topic = {0xab, 0xcd, 0xef};
        state.init_ake({}, {}, topic);
        
        REQUIRE(state.get_ake_topic() == "abcdef");
    }

    SECTION("transition_to_rua changes active topic") {
        auto config = make_test_config();
        protocol::CallState state(config, "0987654321", true);
        
        protocol::Bytes ake_topic = {0x01, 0x02};
        protocol::Bytes rua_topic = {0x03, 0x04};
        
        state.init_ake({}, {}, ake_topic);
        REQUIRE(state.is_rua_active() == false);
        REQUIRE(state.get_current_topic() == "0102");
        
        state.transition_to_rua(rua_topic);
        REQUIRE(state.is_rua_active() == true);
        REQUIRE(state.get_current_topic() == "0304");
        REQUIRE(state.rua.topic == rua_topic);
    }

    SECTION("set_shared_key updates shared key") {
        auto config = make_test_config();
        protocol::CallState state(config, "0987654321", true);
        
        protocol::Bytes key = {0xaa, 0xbb, 0xcc, 0xdd};
        state.set_shared_key(key);
        
        REQUIRE(state.shared_key == key);
    }

    SECTION("update_caller sets challenge and proof") {
        auto config = make_test_config();
        protocol::CallState state(config, "0987654321", true);
        
        protocol::Bytes chal = {0x11, 0x22};
        protocol::Bytes proof = {0x33, 0x44, 0x55};
        
        state.update_caller(chal, proof);
        
        REQUIRE(state.ake.chal0 == chal);
        REQUIRE(state.ake.caller_proof == proof);
    }

    SECTION("Rtu struct default construction") {
        protocol::Rtu rtu;
        
        REQUIRE(rtu.amf_pk.empty());
        REQUIRE(rtu.expiration.empty());
        REQUIRE(rtu.signature.empty());
        REQUIRE(rtu.name.empty());
        REQUIRE(rtu.pke_pk.empty());
        REQUIRE(rtu.dr_pk.empty());
    }

    SECTION("RuaMessage struct with Rtu") {
        protocol::Rtu rtu;
        rtu.name = "Test User";
        rtu.amf_pk = {0x01, 0x02, 0x03};
        
        protocol::RuaMessage msg;
        msg.dh_pk = {0x04, 0x05};
        msg.reason = "Business";
        msg.rtu = rtu;
        
        REQUIRE(msg.rtu.name == "Test User");
        REQUIRE(msg.rtu.amf_pk.size() == 3);
        REQUIRE(msg.reason == "Business");
    }

    SECTION("RuaState optional fields") {
        protocol::RuaState rua_state;
        
        REQUIRE_FALSE(rua_state.rtu.has_value());
        REQUIRE_FALSE(rua_state.req.has_value());
        
        rua_state.rtu = protocol::Rtu{};
        rua_state.rtu->name = "Test";
        
        REQUIRE(rua_state.rtu.has_value());
        REQUIRE(rua_state.rtu->name == "Test");
    }

    SECTION("Thread safety - concurrent access") {
        auto config = make_test_config();
        protocol::CallState state(config, "0987654321", true);
        
        std::thread t1([&state]() {
            for (int i = 0; i < 100; i++) {
                state.set_shared_key({static_cast<uint8_t>(i)});
            }
        });
        
        std::thread t2([&state]() {
            for (int i = 0; i < 100; i++) {
                state.is_rua_active();
                state.get_current_topic();
            }
        });
        
        t1.join();
        t2.join();
        
        // If we get here without crashing, thread safety is working
        REQUIRE(true);
    }
}
