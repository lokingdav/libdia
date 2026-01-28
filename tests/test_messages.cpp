#include <catch2/catch_test_macros.hpp>
#include "protocol/messages.hpp"
#include "protocol/accesstoken.hpp"
#include "crypto/voprf.hpp"
#include "crypto/ecgroup.hpp"
#include "helpers.hpp"

TEST_CASE("Protocol Messages", "[protocol][messages]") {

    SECTION("MessageType enum values") {
        REQUIRE(static_cast<uint8_t>(protocol::MessageType::Unspecified) == 0);
        REQUIRE(static_cast<uint8_t>(protocol::MessageType::AkeRequest) == 1);
        REQUIRE(static_cast<uint8_t>(protocol::MessageType::AkeResponse) == 2);
        REQUIRE(static_cast<uint8_t>(protocol::MessageType::AkeComplete) == 3);
        REQUIRE(static_cast<uint8_t>(protocol::MessageType::RuaRequest) == 4);
        REQUIRE(static_cast<uint8_t>(protocol::MessageType::RuaResponse) == 5);
        REQUIRE(static_cast<uint8_t>(protocol::MessageType::Heartbeat) == 6);
        REQUIRE(static_cast<uint8_t>(protocol::MessageType::Bye) == 7);
    }

    SECTION("Rtu serialize/deserialize roundtrip") {
        protocol::Rtu original;
        original.amf_pk = {0x01, 0x02, 0x03};
        original.expiration = {0x04, 0x05};
        original.signature = {0x06, 0x07, 0x08, 0x09};
        original.name = "Test User";
        original.pke_pk = {0x0a, 0x0b};
        original.dr_pk = {0x0c, 0x0d, 0x0e};

        auto serialized = original.serialize();
        auto restored = protocol::Rtu::deserialize(serialized);

        REQUIRE(restored.amf_pk == original.amf_pk);
        REQUIRE(restored.expiration == original.expiration);
        REQUIRE(restored.signature == original.signature);
        REQUIRE(restored.name == original.name);
        REQUIRE(restored.pke_pk == original.pke_pk);
        REQUIRE(restored.dr_pk == original.dr_pk);
    }

    SECTION("AkeMessage serialize/deserialize roundtrip") {
        protocol::AkeMessage original;
        original.dh_pk = {0x11, 0x22, 0x33};
        original.amf_pk = {0x44, 0x55};
        original.expiration = {0x66};
        original.proof = {0x77, 0x88, 0x99, 0xaa};
        original.pke_pk = {0xbb, 0xcc};
        original.dr_pk = {0xdd, 0xee, 0xff};

        auto serialized = original.serialize();
        auto restored = protocol::AkeMessage::deserialize(serialized);

        REQUIRE(restored.dh_pk == original.dh_pk);
        REQUIRE(restored.amf_pk == original.amf_pk);
        REQUIRE(restored.expiration == original.expiration);
        REQUIRE(restored.proof == original.proof);
        REQUIRE(restored.pke_pk == original.pke_pk);
        REQUIRE(restored.dr_pk == original.dr_pk);
    }

    SECTION("RuaMessage serialize/deserialize roundtrip") {
        protocol::RuaMessage original;
        original.dh_pk = {0x01, 0x02};
        original.reason = "Business Call";
        original.rtu.amf_pk = {0x03, 0x04};
        original.rtu.name = "Alice";
        original.tpc = "topic123";
        original.misc = {0x05};
        original.sigma = {0x06, 0x07, 0x08};

        auto serialized = original.serialize();
        auto restored = protocol::RuaMessage::deserialize(serialized);

        REQUIRE(restored.dh_pk == original.dh_pk);
        REQUIRE(restored.reason == original.reason);
        REQUIRE(restored.rtu.amf_pk == original.rtu.amf_pk);
        REQUIRE(restored.rtu.name == original.rtu.name);
        REQUIRE(restored.tpc == original.tpc);
        REQUIRE(restored.misc == original.misc);
        REQUIRE(restored.sigma == original.sigma);
    }

    SECTION("RuaMessage serialize_for_signing excludes sigma") {
        protocol::RuaMessage msg;
        msg.dh_pk = {0x01};
        msg.reason = "Test";
        msg.rtu.name = "Bob";
        msg.tpc = "topic";
        msg.misc = {0x99};
        msg.sigma = {0xaa, 0xbb, 0xcc};  // This should be excluded

        auto for_signing = msg.serialize_for_signing();
        auto full = msg.serialize();

        // The signing version should be shorter (no sigma, no misc)
        REQUIRE(for_signing.size() < full.size());
    }

    SECTION("ProtocolMessage serialize/deserialize roundtrip") {
        protocol::ProtocolMessage original;
        original.type = protocol::MessageType::AkeRequest;
        original.sender_id = "sender-abc-123";
        original.topic = "topic-xyz";
        original.payload = {0x01, 0x02, 0x03, 0x04};

        auto serialized = original.serialize();
        auto restored = protocol::ProtocolMessage::deserialize(serialized);

        REQUIRE(restored.type == original.type);
        REQUIRE(restored.sender_id == original.sender_id);
        REQUIRE(restored.topic == original.topic);
        REQUIRE(restored.payload == original.payload);
    }

    SECTION("ProtocolMessage type check helpers") {
        protocol::ProtocolMessage msg;
        
        msg.type = protocol::MessageType::AkeRequest;
        REQUIRE(msg.is_ake_request());
        REQUIRE_FALSE(msg.is_ake_response());
        
        msg.type = protocol::MessageType::AkeResponse;
        REQUIRE(msg.is_ake_response());
        
        msg.type = protocol::MessageType::AkeComplete;
        REQUIRE(msg.is_ake_complete());
        
        msg.type = protocol::MessageType::RuaRequest;
        REQUIRE(msg.is_rua_request());
        
        msg.type = protocol::MessageType::RuaResponse;
        REQUIRE(msg.is_rua_response());
        
        msg.type = protocol::MessageType::Heartbeat;
        REQUIRE(msg.is_heartbeat());
        
        msg.type = protocol::MessageType::Bye;
        REQUIRE(msg.is_bye());
    }

    SECTION("ProtocolMessage throws on unspecified type") {
        protocol::ProtocolMessage msg;
        msg.type = protocol::MessageType::Unspecified;
        msg.sender_id = "test";
        
        REQUIRE_THROWS_AS(msg.serialize(), std::runtime_error);
    }

    SECTION("ProtocolMessage throws on empty data") {
        protocol::Bytes empty;
        REQUIRE_THROWS_AS(protocol::ProtocolMessage::deserialize(empty), std::runtime_error);
    }

    SECTION("create_bye_message") {
        auto msg = protocol::create_bye_message("sender123", "topic456");
        
        REQUIRE(msg.type == protocol::MessageType::Bye);
        REQUIRE(msg.sender_id == "sender123");
        REQUIRE(msg.topic == "topic456");
        REQUIRE(msg.payload.empty());
    }

    SECTION("create_heartbeat_message") {
        auto msg = protocol::create_heartbeat_message("sender789", "topicABC");
        
        REQUIRE(msg.type == protocol::MessageType::Heartbeat);
        REQUIRE(msg.sender_id == "sender789");
        REQUIRE(msg.topic == "topicABC");
        REQUIRE(msg.payload.empty());
    }

    SECTION("create_message_mac is deterministic and sensitive to data") {
        protocol::Bytes token = {0x01, 0x02, 0x03, 0x04};
        protocol::Bytes data1 = {0x0a, 0x0b, 0x0c};
        protocol::Bytes data2 = {0x0a, 0x0b, 0x0d};

        auto mac1 = protocol::create_message_mac(token, data1);
        auto mac2 = protocol::create_message_mac(token, data1);
        auto mac3 = protocol::create_message_mac(token, data2);

        REQUIRE(mac1 == mac2);
        REQUIRE(mac1 != mac3);
    }

    SECTION("verify_message_mac succeeds for matching inputs") {
        // token_preimage must match the 32-byte token used by AccessToken (t1)
        protocol::Bytes token_preimage(32, 0x11);
        protocol::Bytes data = {0x01, 0x02, 0x03, 0x04};

        // Derive VOPRF keypair and evaluated token to build token = preimage || evaluated
        auto kp = voprf::keygen();
        auto eval = protocol::accesstoken::evaluate_blinded_access_token(
            kp.sk.to_bytes(),
            ecgroup::G1Point::hash_and_map_to(
                std::string(token_preimage.begin(), token_preimage.end())
            ).to_bytes()
        );

        protocol::Bytes token = dia::utils::concat_bytes(token_preimage, eval);
        auto mac = protocol::create_message_mac(token, data);

        REQUIRE(protocol::verify_message_mac(kp.sk.to_bytes(), token_preimage, data, mac));
    }

    SECTION("verify_message_mac fails for wrong mac or data") {
        protocol::Bytes token_preimage(32, 0x22);
        protocol::Bytes data = {0x09, 0x08, 0x07};

        auto kp = voprf::keygen();

        // Correct mac
        auto eval = protocol::accesstoken::evaluate_blinded_access_token(
            kp.sk.to_bytes(),
            ecgroup::G1Point::hash_and_map_to(
                std::string(token_preimage.begin(), token_preimage.end())
            ).to_bytes()
        );
        protocol::Bytes token = dia::utils::concat_bytes(token_preimage, eval);
        auto mac = protocol::create_message_mac(token, data);

        // Tampered mac
        protocol::Bytes mac_bad = mac;
        mac_bad[0] ^= 0xFF;

        REQUIRE_FALSE(protocol::verify_message_mac(kp.sk.to_bytes(), token_preimage, data, mac_bad));

        // Wrong data
        protocol::Bytes data_bad = {0x09, 0x08, 0x06};
        REQUIRE_FALSE(protocol::verify_message_mac(kp.sk.to_bytes(), token_preimage, data_bad, mac));
    }

    SECTION("Empty fields serialize/deserialize correctly") {
        protocol::Rtu rtu;
        // All fields empty
        auto serialized = rtu.serialize();
        auto restored = protocol::Rtu::deserialize(serialized);
        
        REQUIRE(restored.amf_pk.empty());
        REQUIRE(restored.name.empty());
    }
}
