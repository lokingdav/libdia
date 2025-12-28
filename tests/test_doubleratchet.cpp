#include <catch2/catch_test_macros.hpp>
#include "../src/crypto/doubleratchet.hpp"
#include <sodium.h>
#include <string>

using namespace doubleratchet;

// Helper to generate a random 32-byte key
static Bytes random_key() {
    Bytes key(32);
    randombytes_buf(key.data(), key.size());
    return key;
}

TEST_CASE("keygen generates valid key pair", "[doubleratchet]") {
    auto kp = keygen();
    REQUIRE(kp.public_key.size() == 32);
    REQUIRE(kp.private_key.size() == 32);
    
    // Keys should be different
    REQUIRE(kp.public_key != kp.private_key);
    
    // Generate another - should be different
    auto kp2 = keygen();
    REQUIRE(kp.public_key != kp2.public_key);
    REQUIRE(kp.private_key != kp2.private_key);
}

TEST_CASE("DrHeader serialization", "[doubleratchet]") {
    DrHeader header;
    header.dh = random_key();
    header.n = 42;
    header.pn = 7;
    
    Bytes serialized = header.serialize();
    REQUIRE(serialized.size() == 32 + 4 + 4);  // 32 bytes DH + 4 bytes n + 4 bytes pn
    
    DrHeader deserialized = DrHeader::deserialize(serialized);
    REQUIRE(deserialized.dh == header.dh);
    REQUIRE(deserialized.n == header.n);
    REQUIRE(deserialized.pn == header.pn);
}

TEST_CASE("DrMessage serialization", "[doubleratchet]") {
    DrMessage msg;
    msg.header.dh = random_key();
    msg.header.n = 100;
    msg.header.pn = 50;
    msg.ciphertext = {0x01, 0x02, 0x03, 0x04, 0x05};
    
    Bytes serialized = msg.serialize();
    DrMessage deserialized = DrMessage::deserialize(serialized);
    
    REQUIRE(deserialized.header.dh == msg.header.dh);
    REQUIRE(deserialized.header.n == msg.header.n);
    REQUIRE(deserialized.header.pn == msg.header.pn);
    REQUIRE(deserialized.ciphertext == msg.ciphertext);
}

TEST_CASE("DrSession basic encrypt/decrypt", "[doubleratchet]") {
    // Simulate key exchange: both parties agree on a shared key
    Bytes shared_key = random_key();
    
    // Recipient generates their DR key pair using keygen()
    auto recipient_kp = keygen();
    
    // Initialize sessions
    auto recipient_session = DrSession::init_as_recipient(
        shared_key, recipient_kp.private_key, recipient_kp.public_key);
    
    auto caller_session = DrSession::init_as_caller(
        shared_key, recipient_kp.public_key);
    
    SECTION("Caller sends first message") {
        std::string plaintext_str = "Hello, recipient!";
        Bytes plaintext(plaintext_str.begin(), plaintext_str.end());
        
        // Caller encrypts (returns Bytes)
        Bytes msg = caller_session->encrypt(plaintext);
        
        // Recipient decrypts (takes Bytes)
        Bytes decrypted = recipient_session->decrypt(msg);
        
        REQUIRE(decrypted == plaintext);
    }
    
    SECTION("Multiple messages from caller") {
        std::vector<std::string> messages = {
            "Message 1",
            "Message 2",
            "Message 3"
        };
        
        for (const auto& msg_str : messages) {
            Bytes plaintext(msg_str.begin(), msg_str.end());
            Bytes msg = caller_session->encrypt(plaintext);
            Bytes decrypted = recipient_session->decrypt(msg);
            REQUIRE(decrypted == plaintext);
        }
    }
}

TEST_CASE("DrSession bidirectional communication", "[doubleratchet]") {
    Bytes shared_key = random_key();
    
    auto recipient_kp = keygen();
    
    auto recipient_session = DrSession::init_as_recipient(
        shared_key, recipient_kp.private_key, recipient_kp.public_key);
    
    auto caller_session = DrSession::init_as_caller(
        shared_key, recipient_kp.public_key);
    
    // Caller sends first
    std::string msg1_str = "Hello from caller";
    Bytes msg1_pt(msg1_str.begin(), msg1_str.end());
    Bytes msg1 = caller_session->encrypt(msg1_pt);
    Bytes decrypted1 = recipient_session->decrypt(msg1);
    REQUIRE(decrypted1 == msg1_pt);
    
    // Recipient replies (triggers DH ratchet)
    std::string msg2_str = "Hello from recipient";
    Bytes msg2_pt(msg2_str.begin(), msg2_str.end());
    Bytes msg2 = recipient_session->encrypt(msg2_pt);
    Bytes decrypted2 = caller_session->decrypt(msg2);
    REQUIRE(decrypted2 == msg2_pt);
    
    // Caller sends again (another DH ratchet)
    std::string msg3_str = "Caller speaking again";
    Bytes msg3_pt(msg3_str.begin(), msg3_str.end());
    Bytes msg3 = caller_session->encrypt(msg3_pt);
    Bytes decrypted3 = recipient_session->decrypt(msg3);
    REQUIRE(decrypted3 == msg3_pt);
    
    // Multiple back-and-forth
    for (int i = 0; i < 5; i++) {
        std::string from_recipient = "From recipient #" + std::to_string(i);
        Bytes pt_r(from_recipient.begin(), from_recipient.end());
        Bytes msg_r = recipient_session->encrypt(pt_r);
        REQUIRE(caller_session->decrypt(msg_r) == pt_r);
        
        std::string from_caller = "From caller #" + std::to_string(i);
        Bytes pt_c(from_caller.begin(), from_caller.end());
        Bytes msg_c = caller_session->encrypt(pt_c);
        REQUIRE(recipient_session->decrypt(msg_c) == pt_c);
    }
}

TEST_CASE("DrSession with associated data", "[doubleratchet]") {
    Bytes shared_key = random_key();
    
    auto recipient_kp = keygen();
    
    auto recipient_session = DrSession::init_as_recipient(
        shared_key, recipient_kp.private_key, recipient_kp.public_key);
    
    auto caller_session = DrSession::init_as_caller(
        shared_key, recipient_kp.public_key);
    
    std::string plaintext_str = "Secret message";
    Bytes plaintext(plaintext_str.begin(), plaintext_str.end());
    
    std::string ad_str = "session-123";
    Bytes associated_data(ad_str.begin(), ad_str.end());
    
    Bytes msg = caller_session->encrypt(plaintext, associated_data);
    
    // Correct associated data
    Bytes decrypted = recipient_session->decrypt(msg, associated_data);
    REQUIRE(decrypted == plaintext);
}

TEST_CASE("DrSession with wrong associated data fails", "[doubleratchet]") {
    Bytes shared_key = random_key();
    
    auto recipient_kp = keygen();
    
    auto recipient_session = DrSession::init_as_recipient(
        shared_key, recipient_kp.private_key, recipient_kp.public_key);
    
    auto caller_session = DrSession::init_as_caller(
        shared_key, recipient_kp.public_key);
    
    std::string plaintext_str = "Secret message";
    Bytes plaintext(plaintext_str.begin(), plaintext_str.end());
    
    Bytes correct_ad = {'a', 'b', 'c'};
    Bytes wrong_ad = {'x', 'y', 'z'};
    
    Bytes msg = caller_session->encrypt(plaintext, correct_ad);
    
    // Wrong associated data should fail
    REQUIRE_THROWS_AS(recipient_session->decrypt(msg, wrong_ad), std::runtime_error);
}

TEST_CASE("DrSession out-of-order messages", "[doubleratchet]") {
    Bytes shared_key = random_key();
    
    auto recipient_kp = keygen();
    
    auto recipient_session = DrSession::init_as_recipient(
        shared_key, recipient_kp.private_key, recipient_kp.public_key);
    
    auto caller_session = DrSession::init_as_caller(
        shared_key, recipient_kp.public_key);
    
    // Caller sends 3 messages
    std::string msg1_str = "Message 1";
    std::string msg2_str = "Message 2";
    std::string msg3_str = "Message 3";
    
    Bytes pt1(msg1_str.begin(), msg1_str.end());
    Bytes pt2(msg2_str.begin(), msg2_str.end());
    Bytes pt3(msg3_str.begin(), msg3_str.end());
    
    Bytes encrypted1 = caller_session->encrypt(pt1);
    Bytes encrypted2 = caller_session->encrypt(pt2);
    Bytes encrypted3 = caller_session->encrypt(pt3);
    
    // Recipient receives them out of order: 1, 3, 2
    Bytes decrypted1 = recipient_session->decrypt(encrypted1);
    REQUIRE(decrypted1 == pt1);
    
    Bytes decrypted3 = recipient_session->decrypt(encrypted3);
    REQUIRE(decrypted3 == pt3);
    
    Bytes decrypted2 = recipient_session->decrypt(encrypted2);
    REQUIRE(decrypted2 == pt2);
}

TEST_CASE("DrSession invalid inputs", "[doubleratchet]") {
    SECTION("Wrong shared key size") {
        Bytes wrong_size = {0x01, 0x02, 0x03};  // Too short
        auto recipient_kp = keygen();
        
        REQUIRE_THROWS_AS(
            DrSession::init_as_recipient(wrong_size, recipient_kp.private_key, recipient_kp.public_key),
            std::runtime_error);
        
        REQUIRE_THROWS_AS(
            DrSession::init_as_caller(wrong_size, recipient_kp.public_key),
            std::runtime_error);
    }
    
    SECTION("Wrong key sizes for recipient init") {
        Bytes shared_key = random_key();
        Bytes short_key = {0x01, 0x02};
        Bytes valid_key = random_key();
        
        REQUIRE_THROWS_AS(
            DrSession::init_as_recipient(shared_key, short_key, valid_key),
            std::runtime_error);
        
        REQUIRE_THROWS_AS(
            DrSession::init_as_recipient(shared_key, valid_key, short_key),
            std::runtime_error);
    }
}

TEST_CASE("DrSession large messages", "[doubleratchet]") {
    Bytes shared_key = random_key();
    
    auto recipient_kp = keygen();
    
    auto recipient_session = DrSession::init_as_recipient(
        shared_key, recipient_kp.private_key, recipient_kp.public_key);
    
    auto caller_session = DrSession::init_as_caller(
        shared_key, recipient_kp.public_key);
    
    // 1MB message
    Bytes large_message(1024 * 1024);
    randombytes_buf(large_message.data(), large_message.size());
    
    Bytes msg = caller_session->encrypt(large_message);
    Bytes decrypted = recipient_session->decrypt(msg);
    
    REQUIRE(decrypted == large_message);
}

TEST_CASE("DrSession empty message", "[doubleratchet]") {
    Bytes shared_key = random_key();
    
    auto recipient_kp = keygen();
    
    auto recipient_session = DrSession::init_as_recipient(
        shared_key, recipient_kp.private_key, recipient_kp.public_key);
    
    auto caller_session = DrSession::init_as_caller(
        shared_key, recipient_kp.public_key);
    
    Bytes empty_message;
    Bytes msg = caller_session->encrypt(empty_message);
    Bytes decrypted = recipient_session->decrypt(msg);
    
    REQUIRE(decrypted.empty());
}
