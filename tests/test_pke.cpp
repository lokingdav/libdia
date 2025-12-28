#include <catch2/catch_test_macros.hpp>
#include "crypto/pke.hpp"

#include <string>

TEST_CASE("PKE - Public Key Encryption", "[crypto][pke]") {

    SECTION("keygen generates valid key pair") {
        auto kp = pke::keygen();
        
        REQUIRE(kp.private_key.size() == pke::PRIVATE_KEY_SIZE);
        REQUIRE(kp.public_key.size() == pke::PUBLIC_KEY_SIZE);
        
        // Keys should not be all zeros
        bool private_nonzero = false;
        bool public_nonzero = false;
        for (auto b : kp.private_key) if (b != 0) private_nonzero = true;
        for (auto b : kp.public_key) if (b != 0) public_nonzero = true;
        REQUIRE(private_nonzero);
        REQUIRE(public_nonzero);
    }

    SECTION("keygen produces different keys each time") {
        auto kp1 = pke::keygen();
        auto kp2 = pke::keygen();
        
        REQUIRE(kp1.private_key != kp2.private_key);
        REQUIRE(kp1.public_key != kp2.public_key);
    }

    SECTION("encrypt/decrypt roundtrip - short message") {
        auto kp = pke::keygen();
        
        std::string message = "Hello, World!";
        pke::Bytes plaintext(message.begin(), message.end());
        
        auto ciphertext = pke::encrypt(kp.public_key, plaintext);
        auto decrypted = pke::decrypt(kp, ciphertext);
        
        REQUIRE(decrypted == plaintext);
    }

    SECTION("encrypt/decrypt roundtrip - long message") {
        auto kp = pke::keygen();
        
        // 1KB of data
        pke::Bytes plaintext(1024);
        for (size_t i = 0; i < plaintext.size(); i++) {
            plaintext[i] = static_cast<uint8_t>(i & 0xFF);
        }
        
        auto ciphertext = pke::encrypt(kp.public_key, plaintext);
        auto decrypted = pke::decrypt(kp, ciphertext);
        
        REQUIRE(decrypted == plaintext);
    }

    SECTION("ciphertext has correct overhead") {
        auto kp = pke::keygen();
        
        pke::Bytes plaintext = {0x01, 0x02, 0x03, 0x04, 0x05};
        auto ciphertext = pke::encrypt(kp.public_key, plaintext);
        
        REQUIRE(ciphertext.size() == plaintext.size() + pke::SEAL_OVERHEAD);
    }

    SECTION("different encryptions produce different ciphertexts") {
        auto kp = pke::keygen();
        
        pke::Bytes plaintext = {0xDE, 0xAD, 0xBE, 0xEF};
        
        auto ct1 = pke::encrypt(kp.public_key, plaintext);
        auto ct2 = pke::encrypt(kp.public_key, plaintext);
        
        // Same plaintext should produce different ciphertext (due to ephemeral keys)
        REQUIRE(ct1 != ct2);
        
        // But both should decrypt to the same plaintext
        REQUIRE(pke::decrypt(kp, ct1) == plaintext);
        REQUIRE(pke::decrypt(kp, ct2) == plaintext);
    }

    SECTION("decrypt with wrong key fails") {
        auto kp1 = pke::keygen();
        auto kp2 = pke::keygen();
        
        pke::Bytes plaintext = {0x01, 0x02, 0x03};
        auto ciphertext = pke::encrypt(kp1.public_key, plaintext);
        
        // Decrypting with wrong key should throw
        REQUIRE_THROWS_AS(pke::decrypt(kp2, ciphertext), std::runtime_error);
    }

    SECTION("decrypt corrupted ciphertext fails") {
        auto kp = pke::keygen();
        
        pke::Bytes plaintext = {0x01, 0x02, 0x03};
        auto ciphertext = pke::encrypt(kp.public_key, plaintext);
        
        // Corrupt the ciphertext
        ciphertext[ciphertext.size() / 2] ^= 0xFF;
        
        REQUIRE_THROWS_AS(pke::decrypt(kp, ciphertext), std::runtime_error);
    }

    SECTION("encrypt throws on empty plaintext") {
        auto kp = pke::keygen();
        pke::Bytes empty;
        
        REQUIRE_THROWS_AS(pke::encrypt(kp.public_key, empty), std::invalid_argument);
    }

    SECTION("encrypt throws on invalid public key size") {
        pke::Bytes bad_key = {0x01, 0x02, 0x03};  // Too short
        pke::Bytes plaintext = {0x01, 0x02, 0x03};
        
        REQUIRE_THROWS_AS(pke::encrypt(bad_key, plaintext), std::invalid_argument);
    }

    SECTION("decrypt throws on ciphertext too short") {
        auto kp = pke::keygen();
        pke::Bytes too_short(10);  // Less than SEAL_OVERHEAD
        
        REQUIRE_THROWS_AS(pke::decrypt(kp, too_short), std::invalid_argument);
    }

    SECTION("decrypt throws on invalid key sizes") {
        pke::Bytes bad_key = {0x01, 0x02};
        pke::Bytes ciphertext(100);
        pke::Bytes good_key(32);
        
        REQUIRE_THROWS_AS(pke::decrypt(bad_key, good_key, ciphertext), std::invalid_argument);
        REQUIRE_THROWS_AS(pke::decrypt(good_key, bad_key, ciphertext), std::invalid_argument);
    }
}
