// test_amf.cpp
#include <catch2/catch_test_macros.hpp>

#include "crypto/ecgroup.hpp"
#include "crypto/amf.hpp"

#include <stdexcept> // for std::runtime_error

TEST_CASE("Asymmetric Message Franking (AMF)", "[amf]") {
    // Initialize underlying pairing library once.
    ecgroup::init_pairing();

    // System params
    amf::Params params = amf::Params::Default();
    REQUIRE_FALSE(params.g == ecgroup::G1Point()); // generator not identity

    // Parties
    amf::KeyPair S = amf::KeyGen(params); // sender
    amf::KeyPair R = amf::KeyGen(params); // receiver
    amf::KeyPair J = amf::KeyGen(params); // judge / moderator

    const std::string msg = "hello AMF";

    SECTION("Frank -> Verify & Judge succeed") {
        amf::Signature sig = amf::Frank(S.sk, R.pk, J.pk, msg, params);
        REQUIRE(amf::Verify(S.pk, R.sk, J.pk, msg, sig, params));
        REQUIRE(amf::Judge (S.pk, R.pk, J.sk, msg, sig, params));
    }

    SECTION("Public Forge: both Verify and Judge fail (designated checks broken)") {
        amf::Signature sigF = amf::Forge(S.pk, R.pk, J.pk, msg, params);
        REQUIRE_FALSE(amf::Verify(S.pk, R.sk, J.pk, msg, sigF, params));
        REQUIRE_FALSE(amf::Judge (S.pk, R.pk, J.sk, msg, sigF, params));
    }

    SECTION("Receiver-compromise RForge: Verify passes, Judge fails") {
        amf::Signature sigR = amf::RForge(S.pk, R.sk, J.pk, msg, params);
        REQUIRE(     amf::Verify(S.pk, R.sk, J.pk, msg, sigR, params));
        REQUIRE_FALSE(amf::Judge (S.pk, R.pk, J.sk, msg, sigR, params));
    }

    SECTION("Judge-compromise JForge: both Verify and Judge pass") {
        amf::Signature sigJ = amf::JForge(S.pk, R.pk, J.sk, msg, params);
        REQUIRE(amf::Verify(S.pk, R.sk, J.pk, msg, sigJ, params));
        REQUIRE(amf::Judge (S.pk, R.pk, J.sk, msg, sigJ, params));
    }

    SECTION("Message binding: different message should fail") {
        amf::Signature sig = amf::Frank(S.sk, R.pk, J.pk, msg, params);
        const std::string other = "different message";
        REQUIRE_FALSE(amf::Verify(S.pk, R.sk, J.pk, other, sig, params));
        REQUIRE_FALSE(amf::Judge (S.pk, R.pk, J.sk, other, sig, params));
    }

    SECTION("pk_s binding: wrong sender public key should fail") {
        amf::Signature sig = amf::Frank(S.sk, R.pk, J.pk, msg, params);
        amf::KeyPair S_bad = amf::KeyGen(params);
        REQUIRE_FALSE(amf::Verify(S_bad.pk, R.sk, J.pk, msg, sig, params));
        REQUIRE_FALSE(amf::Judge (S_bad.pk, R.pk, J.sk, msg, sig, params));
    }

    SECTION("Receiver secret mismatch fails Verify") {
        amf::Signature sig = amf::Frank(S.sk, R.pk, J.pk, msg, params);
        amf::KeyPair R_other = amf::KeyGen(params);
        REQUIRE_FALSE(amf::Verify(S.pk, R_other.sk, J.pk, msg, sig, params));
        // Judge check is independent of sk_r; it should still pass here.
        REQUIRE(amf::Judge(S.pk, R.pk, J.sk, msg, sig, params));
    }

    SECTION("Tamper with B breaks Verify’s designated check") {
        amf::Signature sig = amf::Frank(S.sk, R.pk, J.pk, msg, params);
        amf::Signature tam = sig;
        // Overwrite B with unrelated value
        ecgroup::Scalar rnd = ecgroup::Scalar::get_random();
        tam.B = ecgroup::G1Point::mul(params.g, rnd);
        REQUIRE_FALSE(amf::Verify(S.pk, R.sk, J.pk, msg, tam, params));
        // Original (untampered) still fine
        REQUIRE(amf::Verify(S.pk, R.sk, J.pk, msg, sig, params));
    }

    SECTION("Tamper with A breaks Judge's designated check") {
        amf::Signature sig = amf::Frank(S.sk, R.pk, J.pk, msg, params);
        amf::Signature tam = sig;
        ecgroup::Scalar rnd = ecgroup::Scalar::get_random();
        tam.A = ecgroup::G1Point::mul(params.g, rnd);
        REQUIRE_FALSE(amf::Judge(S.pk, R.pk, J.sk, msg, tam, params));
        // Original (untampered) still fine
        REQUIRE(amf::Judge(S.pk, R.pk, J.sk, msg, sig, params));
    }

    SECTION("Freshness: two Franks produce different (A,B) with overwhelming probability") {
        amf::Signature s1 = amf::Frank(S.sk, R.pk, J.pk, msg, params);
        amf::Signature s2 = amf::Frank(S.sk, R.pk, J.pk, msg, params);

        // Not both A and B should be equal.
        bool bothEqual = (s1.A == s2.A) && (s1.B == s2.B);
        REQUIRE_FALSE(bothEqual);
    }

    /* ---------------------- Serialization tests ---------------------- */

    SECTION("AMF signature serialization roundtrip") {
        amf::Signature sig = amf::Frank(S.sk, R.pk, J.pk, msg, params);

        ecgroup::Bytes ser = sig.to_bytes();
        REQUIRE(!ser.empty());

        amf::Signature dec = amf::Signature::from_bytes(ser);

        // Decoded signature verifies and judges for the same message/keys
        REQUIRE(amf::Verify(S.pk, R.sk, J.pk, msg, dec, params));
        REQUIRE(amf::Judge (S.pk, R.pk, J.sk, msg, dec, params));

        // Trailing byte -> should throw
        auto bad = ser;
        bad.push_back(0x00);
        REQUIRE_THROWS_AS(amf::Signature::from_bytes(bad), std::runtime_error);

        // Truncation -> should throw
        auto trunc = ser;
        trunc.pop_back();
        REQUIRE_THROWS_AS(amf::Signature::from_bytes(trunc), std::runtime_error);

        // Bad magic -> should throw
        auto badmagic = ser;
        badmagic[0] ^= 0xFF;
        REQUIRE_THROWS_AS(amf::Signature::from_bytes(badmagic), std::runtime_error);
    }
}
