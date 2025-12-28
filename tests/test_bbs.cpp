// test_bbs.cpp
#include <catch2/catch_test_macros.hpp>

#include "crypto/ecgroup.hpp"
#include "crypto/bbs.hpp"

#include <vector>
#include <string>
#include <utility>
#include <stdexcept>

static ecgroup::Scalar nonzero_e_avoiding(const ecgroup::Scalar& sk, int salt = 0) {
    // Find an e such that sk + e != 0
    for (int i = 0; i < 8; ++i) {
        auto e = ecgroup::Scalar::hash_to_scalar("bbs_test_e_" + std::to_string(salt + i));
        if (!((sk + e) == ecgroup::Scalar())) return e;
    }
    // Fallback: random
    auto e = ecgroup::Scalar::get_random();
    if ((sk + e) == ecgroup::Scalar()) {
        // nudge deterministically
        e = e + ecgroup::Scalar::hash_to_scalar("bbs_nudge");
    }
    return e;
}

TEST_CASE("BBS (compact) sign/verify and selective disclosure", "[bbs]") {
    ecgroup::init_pairing();

    bbs::Params params = bbs::Params::Default();
    bbs::KeyPair issuer = bbs::keygen(params);

    // Build a message vector of length L
    const std::size_t L = 5;
    std::vector<ecgroup::Scalar> msgs(L);
    for (auto& m : msgs) m = ecgroup::Scalar::get_random();

    SECTION("Sign & Verify succeed") {
        bbs::Signature sig = bbs::sign(params, issuer.sk, msgs);
        REQUIRE(bbs::verify(params, issuer.pk, msgs, sig));
    }

    SECTION("Verify fails on tampered message") {
        bbs::Signature sig = bbs::sign(params, issuer.sk, msgs);
        REQUIRE(bbs::verify(params, issuer.pk, msgs, sig));

        // Tamper one message
        auto msgs_bad = msgs;
        msgs_bad[2] = msgs_bad[2] + ecgroup::Scalar::hash_to_scalar("delta");
        REQUIRE_FALSE(bbs::verify(params, issuer.pk, msgs_bad, sig));
    }

    SECTION("Deterministic e via sign_with_e") {
        ecgroup::Scalar e = nonzero_e_avoiding(issuer.sk);
        bbs::Signature sig = bbs::sign_with_e(params, issuer.sk, msgs, e);
        REQUIRE(sig.e == e);
        REQUIRE(bbs::verify(params, issuer.pk, msgs, sig));
    }

    SECTION("Signature serialization roundtrip") {
        bbs::Signature sig = bbs::sign(params, issuer.sk, msgs);
        auto ser = sig.to_bytes();
        REQUIRE(!ser.empty());

        bbs::Signature dec = bbs::Signature::from_bytes(ser);
        REQUIRE(dec.A == sig.A);
        REQUIRE(dec.e == sig.e);
        REQUIRE(bbs::verify(params, issuer.pk, msgs, dec));

        // Trailing data should be rejected
        auto bad = ser;
        bad.push_back(0x00);
        REQUIRE_THROWS_AS(bbs::Signature::from_bytes(bad), std::runtime_error);
    }

    SECTION("Selective disclosure: reveal none (k=0)") {
        bbs::Signature sig = bbs::sign(params, issuer.sk, msgs);

        std::vector<std::size_t> disclose; // empty
        std::string nonce = "proof-nonce-k0";
        bbs::SDProof prf = bbs::create_proof(params, issuer.pk, sig, msgs, disclose, nonce);

        std::vector<std::pair<std::size_t, ecgroup::Scalar>> disclosed_vals; // none
        REQUIRE(bbs::verify_proof(params, issuer.pk, prf, disclosed_vals, L));
    }

    SECTION("Selective disclosure: reveal a subset (e.g., {1,3})") {
        bbs::Signature sig = bbs::sign(params, issuer.sk, msgs);

        std::vector<std::size_t> disclose = {3, 1}; // intentionally unsorted
        std::string nonce = "proof-nonce-subset";
        bbs::SDProof prf = bbs::create_proof(params, issuer.pk, sig, msgs, disclose, nonce);

        // Verifier knows the disclosed values (order doesn't matter)
        std::vector<std::pair<std::size_t, ecgroup::Scalar>> disclosed_vals = {
            {1, msgs[0]}, {3, msgs[2]}
        };
        REQUIRE(bbs::verify_proof(params, issuer.pk, prf, disclosed_vals, L));
    }

    SECTION("Selective disclosure: wrong disclosed value should fail") {
        bbs::Signature sig = bbs::sign(params, issuer.sk, msgs);

        std::vector<std::size_t> disclose = {2, 5};
        std::string nonce = "proof-nonce-wrongval";
        bbs::SDProof prf = bbs::create_proof(params, issuer.pk, sig, msgs, disclose, nonce);

        // Corrupt m5
        auto wrong = msgs[4] + ecgroup::Scalar::hash_to_scalar("oops");
        std::vector<std::pair<std::size_t, ecgroup::Scalar>> disclosed_vals = {
            {2, msgs[1]}, {5, wrong}
        };
        REQUIRE_FALSE(bbs::verify_proof(params, issuer.pk, prf, disclosed_vals, L));
    }

    SECTION("Selective disclosure: different nonce should fail") {
        bbs::Signature sig = bbs::sign(params, issuer.sk, msgs);

        std::vector<std::size_t> disclose = {1, 4};
        std::string nonce = "proof-nonce-A";
        bbs::SDProof prf = bbs::create_proof(params, issuer.pk, sig, msgs, disclose, nonce);

        // Verifier replaces nonce by changing proof copy
        auto tam = prf;
        tam.nonce = "proof-nonce-B";

        std::vector<std::pair<std::size_t, ecgroup::Scalar>> disclosed_vals = {
            {1, msgs[0]}, {4, msgs[3]}
        };
        REQUIRE_FALSE(bbs::verify_proof(params, issuer.pk, tam, disclosed_vals, L));
        // Original still passes
        REQUIRE(bbs::verify_proof(params, issuer.pk, prf, disclosed_vals, L));
    }

    SECTION("Selective disclosure: wrong issuer pk should fail") {
        bbs::Signature sig = bbs::sign(params, issuer.sk, msgs);

        std::vector<std::size_t> disclose = {2};
        std::string nonce = "proof-nonce-pk";
        bbs::SDProof prf = bbs::create_proof(params, issuer.pk, sig, msgs, disclose, nonce);

        bbs::KeyPair other = bbs::keygen(params);

        std::vector<std::pair<std::size_t, ecgroup::Scalar>> disclosed_vals = {
            {2, msgs[1]}
        };
        REQUIRE_FALSE(bbs::verify_proof(params, other.pk, prf, disclosed_vals, L));
        REQUIRE(bbs::verify_proof(params, issuer.pk, prf, disclosed_vals, L));
    }

    SECTION("Selective disclosure: tamper with proof.A or proof.T should fail") {
        bbs::Signature sig = bbs::sign(params, issuer.sk, msgs);

        std::vector<std::size_t> disclose = {1, 3};
        std::string nonce = "proof-nonce-tamper";
        bbs::SDProof prf = bbs::create_proof(params, issuer.pk, sig, msgs, disclose, nonce);

        std::vector<std::pair<std::size_t, ecgroup::Scalar>> disclosed_vals = {
            {1, msgs[0]}, {3, msgs[2]}
        };

        // Tamper A
        auto tamA = prf;
        tamA.A = ecgroup::G1Point::get_random();
        REQUIRE_FALSE(bbs::verify_proof(params, issuer.pk, tamA, disclosed_vals, L));

        // Tamper T
        auto tamT = prf;
        tamT.T = tamT.T.pow(ecgroup::Scalar::get_random());
        REQUIRE_FALSE(bbs::verify_proof(params, issuer.pk, tamT, disclosed_vals, L));

        // Original passes
        REQUIRE(bbs::verify_proof(params, issuer.pk, prf, disclosed_vals, L));
    }

    SECTION("Selective disclosure: hidden vector/z_m size mismatch should fail") {
        bbs::Signature sig = bbs::sign(params, issuer.sk, msgs);

        std::vector<std::size_t> disclose = {2, 4};
        std::string nonce = "proof-nonce-size";
        bbs::SDProof prf = bbs::create_proof(params, issuer.pk, sig, msgs, disclose, nonce);

        std::vector<std::pair<std::size_t, ecgroup::Scalar>> disclosed_vals = {
            {2, msgs[1]}, {4, msgs[3]}
        };

        // Drop one z_m to corrupt sizes
        auto tam = prf;
        if (!tam.z_m.empty()) tam.z_m.pop_back();
        REQUIRE_FALSE(bbs::verify_proof(params, issuer.pk, tam, disclosed_vals, L));
        REQUIRE(bbs::verify_proof(params, issuer.pk, prf, disclosed_vals, L));
    }

    SECTION("SDProof serialization roundtrip (k=0)") {
        bbs::Signature sig = bbs::sign(params, issuer.sk, msgs);
        std::vector<std::size_t> disclose; // none
        std::string nonce = "serdes-k0";
        bbs::SDProof prf = bbs::create_proof(params, issuer.pk, sig, msgs, disclose, nonce);

        auto ser = prf.to_bytes();
        REQUIRE(!ser.empty());

        bbs::SDProof dec = bbs::SDProof::from_bytes(ser);
        // Basic field sanity
        REQUIRE(dec.A == prf.A);
        REQUIRE(dec.z_e == prf.z_e);
        REQUIRE(dec.hidden_indices.size() == prf.hidden_indices.size());
        REQUIRE(dec.z_m.size() == prf.z_m.size());

        std::vector<std::pair<std::size_t, ecgroup::Scalar>> disclosed_vals; // none
        REQUIRE(bbs::verify_proof(params, issuer.pk, dec, disclosed_vals, L));

        // Trailing data should be rejected
        auto bad = ser;
        bad.push_back(0x00);
        REQUIRE_THROWS_AS(bbs::SDProof::from_bytes(bad), std::runtime_error);
    }

    SECTION("SDProof serialization roundtrip (subset {1,3})") {
        bbs::Signature sig = bbs::sign(params, issuer.sk, msgs);
        std::vector<std::size_t> disclose = {1, 3};
        std::string nonce = "serdes-subset";
        bbs::SDProof prf = bbs::create_proof(params, issuer.pk, sig, msgs, disclose, nonce);

        auto ser = prf.to_bytes();
        bbs::SDProof dec = bbs::SDProof::from_bytes(ser);

        std::vector<std::pair<std::size_t, ecgroup::Scalar>> disclosed_vals = {
            {1, msgs[0]}, {3, msgs[2]}
        };
        REQUIRE(bbs::verify_proof(params, issuer.pk, dec, disclosed_vals, L));
    }
}
