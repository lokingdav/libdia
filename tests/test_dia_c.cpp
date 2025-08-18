#include <catch2/catch_test_macros.hpp>
#include <vector>
#include <string>
#include <cstring>
#include <algorithm>

#include "dia/dia_c.h"   // C ABI

// Small helpers for building C-style inputs
static inline std::vector<const unsigned char*> to_ptrs(const std::vector<std::string>& v) {
    std::vector<const unsigned char*> out; out.reserve(v.size());
    for (auto &s : v) out.push_back(reinterpret_cast<const unsigned char*>(s.data()));
    return out;
}
static inline std::vector<size_t> to_lens(const std::vector<std::string>& v) {
    std::vector<size_t> out; out.reserve(v.size());
    for (auto &s : v) out.push_back(s.size());
    return out;
}
static inline std::vector<uint32_t> to_u32(const std::vector<size_t>& v) {
    std::vector<uint32_t> out; out.reserve(v.size());
    for (auto x : v) out.push_back(static_cast<uint32_t>(x));
    return out;
}

TEST_CASE("C ABI: VOPRF / AMF / BBS smoke tests", "[dia_c]") {
    init_dia();

    SECTION("VOPRF end-to-end") {
        unsigned char sk[DIA_FR_LEN], pk[DIA_G2_LEN];
        REQUIRE(dia_voprf_keygen(sk, pk) == DIA_OK);

        const std::string in = "hello voprf";
        unsigned char blinded[DIA_G1_LEN], blind[DIA_FR_LEN];
        REQUIRE(dia_voprf_blind(reinterpret_cast<const unsigned char*>(in.data()), in.size(),
                                blinded, blind) == DIA_OK);

        unsigned char element[DIA_G1_LEN];
        REQUIRE(dia_voprf_evaluate(blinded, sk, element) == DIA_OK);

        unsigned char Y[DIA_G1_LEN];
        REQUIRE(dia_voprf_unblind(element, blind, Y) == DIA_OK);

        // Single verify
        REQUIRE(dia_voprf_verify(reinterpret_cast<const unsigned char*>(in.data()), in.size(),
                                 Y, pk) == DIA_OK);

        // Batch verify (two items)
        std::vector<std::string> ins = {"alpha", "beta"};
        auto ptrs = to_ptrs(ins);
        auto lens = to_lens(ins);

        // compute Ys for both
        unsigned char blinded1[DIA_G1_LEN], blind1[DIA_FR_LEN];
        unsigned char blinded2[DIA_G1_LEN], blind2[DIA_FR_LEN];
        REQUIRE(dia_voprf_blind(reinterpret_cast<const unsigned char*>(ins[0].data()), ins[0].size(), blinded1, blind1) == DIA_OK);
        REQUIRE(dia_voprf_blind(reinterpret_cast<const unsigned char*>(ins[1].data()), ins[1].size(), blinded2, blind2) == DIA_OK);

        unsigned char elem1[DIA_G1_LEN], elem2[DIA_G1_LEN];
        REQUIRE(dia_voprf_evaluate(blinded1, sk, elem1) == DIA_OK);
        REQUIRE(dia_voprf_evaluate(blinded2, sk, elem2) == DIA_OK);

        unsigned char Y1[DIA_G1_LEN], Y2[DIA_G1_LEN];
        REQUIRE(dia_voprf_unblind(elem1, blind1, Y1) == DIA_OK);
        REQUIRE(dia_voprf_unblind(elem2, blind2, Y2) == DIA_OK);

        // Concatenate Y1||Y2 for the C API
        std::vector<unsigned char> Y_concat(DIA_G1_LEN * 2);
        std::memcpy(Y_concat.data(), Y1, DIA_G1_LEN);
        std::memcpy(Y_concat.data() + DIA_G1_LEN, Y2, DIA_G1_LEN);

        REQUIRE(dia_voprf_verify_batch(reinterpret_cast<const unsigned char* const*>(ptrs.data()),
                                       lens.data(), ins.size(),
                                       Y_concat.data(), pk) == DIA_OK);
    }

    SECTION("AMF: Frank -> Verify & Judge; plus negative cases") {
        // Keygen for three parties
        unsigned char S_sk[DIA_FR_LEN], S_pk[DIA_G1_LEN];
        unsigned char R_sk[DIA_FR_LEN], R_pk[DIA_G1_LEN];
        unsigned char J_sk[DIA_FR_LEN], J_pk[DIA_G1_LEN];
        REQUIRE(dia_amf_keygen(S_sk, S_pk) == DIA_OK);
        REQUIRE(dia_amf_keygen(R_sk, R_pk) == DIA_OK);
        REQUIRE(dia_amf_keygen(J_sk, J_pk) == DIA_OK);

        const std::string msg = "hello AMF";
        unsigned char* sig_blob = nullptr; size_t sig_len = 0;

        // Frank
        REQUIRE(dia_amf_frank(S_sk, R_pk, J_pk,
                              reinterpret_cast<const unsigned char*>(msg.data()), msg.size(),
                              &sig_blob, &sig_len) == DIA_OK);
        REQUIRE(sig_blob != nullptr);
        REQUIRE(sig_len > 0);

        // Verify & Judge success
        REQUIRE(dia_amf_verify(S_pk, R_sk, J_pk,
                               reinterpret_cast<const unsigned char*>(msg.data()), msg.size(),
                               sig_blob, sig_len) == DIA_OK);
        REQUIRE(dia_amf_judge(S_pk, R_pk, J_sk,
                              reinterpret_cast<const unsigned char*>(msg.data()), msg.size(),
                              sig_blob, sig_len) == DIA_OK);

        // Negative: different message
        const std::string other = "different message";
        REQUIRE(dia_amf_verify(S_pk, R_sk, J_pk,
                               reinterpret_cast<const unsigned char*>(other.data()), other.size(),
                               sig_blob, sig_len) != DIA_OK);
        REQUIRE(dia_amf_judge(S_pk, R_pk, J_sk,
                              reinterpret_cast<const unsigned char*>(other.data()), other.size(),
                              sig_blob, sig_len) != DIA_OK);

        // Negative: wrong sender pk
        unsigned char S2_sk[DIA_FR_LEN], S2_pk[DIA_G1_LEN];
        REQUIRE(dia_amf_keygen(S2_sk, S2_pk) == DIA_OK);
        REQUIRE(dia_amf_verify(S2_pk, R_sk, J_pk,
                               reinterpret_cast<const unsigned char*>(msg.data()), msg.size(),
                               sig_blob, sig_len) != DIA_OK);
        REQUIRE(dia_amf_judge(S2_pk, R_pk, J_sk,
                              reinterpret_cast<const unsigned char*>(msg.data()), msg.size(),
                              sig_blob, sig_len) != DIA_OK);

        // Negative: wrong receiver secret for Verify (Judge independent)
        unsigned char R2_sk[DIA_FR_LEN], R2_pk[DIA_G1_LEN];
        REQUIRE(dia_amf_keygen(R2_sk, R2_pk) == DIA_OK);
        REQUIRE(dia_amf_verify(S_pk, R2_sk, J_pk,
                               reinterpret_cast<const unsigned char*>(msg.data()), msg.size(),
                               sig_blob, sig_len) != DIA_OK);
        REQUIRE(dia_amf_judge(S_pk, R_pk, J_sk,
                              reinterpret_cast<const unsigned char*>(msg.data()), msg.size(),
                              sig_blob, sig_len) == DIA_OK);

        // Tamper the blob (flip one byte) → verify should fail (or parsing should fail)
        {
            std::vector<unsigned char> tam(sig_blob, sig_blob + sig_len);
            tam[tam.size() / 2] ^= 0x01;
            REQUIRE(dia_amf_verify(S_pk, R_sk, J_pk,
                                   reinterpret_cast<const unsigned char*>(msg.data()), msg.size(),
                                   tam.data(), tam.size()) != DIA_OK);
        }

        free_byte_buffer(sig_blob);
    }

    SECTION("BBS: sign/verify and selective disclosure (GT proof via C ABI)") {
        // Keygen
        unsigned char sk[DIA_FR_LEN], pk[DIA_G2_LEN];
        REQUIRE(dia_bbs_keygen(sk, pk) == DIA_OK);

        // Messages
        std::vector<std::string> msgs = {
            "m0","m1","m2","m3","m4","m5","m6","m7"
        };
        auto m_ptrs = to_ptrs(msgs);
        auto m_lens = to_lens(msgs);

        // Sign
        unsigned char A[DIA_G1_LEN], e[DIA_FR_LEN];
        REQUIRE(dia_bbs_sign(reinterpret_cast<const unsigned char* const*>(m_ptrs.data()),
                             m_lens.data(), msgs.size(),
                             sk, A, e) == DIA_OK);

        // Verify
        REQUIRE(dia_bbs_verify(reinterpret_cast<const unsigned char* const*>(m_ptrs.data()),
                               m_lens.data(), msgs.size(),
                               pk, A, e) == DIA_OK);

        // Proof: reveal none (k=0)
        const std::string nonce = "bbs-proof-nonce";
        unsigned char* prf_blob = nullptr; size_t prf_len = 0;
        REQUIRE(dia_bbs_proof_create(reinterpret_cast<const unsigned char* const*>(m_ptrs.data()),
                                     m_lens.data(), msgs.size(),
                                     nullptr, 0,
                                     pk, A, e,
                                     reinterpret_cast<const unsigned char*>(nonce.data()), nonce.size(),
                                     &prf_blob, &prf_len) == DIA_OK);
        REQUIRE(prf_blob != nullptr); REQUIRE(prf_len > 0);

        // Verify proof with k=0
        REQUIRE(dia_bbs_proof_verify(nullptr,
                                     nullptr, nullptr, 0,
                                     pk,
                                     reinterpret_cast<const unsigned char*>(nonce.data()), nonce.size(),
                                     prf_blob, prf_len) == DIA_OK);

        // Proof: reveal subset {1,3,6} (1-based indices)
        std::vector<size_t> disclose_idx = {1,3,6};
        auto disclose_u32 = to_u32(disclose_idx);
        std::vector<std::string> disclosed = { msgs[0], msgs[2], msgs[5] };
        auto d_ptrs = to_ptrs(disclosed);
        auto d_lens = to_lens(disclosed);

        unsigned char* prf_blob2 = nullptr; size_t prf_len2 = 0;
        REQUIRE(dia_bbs_proof_create(reinterpret_cast<const unsigned char* const*>(m_ptrs.data()),
                                     m_lens.data(), msgs.size(),
                                     disclose_u32.data(), disclose_u32.size(),
                                     pk, A, e,
                                     reinterpret_cast<const unsigned char*>(nonce.data()), nonce.size(),
                                     &prf_blob2, &prf_len2) == DIA_OK);

        REQUIRE(dia_bbs_proof_verify(disclose_u32.data(),
                                     reinterpret_cast<const unsigned char* const*>(d_ptrs.data()),
                                     d_lens.data(), disclosed.size(),
                                     pk,
                                     reinterpret_cast<const unsigned char*>(nonce.data()), nonce.size(),
                                     prf_blob2, prf_len2) == DIA_OK);

        // Negative: wrong nonce
        const std::string bad_nonce = "wrong";
        REQUIRE(dia_bbs_proof_verify(disclose_u32.data(),
                                     reinterpret_cast<const unsigned char* const*>(d_ptrs.data()),
                                     d_lens.data(), disclosed.size(),
                                     pk,
                                     reinterpret_cast<const unsigned char*>(bad_nonce.data()), bad_nonce.size(),
                                     prf_blob2, prf_len2) != DIA_OK);

        // Negative: wrong pk
        unsigned char sk2[DIA_FR_LEN], pk2[DIA_G2_LEN];
        REQUIRE(dia_bbs_keygen(sk2, pk2) == DIA_OK);
        REQUIRE(dia_bbs_proof_verify(disclose_u32.data(),
                                     reinterpret_cast<const unsigned char* const*>(d_ptrs.data()),
                                     d_lens.data(), disclosed.size(),
                                     pk2,
                                     reinterpret_cast<const unsigned char*>(nonce.data()), nonce.size(),
                                     prf_blob2, prf_len2) != DIA_OK);

        // Negative: tamper the proof blob (flip byte) → should fail
        std::vector<unsigned char> tam(prf_blob2, prf_blob2 + prf_len2);
        tam[tam.size()/3] ^= 0x01;
        REQUIRE(dia_bbs_proof_verify(disclose_u32.data(),
                                     reinterpret_cast<const unsigned char* const*>(d_ptrs.data()),
                                     d_lens.data(), disclosed.size(),
                                     pk,
                                     reinterpret_cast<const unsigned char*>(nonce.data()), nonce.size(),
                                     tam.data(), tam.size()) != DIA_OK);

        free_byte_buffer(prf_blob);
        free_byte_buffer(prf_blob2);
    }
}
