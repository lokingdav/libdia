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

    SECTION("Diffie-Hellman end-to-end") {
        unsigned char a[DIA_FR_LEN], A[DIA_G1_LEN];
        REQUIRE(dia_dh_keygen(a, A) == DIA_OK);

        unsigned char b[DIA_FR_LEN], B[DIA_G1_LEN];
        REQUIRE(dia_dh_keygen(b, B) == DIA_OK);

        unsigned char sec1[DIA_G1_LEN], sec2[DIA_G1_LEN];
        REQUIRE(dia_dh_compute_secret(a, B, sec1) == DIA_OK);
        REQUIRE(dia_dh_compute_secret(b, A, sec2) == DIA_OK);

        REQUIRE(std::memcmp(sec1, sec2, DIA_G1_LEN) == 0);
    }


    SECTION("VOPRF end-to-end (deterministic output across re-blinds)") {
        unsigned char sk[DIA_FR_LEN], pk[DIA_G2_LEN];
        REQUIRE(dia_voprf_keygen(sk, pk) == DIA_OK);

        const std::string in = "hello voprf";

        // --- First run ---
        unsigned char blinded[DIA_G1_LEN], blind[DIA_FR_LEN];
        REQUIRE(dia_voprf_blind(reinterpret_cast<const unsigned char*>(in.data()), in.size(),
                                blinded, blind) == DIA_OK);

        unsigned char element[DIA_G1_LEN];
        REQUIRE(dia_voprf_evaluate(blinded, sk, element) == DIA_OK);

        unsigned char Y[DIA_G1_LEN];
        REQUIRE(dia_voprf_unblind(element, blind, Y) == DIA_OK);

        // Verify (single)
        int v_ok = 0;
        REQUIRE(dia_voprf_verify(reinterpret_cast<const unsigned char*>(in.data()), in.size(),
                                Y, pk, &v_ok) == DIA_OK);
        REQUIRE(v_ok == 1);

        // --- Second run on the SAME input (fresh blind) ---
        unsigned char blinded2[DIA_G1_LEN], blind2[DIA_FR_LEN];
        REQUIRE(dia_voprf_blind(reinterpret_cast<const unsigned char*>(in.data()), in.size(),
                                blinded2, blind2) == DIA_OK);

        unsigned char element2[DIA_G1_LEN];
        REQUIRE(dia_voprf_evaluate(blinded2, sk, element2) == DIA_OK);

        unsigned char Y2[DIA_G1_LEN];
        REQUIRE(dia_voprf_unblind(element2, blind2, Y2) == DIA_OK);

        // Blinding randomness should differ (overwhelming probability)
        REQUIRE(std::memcmp(blinded, blinded2, DIA_G1_LEN) != 0);
        REQUIRE(std::memcmp(element, element2, DIA_G1_LEN) != 0);

        // Determinism: final OPRF output must be identical for same input+key
        REQUIRE(std::memcmp(Y, Y2, DIA_G1_LEN) == 0);

        // Different input should yield a different Y (overwhelming probability)
        const std::string in_other = "hello voprf!";
        unsigned char b3[DIA_G1_LEN], r3[DIA_FR_LEN], e3[DIA_G1_LEN], Y3[DIA_G1_LEN];
        REQUIRE(dia_voprf_blind(reinterpret_cast<const unsigned char*>(in_other.data()), in_other.size(), b3, r3) == DIA_OK);
        REQUIRE(dia_voprf_evaluate(b3, sk, e3) == DIA_OK);
        REQUIRE(dia_voprf_unblind(e3, r3, Y3) == DIA_OK);
        REQUIRE(std::memcmp(Y, Y3, DIA_G1_LEN) != 0);


        // --- Batch verify (two items) ---
        std::vector<std::string> ins = {"alpha", "beta"};
        auto ptrs = to_ptrs(ins);
        auto lens = to_lens(ins);

        // compute Ys for both
        unsigned char blinded1[DIA_G1_LEN], blind1[DIA_FR_LEN];
        unsigned char blindedB[DIA_G1_LEN], blindB[DIA_FR_LEN];
        REQUIRE(dia_voprf_blind(reinterpret_cast<const unsigned char*>(ins[0].data()), ins[0].size(), blinded1, blind1) == DIA_OK);
        REQUIRE(dia_voprf_blind(reinterpret_cast<const unsigned char*>(ins[1].data()), ins[1].size(), blindedB, blindB) == DIA_OK);

        unsigned char elem1[DIA_G1_LEN], elemB[DIA_G1_LEN];
        REQUIRE(dia_voprf_evaluate(blinded1, sk, elem1) == DIA_OK);
        REQUIRE(dia_voprf_evaluate(blindedB, sk, elemB) == DIA_OK);

        unsigned char Y1[DIA_G1_LEN], YB[DIA_G1_LEN];
        REQUIRE(dia_voprf_unblind(elem1, blind1, Y1) == DIA_OK);
        REQUIRE(dia_voprf_unblind(elemB, blindB, YB) == DIA_OK);

        // Concatenate Y1||YB for the C API
        std::vector<unsigned char> Y_concat(DIA_G1_LEN * 2);
        std::memcpy(Y_concat.data(), Y1, DIA_G1_LEN);
        std::memcpy(Y_concat.data() + DIA_G1_LEN, YB, DIA_G1_LEN);

        int vb_ok = 0;
        REQUIRE(dia_voprf_verify_batch(reinterpret_cast<const unsigned char* const*>(ptrs.data()),
                                    lens.data(), ins.size(),
                                    Y_concat.data(), pk, &vb_ok) == DIA_OK);
        REQUIRE(vb_ok == 1);
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
        int v_ok = 0, j_ok = 0;
        REQUIRE(dia_amf_verify(S_pk, R_sk, J_pk,
                               reinterpret_cast<const unsigned char*>(msg.data()), msg.size(),
                               sig_blob, sig_len, &v_ok) == DIA_OK);
        REQUIRE(v_ok == 1);
        REQUIRE(dia_amf_judge(S_pk, R_pk, J_sk,
                              reinterpret_cast<const unsigned char*>(msg.data()), msg.size(),
                              sig_blob, sig_len, &j_ok) == DIA_OK);
        REQUIRE(j_ok == 1);

        // Negative: different message
        const std::string other = "different message";
        int v_bad_msg = 0, j_bad_msg = 0;
        REQUIRE(dia_amf_verify(S_pk, R_sk, J_pk,
                               reinterpret_cast<const unsigned char*>(other.data()), other.size(),
                               sig_blob, sig_len, &v_bad_msg) == DIA_OK);
        REQUIRE(v_bad_msg == 0);
        REQUIRE(dia_amf_judge(S_pk, R_pk, J_sk,
                              reinterpret_cast<const unsigned char*>(other.data()), other.size(),
                              sig_blob, sig_len, &j_bad_msg) == DIA_OK);
        REQUIRE(j_bad_msg == 0);

        // Negative: wrong sender pk
        unsigned char S2_sk[DIA_FR_LEN], S2_pk[DIA_G1_LEN];
        REQUIRE(dia_amf_keygen(S2_sk, S2_pk) == DIA_OK);
        int v_bad_s = 0, j_bad_s = 0;
        REQUIRE(dia_amf_verify(S2_pk, R_sk, J_pk,
                               reinterpret_cast<const unsigned char*>(msg.data()), msg.size(),
                               sig_blob, sig_len, &v_bad_s) == DIA_OK);
        REQUIRE(v_bad_s == 0);
        REQUIRE(dia_amf_judge(S2_pk, R_pk, J_sk,
                              reinterpret_cast<const unsigned char*>(msg.data()), msg.size(),
                              sig_blob, sig_len, &j_bad_s) == DIA_OK);
        REQUIRE(j_bad_s == 0);

        // Negative: wrong receiver secret for Verify (Judge independent)
        unsigned char R2_sk[DIA_FR_LEN], R2_pk[DIA_G1_LEN];
        REQUIRE(dia_amf_keygen(R2_sk, R2_pk) == DIA_OK);
        int v_bad_r = 0, j_ok_indep = 0;
        REQUIRE(dia_amf_verify(S_pk, R2_sk, J_pk,
                               reinterpret_cast<const unsigned char*>(msg.data()), msg.size(),
                               sig_blob, sig_len, &v_bad_r) == DIA_OK);
        REQUIRE(v_bad_r == 0);
        REQUIRE(dia_amf_judge(S_pk, R_pk, J_sk,
                              reinterpret_cast<const unsigned char*>(msg.data()), msg.size(),
                              sig_blob, sig_len, &j_ok_indep) == DIA_OK);
        REQUIRE(j_ok_indep == 1);

        // Tamper the blob (flip one byte) → may parse (invalid) or fail to parse.
        {
            std::vector<unsigned char> tam(sig_blob, sig_blob + sig_len);
            tam[tam.size() / 2] ^= 0x01;
            int res = 1; // set to 0 if parsed and invalid
            int rc = dia_amf_verify(S_pk, R_sk, J_pk,
                                    reinterpret_cast<const unsigned char*>(msg.data()), msg.size(),
                                    tam.data(), tam.size(), &res);
            // Accept either: parsed-but-invalid (DIA_OK & res==0) OR parse error (rc != DIA_OK)
            bool acceptable = (rc == DIA_OK) ? (res == 0) : (rc != DIA_OK);
            REQUIRE(acceptable);
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

        // Sign -> opaque signature blob
        unsigned char* sig_blob = nullptr; size_t sig_len = 0;
        REQUIRE(dia_bbs_sign(reinterpret_cast<const unsigned char* const*>(m_ptrs.data()),
                             m_lens.data(), msgs.size(),
                             sk, &sig_blob, &sig_len) == DIA_OK);
        REQUIRE(sig_blob != nullptr);
        REQUIRE(sig_len > 0);

        // Verify signature
        int sig_ok = 0;
        REQUIRE(dia_bbs_verify(reinterpret_cast<const unsigned char* const*>(m_ptrs.data()),
                               m_lens.data(), msgs.size(),
                               pk, sig_blob, sig_len, &sig_ok) == DIA_OK);
        REQUIRE(sig_ok == 1);

        // Proof: reveal none (k=0)
        const std::string nonce = "bbs-proof-nonce";
        unsigned char* prf_blob = nullptr; size_t prf_len = 0;
        REQUIRE(dia_bbs_proof_create(reinterpret_cast<const unsigned char* const*>(m_ptrs.data()),
                                     m_lens.data(), msgs.size(),
                                     nullptr, 0,
                                     pk, sig_blob, sig_len,
                                     reinterpret_cast<const unsigned char*>(nonce.data()), nonce.size(),
                                     &prf_blob, &prf_len) == DIA_OK);
        REQUIRE(prf_blob != nullptr); REQUIRE(prf_len > 0);

        // Verify proof with k=0
        int prf_ok0 = 0;
        REQUIRE(dia_bbs_proof_verify(nullptr,
                                     nullptr, nullptr, 0,
                                     pk,
                                     reinterpret_cast<const unsigned char*>(nonce.data()), nonce.size(),
                                     prf_blob, prf_len, &prf_ok0) == DIA_OK);
        REQUIRE(prf_ok0 == 1);

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
                                     pk, sig_blob, sig_len,
                                     reinterpret_cast<const unsigned char*>(nonce.data()), nonce.size(),
                                     &prf_blob2, &prf_len2) == DIA_OK);

        int prf_ok = 0;
        REQUIRE(dia_bbs_proof_verify(disclose_u32.data(),
                                     reinterpret_cast<const unsigned char* const*>(d_ptrs.data()),
                                     d_lens.data(), disclosed.size(),
                                     pk,
                                     reinterpret_cast<const unsigned char*>(nonce.data()), nonce.size(),
                                     prf_blob2, prf_len2, &prf_ok) == DIA_OK);
        REQUIRE(prf_ok == 1);

        // Negative: wrong nonce → DIA_OK with result=0
        const std::string bad_nonce = "wrong";
        int prf_bad_nonce = 0;
        REQUIRE(dia_bbs_proof_verify(disclose_u32.data(),
                                     reinterpret_cast<const unsigned char* const*>(d_ptrs.data()),
                                     d_lens.data(), disclosed.size(),
                                     pk,
                                     reinterpret_cast<const unsigned char*>(bad_nonce.data()), bad_nonce.size(),
                                     prf_blob2, prf_len2, &prf_bad_nonce) == DIA_OK);
        REQUIRE(prf_bad_nonce == 0);

        // Negative: wrong pk → DIA_OK with result=0
        unsigned char sk2[DIA_FR_LEN], pk2[DIA_G2_LEN];
        REQUIRE(dia_bbs_keygen(sk2, pk2) == DIA_OK);
        int prf_bad_pk = 0;
        REQUIRE(dia_bbs_proof_verify(disclose_u32.data(),
                                     reinterpret_cast<const unsigned char* const*>(d_ptrs.data()),
                                     d_lens.data(), disclosed.size(),
                                     pk2,
                                     reinterpret_cast<const unsigned char*>(nonce.data()), nonce.size(),
                                     prf_blob2, prf_len2, &prf_bad_pk) == DIA_OK);
        REQUIRE(prf_bad_pk == 0);

        // Negative: tamper the proof blob (flip byte) → may parse (invalid) or fail to parse.
        std::vector<unsigned char> tam(prf_blob2, prf_blob2 + prf_len2);
        tam[tam.size()/3] ^= 0x01;
        int res = 1; // will be 0 if parsed as invalid
        int rc = dia_bbs_proof_verify(disclose_u32.data(),
                                      reinterpret_cast<const unsigned char* const*>(d_ptrs.data()),
                                      d_lens.data(), disclosed.size(),
                                      pk,
                                      reinterpret_cast<const unsigned char*>(nonce.data()), nonce.size(),
                                      tam.data(), tam.size(), &res);
        bool acceptable = (rc == DIA_OK) ? (res == 0) : (rc != DIA_OK);
        REQUIRE(acceptable);

        free_byte_buffer(sig_blob);
        free_byte_buffer(prf_blob);
        free_byte_buffer(prf_blob2);
    }
}
