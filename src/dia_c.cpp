#include "dia/dia_c.h"
#include "dia/dia.hpp"   // umbrella (ecgroup.hpp, etc.)
#include "helpers.hpp"

#include "voprf.hpp"
#include "bbs.hpp"
#include "amf.hpp"
#include "dh.hpp"

#include <vector>
#include <string>
#include <cstring>
#include <algorithm>
#include <stdexcept>

/* ============================ Common helpers ============================ */

using ecgroup::Bytes;
using ecgroup::Scalar;
using ecgroup::G1Point;
using ecgroup::G2Point;

static void copy_to_c_buf(const Bytes& vec, unsigned char** buf_out, size_t* len_out) {
    *len_out = vec.size();
    *buf_out = new unsigned char[*len_out];
    if (*len_out) std::memcpy(*buf_out, vec.data(), *len_out);
}

/* ============================== Init/Free =============================== */

void init_dia() { ecgroup::init_pairing(); }
void free_byte_buffer(unsigned char* buf) { delete[] buf; }

/* ============================== DH =============================== */

int dia_dh_keygen(unsigned char sk[DIA_FR_LEN],
                     unsigned char pk[DIA_G1_LEN]) {
    try {
        auto kp = dh::keygen();
        {
            Bytes b = kp.sk.to_bytes();
            std::memcpy(sk, b.data(), b.size());
        }
        {
            Bytes b = kp.pk.to_bytes();
            std::memcpy(pk, b.data(), b.size());
        }
        return DIA_OK;
    } catch (...) { return DIA_ERR; }
}

int dia_dh_compute_secret(const unsigned char a[DIA_FR_LEN],
                       const unsigned char B[DIA_G1_LEN],
                       /*out*/ unsigned char out_element[DIA_G1_LEN]) {
    try {
        G1Point point = G1Point::from_bytes(Bytes(B, B + DIA_G1_LEN));
        Scalar  s = Scalar::from_bytes(Bytes(a, a + DIA_FR_LEN));
        G1Point E = G1Point::mul(point, s);
        Bytes   b = E.to_bytes();
        std::memcpy(out_element, b.data(), b.size());
        return DIA_OK;
    } catch (...) { return DIA_ERR; }
}

/* ================================ VOPRF ================================= */

int dia_voprf_keygen(unsigned char sk[DIA_FR_LEN],
                     unsigned char pk[DIA_G2_LEN]) {
    try {
        auto kp = voprf::keygen();
        {
            Bytes b = kp.sk.to_bytes();
            std::memcpy(sk, b.data(), b.size());
        }
        {
            Bytes b = kp.pk.to_bytes();
            std::memcpy(pk, b.data(), b.size());
        }
        return DIA_OK;
    } catch (...) { return DIA_ERR; }
}

int dia_voprf_blind(const unsigned char* input, size_t input_len,
                    unsigned char out_blinded[DIA_G1_LEN],
                    unsigned char out_blind[DIA_FR_LEN]) {
    try {
        std::string in(reinterpret_cast<const char*>(input), input_len);
        auto [B, r] = voprf::blind(in);
        {
            Bytes b = B.to_bytes();
            std::memcpy(out_blinded, b.data(), b.size());
        }
        {
            Bytes b = r.to_bytes();
            std::memcpy(out_blind, b.data(), b.size());
        }
        return DIA_OK;
    } catch (...) { return DIA_ERR; }
}

int dia_voprf_evaluate(const unsigned char blinded[DIA_G1_LEN],
                       const unsigned char sk[DIA_FR_LEN],
                       unsigned char out_element[DIA_G1_LEN]) {
    try {
        G1Point B = G1Point::from_bytes(Bytes(blinded, blinded + DIA_G1_LEN));
        Scalar  x = Scalar::from_bytes(Bytes(sk, sk + DIA_FR_LEN));
        G1Point E = G1Point::mul(B, x);
        Bytes   b = E.to_bytes();
        std::memcpy(out_element, b.data(), b.size());
        return DIA_OK;
    } catch (...) { return DIA_ERR; }
}

int dia_voprf_unblind(const unsigned char element[DIA_G1_LEN],
                      const unsigned char blind[DIA_FR_LEN],
                      unsigned char out_Y[DIA_G1_LEN]) {
    try {
        G1Point E = G1Point::from_bytes(Bytes(element, element + DIA_G1_LEN));
        Scalar  r = Scalar::from_bytes(Bytes(blind,   blind   + DIA_FR_LEN));
        G1Point Y = voprf::unblind(E, r);
        Bytes   b = Y.to_bytes();
        std::memcpy(out_Y, b.data(), b.size());
        return DIA_OK;
    } catch (...) { return DIA_ERR; }
}

int dia_voprf_verify(const unsigned char* input, size_t input_len,
                     const unsigned char Y[DIA_G1_LEN],
                     const unsigned char pk[DIA_G2_LEN],
                     int* result) {
    if (!result) return DIA_ERR_INVALID_ARG;
    *result = 0;
    try {
        std::string in(reinterpret_cast<const char*>(input), input_len);
        G1Point Yp = G1Point::from_bytes(Bytes(Y,  Y  + DIA_G1_LEN));
        G2Point Pk = G2Point::from_bytes(Bytes(pk, pk + DIA_G2_LEN));
        *result = voprf::verify(in, Yp, Pk) ? 1 : 0;
        return DIA_OK;
    } catch (...) { return DIA_ERR; }
}

int dia_voprf_verify_batch(const unsigned char* const* inputs,
                           const size_t* input_lens,
                           size_t n,
                           const unsigned char* Y_concat,
                           const unsigned char pk[DIA_G2_LEN],
                           int* result) {
    if (!result) return DIA_ERR_INVALID_ARG;
    *result = 0;
    try {
        std::vector<std::string> ins; ins.reserve(n);
        for (size_t i = 0; i < n; ++i)
            ins.emplace_back(reinterpret_cast<const char*>(inputs[i]), input_lens[i]);

        std::vector<G1Point> outs; outs.reserve(n);
        for (size_t i = 0; i < n; ++i) {
            const unsigned char* yi = Y_concat + i * DIA_G1_LEN;
            outs.emplace_back(G1Point::from_bytes(Bytes(yi, yi + DIA_G1_LEN)));
        }

        G2Point Pk = G2Point::from_bytes(Bytes(pk, pk + DIA_G2_LEN));
        *result = voprf::verify_batch(ins, outs, Pk) ? 1 : 0;
        return DIA_OK;
    } catch (...) { return DIA_ERR; }
}

/* ================================= AMF ================================== */

int dia_amf_keygen(unsigned char sk[DIA_FR_LEN],
                   unsigned char pk[DIA_G1_LEN]) {
    try {
        amf::Params params = amf::Params::Default();
        amf::KeyPair kp = amf::KeyGen(params);
        {
            Bytes b = kp.sk.to_bytes();
            std::memcpy(sk, b.data(), b.size());
        }
        {
            Bytes b = kp.pk.to_bytes();
            std::memcpy(pk, b.data(), b.size());
        }
        return DIA_OK;
    } catch (...) { return DIA_ERR; }
}

int dia_amf_frank(const unsigned char sk_sender[DIA_FR_LEN],
                  const unsigned char pk_receiver[DIA_G1_LEN],
                  const unsigned char pk_judge[DIA_G1_LEN],
                  const unsigned char* msg, size_t msg_len,
                  unsigned char** sig_blob,
                  size_t* sig_blob_len) {
    try {
        amf::Params params = amf::Params::Default();
        Scalar  sks = Scalar::from_bytes(Bytes(sk_sender,   sk_sender   + DIA_FR_LEN));
        G1Point PKr = G1Point::from_bytes(Bytes(pk_receiver, pk_receiver + DIA_G1_LEN));
        G1Point PKj = G1Point::from_bytes(Bytes(pk_judge,    pk_judge    + DIA_G1_LEN));
        std::string m(reinterpret_cast<const char*>(msg), msg_len);

        amf::Signature sig = amf::Frank(sks, PKr, PKj, m, params);
        copy_to_c_buf(sig.to_bytes(), sig_blob, sig_blob_len);
        return DIA_OK;
    } catch (...) { return DIA_ERR; }
}

int dia_amf_verify(const unsigned char pk_sender[DIA_G1_LEN],
                   const unsigned char sk_receiver[DIA_FR_LEN],
                   const unsigned char pk_judge[DIA_G1_LEN],
                   const unsigned char* msg, size_t msg_len,
                   const unsigned char* sig_blob, size_t sig_blob_len,
                   int* result) {
    if (!result) return DIA_ERR_INVALID_ARG;
    *result = 0;
    try {
        amf::Params params = amf::Params::Default();
        G1Point PKs = G1Point::from_bytes(Bytes(pk_sender,   pk_sender   + DIA_G1_LEN));
        Scalar  SKr = Scalar::from_bytes(Bytes(sk_receiver,  sk_receiver + DIA_FR_LEN));
        G1Point PKj = G1Point::from_bytes(Bytes(pk_judge,    pk_judge    + DIA_G1_LEN));
        std::string m(reinterpret_cast<const char*>(msg), msg_len);

        amf::Signature sig = amf::Signature::from_bytes(Bytes(sig_blob, sig_blob + sig_blob_len));
        *result = amf::Verify(PKs, SKr, PKj, m, sig, params) ? 1 : 0;
        return DIA_OK;
    } catch (...) { return DIA_ERR; }
}

int dia_amf_judge(const unsigned char pk_sender[DIA_G1_LEN],
                  const unsigned char pk_receiver[DIA_G1_LEN],
                  const unsigned char sk_judge[DIA_FR_LEN],
                  const unsigned char* msg, size_t msg_len,
                  const unsigned char* sig_blob, size_t sig_blob_len,
                  int* result) {
    if (!result) return DIA_ERR_INVALID_ARG;
    *result = 0;
    try {
        amf::Params params = amf::Params::Default();
        G1Point PKs = G1Point::from_bytes(Bytes(pk_sender,   pk_sender   + DIA_G1_LEN));
        G1Point PKr = G1Point::from_bytes(Bytes(pk_receiver, pk_receiver + DIA_G1_LEN));
        Scalar  SKj = Scalar::from_bytes(Bytes(sk_judge,     sk_judge    + DIA_FR_LEN));
        std::string m(reinterpret_cast<const char*>(msg), msg_len);

        amf::Signature sig = amf::Signature::from_bytes(Bytes(sig_blob, sig_blob + sig_blob_len));
        *result = amf::Judge(PKs, PKr, SKj, m, sig, params) ? 1 : 0;
        return DIA_OK;
    } catch (...) { return DIA_ERR; }
}

/* ================================= BBS ================================== */

int dia_bbs_keygen(unsigned char sk[DIA_FR_LEN],
                   unsigned char pk[DIA_G2_LEN]) {
    try {
        bbs::Params params = bbs::Params::Default();
        bbs::KeyPair kp = bbs::keygen(params);
        {
            Bytes b = kp.sk.to_bytes();
            std::memcpy(sk, b.data(), b.size());
        }
        {
            Bytes b = kp.pk.to_bytes();
            std::memcpy(pk, b.data(), b.size());
        }
        return DIA_OK;
    } catch (...) { return DIA_ERR; }
}

int dia_bbs_sign(const unsigned char* const* msgs,
                 const size_t* msg_lens,
                 size_t n_msgs,
                 const unsigned char sk[DIA_FR_LEN],
                 unsigned char** sig_blob,
                 size_t* sig_blob_len) {
    try {
        bbs::Params params = bbs::Params::Default();

        std::vector<Scalar> M; M.reserve(n_msgs);
        for (size_t i = 0; i < n_msgs; ++i) {
            const unsigned char* m = msgs[i];
            size_t len = msg_lens[i];
            M.emplace_back(Scalar::hash_to_scalar(Bytes(m, m + len)));
        }

        Scalar sk_iss = Scalar::from_bytes(Bytes(sk, sk + DIA_FR_LEN));
        bbs::Signature sig = bbs::sign(params, sk_iss, M);

        copy_to_c_buf(sig.to_bytes(), sig_blob, sig_blob_len);
        return DIA_OK;
    } catch (...) { return DIA_ERR; }
}

int dia_bbs_verify(const unsigned char* const* msgs,
                   const size_t* msg_lens,
                   size_t n_msgs,
                   const unsigned char pk[DIA_G2_LEN],
                   const unsigned char* sig_blob,
                   size_t sig_blob_len,
                   int* result) {
    if (!result) return DIA_ERR_INVALID_ARG;
    *result = 0;
    try {
        bbs::Params params = bbs::Params::Default();

        std::vector<Scalar> M; M.reserve(n_msgs);
        for (size_t i = 0; i < n_msgs; ++i) {
            const unsigned char* m = msgs[i];
            size_t len = msg_lens[i];
            M.emplace_back(Scalar::hash_to_scalar(Bytes(m, m + len)));
        }

        G2Point PK = G2Point::from_bytes(Bytes(pk, pk + DIA_G2_LEN));
        bbs::Signature sig = bbs::Signature::from_bytes(Bytes(sig_blob, sig_blob + sig_blob_len));

        *result = bbs::verify(params, PK, M, sig) ? 1 : 0;
        return DIA_OK;
    } catch (...) { return DIA_ERR; }
}

int dia_bbs_proof_create(const unsigned char* const* msgs,
                         const size_t* msg_lens,
                         size_t n_msgs,
                         const uint32_t* disclose_idx_1based,
                         size_t n_disclose,
                         const unsigned char pk[DIA_G2_LEN],
                         const unsigned char* sig_blob,
                         size_t sig_blob_len,
                         const unsigned char* nonce,
                         size_t nonce_len,
                         unsigned char** proof_blob,
                         size_t* proof_blob_len) {
    try {
        bbs::Params params = bbs::Params::Default();

        std::vector<Scalar> M; M.reserve(n_msgs);
        for (size_t i = 0; i < n_msgs; ++i) {
            const unsigned char* m = msgs[i];
            size_t len = msg_lens[i];
            M.emplace_back(Scalar::hash_to_scalar(Bytes(m, m + len)));
        }

        std::vector<std::size_t> D; D.reserve(n_disclose);
        for (size_t i = 0; i < n_disclose; ++i)
            D.push_back(static_cast<std::size_t>(disclose_idx_1based[i]));

        G2Point PK = G2Point::from_bytes(Bytes(pk, pk + DIA_G2_LEN));
        bbs::Signature sig = bbs::Signature::from_bytes(Bytes(sig_blob, sig_blob + sig_blob_len));
        std::string n(reinterpret_cast<const char*>(nonce), nonce_len);

        bbs::SDProof P = bbs::create_proof(params, PK, sig, M, D, n);
        copy_to_c_buf(P.to_bytes(), proof_blob, proof_blob_len);
        return DIA_OK;
    } catch (...) { return DIA_ERR; }
}

int dia_bbs_proof_verify(const uint32_t* disclosed_idx_1based,
                         const unsigned char* const* disclosed_msgs,
                         const size_t* disclosed_lens,
                         size_t n_disclosed,
                         const unsigned char pk[DIA_G2_LEN],
                         const unsigned char* nonce,
                         size_t nonce_len,
                         const unsigned char* proof_blob,
                         size_t proof_blob_len,
                         int* result) {
    if (!result) return DIA_ERR_INVALID_ARG;
    *result = 0;
    try {
        bbs::SDProof P = bbs::SDProof::from_bytes(Bytes(proof_blob, proof_blob + proof_blob_len));

        std::vector<std::pair<std::size_t, Scalar>> disclosed;
        disclosed.reserve(n_disclosed);

        std::size_t L = 0; // inferred total messages = max(seen indices)
        for (size_t i = 0; i < n_disclosed; ++i) {
            std::size_t idx = static_cast<std::size_t>(disclosed_idx_1based[i]);
            L = std::max(L, idx);
            const unsigned char* m = disclosed_msgs[i];
            size_t len = disclosed_lens[i];
            disclosed.emplace_back(idx, Scalar::hash_to_scalar(Bytes(m, m + len)));
        }
        for (auto j : P.hidden_indices) L = std::max(L, j);

        std::string n(reinterpret_cast<const char*>(nonce), nonce_len);
        if (n != P.nonce) { *result = 0; return DIA_OK; } // context mismatch → invalid proof

        bbs::Params params = bbs::Params::Default();
        G2Point PK = G2Point::from_bytes(Bytes(pk, pk + DIA_G2_LEN));

        *result = bbs::verify_proof(params, PK, P, disclosed, L) ? 1 : 0;
        return DIA_OK;
    } catch (const std::runtime_error&) {
        // Parsing / argument errors
        return DIA_ERR_INVALID_ARG;
    } catch (...) {
        return DIA_ERR;
    }
}
