#include "dia/dia_c.h"
#include "dia/dia.hpp"   // umbrella (ecgroup.hpp, etc.)
#include "voprf.hpp"
#include "bbs.hpp"
#include "amf.hpp"

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
using ecgroup::PairingResult;

static inline int ret_ok(bool b) { return b ? DIA_OK : DIA_ERR_VERIFY_FAIL; }

static inline Scalar fr_from(const unsigned char in[DIA_FR_LEN]) {
    return Scalar::from_bytes(Bytes(in, in + DIA_FR_LEN));
}
static inline G1Point g1_from(const unsigned char in[DIA_G1_LEN]) {
    return G1Point::from_bytes(Bytes(in, in + DIA_G1_LEN));
}
static inline G2Point g2_from(const unsigned char in[DIA_G2_LEN]) {
    return G2Point::from_bytes(Bytes(in, in + DIA_G2_LEN));
}

static inline void fr_to(const Scalar& s, unsigned char out[DIA_FR_LEN]) {
    Bytes b = s.to_bytes(); std::memcpy(out, b.data(), b.size());
}
static inline void g1_to(const G1Point& p, unsigned char out[DIA_G1_LEN]) {
    Bytes b = p.to_bytes(); std::memcpy(out, b.data(), b.size());
}
static inline void g2_to(const G2Point& p, unsigned char out[DIA_G2_LEN]) {
    Bytes b = p.to_bytes(); std::memcpy(out, b.data(), b.size());
}

static void copy_to_c_buf(const Bytes& vec, unsigned char** buf_out, size_t* len_out) {
    *len_out = vec.size();
    *buf_out = new unsigned char[*len_out];
    if (*len_out) std::memcpy(*buf_out, vec.data(), *len_out);
}

/* ============================== Init/Free =============================== */

void init_dia() { ecgroup::init_pairing(); }
void free_byte_buffer(unsigned char* buf) { delete[] buf; }

/* ================================ VOPRF ================================= */

int dia_voprf_keygen(unsigned char sk[DIA_FR_LEN],
                     unsigned char pk[DIA_G2_LEN]) {
    try {
        auto kp = voprf::keygen();
        fr_to(kp.sk, sk);
        g2_to(kp.pk, pk);
        return DIA_OK;
    } catch (...) { return DIA_ERR; }
}

int dia_voprf_blind(const unsigned char* input, size_t input_len,
                    unsigned char out_blinded[DIA_G1_LEN],
                    unsigned char out_blind[DIA_FR_LEN]) {
    try {
        std::string in(reinterpret_cast<const char*>(input), input_len);
        auto [B, r] = voprf::blind(in);
        g1_to(B, out_blinded);
        fr_to(r, out_blind);
        return DIA_OK;
    } catch (...) { return DIA_ERR; }
}

int dia_voprf_evaluate(const unsigned char blinded[DIA_G1_LEN],
                       const unsigned char sk[DIA_FR_LEN],
                       unsigned char out_element[DIA_G1_LEN]) {
    try {
        auto B = g1_from(blinded);
        auto x = fr_from(sk);
        g1_to(ecgroup::G1Point::mul(B, x), out_element);
        return DIA_OK;
    } catch (...) { return DIA_ERR; }
}

int dia_voprf_unblind(const unsigned char element[DIA_G1_LEN],
                      const unsigned char blind[DIA_FR_LEN],
                      unsigned char out_Y[DIA_G1_LEN]) {
    try {
        auto E = g1_from(element);
        auto r = fr_from(blind);
        g1_to(voprf::unblind(E, r), out_Y);
        return DIA_OK;
    } catch (...) { return DIA_ERR; }
}

int dia_voprf_verify(const unsigned char* input, size_t input_len,
                     const unsigned char Y[DIA_G1_LEN],
                     const unsigned char pk[DIA_G2_LEN]) {
    try {
        std::string in(reinterpret_cast<const char*>(input), input_len);
        return ret_ok(voprf::verify(in, g1_from(Y), g2_from(pk)));
    } catch (...) { return DIA_ERR; }
}

int dia_voprf_verify_batch(const unsigned char* const* inputs,
                           const size_t* input_lens,
                           size_t n,
                           const unsigned char* Y_concat,
                           const unsigned char pk[DIA_G2_LEN]) {
    try {
        std::vector<std::string> ins; ins.reserve(n);
        for (size_t i = 0; i < n; ++i)
            ins.emplace_back(reinterpret_cast<const char*>(inputs[i]), input_lens[i]);

        std::vector<G1Point> outs; outs.reserve(n);
        for (size_t i = 0; i < n; ++i)
            outs.emplace_back(g1_from(Y_concat + i * DIA_G1_LEN));

        return ret_ok(voprf::verify_batch(ins, outs, g2_from(pk)));
    } catch (...) { return DIA_ERR; }
}

/* ================================= AMF ================================== */
/* NOTE: All serialization lives in amf::{Signature::to_bytes, from_bytes}.  */

int dia_amf_keygen(unsigned char sk[DIA_FR_LEN],
                   unsigned char pk[DIA_G1_LEN]) {
    try {
        amf::Params params = amf::Params::Default();
        amf::KeyPair kp = amf::KeyGen(params);
        fr_to(kp.sk, sk);
        g1_to(kp.pk, pk);
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
        Scalar sks = fr_from(sk_sender);
        G1Point PKr = g1_from(pk_receiver);
        G1Point PKj = g1_from(pk_judge);
        std::string m(reinterpret_cast<const char*>(msg), msg_len);

        amf::Signature sig = amf::Frank(sks, PKr, PKj, m, params);
        Bytes blob = sig.to_bytes();
        copy_to_c_buf(blob, sig_blob, sig_blob_len);
        return DIA_OK;
    } catch (...) { return DIA_ERR; }
}

int dia_amf_verify(const unsigned char pk_sender[DIA_G1_LEN],
                   const unsigned char sk_receiver[DIA_FR_LEN],
                   const unsigned char pk_judge[DIA_G1_LEN],
                   const unsigned char* msg, size_t msg_len,
                   const unsigned char* sig_blob, size_t sig_blob_len) {
    try {
        amf::Params params = amf::Params::Default();
        G1Point PKs = g1_from(pk_sender);
        Scalar  SKr = fr_from(sk_receiver);
        G1Point PKj = g1_from(pk_judge);
        std::string m(reinterpret_cast<const char*>(msg), msg_len);

        amf::Signature sig = amf::Signature::from_bytes(Bytes(sig_blob, sig_blob + sig_blob_len));
        return ret_ok(amf::Verify(PKs, SKr, PKj, m, sig, params));
    } catch (...) { return DIA_ERR; }
}

int dia_amf_judge(const unsigned char pk_sender[DIA_G1_LEN],
                  const unsigned char pk_receiver[DIA_G1_LEN],
                  const unsigned char sk_judge[DIA_FR_LEN],
                  const unsigned char* msg, size_t msg_len,
                  const unsigned char* sig_blob, size_t sig_blob_len) {
    try {
        amf::Params params = amf::Params::Default();
        G1Point PKs = g1_from(pk_sender);
        G1Point PKr = g1_from(pk_receiver);
        Scalar  SKj = fr_from(sk_judge);
        std::string m(reinterpret_cast<const char*>(msg), msg_len);

        amf::Signature sig = amf::Signature::from_bytes(Bytes(sig_blob, sig_blob + sig_blob_len));
        return ret_ok(amf::Judge(PKs, PKr, SKj, m, sig, params));
    } catch (...) { return DIA_ERR; }
}

/* ================================= BBS ================================== */

static inline Scalar hash_msg_to_scalar(const unsigned char* m, size_t len) {
    return Scalar::hash_to_scalar(Bytes(m, m + len));
}

int dia_bbs_keygen(unsigned char sk[DIA_FR_LEN],
                   unsigned char pk[DIA_G2_LEN]) {
    try {
        bbs::Params params = bbs::Params::Default();
        bbs::KeyPair kp = bbs::keygen(params);
        fr_to(kp.sk, sk);
        g2_to(kp.pk, pk);
        return DIA_OK;
    } catch (...) { return DIA_ERR; }
}

int dia_bbs_sign(const unsigned char* const* msgs,
                 const size_t* msg_lens,
                 size_t n_msgs,
                 const unsigned char sk[DIA_FR_LEN],
                 unsigned char A[DIA_G1_LEN],
                 unsigned char e[DIA_FR_LEN]) {
    try {
        bbs::Params params = bbs::Params::Default();
        std::vector<Scalar> M; M.reserve(n_msgs);
        for (size_t i = 0; i < n_msgs; ++i)
            M.emplace_back(hash_msg_to_scalar(msgs[i], msg_lens[i]));
        bbs::Signature sig = bbs::sign(params, fr_from(sk), M);
        g1_to(sig.A, A);
        fr_to(sig.e, e);
        return DIA_OK;
    } catch (...) { return DIA_ERR; }
}

int dia_bbs_verify(const unsigned char* const* msgs,
                   const size_t* msg_lens,
                   size_t n_msgs,
                   const unsigned char pk[DIA_G2_LEN],
                   const unsigned char A[DIA_G1_LEN],
                   const unsigned char e[DIA_FR_LEN]) {
    try {
        bbs::Params params = bbs::Params::Default();
        std::vector<Scalar> M; M.reserve(n_msgs);
        for (size_t i = 0; i < n_msgs; ++i)
            M.emplace_back(hash_msg_to_scalar(msgs[i], msg_lens[i]));
        bbs::Signature sig{ g1_from(A), fr_from(e) };
        return ret_ok(bbs::verify(params, g2_from(pk), M, sig));
    } catch (...) { return DIA_ERR; }
}

// --- GT-based SD proof encoding lives in bbs.cpp; dia_c only passes blobs ---
static ecgroup::Bytes serialize_bbs_proof(const bbs::SDProof& P) {
    // Delegating to bbs side would be ideal; keeping the working serializer we already had:
    std::vector<uint8_t> buf;
    // A
    { Bytes b=P.A.to_bytes(); buf.insert(buf.end(), b.begin(), b.end()); }
    // T (GT)
    { Bytes b=P.T.to_bytes(); buf.insert(buf.end(), b.begin(), b.end()); }
    // z_e
    { Bytes b=P.z_e.to_bytes(); buf.insert(buf.end(), b.begin(), b.end()); }
    auto u32_be = [&](uint32_t v){
        buf.push_back((v>>24)&0xFF); buf.push_back((v>>16)&0xFF);
        buf.push_back((v>>8)&0xFF);  buf.push_back(v&0xFF);
    };
    u32_be((uint32_t)P.hidden_indices.size());
    for (auto idx: P.hidden_indices) u32_be((uint32_t)idx);
    u32_be((uint32_t)P.z_m.size());
    for (auto &z: P.z_m) { Bytes b=z.to_bytes(); buf.insert(buf.end(), b.begin(), b.end()); }
    u32_be((uint32_t)P.nonce.size());
    buf.insert(buf.end(), P.nonce.begin(), P.nonce.end());
    return buf;
}

static bool deserialize_bbs_proof(const unsigned char* data, size_t len, bbs::SDProof& out) {
    const uint8_t* p = data;
    const uint8_t* end = data + len;
    auto need = [&](size_t n){ return size_t(end - p) >= n; };

    if (!need(DIA_G1_LEN)) return false;
    out.A = G1Point::from_bytes(Bytes(p, p + DIA_G1_LEN)); p += DIA_G1_LEN;

    if (!need(DIA_GT_LEN)) return false;
    mcl::bn::Fp12 gt;
    if (gt.deserialize(p, DIA_GT_LEN) != DIA_GT_LEN) return false;
    out.T = PairingResult(gt); p += DIA_GT_LEN;

    if (!need(DIA_FR_LEN)) return false;
    out.z_e = Scalar::from_bytes(Bytes(p, p + DIA_FR_LEN)); p += DIA_FR_LEN;

    auto read_u32 = [&](uint32_t& v)->bool {
        if (!need(4)) return false;
        v = (uint32_t(p[0])<<24) | (uint32_t(p[1])<<16) | (uint32_t(p[2])<<8) | uint32_t(p[3]);
        p += 4; return true;
    };

    uint32_t hc=0; if (!read_u32(hc)) return false;
    out.hidden_indices.clear(); out.hidden_indices.reserve(hc);
    for (uint32_t i=0;i<hc;++i){ uint32_t idx; if(!read_u32(idx)) return false; out.hidden_indices.push_back((size_t)idx); }

    uint32_t zc=0; if (!read_u32(zc)) return false;
    out.z_m.clear(); out.z_m.reserve(zc);
    for (uint32_t i=0;i<zc;++i){
        if (!need(DIA_FR_LEN)) return false;
        out.z_m.push_back(Scalar::from_bytes(Bytes(p, p + DIA_FR_LEN)));
        p += DIA_FR_LEN;
    }

    uint32_t nl=0; if (!read_u32(nl)) return false;
    if (!need(nl)) return false;
    out.nonce.assign(reinterpret_cast<const char*>(p), nl); p += nl;

    return p==end;
}

int dia_bbs_proof_create(const unsigned char* const* msgs,
                         const size_t* msg_lens,
                         size_t n_msgs,
                         const uint32_t* disclose_idx_1based,
                         size_t n_disclose,
                         const unsigned char pk[DIA_G2_LEN],
                         const unsigned char A[DIA_G1_LEN],
                         const unsigned char e[DIA_FR_LEN],
                         const unsigned char* nonce,
                         size_t nonce_len,
                         unsigned char** proof_blob,
                         size_t* proof_blob_len) {
    try {
        bbs::Params params = bbs::Params::Default();

        std::vector<Scalar> M; M.reserve(n_msgs);
        for (size_t i = 0; i < n_msgs; ++i)
            M.emplace_back(Scalar::hash_to_scalar(Bytes(msgs[i], msgs[i]+msg_lens[i])));

        std::vector<size_t> D; D.reserve(n_disclose);
        for (size_t i = 0; i < n_disclose; ++i) D.push_back((size_t)disclose_idx_1based[i]);

        bbs::Signature sig{ g1_from(A), fr_from(e) };
        std::string n(reinterpret_cast<const char*>(nonce), nonce_len);

        bbs::SDProof P = bbs::create_proof(params, g2_from(pk), sig, M, D, n);
        Bytes blob = serialize_bbs_proof(P);
        copy_to_c_buf(blob, proof_blob, proof_blob_len);
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
                         size_t proof_blob_len) {
    try {
        bbs::SDProof P;
        if (!deserialize_bbs_proof(proof_blob, proof_blob_len, P))
            return DIA_ERR_INVALID_ARG;

        std::vector<std::pair<size_t, Scalar>> disclosed;
        size_t L = 0;
        disclosed.reserve(n_disclosed);
        for (size_t i = 0; i < n_disclosed; ++i) {
            size_t idx = (size_t)disclosed_idx_1based[i];
            L = std::max(L, idx);
            disclosed.emplace_back(idx, Scalar::hash_to_scalar(Bytes(disclosed_msgs[i], disclosed_msgs[i]+disclosed_lens[i])));
        }
        for (auto j : P.hidden_indices) L = std::max(L, j);

        std::string n(reinterpret_cast<const char*>(nonce), nonce_len);
        if (n != P.nonce) return DIA_ERR_VERIFY_FAIL;

        bbs::Params params = bbs::Params::Default();
        return ret_ok(bbs::verify_proof(params, g2_from(pk), P, disclosed, L));
    } catch (...) { return DIA_ERR; }
}
