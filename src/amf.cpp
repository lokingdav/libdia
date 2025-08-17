#include "amf.hpp"
#include <array>
#include <cstdint>
#include <cstring>

using namespace ecgroup;

namespace amf {
namespace {

// ===== Helpers: bytes, length-prefix, hashing (Fiat–Shamir) =====

inline Bytes toBytes(const std::string& s) {
    return Bytes(s.begin(), s.end());
}

inline void appendU32BE(Bytes& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >>  8) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >>  0) & 0xFF));
}

inline void appendLP(Bytes& out, const Bytes& b) {
    appendU32BE(out, static_cast<uint32_t>(b.size()));
    out.insert(out.end(), b.begin(), b.end());
}

inline void appendPoint(Bytes& out, const G1Point& P) {
    appendLP(out, P.to_bytes());
}

inline void appendScalar(Bytes& out, const Scalar& s) {
    appendLP(out, s.to_bytes());
}

// Compute FS challenge c = H(domain || m || statement || commits) -> Fr
Scalar fs_challenge(const std::string& domain,
                    const std::string& msg,
                    const G1Point& pk_s,
                    const G1Point& pk_j,
                    const G1Point& T,
                    const G1Point& U,
                    const G1Point& A,
                    const G1Point& B,
                    const DisjSchnorrSchnorrCommit& left_cmt,
                    const DisjCPorSchnorrCommit& right_cmt)
{
    Bytes buf;
    appendLP(buf, toBytes(domain));      // domain sep
    appendLP(buf, toBytes("AMF|DMF|FSv1"));

    appendLP(buf, toBytes(msg));

    appendPoint(buf, pk_s);
    appendPoint(buf, pk_j);
    appendPoint(buf, T);
    appendPoint(buf, U);
    appendPoint(buf, A);
    appendPoint(buf, B);

    // Left disjunction commits: (t0, t1)
    appendPoint(buf, left_cmt.t0);
    appendPoint(buf, left_cmt.t1);

    // Right disjunction commits: CP (vt, wt), then Schnorr t1
    appendPoint(buf, right_cmt.cp_t.vt);
    appendPoint(buf, right_cmt.cp_t.wt);
    appendPoint(buf, right_cmt.t1);

    return Scalar::hash_to_scalar(buf);
}

// Basic group ops helpers
inline G1Point add(const G1Point& a, const G1Point& b) { return a.add(b); }
inline G1Point neg(const G1Point& a) { return a.negate(); }
inline G1Point mul(const G1Point& P, const Scalar& s) { return G1Point::mul(P, s); }
inline Scalar  sub(const Scalar& a, const Scalar& b) { return a + Scalar::neg(b); }

// ===== Schnorr over G1: y = w * g =====
struct SchnorrCommitOut {
    G1Point t;
    Scalar  r; // nonce
};

inline SchnorrCommitOut schnorr_commit(const G1Point& g) {
    SchnorrCommitOut out;
    out.r = Scalar::get_random();
    out.t = mul(g, out.r);
    return out;
}

inline Scalar schnorr_response(const Scalar& w, const Scalar& c, const Scalar& r) {
    // z = r + w * c
    return r + (w * c);
}

inline bool schnorr_verify(const G1Point& g, const G1Point& y,
                           const G1Point& t, const Scalar& c, const Scalar& z)
{
    // g^z ?= t + y^c
    G1Point lhs = mul(g, z);
    G1Point rhs = add(t, mul(y, c));
    return lhs == rhs;
}

inline std::pair<G1Point, Scalar> schnorr_simulate(const G1Point& g,
                                                    const G1Point& y,
                                                    const Scalar& c)
{
    // choose z, set t = g^z - y^c
    Scalar z = Scalar::get_random();
    G1Point t = add(mul(g, z), neg(mul(y, c)));
    return {t, z};
}

// ===== Chaum–Pedersen for DH triple: prove z s.t.
//     v == z * g  and  w == z * u
// commit: pick r, vt = r*g, wt = r*u
// verify: g^z == vt + v^c  and  u^z == wt + w^c
struct CPCommitOut {
    CPCommit t;
    Scalar   r;
};

inline CPCommitOut cp_commit(const G1Point& g, const G1Point& u) {
    CPCommitOut out;
    out.r      = Scalar::get_random();
    out.t.vt   = mul(g, out.r);
    out.t.wt   = mul(u, out.r);
    return out;
}

inline Scalar cp_response(const Scalar& z_witness, const Scalar& c, const Scalar& r) {
    // z = r + z_witness * c
    return r + (z_witness * c);
}

inline bool cp_verify(const G1Point& g, const G1Point& u,
                      const G1Point& v, const G1Point& w,
                      const CPCommit& t, const Scalar& c, const Scalar& z)
{
    G1Point lhs1 = mul(g, z);
    G1Point rhs1 = add(t.vt, mul(v, c));
    if (!(lhs1 == rhs1)) return false;

    G1Point lhs2 = mul(u, z);
    G1Point rhs2 = add(t.wt, mul(w, c));
    return lhs2 == rhs2;
}

inline std::pair<CPCommit, Scalar> cp_simulate(const G1Point& g, const G1Point& u,
                                               const G1Point& v, const G1Point& w,
                                               const Scalar& c)
{
    Scalar z = Scalar::get_random();
    CPCommit t;
    t.vt = add(mul(g, z), neg(mul(v, c)));
    t.wt = add(mul(u, z), neg(mul(w, c)));
    return {t, z};
}

// ===== Build the AMF proof (FS over AND of two ORs) =====
// left:  Schnorr(pk_s) OR Schnorr(T)
// right: CP(pk_j, A, T) OR Schnorr(U)

struct LeftDisjWork {
    // true branch index and its witness; here we signal which branch is real
    int     b;        // 0 => Schnorr(pk_s) is real; 1 => Schnorr(T) is real
    Scalar  w_real;   // witness for the real branch (sk_s or log_g(T))
    // commits/aux:
    DisjSchnorrSchnorrCommit commit;
    // for simulated branch we keep (c_sim, z_sim)
    Scalar  c_sim;
    Scalar  z_sim;
    // for real branch we keep nonce r_real
    Scalar  r_real;
};

struct RightDisjWork {
    int     b;       // 0 => CP is real; 1 => Schnorr(U) is real
    Scalar  w_real;  // real witness (alpha for CP, or log_g(U) for Schnorr)
    DisjCPorSchnorrCommit commit;
    Scalar  c_sim;
    Scalar  z_sim;
    Scalar  r_real;  // nonce for real branch (CP.r or Schnorr.r)
};

inline LeftDisjWork make_left_disj(int b, const Scalar& w_real,
                                   const Params& params,
                                   const G1Point& pk_s,
                                   const G1Point& T)
{
    LeftDisjWork L;
    L.b = b; L.w_real = w_real;

    const int d = 1 - b;

    if (b == 0) {
        // Real on pk_s, simulate on T
        auto real = schnorr_commit(params.g);
        L.commit.t0 = real.t;
        auto c_sim  = Scalar::get_random();
        auto sim    = schnorr_simulate(params.g, T, c_sim);
        L.commit.t1 = sim.first;
        L.c_sim     = c_sim;
        L.z_sim     = sim.second;
        L.r_real    = real.r;
    } else {
        // Real on T, simulate on pk_s
        auto real = schnorr_commit(params.g);
        L.commit.t1 = real.t;
        auto c_sim  = Scalar::get_random();
        auto sim    = schnorr_simulate(params.g, pk_s, c_sim);
        L.commit.t0 = sim.first;
        L.c_sim     = c_sim;
        L.z_sim     = sim.second;
        L.r_real    = real.r;
    }
    return L;
}

inline DisjSchnorrSchnorrResp finish_left_disj(const LeftDisjWork& L,
                                               const Scalar& c,
                                               const G1Point& pk_s,
                                               const G1Point& T,
                                               const Params& params)
{
    DisjSchnorrSchnorrResp z;
    const int b = L.b;
    const int d = 1 - b;

    Scalar c_b  = sub(c, L.c_sim);          // c_b = c - c_sim
    Scalar z_b  = schnorr_response(L.w_real, c_b, L.r_real);

    if (b == 0) {
        // c0 corresponds to branch 0 (pk_s)
        z.c0 = c_b;
        z.z0 = z_b;
        z.z1 = L.z_sim;
    } else {
        // branch 1 is real -> c0 is simulated share
        z.c0 = L.c_sim;
        z.z0 = L.z_sim;
        z.z1 = z_b;
    }
    return z;
}

inline RightDisjWork make_right_disj(int b, const Scalar& w_real,
                                     const Params& params,
                                     const G1Point& pk_j,
                                     const G1Point& A,
                                     const G1Point& T,
                                     const G1Point& U)
{
    RightDisjWork R;
    R.b = b; R.w_real = w_real;

    if (b == 0) {
        // Real CP(pk_j, A, T), simulate Schnorr(U)
        auto real = cp_commit(params.g, pk_j);
        R.commit.cp_t = real.t;
        auto c_sim    = Scalar::get_random();
        auto sim      = schnorr_simulate(params.g, U, c_sim);
        R.commit.t1   = sim.first;

        R.c_sim  = c_sim;
        R.z_sim  = sim.second;
        R.r_real = real.r;
    } else {
        // Real Schnorr(U), simulate CP
        auto real = schnorr_commit(params.g);
        R.commit.t1 = real.t;

        auto c_sim  = Scalar::get_random();
        auto sim    = cp_simulate(params.g, pk_j, A, T, c_sim);
        R.commit.cp_t = sim.first;

        R.c_sim  = c_sim;
        R.z_sim  = sim.second;
        R.r_real = real.r;
    }
    return R;
}

inline DisjCPorSchnorrResp finish_right_disj(const RightDisjWork& R,
                                             const Scalar& c,
                                             const Params& params,
                                             const G1Point& pk_j,
                                             const G1Point& A,
                                             const G1Point& T,
                                             const G1Point& U)
{
    DisjCPorSchnorrResp z;
    const int b = R.b;

    Scalar c_b  = sub(c, R.c_sim);   // c_b = c - c_sim
    Scalar z_b;

    if (b == 0) {
        // real CP
        z_b  = cp_response(R.w_real, c_b, R.r_real);
        z.c0 = c_b;     // c0 belongs to CP branch
        z.z0 = z_b;     // CP response
        z.z1 = R.z_sim; // Schnorr(U) simulated response
    } else {
        // real Schnorr(U)
        z_b  = schnorr_response(R.w_real, c_b, R.r_real);
        z.c0 = R.c_sim; // CP simulated share stored as c0
        z.z0 = R.z_sim; // CP simulated response
        z.z1 = z_b;     // real Schnorr(U) response
    }
    return z;
}

// Verify both disjunctions given c
inline bool verify_left_disj(const DisjSchnorrSchnorrCommit& tc,
                             const DisjSchnorrSchnorrResp&   tr,
                             const Scalar& c,
                             const Params& params,
                             const G1Point& pk_s,
                             const G1Point& T)
{
    Scalar c0 = tr.c0;
    Scalar c1 = sub(c, c0);
    bool b0 = schnorr_verify(params.g, pk_s, tc.t0, c0, tr.z0);
    bool b1 = schnorr_verify(params.g, T,   tc.t1, c1, tr.z1);
    return b0 && b1;
}

inline bool verify_right_disj(const DisjCPorSchnorrCommit& tc,
                              const DisjCPorSchnorrResp&   tr,
                              const Scalar& c,
                              const Params& params,
                              const G1Point& pk_j,
                              const G1Point& A,
                              const G1Point& T,
                              const G1Point& U)
{
    Scalar c0 = tr.c0;
    Scalar c1 = sub(c, c0);
    bool b0 = cp_verify(params.g, pk_j, A, T, tc.cp_t, c0, tr.z0);
    bool b1 = schnorr_verify(params.g, U,  tc.t1,     c1, tr.z1);
    return b0 && b1;
}

} // namespace (anon)

// ===== Public API =====

Params Params::Default() {
    Params p;
    // Deterministic generator via hash-to-curve (cofactor-cleared by MCL)
    p.g = G1Point::hash_and_map_to("AMF:G1:generator");
    p.domain_tag = "AMF:DMF:BN256";
    return p;
}

KeyPair KeyGen(const Params& params) {
    KeyPair kp;
    kp.sk = Scalar::get_random();
    kp.pk = G1Point::mul(params.g, kp.sk);
    return kp;
}

Signature Frank(const Scalar& sk_s,
                const G1Point& pk_r,
                const G1Point& pk_j,
                const std::string& msg,
                const Params& params)
{
    // Fresh session randomness
    Scalar alpha = Scalar::get_random();
    Scalar beta  = Scalar::get_random();

    // Public tuple
    G1Point A = G1Point::mul(params.g, alpha);
    G1Point B = G1Point::mul(params.g, beta);
    G1Point T = G1Point::mul(pk_j,     alpha);  // T = alpha * pk_j
    G1Point U = G1Point::mul(pk_r,     beta);   // U = beta  * pk_r

    // Build disjunctions:
    // left: real = Schnorr(pk_s) with witness sk_s
    auto Lw  = make_left_disj(/*b=*/0, /*w_real=*/sk_s, params, /*pk_s=*/G1Point::mul(params.g, sk_s), T);

    // right: real = CP(pk_j, A, T) with witness alpha
    auto Rw  = make_right_disj(/*b=*/0, /*w_real=*/alpha, params, pk_j, A, T, U);

    // Fiat–Shamir challenge
    Scalar c = fs_challenge(params.domain_tag, msg,
                            /*pk_s=*/G1Point::mul(params.g, sk_s),
                            pk_j, T, U, A, B,
                            Lw.commit, Rw.commit);

    // Finish responses
    DisjSchnorrSchnorrResp Lz = finish_left_disj (Lw, c, /*pk_s=*/G1Point::mul(params.g, sk_s), T, params);
    DisjCPorSchnorrResp    Rz = finish_right_disj(Rw, c, params, pk_j, A, T, U);

    Signature s;
    s.proof.left_commit  = Lw.commit;
    s.proof.right_commit = Rw.commit;
    s.proof.left_resp    = Lz;
    s.proof.right_resp   = Rz;
    s.T = T; s.U = U; s.A = A; s.B = B;
    return s;
}

Signature Forge(const G1Point& pk_s,
                const G1Point& pk_r,
                const G1Point& pk_j,
                const std::string& msg,
                const Params& params)
{
    Scalar alpha = Scalar::get_random();
    Scalar beta  = Scalar::get_random();
    Scalar gamma = Scalar::get_random();
    Scalar delta = Scalar::get_random();

    G1Point A = G1Point::mul(params.g, alpha);
    G1Point B = G1Point::mul(params.g, beta);
    G1Point T = G1Point::mul(params.g, gamma); // not linked to pk_j -> judge check fails
    G1Point U = G1Point::mul(params.g, delta); // not linked to pk_r -> receiver check fails

    // left: real = Schnorr(T) with witness gamma
    auto Lw = make_left_disj(/*b=*/1, /*w_real=*/gamma, params, pk_s, T);

    // right: real = Schnorr(U) with witness delta
    auto Rw = make_right_disj(/*b=*/1, /*w_real=*/delta, params, pk_j, A, T, U);

    Scalar c = fs_challenge(params.domain_tag, msg, pk_s, pk_j, T, U, A, B,
                            Lw.commit, Rw.commit);

    auto Lz = finish_left_disj (Lw, c, pk_s, T, params);
    auto Rz = finish_right_disj(Rw, c, params, pk_j, A, T, U);

    Signature s;
    s.proof.left_commit  = Lw.commit;
    s.proof.right_commit = Rw.commit;
    s.proof.left_resp    = Lz;
    s.proof.right_resp   = Rz;
    s.T = T; s.U = U; s.A = A; s.B = B;
    return s;
}

Signature RForge(const G1Point& pk_s,
                 const Scalar&  sk_r,
                 const G1Point& pk_j,
                 const std::string& msg,
                 const Params& params)
{
    // derive pk_r from sk_r
    G1Point pk_r = G1Point::mul(params.g, sk_r);

    // receiver knows sk_r
    Scalar alpha = Scalar::get_random();
    Scalar beta  = Scalar::get_random();
    Scalar gamma = Scalar::get_random();

    G1Point A = G1Point::mul(params.g, alpha);
    G1Point B = G1Point::mul(params.g, beta);
    G1Point T = G1Point::mul(params.g, gamma);        // breaks judge check
    G1Point U = G1Point::mul(pk_r, beta);             // passes receiver check

    // left: real = Schnorr(T) with witness gamma (so FS proof verifies)
    auto Lw = make_left_disj(/*b=*/1, /*w_real=*/gamma, params, pk_s, T);

    // right: real = Schnorr(U) with witness (beta * sk_r)
    Scalar wU = beta * sk_r;
    auto Rw = make_right_disj(/*b=*/1, /*w_real=*/wU, params, pk_j, A, T, U);

    Scalar c = fs_challenge(params.domain_tag, msg, pk_s, pk_j, T, U, A, B,
                            Lw.commit, Rw.commit);

    auto Lz = finish_left_disj (Lw, c, pk_s, T, params);
    auto Rz = finish_right_disj(Rw, c, params, pk_j, A, T, U);

    Signature s;
    s.proof.left_commit  = Lw.commit;
    s.proof.right_commit = Rw.commit;
    s.proof.left_resp    = Lz;
    s.proof.right_resp   = Rz;
    s.T = T; s.U = U; s.A = A; s.B = B;
    return s;
}

Signature JForge(const G1Point& pk_s,
                 const G1Point& pk_r,
                 const Scalar&  sk_j,
                 const std::string& msg,
                 const Params& params)
{
    // judge knows sk_j
    Scalar alpha = Scalar::get_random();
    Scalar beta  = Scalar::get_random();

    G1Point A = G1Point::mul(params.g, alpha);
    G1Point B = G1Point::mul(params.g, beta);
    G1Point T = G1Point::mul(G1Point::mul(params.g, sk_j), alpha);  // T = alpha * pk_j
    G1Point U = G1Point::mul(pk_r, beta);

    // left: real = Schnorr(T) with witness alpha*sk_j
    Scalar wT = alpha * sk_j;
    auto Lw = make_left_disj(/*b=*/1, /*w_real=*/wT, params, pk_s, T);

    // right: real = CP(pk_j, A, T) with witness alpha
    auto Rw = make_right_disj(/*b=*/0, /*w_real=*/alpha, params, G1Point::mul(params.g, sk_j), A, T, U);

    Scalar c = fs_challenge(params.domain_tag, msg, pk_s, G1Point::mul(params.g, sk_j),
                            T, U, A, B, Lw.commit, Rw.commit);

    auto Lz = finish_left_disj (Lw, c, pk_s, T, params);
    auto Rz = finish_right_disj(Rw, c, params, G1Point::mul(params.g, sk_j), A, T, U);

    Signature s;
    s.proof.left_commit  = Lw.commit;
    s.proof.right_commit = Rw.commit;
    s.proof.left_resp    = Lz;
    s.proof.right_resp   = Rz;
    s.T = T; s.U = U; s.A = A; s.B = B;
    return s;
}

bool Verify(const G1Point& pk_s,
            const Scalar&  sk_r,
            const G1Point& pk_j,
            const std::string& msg,
            const Signature& sig,
            const Params& params)
{
    // Designated check for receiver: U == sk_r * B
    if (!(sig.U == G1Point::mul(sig.B, sk_r))) return false;

    // Fiat–Shamir challenge
    Scalar c = fs_challenge(params.domain_tag, msg,
                            pk_s, pk_j, sig.T, sig.U, sig.A, sig.B,
                            sig.proof.left_commit, sig.proof.right_commit);

    // Verify both disjunctions
    bool L = verify_left_disj(sig.proof.left_commit,  sig.proof.left_resp,
                              c, params, pk_s, sig.T);
    if (!L) return false;

    bool R = verify_right_disj(sig.proof.right_commit, sig.proof.right_resp,
                               c, params, pk_j, sig.A, sig.T, sig.U);
    return R;
}

bool Judge(const G1Point& pk_s,
           const G1Point& pk_r,
           const Scalar&  sk_j,
           const std::string& msg,
           const Signature& sig,
           const Params& params)
{
    G1Point pk_j = G1Point::mul(params.g, sk_j);

    // Designated check for judge: T == sk_j * A
    if (!(sig.T == G1Point::mul(sig.A, sk_j))) return false;

    Scalar c = fs_challenge(params.domain_tag, msg,
                            pk_s, pk_j, sig.T, sig.U, sig.A, sig.B,
                            sig.proof.left_commit, sig.proof.right_commit);

    bool L = verify_left_disj(sig.proof.left_commit,  sig.proof.left_resp,
                              c, params, pk_s, sig.T);
    if (!L) return false;

    bool R = verify_right_disj(sig.proof.right_commit, sig.proof.right_resp,
                               c, params, pk_j, sig.A, sig.T, sig.U);
    return R;
}

} // namespace amf
