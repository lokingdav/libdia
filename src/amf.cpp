#include "amf.hpp"
#include <stdexcept>
#include <cstring>   // std::memcpy
#include <cstdint>

namespace amf {

using ecgroup::PairingResult;
using ecgroup::FR_SERIALIZED_SIZE;
using ecgroup::G1_SERIALIZED_SIZE;

/* ============================== Utilities =============================== */

static inline Scalar fr_neg(const Scalar& a) { return Scalar::neg(a); }
static inline Scalar fr_sub(const Scalar& a, const Scalar& b) { return a + fr_neg(b); }

static inline void append_bytes(std::vector<uint8_t>& out, const Bytes& b) {
    out.insert(out.end(), b.begin(), b.end());
}

static inline uint32_t be32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}
static inline void be32_write(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back(uint8_t((v >> 24) & 0xFF));
    out.push_back(uint8_t((v >> 16) & 0xFF));
    out.push_back(uint8_t((v >>  8) & 0xFF));
    out.push_back(uint8_t((v >>  0) & 0xFF));
}

/* Schnorr: proof of knowledge of w such that y = w*g (additive group) */
struct SchnorrT { G1Point t; };

static inline SchnorrT schnorr_commit(const Scalar& a, const G1Point& g) {
    return { G1Point::mul(g, a) };
}
static inline SchnorrT schnorr_sim(const Scalar& z, const Scalar& c,
                                   const G1Point& g, const G1Point& y) {
    // t = z*g - c*y
    return { G1Point::mul(g, z).add(G1Point::mul(y, fr_neg(c))) };
}
static inline bool schnorr_verify(const G1Point& t, const Scalar& c, const Scalar& z,
                                  const G1Point& g, const G1Point& y) {
    // z*g == t + c*y
    G1Point lhs = G1Point::mul(g, z);
    G1Point rhs = t.add(G1Point::mul(y, c));
    return lhs == rhs;
}

/* Chaum–Pedersen for DH triple: u, v=B*g, w=B*u with same B (unknown).
 * Commit: b -> (v_t = b*g, w_t = b*u)
 * Verify: z*g == v_t + c*v   AND   z*u == w_t + c*w
 */
struct CPT { G1Point vt, wt; };

static inline CPT cp_commit(const Scalar& b, const G1Point& g, const G1Point& u) {
    return { G1Point::mul(g, b), G1Point::mul(u, b) };
}
static inline CPT cp_sim(const Scalar& z, const Scalar& c, const G1Point& g,
                         const G1Point& u, const G1Point& v, const G1Point& w) {
    (void)u;
    // vt = z*g - c*v ; wt = z*u - c*w  (we still pass u to be explicit)
    G1Point vt = G1Point::mul(g, z).add(G1Point::mul(v, fr_neg(c)));
    G1Point wt = G1Point::mul(u, z).add(G1Point::mul(w, fr_neg(c)));
    return { vt, wt };
}
static inline bool cp_verify(const CPT& t, const Scalar& c, const Scalar& z,
                             const G1Point& g, const G1Point& u,
                             const G1Point& v, const G1Point& w) {
    G1Point lhs1 = G1Point::mul(g, z);
    G1Point rhs1 = t.vt.add(G1Point::mul(v, c));
    G1Point lhs2 = G1Point::mul(u, z);
    G1Point rhs2 = t.wt.add(G1Point::mul(w, c));
    return (lhs1 == rhs1) && (lhs2 == rhs2);
}

/* Fiat–Shamir challenge over (domain || msg || t00 || t01 || vt10 || wt10 || t11) */
static Scalar amf_challenge(const std::string& msg,
                            const G1Point& t00, const G1Point& t01,
                            const G1Point& vt10, const G1Point& wt10,
                            const G1Point& t11) {
    Bytes buf;
    const char* tag = "AMF:FS:v1";
    buf.insert(buf.end(), tag, tag + std::strlen(tag));
    buf.insert(buf.end(), msg.begin(), msg.end());
    auto put = [&](const G1Point& P){ Bytes b = P.to_bytes(); buf.insert(buf.end(), b.begin(), b.end()); };
    put(t00); put(t01); put(vt10); put(wt10); put(t11);
    return Scalar::hash_to_scalar(buf);
}

/* =========================== Public API impl ============================ */

Params Params::Default() {
    Params p;
    p.g = G1Point::hash_and_map_to("AMF:g1");
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
                const Params& params) {
    const G1Point& g = params.g;
    Signature S{};

    // Fresh randomness
    Scalar alpha = Scalar::get_random();
    Scalar beta  = Scalar::get_random();

    // Public tuple: binding to R and J
    S.T = G1Point::mul(pk_j, alpha);
    S.U = G1Point::mul(pk_r, beta);
    S.A = G1Point::mul(g,    alpha);
    S.B = G1Point::mul(g,    beta);

    /* disj0: OR(Schnorr(pk_s), Schnorr(T)) -- real on pk_s (branch 0), simulate T (branch 1) */
    Scalar a0  = Scalar::get_random();
    S.t00 = schnorr_commit(a0, g).t;
    Scalar cd0 = Scalar::get_random();
    Scalar zd0 = Scalar::get_random();
    S.t01 = schnorr_sim(zd0, cd0, g, S.T).t;

    /* disj1: OR(CP(pk_j,A,T), Schnorr(U)) -- real CP (branch 0), simulate Schnorr(U) (branch 1) */
    Scalar b0  = Scalar::get_random();
    CPT t_b1 = cp_commit(b0, g, pk_j);
    S.vt10 = t_b1.vt; S.wt10 = t_b1.wt;
    Scalar cd1 = Scalar::get_random();
    Scalar zd1 = Scalar::get_random();
    S.t11 = schnorr_sim(zd1, cd1, g, S.U).t;

    // FS challenge
    Scalar c = amf_challenge(msg, S.t00, S.t01, S.vt10, S.wt10, S.t11);

    // disj0 responses
    Scalar c_b0 = fr_sub(c, cd0);
    S.c0 = c_b0;
    S.z0 = a0 + (sk_s * c_b0);
    S.z1 = zd0;

    // disj1 responses
    Scalar c_b1 = fr_sub(c, cd1);
    S.c0p = c_b1;
    S.z0p = b0 + (alpha * c_b1);
    S.z1p = zd1;

    return S;
}

bool Verify(const G1Point& pk_s,
            const Scalar&  sk_r,
            const G1Point& pk_j,
            const std::string& msg,
            const Signature& S,
            const Params& params) {
    const G1Point& g = params.g;

    // Receiver binding
    if (!(S.U == G1Point::mul(S.B, sk_r))) return false;

    // FS challenge
    Scalar c = amf_challenge(msg, S.t00, S.t01, S.vt10, S.wt10, S.t11);

    // disj0: branch-0 Schnorr(pk_s), branch-1 Schnorr(T)
    Scalar c1 = fr_sub(c, S.c0);
    if (!(schnorr_verify(S.t00, S.c0, S.z0, g, pk_s) &&
          schnorr_verify(S.t01, c1,   S.z1, g, S.T))) {
        return false;
    }

    // disj1: branch-0 CP(pk_j,A,T), branch-1 Schnorr(U)
    Scalar c1p = fr_sub(c, S.c0p);
    CPT t{ S.vt10, S.wt10 };
    if (!(cp_verify(t, S.c0p, S.z0p, g, pk_j, S.A, S.T) &&
          schnorr_verify(S.t11, c1p,   S.z1p, g, S.U))) {
        return false;
    }
    return true;
}

bool Judge(const G1Point& pk_s,
           const G1Point& pk_r,
           const Scalar&  sk_j,
           const std::string& msg,
           const Signature& S,
           const Params& params) {
    (void)pk_r; // not needed for the math; keep for API symmetry
    const G1Point& g = params.g;

    // Judge binding
    if (!(S.T == G1Point::mul(S.A, sk_j))) return false;

    Scalar c = amf_challenge(msg, S.t00, S.t01, S.vt10, S.wt10, S.t11);

    // disj0
    Scalar c1 = fr_sub(c, S.c0);
    if (!(schnorr_verify(S.t00, S.c0, S.z0, g, pk_s) &&
          schnorr_verify(S.t01, c1,   S.z1, g, S.T))) {
        return false;
    }

    // disj1 (use pk_j = sk_j * g)
    G1Point pk_j = G1Point::mul(g, sk_j);
    Scalar c1p = fr_sub(c, S.c0p);
    CPT t{ S.vt10, S.wt10 };
    if (!(cp_verify(t, S.c0p, S.z0p, g, pk_j, S.A, S.T) &&
          schnorr_verify(S.t11, c1p,   S.z1p, g, S.U))) {
        return false;
    }
    return true;
}

/* ------------------------------ Forgeries ------------------------------ */
/* These construct signatures with different “real” branches to match tests.  */

/** Public Forge: break both bindings, keep proofs valid.
 *  - Set T = gamma*g, U = delta*g (no relation to pk_r, pk_j).
 *  - disj0 real branch: Schnorr(T) (branch-1) with witness gamma.
 *  - disj1 real branch: Schnorr(U) (branch-1) with witness delta.
 */
Signature Forge(const G1Point& pk_s,
                const G1Point& pk_r,
                const G1Point& pk_j,
                const std::string& msg,
                const Params& params) {
    (void)pk_s; (void)pk_r; (void)pk_j;
    const G1Point& g = params.g;
    Signature S{};

    Scalar alpha = Scalar::get_random();
    Scalar beta  = Scalar::get_random();
    Scalar gamma = Scalar::get_random();
    Scalar delta = Scalar::get_random();

    S.T = G1Point::mul(g, gamma);
    S.U = G1Point::mul(g, delta);
    S.A = G1Point::mul(g, alpha);
    S.B = G1Point::mul(g, beta);

    // disj0: simulate branch-0 (pk_s), real branch-1 (T with witness gamma)
    Scalar cd0 = Scalar::get_random(), zd0 = Scalar::get_random();
    S.t00 = schnorr_sim(zd0, cd0, g, G1Point::mul(g, Scalar::get_random())).t; // y unused; any y ok since simulated
    // Use pk_s as y for simulation to be consistent:
    S.t00 = schnorr_sim(zd0, cd0, g, pk_s).t;

    Scalar a1 = Scalar::get_random();
    S.t01 = schnorr_commit(a1, g).t;

    // disj1: simulate branch-0 (CP), real branch-1 (Schnorr(U) with witness delta)
    Scalar cd1 = Scalar::get_random(), zd1 = Scalar::get_random();
    // CP simulate with v=A, w=T and u=pk_j:
    CPT tcp = cp_sim(zd1, cd1, g, pk_j, S.A, S.T);
    S.vt10 = tcp.vt; S.wt10 = tcp.wt;

    Scalar aU = Scalar::get_random();
    S.t11 = schnorr_commit(aU, g).t;

    // FS challenge
    Scalar c = amf_challenge(msg, S.t00, S.t01, S.vt10, S.wt10, S.t11);

    // disj0 responses (store c0 for branch-0; real is branch-1)
    S.c0 = cd0;
    Scalar c1 = fr_sub(c, S.c0);
    S.z0 = zd0;                        // simulated
    S.z1 = a1 + (gamma * c1);          // real

    // disj1 responses (store c0p for branch-0; real is branch-1)
    S.c0p = cd1;
    Scalar c1p = fr_sub(c, S.c0p);
    S.z0p = zd1;                       // simulated CP
    S.z1p = aU + (delta * c1p);        // real Schnorr(U)

    return S;
}

/** RForge: Verify passes, Judge fails.
 *  - Set U = beta*pk_r (so U == sk_r*B), T = gamma*g (unrelated to A).
 *  - disj0 real branch: Schnorr(T) (branch-1) with witness gamma.
 *  - disj1 real branch: Schnorr(U) (branch-1) with witness beta*sk_r (exists).
 */
Signature RForge(const G1Point& pk_s,
                 const Scalar&  sk_r,
                 const G1Point& pk_j,
                 const std::string& msg,
                 const Params& params) {
    (void)pk_s; (void)pk_j;
    const G1Point& g = params.g;
    Signature S{};

    Scalar alpha = Scalar::get_random();
    Scalar beta  = Scalar::get_random();
    Scalar gamma = Scalar::get_random();

    S.T = G1Point::mul(g, gamma);
    S.U = G1Point::mul(G1Point::mul(g, sk_r), beta);  // = (beta*sk_r)*g = beta*pk_r
    S.A = G1Point::mul(g, alpha);
    S.B = G1Point::mul(g, beta);

    // disj0: simulate branch-0 (pk_s), real branch-1 (T)
    Scalar cd0 = Scalar::get_random(), zd0 = Scalar::get_random();
    S.t00 = schnorr_sim(zd0, cd0, g, pk_s).t;

    Scalar a1 = Scalar::get_random();
    S.t01 = schnorr_commit(a1, g).t;

    // disj1: simulate CP (branch-0), real Schnorr(U) (branch-1)
    Scalar cd1 = Scalar::get_random(), zd1 = Scalar::get_random();
    CPT tcp = cp_sim(zd1, cd1, g, pk_j, S.A, S.T);
    S.vt10 = tcp.vt; S.wt10 = tcp.wt;

    Scalar aU = Scalar::get_random();
    S.t11 = schnorr_commit(aU, g).t;

    Scalar c = amf_challenge(msg, S.t00, S.t01, S.vt10, S.wt10, S.t11);

    S.c0 = cd0;
    Scalar c1 = fr_sub(c, S.c0);
    S.z0 = zd0;
    S.z1 = a1 + (gamma * c1);

    S.c0p = cd1;
    Scalar c1p = fr_sub(c, S.c0p);
    Scalar wU = beta * sk_r; // witness for U relative to g
    S.z0p = zd1;
    S.z1p = aU + (wU * c1p);

    return S;
}

/** JForge: both Verify and Judge pass.
 *  - Set T = alpha*pk_j, U = beta*pk_r (both bindings hold).
 *  - disj0 real branch: Schnorr(T) (branch-1) with witness alpha*sk_j.
 *  - disj1 real branch: CP (branch-0) with witness alpha.
 */
Signature JForge(const G1Point& pk_s,
                 const G1Point& pk_r,
                 const Scalar&  sk_j,
                 const std::string& msg,
                 const Params& params) {
    (void)pk_s; (void)pk_r;
    const G1Point& g = params.g;
    Signature S{};

    Scalar alpha = Scalar::get_random();
    Scalar beta  = Scalar::get_random();

    S.T = G1Point::mul(G1Point::mul(g, sk_j), alpha); // = (alpha*sk_j)*g = alpha*pk_j
    S.U = G1Point::mul(pk_r, beta);                   // = beta*pk_r
    S.A = G1Point::mul(g, alpha);
    S.B = G1Point::mul(g, beta);

    // disj0: simulate branch-0 (pk_s), real branch-1 (Schnorr(T) with witness alpha*sk_j)
    Scalar cd0 = Scalar::get_random(), zd0 = Scalar::get_random();
    S.t00 = schnorr_sim(zd0, cd0, g, pk_s).t;

    Scalar aT = Scalar::get_random();
    S.t01 = schnorr_commit(aT, g).t;

    // disj1: real CP (branch-0) with witness alpha, simulate Schnorr(U) (branch-1)
    Scalar b0 = Scalar::get_random();
    G1Point pk_j = G1Point::mul(g, sk_j);
    CPT t_b1 = cp_commit(b0, g, pk_j);
    S.vt10 = t_b1.vt; S.wt10 = t_b1.wt;

    Scalar cd1 = Scalar::get_random(), zd1 = Scalar::get_random();
    S.t11 = schnorr_sim(zd1, cd1, g, S.U).t;

    // FS challenge
    Scalar c = amf_challenge(msg, S.t00, S.t01, S.vt10, S.wt10, S.t11);

    // disj0 responses
    S.c0 = cd0;                   // branch-0 simulated
    Scalar c1 = fr_sub(c, S.c0);  // branch-1 real
    Scalar wT = alpha * sk_j;
    S.z0 = zd0;
    S.z1 = aT + (wT * c1);

    // disj1 responses
    Scalar c_b1 = fr_sub(c, cd1); // branch-0 real CP (c0p)
    S.c0p = c_b1;
    S.z0p = b0 + (alpha * c_b1);  // CP response
    S.z1p = zd1;                  // Schnorr(U) simulated

    return S;
}

/* ============================ Serialization ============================ */
/*
 * Versioned, fixed-length concatenation:
 *   magic "AMF1" (4 bytes big-endian)
 *   T,U,A,B                 (4 × G1)
 *   t00,t01                 (2 × G1)
 *   c0,z0,z1                (3 × Fr)
 *   vt10,wt10,t11           (3 × G1)
 *   c0p,z0p,z1p             (3 × Fr)
 */

static constexpr uint32_t AMF_MAGIC = 0x414D4631u; // "AMF1"

Bytes Signature::to_bytes() const {
    std::vector<uint8_t> out;
    out.reserve(4 + 9 * G1_SERIALIZED_SIZE + 6 * FR_SERIALIZED_SIZE);

    be32_write(out, AMF_MAGIC);

    auto put_g1 = [&](const G1Point& P){ append_bytes(out, P.to_bytes()); };
    auto put_fr = [&](const Scalar& s){ append_bytes(out, s.to_bytes()); };

    put_g1(T); put_g1(U); put_g1(A); put_g1(B);
    put_g1(t00); put_g1(t01);
    put_fr(c0); put_fr(z0); put_fr(z1);
    put_g1(vt10); put_g1(wt10); put_g1(t11);
    put_fr(c0p); put_fr(z0p); put_fr(z1p);

    return out;
}

Signature Signature::from_bytes(const Bytes& in) {
    Signature S{};
    const uint8_t* p   = in.data();
    const uint8_t* end = in.data() + in.size();

    auto need = [&](size_t n){ return size_t(end - p) >= n; };
    auto rd_g1 = [&](G1Point& P)->bool {
        if (!need(G1_SERIALIZED_SIZE)) return false;
        P = G1Point::from_bytes(Bytes(p, p + G1_SERIALIZED_SIZE));
        p += G1_SERIALIZED_SIZE; return true;
    };
    auto rd_fr = [&](Scalar& s)->bool {
        if (!need(FR_SERIALIZED_SIZE)) return false;
        s = Scalar::from_bytes(Bytes(p, p + FR_SERIALIZED_SIZE));
        p += FR_SERIALIZED_SIZE; return true;
    };

    if (!need(4)) throw std::runtime_error("amf::Signature: truncated");
    uint32_t magic = be32(p); p += 4;
    if (magic != AMF_MAGIC) throw std::runtime_error("amf::Signature: bad magic");

    if (!rd_g1(S.T) || !rd_g1(S.U) || !rd_g1(S.A) || !rd_g1(S.B)) goto err;
    if (!rd_g1(S.t00) || !rd_g1(S.t01)) goto err;
    if (!rd_fr(S.c0)  || !rd_fr(S.z0)  || !rd_fr(S.z1)) goto err;
    if (!rd_g1(S.vt10) || !rd_g1(S.wt10) || !rd_g1(S.t11)) goto err;
    if (!rd_fr(S.c0p)  || !rd_fr(S.z0p)  || !rd_fr(S.z1p)) goto err;

    if (p != end) throw std::runtime_error("amf::Signature: extra bytes");
    return S;
err:
    throw std::runtime_error("amf::Signature: truncated");
}

} // namespace amf
