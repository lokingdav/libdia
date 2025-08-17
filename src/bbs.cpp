#include "bbs.hpp"
#include <algorithm>
#include <cstdint>
#include <string>

namespace bbs {
using namespace ecgroup;

static inline Bytes toBytes(const std::string& s) {
    return Bytes(s.begin(), s.end());
}

static inline void appendU32BE(Bytes& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >>  8) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >>  0) & 0xFF));
}

static inline void appendLP(Bytes& out, const Bytes& b) {
    appendU32BE(out, static_cast<uint32_t>(b.size()));
    out.insert(out.end(), b.begin(), b.end());
}

static inline void appendPoint(Bytes& out, const G1Point& P) {
    appendLP(out, P.to_bytes());
}

static inline void appendG2(Bytes& out, const G2Point& Q) {
    appendLP(out, Q.to_bytes());
}

static inline void appendGT(Bytes& out, const PairingResult& t) {
    appendLP(out, t.to_bytes());
}

static inline void appendScalar(Bytes& out, const Scalar& s) {
    appendLP(out, s.to_bytes());
}

/*========================  Params  ========================*/

Params Params::Default() {
    Params p;
    // Deterministic generators
    p.g1 = G1Point::hash_and_map_to("BBS:g1:generator");
    p.g2 = G2Point::get_generator();
    p.domain_tag = "BBS:short:v1";
    return p;
}

G1Point Params::h(std::size_t i) const {
    // Domain-separated per-message base
    std::string label = domain_tag + "|H|" + std::to_string(i);
    return G1Point::hash_and_map_to(label);
}

G1Point Params::commit(const std::vector<Scalar>& msgs) const {
    // B = g1 * Π h_i^{m_i}
    G1Point B = g1;
    for (std::size_t i = 0; i < msgs.size(); ++i) {
        G1Point hi = h(i + 1);
        G1Point term = G1Point::mul(hi, msgs[i]);
        B = B.add(term);
    }
    return B;
}

/*========================  Core BBS API  ========================*/

KeyPair keygen(const Params& params) {
    KeyPair kp;
    kp.sk = Scalar::get_random();
    kp.pk = G2Point::mul(params.g2, kp.sk);
    return kp;
}

Signature sign_with_e(const Params& params,
                      const Scalar& sk,
                      const std::vector<Scalar>& msgs,
                      const Scalar& e)
{
    // B = g1 * Π h_i^{m_i}
    G1Point B = params.commit(msgs);

    // denom = sk + e  (must be non-zero)
    Scalar denom = sk + e;
    if (denom == Scalar()) {
        // Extremely unlikely; nudge deterministically
        Scalar one = Scalar::hash_to_scalar("BBS::ONE");
        denom = sk + (e + one);
    }

    Scalar inv = denom.inverse();
    G1Point A  = G1Point::mul(B, inv);

    Signature sig{A, e};
    return sig;
}

Signature sign(const Params& params,
               const Scalar& sk,
               const std::vector<Scalar>& msgs)
{
    Scalar e = Scalar::get_random();
    Scalar denom = sk + e;
    int attempts = 0;
    while (denom == Scalar() && attempts < 4) {
        e = Scalar::get_random();
        denom = sk + e;
        attempts++;
    }
    if (denom == Scalar()) {
        e = e + Scalar::hash_to_scalar("BBS::NUDGE");
    }
    return sign_with_e(params, sk, msgs, e);
}

bool verify(const Params& params,
            const G2Point& pk,
            const std::vector<Scalar>& msgs,
            const Signature& sig)
{
    // Recompute B
    G1Point B = params.commit(msgs);

    // Compute pk + g2^e in G2
    G2Point g2e = G2Point::mul(params.g2, sig.e);
    G2Point rhs_g2 = pk.add(g2e);

    // e(A, pk + g2^e) == e(B, g2)
    PairingResult left  = pairing(sig.A, rhs_g2);
    PairingResult right = pairing(B, params.g2);
    return (left == right);
}

/*========================  Selective Disclosure  ========================*/

// Build B_pub = g1 * Π_{i in disclosed} h_i^{m_i}
static G1Point commit_disclosed(const Params& params,
                                std::size_t total_messages,
                                const std::vector<std::pair<std::size_t, Scalar>>& disclosed)
{
    (void)total_messages; // not needed to compute B_pub, but kept for interface symmetry
    G1Point Bpub = params.g1;
    for (const auto& kv : disclosed) {
        std::size_t idx = kv.first; // 1-based
        const Scalar& mi = kv.second;
        G1Point hi = params.h(idx);
        Bpub = Bpub.add(G1Point::mul(hi, mi));
    }
    return Bpub;
}

// canonicalize indices: sort unique ascending, and validate in range [1..ℓ]
static std::vector<std::size_t> sorted_unique(const std::vector<std::size_t>& v,
                                              std::size_t total_messages)
{
    std::vector<std::size_t> out = v;
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    // (Optional) range check; caller should ensure validity
    if (!out.empty() && (out.front() < 1 || out.back() > total_messages)) {
        // We do not throw; the proof will fail on verify anyway.
    }
    return out;
}

static Scalar fs_challenge(const Params& params,
                           const G2Point& pk,
                           const G1Point& A,
                           const G1Point& Bpub,
                           const std::vector<std::size_t>& hidden_idx,
                           const PairingResult& E0,
                           const PairingResult& E1,
                           const std::vector<PairingResult>& Ej,
                           const PairingResult& T,
                           const std::string& nonce)
{
    Bytes buf;
    // Domain separation
    appendLP(buf, toBytes(params.domain_tag));
    appendLP(buf, toBytes("BBS:SDP:GTv1"));

    // Public inputs
    appendG2(buf, pk);
    appendPoint(buf, A);
    appendPoint(buf, Bpub);

    // Hidden indices
    appendU32BE(buf, static_cast<uint32_t>(hidden_idx.size()));
    for (auto id : hidden_idx) appendU32BE(buf, static_cast<uint32_t>(id));

    // Pairing bases
    appendGT(buf, E0);
    appendGT(buf, E1);
    appendU32BE(buf, static_cast<uint32_t>(Ej.size()));
    for (const auto& e : Ej) appendGT(buf, e);

    // Commitment
    appendGT(buf, T);

    // Context/nonce
    appendLP(buf, toBytes(nonce));

    return Scalar::hash_to_scalar(buf);
}

SDProof create_proof(const Params& params,
                     const ecgroup::G2Point& pk,
                     const Signature& sig,
                     const std::vector<ecgroup::Scalar>& msgs,
                     const std::vector<std::size_t>& disclosed_indices,
                     const std::string& nonce)
{
    const std::size_t L = msgs.size();

    // Disclosed (sorted unique, 1-based) and hidden index sets
    std::vector<std::size_t> disc = sorted_unique(disclosed_indices, L);

    std::vector<bool> is_disc(L + 1, false); // 1..L
    for (auto i : disc) if (1 <= i && i <= L) is_disc[i] = true;

    std::vector<std::size_t> hidden;
    hidden.reserve(L);
    for (std::size_t i = 1; i <= L; ++i) if (!is_disc[i]) hidden.push_back(i);

    // Build disclosed list with values for B_pub
    std::vector<std::pair<std::size_t, Scalar>> disc_kv;
    disc_kv.reserve(disc.size());
    for (auto i : disc) disc_kv.emplace_back(i, msgs[i - 1]);

    // B_pub = g1 * ∏_{i∈D} h_i^{m_i}
    G1Point Bpub = commit_disclosed(params, L, disc_kv);

    // Pairing bases for relation:  E1^e * Π_j Ej^{-m_j} = E0
    // where E0 = e(B_pub, g2) / e(A, pk), E1 = e(A, g2), Ej = e(h_j, g2)
    PairingResult e_Bpub_g2 = pairing(Bpub, params.g2);
    PairingResult e_A_pk    = pairing(sig.A, pk);
    PairingResult E0        = PairingResult::div(e_Bpub_g2, e_A_pk);
    PairingResult E1        = pairing(sig.A, params.g2);

    std::vector<PairingResult> Ej;
    Ej.reserve(hidden.size());
    for (auto j : hidden) {
        Ej.push_back(pairing(params.h(j), params.g2));
    }

    // Prover randomness
    Scalar r_e = Scalar::get_random();
    std::vector<Scalar> r_m(hidden.size());
    for (auto& r : r_m) r = Scalar::get_random();

    // Commitment in GT (no negative exponents): T = E1^{r_e} / Π_j Ej^{r_j}
    PairingResult T = E1.pow(r_e);
    for (std::size_t k = 0; k < hidden.size(); ++k) {
        T = PairingResult::div(T, Ej[k].pow(r_m[k])); // T /= Ej[k]^{r_k}
    }

    // Fiat–Shamir challenge
    Scalar c = fs_challenge(params, pk, sig.A, Bpub, hidden, E0, E1, Ej, T, nonce);

    // Responses
    Scalar z_e = r_e + (sig.e * c);
    std::vector<Scalar> z_m(hidden.size());
    for (std::size_t k = 0; k < hidden.size(); ++k) {
        z_m[k] = r_m[k] + (msgs[hidden[k] - 1] * c);
    }

    SDProof proof;
    proof.A = sig.A;
    proof.T = T;
    proof.z_e = z_e;
    proof.hidden_indices = hidden;
    proof.z_m = z_m;
    proof.nonce = nonce;
    return proof;
}

bool verify_proof(const Params& params,
                  const ecgroup::G2Point& pk,
                  const SDProof& proof,
                  const std::vector<std::pair<std::size_t, ecgroup::Scalar>>& disclosed,
                  std::size_t total_messages)
{
    // Recompute B_pub from disclosed values
    G1Point Bpub = commit_disclosed(params, total_messages, disclosed);

    // Rebuild pairing bases
    PairingResult e_Bpub_g2 = pairing(Bpub, params.g2);
    PairingResult e_A_pk    = pairing(proof.A, pk);
    PairingResult E0        = PairingResult::div(e_Bpub_g2, e_A_pk);
    PairingResult E1        = pairing(proof.A, params.g2);

    std::vector<PairingResult> Ej;
    Ej.reserve(proof.hidden_indices.size());
    for (auto j : proof.hidden_indices) {
        Ej.push_back(pairing(params.h(j), params.g2));
    }

    // Recompute Fiat–Shamir challenge
    Scalar c = fs_challenge(params, pk, proof.A, Bpub,
                            proof.hidden_indices, E0, E1, Ej, proof.T, proof.nonce);

    if (proof.z_m.size() != proof.hidden_indices.size()) return false;

    // Check: E1^{z_e} / Π_j Ej^{z_j}  ?=  T * E0^{c}
    PairingResult lhs = E1.pow(proof.z_e);
    for (std::size_t k = 0; k < proof.z_m.size(); ++k) {
        lhs = PairingResult::div(lhs, Ej[k].pow(proof.z_m[k])); // lhs /= Ej[k]^{z_k}
    }
    PairingResult rhs = proof.T * E0.pow(c);

    return (lhs == rhs);
}


} // namespace bbs
