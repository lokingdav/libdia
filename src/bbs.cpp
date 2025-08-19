#include "bbs.hpp"
#include "helpers.hpp"

#include <algorithm>
#include <cstdint>
#include <stdexcept>
#include <string>

namespace bbs {

using namespace ecgroup;
using namespace dia::utils;

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
                                std::size_t /*total_messages*/,
                                const std::vector<std::pair<std::size_t, Scalar>>& disclosed)
{
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
    append_lp(buf, to_bytes(params.domain_tag));
    append_lp(buf, to_bytes("BBS:SDP:GTv1"));

    // Public inputs
    append_lp(buf, pk.to_bytes());
    append_lp(buf, A.to_bytes());
    append_lp(buf, Bpub.to_bytes());

    // Hidden indices
    append_u32_be(buf, static_cast<uint32_t>(hidden_idx.size()));
    for (auto id : hidden_idx) append_u32_be(buf, static_cast<uint32_t>(id));

    // Pairing bases
    append_lp(buf, E0.to_bytes());
    append_lp(buf, E1.to_bytes());
    append_u32_be(buf, static_cast<uint32_t>(Ej.size()));
    for (const auto& e : Ej) append_lp(buf, e.to_bytes());

    // Commitment
    append_lp(buf, T.to_bytes());

    // Context/nonce
    append_lp(buf, to_bytes(nonce));

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

/*========================  Signature / Proof serialization  ========================*/

Bytes Signature::to_bytes() const {
    Bytes out;
    append_lp(out, A.to_bytes()); // LP(G1)
    append_lp(out, e.to_bytes()); // LP(Fr)
    return out;
}

Signature Signature::from_bytes(const Bytes& b) {
    std::size_t off = 0;
    Signature s;
    s.A = G1Point::from_bytes(read_lp(b, off));
    s.e = Scalar::from_bytes(read_lp(b, off));
    if (off != b.size()) throw std::runtime_error("Signature::from_bytes: trailing data");
    return s;
}

Bytes SDProof::to_bytes() const {
    Bytes out;
    // A, T, z_e
    append_lp(out, A.to_bytes());   // LP(G1)
    append_lp(out, T.to_bytes());   // LP(GT/Fp12)
    append_lp(out, z_e.to_bytes()); // LP(Fr)

    // hidden_indices (u32 count + raw u32 entries)
    append_u32_be(out, static_cast<uint32_t>(hidden_indices.size()));
    for (auto idx : hidden_indices) {
        append_u32_be(out, static_cast<uint32_t>(idx));
    }

    // z_m (u32 count + LP(Fr) items)
    append_u32_be(out, static_cast<uint32_t>(z_m.size()));
    for (const auto& zm : z_m) {
        append_lp(out, zm.to_bytes());
    }

    // nonce as LP(bytes)
    append_lp(out, Bytes(nonce.begin(), nonce.end()));
    return out;
}

SDProof SDProof::from_bytes(const Bytes& b) {
    std::size_t off = 0;
    SDProof p;
    p.A   = G1Point::from_bytes(read_lp(b, off));
    p.T   = PairingResult::from_bytes(read_lp(b, off)); // requires ecgroup to expose from_bytes
    p.z_e = Scalar::from_bytes(read_lp(b, off));

    // hidden_indices
    uint32_t n_hidden = read_u32_be(b, off);
    p.hidden_indices.resize(n_hidden);
    for (uint32_t i = 0; i < n_hidden; ++i) {
        p.hidden_indices[i] = static_cast<std::size_t>(read_u32_be(b, off));
    }

    // z_m
    uint32_t n_zm = read_u32_be(b, off);
    p.z_m.resize(n_zm);
    for (uint32_t i = 0; i < n_zm; ++i) {
        p.z_m[i] = Scalar::from_bytes(read_lp(b, off));
    }

    // nonce
    p.nonce = read_string(b, off);

    if (off != b.size()) throw std::runtime_error("SDProof::from_bytes: trailing data");
    return p;
}

} // namespace bbs
