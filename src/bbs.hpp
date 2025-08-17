#pragma once
#ifndef DIA_BBS_HPP
#define DIA_BBS_HPP

#include "ecgroup.hpp"
#include <string>
#include <vector>
#include <cstddef>
#include <utility>
#include <cstdint>

namespace bbs {

using ecgroup::Bytes;
using ecgroup::Scalar;
using ecgroup::G1Point;
using ecgroup::G2Point;
using ecgroup::PairingResult;

/**
 * Compact BBS parameters.
 * g1 ∈ G1, g2 ∈ G2. Per-message generators h_i are derived via hash-to-curve
 * with domain separation using `domain_tag`.
 */
struct Params {
    G1Point     g1;
    G2Point     g2;
    std::string domain_tag;   // e.g., "BBS:short:v1"

    /// Construct default params.
    static Params Default();

    /// Derive per-message generator h_i (1-based index) with domain separation.
    G1Point h(std::size_t i) const;

    /// Compute commitment B = g1 * ∏ h_i^{m_i}.
    G1Point commit(const std::vector<Scalar>& msgs) const;
};

/// Secret key x ∈ Fr; public key X2 = g2^x ∈ G2.
struct KeyPair {
    Scalar  sk;
    G2Point pk;
};

/// Two-element BBS signature σ = (A, e) with A ∈ G1, e ∈ Fr.
struct Signature {
    G1Point A;
    Scalar  e;
};

/// Key generation: sk ← Fr, pk = g2^sk.
KeyPair keygen(const Params& params);

/// Sign (random e): σ = (A, e), where A = B^{1/(sk + e)}, B = g1 * ∏ h_i^{m_i}.
Signature sign(const Params& params,
               const Scalar& sk,
               const std::vector<Scalar>& msgs);

/// Sign with caller-provided e (useful for deterministic/AGM-friendly variants).
Signature sign_with_e(const Params& params,
                      const Scalar& sk,
                      const std::vector<Scalar>& msgs,
                      const Scalar& e);

/// Verify: check e(A, pk + g2^e) == e(B, g2).
bool verify(const Params& params,
            const G2Point& pk,
            const std::vector<Scalar>& msgs,
            const Signature& sig);

/*========================  Selective Disclosure Proofs  ========================*/

/**
 * Proof (GT-Schnorr) that a BBS signature (A,e) authenticates messages where
 * only a subset `disclosed` is revealed. The proof is zero-knowledge for e and
 * the hidden messages. NOTE: This first version includes A in the proof; that
 * makes proofs linkable if the same signature is reused. We can later switch to
 * the 2×G1 ultra-compact form that avoids leaking A.
 */
struct SDProof {
    // Copy of signature's A so the verifier can compute pairings (see note above).
    G1Point A;

    // Commitment in GT: T = E1^{r_e} * Π_j Ej^{ - r_j }
    ecgroup::PairingResult T;

    // Responses
    Scalar z_e;                     // z_e = r_e + c * e
    std::vector<std::size_t> hidden_indices; // 1-based indices of hidden messages (ascending)
    std::vector<Scalar>      z_m;           // z_m[j] = r_j + c * m_{hidden_indices[j]}

    // For challenge binding/context
    std::string nonce;   // optional domain/context/nonce bound into the challenge
};

/**
 * Create a selective disclosure proof.
 *
 * @param params   BBS parameters
 * @param pk       issuer public key in G2
 * @param sig      signature (A,e)
 * @param msgs     full message vector (length ℓ)
 * @param disclosed_indices  1-based indices to disclose (ascending or not; we sort internally)
 * @param nonce    optional context/nonce (bound into Fiat–Shamir challenge)
 *
 * @return SDProof with (A, T, z_e, hidden indices, z_m, nonce).
 */
SDProof create_proof(const Params& params,
                     const G2Point& pk,
                     const Signature& sig,
                     const std::vector<Scalar>& msgs,
                     const std::vector<std::size_t>& disclosed_indices,
                     const std::string& nonce);

/**
 * Verify a selective disclosure proof.
 *
 * @param params   BBS parameters
 * @param pk       issuer public key in G2
 * @param proof    SDProof produced by create_proof
 * @param disclosed  vector of (index, value) for disclosed messages (1-based indices)
 * @param total_messages  total number of messages ℓ
 *
 * @return true iff the proof verifies for the disclosed set and context.
 */
bool verify_proof(const Params& params,
                  const G2Point& pk,
                  const SDProof& proof,
                  const std::vector<std::pair<std::size_t, Scalar>>& disclosed,
                  std::size_t total_messages);

} // namespace bbs

#endif // DIA_BBS_HPP
