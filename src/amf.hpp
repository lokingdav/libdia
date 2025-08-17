#pragma once
#ifndef DIA_AMF_HPP
#define DIA_AMF_HPP

#include "ecgroup.hpp"
#include <string>
#include <vector>

namespace amf {

using ecgroup::Bytes;
using ecgroup::G1Point;
using ecgroup::Scalar;

/// AMF system parameters (we only need a fixed G1 generator for this construction).
struct Params {
    G1Point g;                 // Deterministic generator in G1
    std::string domain_tag;    // Domain separation for hashing

    /// Build default Params with a deterministic generator derived via hash-to-curve.
    static Params Default();
};

/// Simple keypair for (pk = sk * g).
struct KeyPair {
    Scalar  sk;
    G1Point pk;
};

/// --- Proof transcript types for the specific DMF relation ---
/// Left disjunction: Schnorr(pk_s) OR Schnorr(T)
struct DisjSchnorrSchnorrCommit {
    G1Point t0; // commit for Schnorr over pk_s
    G1Point t1; // commit for Schnorr over T
};
struct DisjSchnorrSchnorrResp {
    Scalar  c0; // challenge share for first branch
    Scalar  z0; // response for first branch
    Scalar  z1; // response for second branch
};

/// Right disjunction: Chaum-Pedersen(pk_j, A, T) OR Schnorr(U)
struct CPCommit {
    G1Point vt; // v_t = a * g
    G1Point wt; // w_t = a * pk_j
};
struct DisjCPorSchnorrCommit {
    CPCommit cp_t; // commit for CP
    G1Point  t1;   // commit for Schnorr over U
};
struct DisjCPorSchnorrResp {
    Scalar  c0; // challenge share for CP branch
    Scalar  z0; // CP response (scalar)
    Scalar  z1; // Schnorr(U) response (scalar)
};

/// Conjunction of the two disjunctions
struct AMFProof {
    DisjSchnorrSchnorrCommit left_commit;
    DisjCPorSchnorrCommit    right_commit;

    DisjSchnorrSchnorrResp   left_resp;
    DisjCPorSchnorrResp      right_resp;
};

/// Full AMF signature: FS proof + the public tuple (T,U,A,B).
struct Signature {
    AMFProof proof;
    G1Point  T;
    G1Point  U;
    G1Point  A;
    G1Point  B;
};

/// Key generation (pk = sk * params.g)
KeyPair KeyGen(const Params& params);

/// Sender “Frank”: produce AMF signature on msg.
/// Inputs: sender sk_s, receiver pk_r, judge pk_j.
Signature Frank(const Scalar& sk_s,
                const G1Point& pk_r,
                const G1Point& pk_j,
                const std::string& msg,
                const Params& params);

/// Public forgeries for deniability (as in the reference Python):
Signature Forge (const G1Point& pk_s,
                 const G1Point& pk_r,
                 const G1Point& pk_j,
                 const std::string& msg,
                 const Params& params);

Signature RForge(const G1Point& pk_s,
                 const Scalar&  sk_r,
                 const G1Point& pk_j,
                 const std::string& msg,
                 const Params& params);

Signature JForge(const G1Point& pk_s,
                 const G1Point& pk_r,
                 const Scalar&  sk_j,
                 const std::string& msg,
                 const Params& params);

/// Receiver-side verification (designated check + proof)
bool Verify(const G1Point& pk_s,
            const Scalar&  sk_r,
            const G1Point& pk_j,
            const std::string& msg,
            const Signature& sig,
            const Params& params);

/// Judge-side verification (designated check + proof)
bool Judge (const G1Point& pk_s,
            const G1Point& pk_r,
            const Scalar&  sk_j,
            const std::string& msg,
            const Signature& sig,
            const Params& params);

} // namespace amf

#endif // DIA_AMF_HPP
