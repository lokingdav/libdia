#ifndef DIA_AMF_HPP
#define DIA_AMF_HPP

#include "ecgroup.hpp"
#include <string>
#include <vector>
#include <cstdint>

namespace amf {

using ecgroup::Scalar;
using ecgroup::G1Point;
using ecgroup::Bytes;

/** Parameters for AMF. Currently just a fixed base point g in G1. */
struct Params {
    G1Point g;

    static Params Default();
};

/** Key pair (sk in Fr, pk in G1). */
struct KeyPair {
    Scalar  sk;
    G1Point pk;
};

/** AMF signature: contains public tuple (T,U,A,B) and a 2×(disjunction) FS proof. */
struct Signature {
    // Public values
    G1Point T;  // = alpha * pk_j        or forged variant
    G1Point U;  // = beta  * pk_r        or forged variant
    G1Point A;  // = alpha * g
    G1Point B;  // = beta  * g

    // Disjunction 0: OR( Schnorr(pk_s), Schnorr(T) )
    // We fix ordering as: branch-0 is pk_s, branch-1 is T.
    G1Point t00;    // commitment for branch-0
    G1Point t01;    // commitment for branch-1
    Scalar  c0;     // challenge share for branch-0
    Scalar  z0;     // response for branch-0
    Scalar  z1;     // response for branch-1

    // Disjunction 1: OR( Chaum–Pedersen(pk_j,A,T), Schnorr(U) )
    // We fix ordering as: branch-0 is CP, branch-1 is Schnorr(U).
    G1Point vt10;   // CP v_t commitment for branch-0
    G1Point wt10;   // CP w_t commitment for branch-0
    G1Point t11;    // Schnorr(U) commitment for branch-1
    Scalar  c0p;    // challenge share for branch-0
    Scalar  z0p;    // response for branch-0 (CP)
    Scalar  z1p;    // response for branch-1 (Schnorr(U))

    /** Serialize to a stable, versioned byte format (opaque to callers). */
    Bytes to_bytes() const;

    /** Parse from bytes previously produced by to_bytes(). Throws on error. */
    static Signature from_bytes(const Bytes& in);
};

/** Generate a fresh key pair: pk = sk * g. */
KeyPair KeyGen(const Params& params);

/**
 * Sender creates a franked signature for (msg) bound to receiver pk_r and judge pk_j.
 * sk_s  : sender secret
 * pk_r  : receiver public key (G1)
 * pk_j  : judge public key (G1)
 * msg   : arbitrary message
 */
Signature Frank(const Scalar& sk_s,
                const G1Point& pk_r,
                const G1Point& pk_j,
                const std::string& msg,
                const Params& params);

/**
 * Receiver verification:
 *  - checks U == sk_r * B
 *  - verifies both FS disjunctions w.r.t. pk_s, pk_j and transcript bound to msg
 */
bool Verify(const G1Point& pk_s,
            const Scalar&  sk_r,
            const G1Point& pk_j,
            const std::string& msg,
            const Signature& sig,
            const Params& params);

/**
 * Judge verification:
 *  - checks T == sk_j * A
 *  - verifies both FS disjunctions w.r.t. pk_s, pk_j and transcript bound to msg
 */
bool Judge(const G1Point& pk_s,
           const G1Point& pk_r,
           const Scalar&  sk_j,
           const std::string& msg,
           const Signature& sig,
           const Params& params);

/* ---------------------- Testing forgeries (as in tests) ---------------------- */

/** Public Forge: break both bindings; proofs still algebraically valid. */
Signature Forge(const G1Point& pk_s,
                const G1Point& pk_r,
                const G1Point& pk_j,
                const std::string& msg,
                const Params& params);

/** Receiver-compromise Forge: Verify passes, Judge fails. */
Signature RForge(const G1Point& pk_s,
                 const Scalar&  sk_r,
                 const G1Point& pk_j,
                 const std::string& msg,
                 const Params& params);

/** Judge-compromise Forge: both Verify and Judge pass. */
Signature JForge(const G1Point& pk_s,
                 const G1Point& pk_r,
                 const Scalar&  sk_j,
                 const std::string& msg,
                 const Params& params);

} // namespace amf

#endif // DIA_AMF_HPP
