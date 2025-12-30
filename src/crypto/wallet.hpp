#ifndef DIA_CRYPTO_WALLET_HPP
#define DIA_CRYPTO_WALLET_HPP

#include "ecgroup.hpp"
#include <vector>
#include <string>
#include <map>

namespace crypto {

using Bytes = ecgroup::Bytes;

// -----------------------------------------------------------------------------
// VerificationResult - Result of presentation verification
// -----------------------------------------------------------------------------
struct VerificationResult {
    bool                              verified;            // Overall verification status
    std::map<std::string, std::string> disclosed_attributes; // Attribute name -> value
    std::string                        issuer;              // Credential issuer
    std::string                        credential_type;     // Type of credential (e.g., "mDL", "VC")
    std::string                        issuance_date;       // When credential was issued
    std::string                        expiration_date;     // When credential expires
};

// -----------------------------------------------------------------------------
// BasicWallet - Mock wallet for ODA protocol
// -----------------------------------------------------------------------------
class BasicWallet {
public:
    BasicWallet();
    ~BasicWallet();

    /**
     * Create a presentation in response to an ODA request.
     * For now, this creates a BBS signature over (nonce || attributes).
     * 
     * @param nonce Challenge nonce from verifier
     * @param requested_attributes Attributes being requested
     * @return Signed presentation bytes
     */
    Bytes present(const Bytes& nonce, const std::vector<std::string>& requested_attributes);

    /**
     * Verify a presentation.
     * For now, this verifies the BBS signature and returns mock attribute data.
     * 
     * @param presentation The presentation bytes to verify
     * @param nonce The original challenge nonce
     * @param requested_attributes The original requested attributes
     * @return Verification result with disclosed attributes
     */
    VerificationResult verify(const Bytes& presentation, 
                             const Bytes& nonce, 
                             const std::vector<std::string>& requested_attributes);

private:
    class Impl;
    Impl* impl_;
};

} // namespace crypto

#endif // DIA_CRYPTO_WALLET_HPP
