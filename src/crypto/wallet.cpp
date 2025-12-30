#include "wallet.hpp"
#include "bbs.hpp"
#include "../helpers.hpp"
#include <ctime>
#include <iomanip>
#include <sstream>

namespace crypto {

using dia::utils::append_lp;
using dia::utils::read_lp;
using dia::utils::to_bytes;

// -----------------------------------------------------------------------------
// BasicWallet::Impl - Implementation details
// -----------------------------------------------------------------------------
class BasicWallet::Impl {
public:
    bbs::Params params;
    bbs::KeyPair keypair;
    
    Impl() : params(bbs::Params::Default()) {
        // Generate a key pair for the wallet
        keypair = bbs::keygen(params);
    }
    
    Bytes create_message_to_sign(const Bytes& nonce, const std::vector<std::string>& attributes) {
        Bytes msg;
        append_lp(msg, nonce);
        for (const auto& attr : attributes) {
            append_lp(msg, to_bytes(attr));
        }
        return msg;
    }
    
    std::string get_current_date() {
        auto now = std::time(nullptr);
        auto tm = *std::localtime(&now);
        std::ostringstream oss;
        oss << std::put_time(&tm, "%Y-%m-%d");
        return oss.str();
    }
    
    std::string get_future_date(int years) {
        auto now = std::time(nullptr);
        auto tm = *std::localtime(&now);
        tm.tm_year += years;
        std::ostringstream oss;
        oss << std::put_time(&tm, "%Y-%m-%d");
        return oss.str();
    }
};

// -----------------------------------------------------------------------------
// BasicWallet implementation
// -----------------------------------------------------------------------------

BasicWallet::BasicWallet() : impl_(new Impl()) {}

BasicWallet::~BasicWallet() {
    delete impl_;
}

Bytes BasicWallet::present(const Bytes& nonce, const std::vector<std::string>& requested_attributes) {
    // Create message: nonce || attributes
    Bytes msg = impl_->create_message_to_sign(nonce, requested_attributes);
    
    // Convert to scalars for BBS
    std::vector<ecgroup::Scalar> scalars;
    scalars.push_back(ecgroup::Scalar::from_bytes(nonce));
    for (const auto& attr : requested_attributes) {
        Bytes attr_bytes = to_bytes(attr);
        scalars.push_back(ecgroup::Scalar::from_bytes(attr_bytes));
    }
    
    // Sign with BBS
    bbs::Signature signature = bbs::sign(impl_->params, impl_->keypair.sk, scalars);
    
    // Serialize signature
    Bytes sig_bytes = signature.A.to_bytes();
    Bytes e_bytes = signature.e.to_bytes();
    
    // Presentation format: sig_A || sig_e || public_key || msg
    Bytes presentation;
    append_lp(presentation, sig_bytes);
    append_lp(presentation, e_bytes);
    append_lp(presentation, impl_->keypair.pk.to_bytes());
    append_lp(presentation, msg);
    
    return presentation;
}

VerificationResult BasicWallet::verify(const Bytes& presentation,
                                       const Bytes& nonce,
                                       const std::vector<std::string>& requested_attributes) {
    VerificationResult result;
    result.verified = false;
    
    try {
        // Parse presentation: sig_A || sig_e || public_key || msg
        size_t off = 0;
        Bytes sig_a_bytes = read_lp(presentation, off);
        Bytes sig_e_bytes = read_lp(presentation, off);
        Bytes public_key_bytes = read_lp(presentation, off);
        Bytes signed_msg = read_lp(presentation, off);
        
        // Recreate expected message
        Bytes expected_msg = impl_->create_message_to_sign(nonce, requested_attributes);
        
        // Verify message matches
        if (signed_msg != expected_msg) {
            return result; // Message mismatch
        }
        
        // Reconstruct signature and public key
        bbs::Signature signature;
        signature.A = ecgroup::G1Point::from_bytes(sig_a_bytes);
        signature.e = ecgroup::Scalar::from_bytes(sig_e_bytes);
        ecgroup::G2Point public_key = ecgroup::G2Point::from_bytes(public_key_bytes);
        
        // Convert message to scalars
        std::vector<ecgroup::Scalar> scalars;
        scalars.push_back(ecgroup::Scalar::from_bytes(nonce));
        for (const auto& attr : requested_attributes) {
            Bytes attr_bytes = to_bytes(attr);
            scalars.push_back(ecgroup::Scalar::from_bytes(attr_bytes));
        }
        
        // Verify signature
        bool sig_valid = bbs::verify(impl_->params, public_key, scalars, signature);
        
        if (!sig_valid) {
            return result; // Invalid signature
        }
        
        // Signature is valid - populate mock verification result
        result.verified = true;
        result.issuer = "MockIssuer";
        result.credential_type = "VerifiableCredential";
        result.issuance_date = impl_->get_current_date();
        result.expiration_date = impl_->get_future_date(5); // 5 years from now
        
        // Populate mock disclosed attributes
        for (const auto& attr : requested_attributes) {
            if (attr == "age" || attr == "age_over_18" || attr == "age_over_21") {
                result.disclosed_attributes[attr] = "true";
            } else if (attr == "name" || attr == "full_name") {
                result.disclosed_attributes[attr] = "John Doe";
            } else if (attr == "nationality" || attr == "country") {
                result.disclosed_attributes[attr] = "US";
            } else if (attr == "driver_license_number" || attr == "license_number") {
                result.disclosed_attributes[attr] = "D1234567";
            } else if (attr == "birth_date" || attr == "date_of_birth") {
                result.disclosed_attributes[attr] = "1990-01-01";
            } else {
                // Generic mock value for unknown attributes
                result.disclosed_attributes[attr] = "mock_value_" + attr;
            }
        }
        
    } catch (...) {
        result.verified = false;
    }
    
    return result;
}

} // namespace crypto
