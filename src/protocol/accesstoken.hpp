#ifndef DIA_PROTOCOL_ACCESSTOKEN_HPP
#define DIA_PROTOCOL_ACCESSTOKEN_HPP

#include "../crypto/ecgroup.hpp"

#include <cstddef>
#include <stdexcept>
#include <string>
#include <vector>

namespace protocol {
namespace accesstoken {

using ecgroup::Bytes;

class AccessTokenError : public std::runtime_error {
public:
    explicit AccessTokenError(const std::string& msg) : std::runtime_error(msg) {}
};

// Client-side blinded access token request material.
struct BlindedAccessToken {
    Bytes input;   // Random input (opaque bytes)
    Bytes blinded; // Blinded point (sent to server)
    Bytes blind;   // Blind factor (kept secret by client)
};

// Finalized access token (after server evaluation + client unblinding).
struct AccessToken {
    // Kept as t1/t2 for compact serialization and compatibility.
    Bytes t1; // Original input
    Bytes t2; // Server-evaluated output (unblinded)

    Bytes to_bytes() const;
    static AccessToken from_bytes(const Bytes& data);
};

// Client: generate one blinded access token.
BlindedAccessToken blind_access_token();

// Client: generate N blinded access tokens.
std::vector<BlindedAccessToken> blind_access_tokens(std::size_t count);

// Server: evaluate a single blinded token with the access-throttling private key.
Bytes evaluate_blinded_access_token(const Bytes& at_private_key, const Bytes& blinded_token);

// Server: evaluate multiple blinded tokens.
std::vector<Bytes> evaluate_blinded_access_tokens(
    const Bytes& at_private_key,
    const std::vector<Bytes>& blinded_tokens
);

// Client: finalize a single access token after receiving server evaluation.
AccessToken finalize_access_token(const BlindedAccessToken& blinded, const Bytes& evaluated_token);

// Client: finalize multiple access tokens.
std::vector<AccessToken> finalize_access_tokens(
    const std::vector<BlindedAccessToken>& blinded,
    const std::vector<Bytes>& evaluated
);

// Anyone: verify a token against the server's public verification key.
bool verify_access_token(const AccessToken& token, const Bytes& verification_key);

} // namespace accesstoken
} // namespace protocol

#endif // DIA_PROTOCOL_ACCESSTOKEN_HPP
