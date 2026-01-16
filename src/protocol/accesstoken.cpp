#include "accesstoken.hpp"

#include "../crypto/voprf.hpp"

#include <string>

namespace protocol {
namespace accesstoken {

using ecgroup::Bytes;
using ecgroup::Scalar;
using ecgroup::G1Point;
using ecgroup::G2Point;

Bytes AccessToken::to_bytes() const {
    Bytes result;
    result.reserve(t1.size() + t2.size());
    result.insert(result.end(), t1.begin(), t1.end());
    result.insert(result.end(), t2.begin(), t2.end());
    return result;
}

AccessToken AccessToken::from_bytes(const Bytes& data) {
    if (data.size() < 32) {
        throw AccessTokenError("Invalid access token data: too short");
    }
    AccessToken t;
    t.t1 = Bytes(data.begin(), data.begin() + 32);
    t.t2 = Bytes(data.begin() + 32, data.end());
    return t;
}

BlindedAccessToken blind_access_token() {
    // Generate random input (use VOPRF keygen to get random scalar bytes as input).
    voprf::KeyPair temp_kp = voprf::keygen();
    Bytes input = temp_kp.sk.to_bytes();

    std::string input_str(input.begin(), input.end());

    auto [blinded_point, blind] = voprf::blind(input_str);

    BlindedAccessToken token;
    token.input = std::move(input);
    token.blinded = blinded_point.to_bytes();
    token.blind = blind.to_bytes();
    return token;
}

std::vector<BlindedAccessToken> blind_access_tokens(std::size_t count) {
    std::vector<BlindedAccessToken> tokens;
    tokens.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        tokens.push_back(blind_access_token());
    }
    return tokens;
}

Bytes evaluate_blinded_access_token(const Bytes& at_private_key, const Bytes& blinded_token) {
    if (at_private_key.empty()) {
        throw AccessTokenError("Missing access-throttling private key");
    }

    // Parse blinded point
    G1Point blinded_point = G1Point::from_bytes(blinded_token);

    // Parse private key scalar
    Scalar at_sk = Scalar::from_bytes(at_private_key);

    // Evaluate: multiply by private key
    G1Point evaluated = G1Point::mul(blinded_point, at_sk);
    return evaluated.to_bytes();
}

std::vector<Bytes> evaluate_blinded_access_tokens(
    const Bytes& at_private_key,
    const std::vector<Bytes>& blinded_tokens
) {
    std::vector<Bytes> out;
    out.reserve(blinded_tokens.size());
    for (const auto& b : blinded_tokens) {
        out.push_back(evaluate_blinded_access_token(at_private_key, b));
    }
    return out;
}

AccessToken finalize_access_token(const BlindedAccessToken& blinded, const Bytes& evaluated_token) {
    // Parse evaluated point
    G1Point eval_point = G1Point::from_bytes(evaluated_token);

    // Parse blind
    Scalar blind = Scalar::from_bytes(blinded.blind);

    // Unblind
    G1Point output = voprf::unblind(eval_point, blind);

    AccessToken token;
    token.t1 = blinded.input;
    token.t2 = output.to_bytes();
    return token;
}

std::vector<AccessToken> finalize_access_tokens(
    const std::vector<BlindedAccessToken>& blinded,
    const std::vector<Bytes>& evaluated
) {
    if (blinded.size() != evaluated.size()) {
        throw AccessTokenError("Mismatched blinded and evaluated token counts");
    }

    std::vector<AccessToken> tokens;
    tokens.reserve(blinded.size());
    for (std::size_t i = 0; i < blinded.size(); ++i) {
        tokens.push_back(finalize_access_token(blinded[i], evaluated[i]));
    }
    return tokens;
}

bool verify_access_token(const AccessToken& token, const Bytes& verification_key) {
    // Parse the verification key (VOPRF public key)
    G2Point vk = G2Point::from_bytes(verification_key);

    // Parse the token output (unblinded VOPRF result)
    G1Point output = G1Point::from_bytes(token.t2);

    // Convert token input to string
    std::string input_str(token.t1.begin(), token.t1.end());

    return voprf::verify(input_str, output, vk);
}

} // namespace accesstoken
} // namespace protocol
