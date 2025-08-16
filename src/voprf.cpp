#include "voprf.hpp"
#include "ecgroup.hpp"

namespace voprf {
    using namespace ecgroup;

    /**
     * @brief Generates a new random key pair for the OPRF server.
     */
    KeyPair keygen() {
        KeyPair kp;
        kp.sk.set_random();
        G2Point g2_generator = G2Point::get_generator();
        kp.pk = G2Point::mul(g2_generator, kp.sk);
        return kp;
    }

    /**
     * @brief Client function to blind an input string.
     */
    std::pair<G1Point, Scalar> blind(const std::string& input) {
        G1Point hashed_input = G1Point::hash_and_map_to(input);
        Scalar blind_scalar = Scalar::get_random();
        G1Point blinded_element = G1Point::mul(hashed_input, blind_scalar);
        return std::make_pair(blinded_element, blind_scalar);
    }

    /**
     * @brief Client function to unblind the server's evaluated element.
     */
    G1Point unblind(const G1Point& element, const Scalar& blind) {
        Scalar blind_inverse = blind.inverse();
        G1Point unblinded_element = G1Point::mul(element, blind_inverse);
        return unblinded_element;
    }

    /**
     * @brief Verifies the OPRF output against the server's public key.
     */
    bool verify(const std::string& input, G1Point output, G2Point pk) {
        G2Point g2_generator = G2Point::get_generator();
        G1Point hashed_input = G1Point::hash_and_map_to(input);
        PairingResult lhs = pairing(output, g2_generator);
        PairingResult rhs = pairing(hashed_input, pk);
        return lhs == rhs;
    }

} // namespace voprf
