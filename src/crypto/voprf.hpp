#ifndef DIA_VOPRF_HPP
#define DIA_VOPRF_HPP

#include "ecgroup.hpp"
#include <vector>
#include <string>

namespace voprf {
    // Using directives for cleaner syntax within the voprf namespace
    using namespace ecgroup;

    /**
     * @brief Represents the server's private/public key pair.
     */
    struct KeyPair {
        Scalar sk; // private key
        G2Point pk; // public key
    };

    /**
     * @brief Generates a new random key pair for the OPRF server.
     * @return A KeyPair struct containing a new private and public key.
     */
    KeyPair keygen();

    /**
     * @brief Client function to blind an input string.
     * Hashes the input to a G1 point and multiplies it by a random scalar (the blind).
     * @param input The raw input data.
     * @return A std::pair containing:
     * - The blinded G1Point to be sent to the server.
     * - The secret blind (Scalar) to be used for unblinding.
     */
    std::pair<G1Point, Scalar> blind(const std::string& input);

    /**
     * @brief Client function to unblind the server's evaluated element.
     * This computes the final PRF output by removing the blind.
     * @param element The evaluated G1Point received from the server.
     * @param blind The secret scalar returned by the blind() function.
     * @return The final OPRF output as a G1Point.
     */
    G1Point unblind(const G1Point& element, const Scalar& blind);

    /**
     * @brief Verifies the OPRF output.
     * @param input The original raw input data.
     * @param output The final unblinded G1Point from the protocol.
     * @param pk The server's public key.
     * @return True if the verification succeeds, false otherwise.
     */
    bool verify(const std::string& input, G1Point output, G2Point pk);

    /**
     * @brief Verifies a batch of OPRF outputs in a single operation.
     * This is more efficient than verifying one by one as it uses only two pairings.
     * @param inputs A vector of the original raw input data.
     * @param outputs A vector of the final unblinded G1Points.
     * @param pk The server's public key.
     * @return True if all outputs are valid for their corresponding inputs, false otherwise.
     */
    bool verify_batch(const std::vector<std::string>& inputs,
                      const std::vector<G1Point>& outputs,
                      G2Point pk);

} // namespace voprf

#endif // DIA_VOPRF_HPP
