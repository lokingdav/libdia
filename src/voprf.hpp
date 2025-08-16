#ifndef DIA_VOPRF_HPP
#define DIA_VOPRF_HPP

#include "ecgroup.hpp"

namespace voprf {
    using namespace ecgroup;

    struct KeyPair {
        Scalar sk;
        G2Point pk;
    };

    KeyPair keygen();
    std::pair<G1Point, Scalar> blind(const std::string& input);
    G1Point unblind(const G1Point& element, const Scalar& blind);
    bool verify(const std::string& input, G1Point output, G2Point pk);
    

} // namespace voprf

#endif // DIA_VOPRF_HPP
