#pragma once
#ifndef DIA_DH_HPP
#define DIA_DH_HPP

#include "ecgroup.hpp"
#include <string>
#include <vector>

namespace dh {
    struct KeyPair {
        ecgroup::Scalar sk;
        ecgroup::G1Point pk;
    };

    KeyPair keygen();

    ecgroup::G1Point compute_secret(const ecgroup::Scalar &a, const ecgroup::G1Point &B);
}
#endif // DIA_DH_HPP