#include "dh.hpp"
#include "ecgroup.hpp"
#include <vector>

namespace dh {
    using ecgroup::G1Point;
    using ecgroup::Scalar;

    KeyPair keygen() {
        KeyPair kp;
        kp.sk.set_random();
        kp.pk = G1Point::mul(G1Point::get_generator(), kp.sk);
        return kp;
    }

    G1Point compute_secret(const Scalar &a, const G1Point &A) {
        return G1Point::mul(A, a);
    }

} // namespace dh
