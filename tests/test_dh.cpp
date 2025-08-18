#include <catch2/catch_test_macros.hpp>
#include "dh.hpp"
#include "ecgroup.hpp"
#include <vector>
#include <string>

TEST_CASE("Diffie-Hellman", "[dh]") {
    ecgroup::init_pairing();

    SECTION("Full Protocol Flow (Success Case)") {
        dh::KeyPair kp1 = dh::keygen();
        dh::KeyPair kp2 = dh::keygen();

        REQUIRE_FALSE(kp1.sk == kp2.sk);
        REQUIRE_FALSE(kp1.pk == kp2.pk);

        ecgroup::G1Point v1 = dh::compute_secret(kp1.sk, kp2.pk);
        ecgroup::G1Point v2 = dh::compute_secret(kp2.sk, kp1.pk);

        REQUIRE(v1 == v2);
    }
}
