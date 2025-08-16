#include <catch2/catch_test_macros.hpp>
#include "voprf.hpp"
#include "ecgroup.hpp"
#include <vector>
#include <string>

// Test case for the Verifiable Oblivious Pseudorandom Function protocol
TEST_CASE("VOPRF Protocol", "[voprf]") {
    // Initialize the pairing library once for all tests in this case.
    ecgroup::init_pairing();

    SECTION("Full Protocol Flow (Success Case)") {
        // 1. Server generates a key pair.
        voprf::KeyPair kp = voprf::keygen();

        // 2. Client prepares an input.
        std::string input = "my secret password";

        // 3. Client blinds the input.
        // The client keeps 'blind_scalar' secret and sends 'blinded_element' to the server.
        auto [blinded_element, blind_scalar] = voprf::blind(input);

        // 4. Server evaluates the blinded element with its secret key.
        // This is the core OPRF operation on the server side.
        ecgroup::G1Point evaluated_element = ecgroup::G1Point::mul(blinded_element, kp.sk);

        // 5. Client receives the evaluated element and unblinds it.
        ecgroup::G1Point final_output = voprf::unblind(evaluated_element, blind_scalar);

        // 6. Client can verify that the server used the correct key.
        // This confirms the output is valid for the given public key.
        bool is_valid = voprf::verify(input, final_output, kp.pk);
        REQUIRE(is_valid == true);

        // Also check that the output is not the same as the initial hash
        ecgroup::G1Point initial_hash = ecgroup::G1Point::hash_and_map_to(input);
        REQUIRE_FALSE(final_output == initial_hash);
    }

    SECTION("Verification Failure Cases") {
        // Setup a standard successful run to get a valid output.
        voprf::KeyPair kp1 = voprf::keygen();
        std::string input = "my secret password";
        auto [blinded_element, blind_scalar] = voprf::blind(input);
        ecgroup::G1Point evaluated_element = ecgroup::G1Point::mul(blinded_element, kp1.sk);
        ecgroup::G1Point final_output = voprf::unblind(evaluated_element, blind_scalar);

        // Ensure the baseline verification works before testing failures.
        REQUIRE(voprf::verify(input, final_output, kp1.pk) == true);

        // Test Case 1: Verification should fail with the wrong public key.
        voprf::KeyPair kp2 = voprf::keygen(); // A different server key.
        REQUIRE_FALSE(voprf::verify(input, final_output, kp2.pk));

        // Test Case 2: Verification should fail with the wrong original input.
        std::string wrong_input = "not my password";
        REQUIRE_FALSE(voprf::verify(wrong_input, final_output, kp1.pk));

        // Test Case 3: Verification should fail with a tampered/modified output.
        ecgroup::G1Point tampered_output = final_output.add(ecgroup::G1Point::get_random());
        REQUIRE_FALSE(voprf::verify(input, tampered_output, kp1.pk));
    }

    SECTION("Batch Verification") {
        // 1. Setup: Generate a keypair and a batch of 3 input/output pairs.
        voprf::KeyPair kp = voprf::keygen();
        std::vector<std::string> inputs = {"input1", "input2", "input3"};
        std::vector<ecgroup::G1Point> outputs;
        
        for (const auto& input : inputs) {
            auto [blinded_element, blind_scalar] = voprf::blind(input);
            ecgroup::G1Point evaluated_element = ecgroup::G1Point::mul(blinded_element, kp.sk);
            outputs.push_back(voprf::unblind(evaluated_element, blind_scalar));
        }

        // 2. Success Case: Verification should pass with correct data.
        REQUIRE(voprf::verify_batch(inputs, outputs, kp.pk) == true);
        
        // Test with a single item batch, which should also work.
        std::vector<std::string> single_input = {"input1"};
        std::vector<ecgroup::G1Point> single_output = {outputs[0]};
        REQUIRE(voprf::verify_batch(single_input, single_output, kp.pk) == true);

        // 3. Failure Cases
        
        // Case 3a: Wrong public key
        voprf::KeyPair kp2 = voprf::keygen();
        REQUIRE_FALSE(voprf::verify_batch(inputs, outputs, kp2.pk));

        // Case 3b: Tampered output in the batch
        std::vector<ecgroup::G1Point> tampered_outputs = outputs;
        tampered_outputs[1] = tampered_outputs[1].add(ecgroup::G1Point::get_random());
        REQUIRE_FALSE(voprf::verify_batch(inputs, tampered_outputs, kp.pk));

        // Case 3c: Mismatched input/output vectors (wrong size)
        std::vector<std::string> fewer_inputs = {"input1", "input2"};
        REQUIRE_FALSE(voprf::verify_batch(fewer_inputs, outputs, kp.pk));

        // Case 3d: Empty vectors
        std::vector<std::string> empty_inputs;
        std::vector<ecgroup::G1Point> empty_outputs;
        REQUIRE_FALSE(voprf::verify_batch(empty_inputs, empty_outputs, kp.pk));
    }
}
