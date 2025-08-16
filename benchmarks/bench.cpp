#include <iostream>
#include <chrono>
#include <vector>
#include <string>
#include <iomanip>
#include <functional>

#include "dia/dia.hpp"

/**
 * @brief A simple class to run benchmarks and print formatted results.
 */
class BenchmarkRunner {
public:
    int num_iters;

    explicit BenchmarkRunner(int iterations) : num_iters(iterations) {}

    void run(const std::string& name, const std::function<void()>& func) {
        // Run once to warm up caches, JIT, etc.
        func(); 

        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < num_iters; ++i) {
            func();
        }
        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> elapsed = end - start;

        std::cout << std::left << std::setw(28) << name 
                  << ": " << std::fixed << std::setprecision(6) 
                  << elapsed.count() / num_iters << " ms" << std::endl;
    }
};

int main() {
    ecgroup::init_pairing();

    BenchmarkRunner primitive_runner(10000); // More iterations for fast ops
    BenchmarkRunner protocol_runner(100);    // Fewer iterations for slow ops

    // =====================================================================
    // SECTION 1: Low-Level Cryptographic Primitives
    // =====================================================================
    std::cout << "\n--- Low-Level Cryptographic Primitives (Avg over " << primitive_runner.num_iters << " iters) ---" << std::endl;

    ecgroup::Scalar s1 = ecgroup::Scalar::get_random();
    ecgroup::Scalar s2 = ecgroup::Scalar::get_random();
    primitive_runner.run("Scalar Multiplication", [&]() {
        auto r = s1 * s2;
    });

    ecgroup::G1Point p1 = ecgroup::G1Point::get_random();
    primitive_runner.run("G1 Scalar Multiplication", [&]() {
        auto r = ecgroup::G1Point::mul(p1, s1);
    });

    ecgroup::G2Point p2 = ecgroup::G2Point::get_random();
    primitive_runner.run("G2 Scalar Multiplication", [&]() {
        auto r = ecgroup::G2Point::mul(p2, s1);
    });
    
    ecgroup::PairingResult pr = ecgroup::pairing(p1, p2);
    primitive_runner.run("Pairing Exponentiation", [&]() {
        auto r = pr.pow(s1);
    });

    protocol_runner.run("Pairing", [&]() { // Pairing is slower, use fewer iters
        auto r = ecgroup::pairing(p1, p2);
    });

    return 0;
}