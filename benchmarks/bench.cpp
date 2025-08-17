#include <iostream>
#include <chrono>
#include <vector>
#include <string>
#include <iomanip>
#include <functional>

#include "dia/dia.hpp"
#include "amf.hpp"   // <-- add this

/**
 * @brief A simple class to run benchmarks and print formatted results.
 */
class BenchmarkRunner {
public:
    int num_iters;

    explicit BenchmarkRunner(int iterations) : num_iters(iterations) {}

    void run(const std::string& name, const std::function<void()>& func) {
        // Warm-up
        func();

        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < num_iters; ++i) {
            func();
        }
        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> elapsed = end - start;

        std::cout << std::left << std::setw(28) << name
                  << ": " << std::fixed << std::setprecision(6)
                  << (elapsed.count() / num_iters) << " ms" << std::endl;
    }
};

int main() {
    ecgroup::init_pairing();

    BenchmarkRunner primitive_runner(10000); // More iterations for fast ops
    BenchmarkRunner protocol_runner(100);    // Fewer iterations for slow ops

    // =====================================================================
    // SECTION 1: Low-Level Cryptographic Primitives
    // =====================================================================
    std::cout << "\n--- Low-Level Cryptographic Primitives (Avg over "
              << primitive_runner.num_iters << " iters) ---" << std::endl;

    ecgroup::Scalar s1 = ecgroup::Scalar::get_random();
    ecgroup::Scalar s2 = ecgroup::Scalar::get_random();
    primitive_runner.run("Scalar Multiplication", [&]() {
        auto r = s1 * s2;
        (void)r;
    });

    ecgroup::G1Point p1 = ecgroup::G1Point::get_random();
    primitive_runner.run("G1 Scalar Multiplication", [&]() {
        auto r = ecgroup::G1Point::mul(p1, s1);
        (void)r;
    });

    ecgroup::G2Point p2 = ecgroup::G2Point::get_random();
    primitive_runner.run("G2 Scalar Multiplication", [&]() {
        auto r = ecgroup::G2Point::mul(p2, s1);
        (void)r;
    });

    ecgroup::PairingResult pr = ecgroup::pairing(p1, p2);
    primitive_runner.run("Pairing Exponentiation", [&]() {
        auto r = pr.pow(s1);
        (void)r;
    });

    protocol_runner.run("Pairing", [&]() { // Pairing is slower, use fewer iters
        auto r = ecgroup::pairing(p1, p2);
        (void)r;
    });

    // =====================================================================
    // SECTION 2: AMF (Asymmetric Message Franking)
    // =====================================================================
    std::cout << "\n--- AMF (Avg over " << protocol_runner.num_iters << " iters) ---" << std::endl;

    // Params & keys
    amf::Params params = amf::Params::Default();
    amf::KeyPair S = amf::KeyGen(params); // sender
    amf::KeyPair R = amf::KeyGen(params); // receiver
    amf::KeyPair J = amf::KeyGen(params); // judge
    const std::string msg = "hello AMF";

    // Frank (sign)
    protocol_runner.run("AMF Frank (sign)", [&]() {
        auto sig = amf::Frank(S.sk, R.pk, J.pk, msg, params);
        // prevent over-aggressive DCE
        volatile bool sink = (sig.A == sig.B);
        (void)sink;
    });

    // Precompute a valid signature for Verify/Judge benches
    amf::Signature sig_ok = amf::Frank(S.sk, R.pk, J.pk, msg, params);

    // Verify (receiver check + proof verify)
    protocol_runner.run("AMF Verify (receiver)", [&]() {
        bool ok = amf::Verify(S.pk, R.sk, J.pk, msg, sig_ok, params);
        volatile bool sink = ok;
        (void)sink;
    });

    // Judge (moderator check + proof verify)
    protocol_runner.run("AMF Judge (moderator)", [&]() {
        bool ok = amf::Judge(S.pk, R.pk, J.sk, msg, sig_ok, params);
        volatile bool sink = ok;
        (void)sink;
    });

    // Public Forge (deniability)
    protocol_runner.run("AMF Forge (public)", [&]() {
        auto sig = amf::Forge(S.pk, R.pk, J.pk, msg, params);
        volatile bool sink = (sig.A == sig.B);
        (void)sink;
    });

    // Receiver-compromise RForge
    protocol_runner.run("AMF RForge", [&]() {
        auto sig = amf::RForge(S.pk, R.sk, J.pk, msg, params);
        volatile bool sink = (sig.U == sig.B); // arbitrary use
        (void)sink;
    });

    // Judge-compromise JForge
    protocol_runner.run("AMF JForge", [&]() {
        auto sig = amf::JForge(S.pk, R.pk, J.sk, msg, params);
        volatile bool sink = (sig.T == sig.A); // arbitrary use
        (void)sink;
    });

    return 0;
}
