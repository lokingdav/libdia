#include <iostream>
#include <chrono>
#include <vector>
#include <string>
#include <iomanip>
#include <functional>

#include "dia/dia.hpp"
#include "amf.hpp"
#include "voprf.hpp"

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

    BenchmarkRunner primitive_runner(10000); // fast ops
    BenchmarkRunner protocol_runner(100);    // slower ops

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

    amf::Params params = amf::Params::Default();
    amf::KeyPair S = amf::KeyGen(params); // sender
    amf::KeyPair R = amf::KeyGen(params); // receiver
    amf::KeyPair J = amf::KeyGen(params); // judge
    const std::string msg = "hello AMF";

    protocol_runner.run("AMF Frank (sign)", [&]() {
        auto sig = amf::Frank(S.sk, R.pk, J.pk, msg, params);
        volatile bool sink = (sig.A == sig.B);
        (void)sink;
    });

    amf::Signature sig_ok = amf::Frank(S.sk, R.pk, J.pk, msg, params);

    protocol_runner.run("AMF Verify (receiver)", [&]() {
        bool ok = amf::Verify(S.pk, R.sk, J.pk, msg, sig_ok, params);
        volatile bool sink = ok;
        (void)sink;
    });

    protocol_runner.run("AMF Judge (moderator)", [&]() {
        bool ok = amf::Judge(S.pk, R.pk, J.sk, msg, sig_ok, params);
        volatile bool sink = ok;
        (void)sink;
    });

    protocol_runner.run("AMF Forge (public)", [&]() {
        auto sig = amf::Forge(S.pk, R.pk, J.pk, msg, params);
        volatile bool sink = (sig.T == sig.U);
        (void)sink;
    });

    protocol_runner.run("AMF RForge", [&]() {
        auto sig = amf::RForge(S.pk, R.sk, J.pk, msg, params);
        volatile bool sink = (sig.U == ecgroup::G1Point::mul(sig.B, R.sk));
        (void)sink;
    });

    protocol_runner.run("AMF JForge", [&]() {
        auto sig = amf::JForge(S.pk, R.pk, J.sk, msg, params);
        volatile bool sink = (sig.T == ecgroup::G1Point::mul(sig.A, J.sk));
        (void)sink;
    });

    // =====================================================================
    // SECTION 3: VOPRF
    // =====================================================================
    std::cout << "\n--- VOPRF (Avg over " << protocol_runner.num_iters << " iters) ---" << std::endl;

    // Server keygen
    voprf::KeyPair svr = voprf::keygen();
    protocol_runner.run("VOPRF KeyGen", [&]() {
        auto kp = voprf::keygen();
        volatile bool sink = (kp.pk == svr.pk); // arbitrary
        (void)sink;
    });

    // One message to exercise client/server flow
    const std::string in = "voprf input";

    // Blind
    protocol_runner.run("VOPRF Blind (client)", [&]() {
        auto [B, r] = voprf::blind(in);
        volatile bool sink = (B == ecgroup::G1Point()); // unlikely
        (void)sink;
    });

    // Server evaluate (on blinded element): element = sk * B
    auto [B0, r0] = voprf::blind(in);
    protocol_runner.run("VOPRF Evaluate (server)", [&]() {
        auto element = ecgroup::G1Point::mul(B0, svr.sk);
        volatile bool sink = (element == B0);
        (void)sink;
    });

    // Unblind (client)
    auto element0 = ecgroup::G1Point::mul(B0, svr.sk);
    protocol_runner.run("VOPRF Unblind (client)", [&]() {
        auto Y = voprf::unblind(element0, r0);
        volatile bool sink = (Y == element0);
        (void)sink;
    });

    // Verify (single)
    auto Y0 = voprf::unblind(element0, r0); // final PRF output for `in`
    protocol_runner.run("VOPRF Verify (single)", [&]() {
        bool ok = voprf::verify(in, Y0, svr.pk);
        volatile bool sink = ok;
        (void)sink;
    });

    // End-to-end round (blind + eval + unblind + verify)
    protocol_runner.run("VOPRF End-to-End (1 msg)", [&]() {
        auto [B, r] = voprf::blind(in);
        auto element = ecgroup::G1Point::mul(B, svr.sk);
        auto Y = voprf::unblind(element, r);
        bool ok = voprf::verify(in, Y, svr.pk);
        volatile bool sink = ok;
        (void)sink;
    });

    // Batch verify: prepare a batch once, then benchmark verification only
    const size_t N = 32;
    std::vector<std::string> inputs;
    std::vector<ecgroup::G1Point> outputs;
    inputs.reserve(N);
    outputs.reserve(N);
    for (size_t i = 0; i < N; ++i) {
        std::string s = "input_" + std::to_string(i);
        inputs.push_back(s);
        // Y_i = sk * H1(s)  (client would get this via blind/eval/unblind)
        auto Hi = ecgroup::G1Point::hash_and_map_to(s);
        auto Yi = ecgroup::G1Point::mul(Hi, svr.sk);
        outputs.push_back(Yi);
    }
    protocol_runner.run("VOPRF Verify Batch (N=32)", [&]() {
        bool ok = voprf::verify_batch(inputs, outputs, svr.pk);
        volatile bool sink = ok;
        (void)sink;
    });

    return 0;
}
