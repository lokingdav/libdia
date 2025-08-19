#include <iostream>
#include <chrono>
#include <vector>
#include <string>
#include <iomanip>
#include <functional>

#include "dia/dia.hpp"
#include "amf.hpp"
#include "voprf.hpp"
#include "bbs.hpp"

using ecgroup::Bytes;

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

        std::cout << std::left << std::setw(34) << name
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

    // --- AMF serialization micro-benchmarks ---
    {
        Bytes amf_bytes = sig_ok.to_bytes();
        std::cout << "AMF Signature size: " << amf_bytes.size() << " bytes\n";
        protocol_runner.run("AMF Sig Serialize", [&]() {
            Bytes b = sig_ok.to_bytes();
            volatile size_t sink = b.size();
            (void)sink;
        });
        protocol_runner.run("AMF Sig Deserialize", [&]() {
            amf::Signature s = amf::Signature::from_bytes(amf_bytes);
            volatile bool sink = (s.A == sig_ok.A); // arbitrary equality check
            (void)sink;
        });
    }

    // =====================================================================
    // SECTION 3: VOPRF
    // =====================================================================
    std::cout << "\n--- VOPRF (Avg over " << protocol_runner.num_iters << " iters) ---" << std::endl;

    voprf::KeyPair svr = voprf::keygen();
    protocol_runner.run("VOPRF KeyGen", [&]() {
        auto kp = voprf::keygen();
        volatile bool sink = (kp.pk == svr.pk); // arbitrary sink
        (void)sink;
    });

    const std::string in = "voprf input";
    protocol_runner.run("VOPRF Blind (client)", [&]() {
        auto [B, r] = voprf::blind(in);
        volatile bool sink = (B == ecgroup::G1Point()); // unlikely
        (void)sink;
    });

    auto [B0, r0] = voprf::blind(in);
    protocol_runner.run("VOPRF Evaluate (server)", [&]() {
        auto element = ecgroup::G1Point::mul(B0, svr.sk);
        volatile bool sink = (element == B0);
        (void)sink;
    });

    auto element0 = ecgroup::G1Point::mul(B0, svr.sk);
    protocol_runner.run("VOPRF Unblind (client)", [&]() {
        auto Y = voprf::unblind(element0, r0);
        volatile bool sink = (Y == element0);
        (void)sink;
    });

    auto Y0 = voprf::unblind(element0, r0);
    protocol_runner.run("VOPRF Verify (single)", [&]() {
        bool ok = voprf::verify(in, Y0, svr.pk);
        volatile bool sink = ok;
        (void)sink;
    });

    protocol_runner.run("VOPRF End-to-End (1 msg)", [&]() {
        auto [B, r] = voprf::blind(in);
        auto element = ecgroup::G1Point::mul(B, svr.sk);
        auto Y = voprf::unblind(element, r);
        bool ok = voprf::verify(in, Y, svr.pk);
        volatile bool sink = ok;
        (void)sink;
    });

    const size_t N = 32;
    std::vector<std::string> inputs;
    std::vector<ecgroup::G1Point> outputs;
    inputs.reserve(N);
    outputs.reserve(N);
    for (size_t i = 0; i < N; ++i) {
        std::string s = "input_" + std::to_string(i);
        inputs.push_back(s);
        auto Hi = ecgroup::G1Point::hash_and_map_to(s);
        auto Yi = ecgroup::G1Point::mul(Hi, svr.sk);
        outputs.push_back(Yi);
    }
    protocol_runner.run("VOPRF Verify Batch (N=32)", [&]() {
        bool ok = voprf::verify_batch(inputs, outputs, svr.pk);
        volatile bool sink = ok;
        (void)sink;
    });

    // =====================================================================
    // SECTION 4: BBS (compact) + Selective Disclosure
    // =====================================================================
    std::cout << "\n--- BBS (Avg over " << protocol_runner.num_iters << " iters) ---" << std::endl;

    bbs::Params bparams = bbs::Params::Default();
    bbs::KeyPair issuer = bbs::keygen(bparams);

    // Message vector
    const std::size_t L = 8;
    std::vector<ecgroup::Scalar> msgs(L);
    for (auto &m : msgs) m = ecgroup::Scalar::get_random();

    protocol_runner.run("BBS KeyGen", [&]() {
        auto kp = bbs::keygen(bparams);
        volatile bool sink = (kp.pk == issuer.pk);
        (void)sink;
    });

    protocol_runner.run("BBS Sign (L=8)", [&]() {
        auto sig = bbs::sign(bparams, issuer.sk, msgs);
        volatile bool sink = (sig.e == ecgroup::Scalar()); // arbitrary sink
        (void)sink;
    });

    bbs::Signature bsig = bbs::sign(bparams, issuer.sk, msgs);

    protocol_runner.run("BBS Verify", [&]() {
        bool ok = bbs::verify(bparams, issuer.pk, msgs, bsig);
        volatile bool sink = ok;
        (void)sink;
    });

    // --- BBS signature serialization micro-benchmarks ---
    {
        Bytes bbs_sig_bytes = bsig.to_bytes();
        std::cout << "BBS Signature size: " << bbs_sig_bytes.size() << " bytes\n";
        protocol_runner.run("BBS Sig Serialize", [&]() {
            Bytes b = bsig.to_bytes();
            volatile size_t sink = b.size();
            (void)sink;
        });
        protocol_runner.run("BBS Sig Deserialize", [&]() {
            bbs::Signature s = bbs::Signature::from_bytes(bbs_sig_bytes);
            volatile bool sink = (s.e == bsig.e);
            (void)sink;
        });
    }

    // --- Selective Disclosure: k = 0 (reveal none) ---
    std::vector<std::size_t> disclose0; // empty
    bbs::SDProof prf0 = bbs::create_proof(bparams, issuer.pk, bsig, msgs, disclose0, "bench-k0");

    protocol_runner.run("BBS SDP Create (k=0)", [&]() {
        auto prf = bbs::create_proof(bparams, issuer.pk, bsig, msgs, disclose0, "bench-k0");
        volatile bool sink = (prf.hidden_indices.size() == L);
        (void)sink;
    });

    std::vector<std::pair<std::size_t, ecgroup::Scalar>> disclosed_vals0; // none
    protocol_runner.run("BBS SDP Verify (k=0)", [&]() {
        bool ok = bbs::verify_proof(bparams, issuer.pk, prf0, disclosed_vals0, L);
        volatile bool sink = ok;
        (void)sink;
    });

    // --- SD proof serialization (k=0) ---
    {
        Bytes prf0_bytes = prf0.to_bytes();
        std::cout << "BBS SDProof(k=0) size: " << prf0_bytes.size() << " bytes\n";
        protocol_runner.run("BBS SDP Serialize (k=0)", [&]() {
            Bytes b = prf0.to_bytes();
            volatile size_t sink = b.size();
            (void)sink;
        });
        protocol_runner.run("BBS SDP Deserialize (k=0)", [&]() {
            bbs::SDProof q = bbs::SDProof::from_bytes(prf0_bytes);
            volatile bool sink = (q.hidden_indices.size() == prf0.hidden_indices.size());
            (void)sink;
        });
    }

    // --- Selective Disclosure: k ≈ L/2 (reveal half) ---
    std::vector<std::size_t> discloseHalf;
    for (std::size_t i = 1; i <= L; i += 2) discloseHalf.push_back(i); // 1,3,5,7
    bbs::SDProof prfH = bbs::create_proof(bparams, issuer.pk, bsig, msgs, discloseHalf, "bench-kH");

    protocol_runner.run("BBS SDP Create (k=L/2)", [&]() {
        auto prf = bbs::create_proof(bparams, issuer.pk, bsig, msgs, discloseHalf, "bench-kH");
        volatile bool sink = (prf.hidden_indices.size() == (L - discloseHalf.size()));
        (void)sink;
    });

    std::vector<std::pair<std::size_t, ecgroup::Scalar>> disclosed_valsH;
    disclosed_valsH.reserve(discloseHalf.size());
    for (auto idx : discloseHalf) {
        disclosed_valsH.emplace_back(idx, msgs[idx - 1]); // 1-based index
    }
    protocol_runner.run("BBS SDP Verify (k=L/2)", [&]() {
        bool ok = bbs::verify_proof(bparams, issuer.pk, prfH, disclosed_valsH, L);
        volatile bool sink = ok;
        (void)sink;
    });

    // --- SD proof serialization (k=L/2) ---
    {
        Bytes prfH_bytes = prfH.to_bytes();
        std::cout << "BBS SDProof(k=L/2) size: " << prfH_bytes.size() << " bytes\n";
        protocol_runner.run("BBS SDP Serialize (k=L/2)", [&]() {
            Bytes b = prfH.to_bytes();
            volatile size_t sink = b.size();
            (void)sink;
        });
        protocol_runner.run("BBS SDP Deserialize (k=L/2)", [&]() {
            bbs::SDProof q = bbs::SDProof::from_bytes(prfH_bytes);
            volatile bool sink = (q.hidden_indices.size() == prfH.hidden_indices.size());
            (void)sink;
        });
    }

    return 0;
}
