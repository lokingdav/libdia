#include "benchmark.hpp"

#include "ake.hpp"
#include "accesstoken.hpp"
#include "callstate.hpp"
#include "enrollment.hpp"
#include "oda.hpp"
#include "rua.hpp"

#include "../crypto/amf.hpp"
#include "../crypto/bbs.hpp"
#include "../crypto/voprf.hpp"

#include "../crypto/ecgroup.hpp"

#include <sodium.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <iomanip>
#include <unordered_map>
#include <numeric>
#include <sstream>
#include <memory>
#include <stdexcept>
#include <utility>

namespace protocol {
namespace bench {

static void ensure_crypto_init() {
    // libsodium is used directly (randombytes_buf) in protocol code.
    // It's safe to call sodium_init() multiple times.
    if (sodium_init() < 0) {
        throw std::runtime_error("libsodium init failed");
    }

    // Pairing is required by protocol crypto.
    ecgroup::init_pairing();
}

static double median_of_sorted(const std::vector<double>& sorted) {
    if (sorted.empty()) {
        return 0.0;
    }
    const std::size_t n = sorted.size();
    const std::size_t mid = n / 2;
    if ((n % 2) == 1) {
        return sorted[mid];
    }
    return 0.5 * (sorted[mid - 1] + sorted[mid]);
}

static Stats compute_stats_ms(const std::vector<double>& samples_ms) {
    Stats s;
    if (samples_ms.empty()) {
        return s;
    }

    std::vector<double> sorted = samples_ms;
    std::sort(sorted.begin(), sorted.end());

    s.min_ms = sorted.front();
    s.max_ms = sorted.back();

    const double sum = std::accumulate(sorted.begin(), sorted.end(), 0.0);
    s.mean_ms = sum / static_cast<double>(sorted.size());
    s.median_ms = median_of_sorted(sorted);

    double var = 0.0;
    for (double x : sorted) {
        const double d = x - s.mean_ms;
        var += d * d;
    }
    var /= static_cast<double>(sorted.size());
    s.stddev_ms = std::sqrt(var);

    std::vector<double> abs_dev;
    abs_dev.reserve(sorted.size());
    for (double x : sorted) {
        abs_dev.push_back(std::fabs(x - s.median_ms));
    }
    std::sort(abs_dev.begin(), abs_dev.end());
    s.mad_ms = median_of_sorted(abs_dev);
    return s;
}

struct RawBench {
    BenchResult summary;
    std::vector<double> samples_ms;
};

static std::string csv_escape(const std::string& v) {
    const bool needs_quotes =
        (v.find(',') != std::string::npos) || (v.find('"') != std::string::npos) ||
        (v.find('\n') != std::string::npos) || (v.find('\r') != std::string::npos);
    if (!needs_quotes) {
        return v;
    }
    std::string out;
    out.reserve(v.size() + 2);
    out.push_back('"');
    for (char c : v) {
        if (c == '"') {
            out.push_back('"');
        }
        out.push_back(c);
    }
    out.push_back('"');
    return out;
}

struct Fixtures {
    ServerConfig server;

    // One request/response/keys triple used for isolated enrollment benches.
    EnrollmentKeys enrollment_keys;
    EnrollmentRequest enrollment_request;
    EnrollmentResponse enrollment_response;

    // Enrolled client configs.
    ClientConfig alice_cfg;
    ClientConfig bob_cfg;

    // Cached peer state (post-AKE) for RUA-only flows.
    PeerSessionState alice_peer;
    PeerSessionState bob_peer;

    // Fixed timestamp used across prepared contexts so AKE topics match.
    std::string ts;
};

static ServerConfig make_server_config() {
    ServerConfig cfg;

    // Credential issuer keys (BBS)
    bbs::Params bbs_params = bbs::Params::Default();
    bbs::KeyPair ci = bbs::keygen(bbs_params);
    cfg.ci_private_key = ci.sk.to_bytes();
    cfg.ci_public_key = ci.pk.to_bytes();

    // Access throttling keys (VOPRF)
    voprf::KeyPair at = voprf::keygen();
    cfg.at_private_key = at.sk.to_bytes();
    cfg.at_public_key = at.pk.to_bytes();

    // AMF moderator keys
    amf::Params amf_params = amf::Params::Default();
    amf::KeyPair mod = amf::KeyGen(amf_params);
    cfg.amf_private_key = mod.sk.to_bytes();
    cfg.amf_public_key = mod.pk.to_bytes();

    cfg.enrollment_duration_days = 30;
    return cfg;
}

struct CallPair {
    std::unique_ptr<CallState> alice;
    std::unique_ptr<CallState> bob;
};

static CallPair make_call_pair(const ClientConfig& alice_cfg, const ClientConfig& bob_cfg);
static void set_fixed_ts(CallState& alice, CallState& bob, const std::string& ts);
static void run_rua_handshake(CallState& alice, CallState& bob);

struct WireBytes {
    std::size_t enrollment_req = 0;
    std::size_t enrollment_resp = 0;

    std::size_t ake_req = 0;
    std::size_t ake_resp = 0;
    std::size_t ake_complete = 0;

    std::size_t rua_req = 0;
    std::size_t rua_resp = 0;

    std::size_t oda_req = 0;
    std::size_t oda_resp = 0;

    std::size_t token_blinded = 0;
    std::size_t token_evaluated = 0;

    std::size_t delegation_cert = 0;
};

static WireBytes compute_wire_bytes(const Fixtures& fx) {
    WireBytes b;

    // Enrollment wire sizes (serialized request/response).
    {
        b.enrollment_req = fx.enrollment_request.serialize().size();
        b.enrollment_resp = fx.enrollment_response.serialize().size();
    }

    // Access token minting roundtrip sizes.
    {
        auto bt = accesstoken::blind_access_token();
        b.token_blinded = bt.blinded.size();
        b.token_evaluated = accesstoken::evaluate_blinded_access_token(fx.server.at_private_key, bt.blinded).size();
    }

    // Delegation certificate size (expiration + signature).
    {
        auto d = create_delegation(
            fx.server.ci_private_key,
            fx.enrollment_keys.subscriber_public_key,
            30,
            fx.enrollment_request.telephone_number,
            {}
        );
        b.delegation_cert = d.expiration.size() + d.signature.size();
    }

    // AKE message sizes.
    {
        auto pair = make_call_pair(fx.alice_cfg, fx.bob_cfg);
        set_fixed_ts(*pair.alice, *pair.bob, fx.ts);

        init_ake(*pair.alice);
        init_ake(*pair.bob);

        Bytes req_bytes = ake_request(*pair.alice);
        b.ake_req = req_bytes.size();
        ProtocolMessage req_msg = ProtocolMessage::deserialize(req_bytes);

        Bytes resp_bytes = ake_response(*pair.bob, req_msg);
        b.ake_resp = resp_bytes.size();
        ProtocolMessage resp_msg = ProtocolMessage::deserialize(resp_bytes);

        Bytes complete_bytes = ake_complete(*pair.alice, resp_msg);
        b.ake_complete = complete_bytes.size();
    }

    // RUA message sizes (cached peer state = subsequent call flow).
    {
        auto pair = make_call_pair(fx.alice_cfg, fx.bob_cfg);
        set_fixed_ts(*pair.alice, *pair.bob, fx.ts);

        pair.alice->apply_peer_session(fx.alice_peer);
        pair.bob->apply_peer_session(fx.bob_peer);

        Bytes req_bytes = rua_request(*pair.alice);
        b.rua_req = req_bytes.size();
        ProtocolMessage req_msg = ProtocolMessage::deserialize(req_bytes);

        Bytes resp_bytes = rua_response(*pair.bob, req_msg);
        b.rua_resp = resp_bytes.size();
    }

    // ODA message sizes (after RUA established).
    {
        auto pair = make_call_pair(fx.alice_cfg, fx.bob_cfg);
        set_fixed_ts(*pair.alice, *pair.bob, fx.ts);

        pair.alice->apply_peer_session(fx.alice_peer);
        pair.bob->apply_peer_session(fx.bob_peer);
        run_rua_handshake(*pair.alice, *pair.bob);

        std::vector<std::string> attrs = {"name"};
        Bytes req_bytes = oda_request(*pair.alice, attrs);
        b.oda_req = req_bytes.size();
        ProtocolMessage req_msg = ProtocolMessage::deserialize(req_bytes);

        Bytes resp_bytes = oda_response(*pair.bob, req_msg);
        b.oda_resp = resp_bytes.size();
    }

    return b;
}

static ClientConfig enroll_client(
    const ServerConfig& server,
    const std::string& phone,
    const std::string& name,
    const std::string& logo_url,
    std::size_t num_tickets)
{
    auto [keys, req] = create_enrollment_request(phone, name, logo_url, num_tickets);
    EnrollmentResponse resp = process_enrollment(server, req);
    return finalize_enrollment(keys, resp, phone, name, logo_url);
}

static CallPair make_call_pair(const ClientConfig& alice_cfg, const ClientConfig& bob_cfg) {
    // Create CallStates. Keep ts aligned to simulate a single call.
    auto alice = std::make_unique<CallState>(alice_cfg, bob_cfg.my_phone, true);
    auto bob = std::make_unique<CallState>(bob_cfg, alice_cfg.my_phone, false);

    alice->src = alice_cfg.my_phone;
    alice->dst = bob_cfg.my_phone;
    alice->ts = get_normalized_ts();
    alice->call_reason = "Benchmark Call";

    bob->src = alice_cfg.my_phone;
    bob->dst = bob_cfg.my_phone;
    bob->ts = alice->ts;

    return CallPair{std::move(alice), std::move(bob)};
}

static void run_ake_handshake(CallState& alice, CallState& bob) {
    init_ake(alice);
    init_ake(bob);

    Bytes req_bytes = ake_request(alice);
    ProtocolMessage req_msg = ProtocolMessage::deserialize(req_bytes);

    Bytes resp_bytes = ake_response(bob, req_msg);
    ProtocolMessage resp_msg = ProtocolMessage::deserialize(resp_bytes);

    Bytes complete_bytes = ake_complete(alice, resp_msg);
    ProtocolMessage complete_msg = ProtocolMessage::deserialize(complete_bytes);

    ake_finalize(bob, complete_msg);
}

static void run_rua_handshake(CallState& alice, CallState& bob) {
    Bytes req_bytes = rua_request(alice);
    ProtocolMessage req_msg = ProtocolMessage::deserialize(req_bytes);

    Bytes resp_bytes = rua_response(bob, req_msg);
    ProtocolMessage resp_msg = ProtocolMessage::deserialize(resp_bytes);

    rua_finalize(alice, resp_msg);
}

// -----------------------------------------------------------------------------
// Prepared per-iteration contexts (one-shot)
// -----------------------------------------------------------------------------

struct AkeRequestCtx {
    std::unique_ptr<CallState> caller;
};

struct AkeResponseCtx {
    std::unique_ptr<CallState> recipient;
    ProtocolMessage request_msg;
};

struct AkeCompleteCtx {
    std::unique_ptr<CallState> caller;
    ProtocolMessage response_msg;
};

struct AkeFinalizeCtx {
    std::unique_ptr<CallState> recipient;
    ProtocolMessage complete_msg;
};

struct RuaRequestCtx {
    std::unique_ptr<CallState> caller;
};

struct RuaResponseCtx {
    std::unique_ptr<CallState> recipient;
    ProtocolMessage request_msg;
};

struct RuaFinalizeCtx {
    std::unique_ptr<CallState> caller;
    ProtocolMessage response_msg;
};

struct OdaRequestCtx {
    std::unique_ptr<CallState> verifier;
};

struct OdaResponseCtx {
    std::unique_ptr<CallState> prover;
    ProtocolMessage request_msg;
};

struct OdaVerifyCtx {
    std::unique_ptr<CallState> verifier;
    ProtocolMessage response_msg;
};

static void set_fixed_ts(CallState& alice, CallState& bob, const std::string& ts) {
    alice.ts = ts;
    bob.ts = ts;
}

static std::vector<AkeRequestCtx> prepare_ake_request_ctxs(const Fixtures& fx, int n) {
    std::vector<AkeRequestCtx> out;
    out.reserve(n);
    for (int i = 0; i < n; ++i) {
        auto pair = make_call_pair(fx.alice_cfg, fx.bob_cfg);
        set_fixed_ts(*pair.alice, *pair.bob, fx.ts);
        init_ake(*pair.alice);
        out.push_back(AkeRequestCtx{std::move(pair.alice)});
    }
    return out;
}

static std::vector<AkeResponseCtx> prepare_ake_response_ctxs(const Fixtures& fx, int n) {
    std::vector<AkeResponseCtx> out;
    out.reserve(n);
    for (int i = 0; i < n; ++i) {
        auto pair = make_call_pair(fx.alice_cfg, fx.bob_cfg);
        set_fixed_ts(*pair.alice, *pair.bob, fx.ts);
        init_ake(*pair.alice);
        init_ake(*pair.bob);

        Bytes req_bytes = ake_request(*pair.alice);
        ProtocolMessage req_msg = ProtocolMessage::deserialize(req_bytes);

        out.push_back(AkeResponseCtx{std::move(pair.bob), std::move(req_msg)});
    }
    return out;
}

static std::vector<AkeCompleteCtx> prepare_ake_complete_ctxs(const Fixtures& fx, int n) {
    std::vector<AkeCompleteCtx> out;
    out.reserve(n);
    for (int i = 0; i < n; ++i) {
        auto pair = make_call_pair(fx.alice_cfg, fx.bob_cfg);
        set_fixed_ts(*pair.alice, *pair.bob, fx.ts);
        init_ake(*pair.alice);
        init_ake(*pair.bob);

        Bytes req_bytes = ake_request(*pair.alice);
        ProtocolMessage req_msg = ProtocolMessage::deserialize(req_bytes);

        Bytes resp_bytes = ake_response(*pair.bob, req_msg);
        ProtocolMessage resp_msg = ProtocolMessage::deserialize(resp_bytes);

        out.push_back(AkeCompleteCtx{std::move(pair.alice), std::move(resp_msg)});
    }
    return out;
}

static std::vector<AkeFinalizeCtx> prepare_ake_finalize_ctxs(const Fixtures& fx, int n) {
    std::vector<AkeFinalizeCtx> out;
    out.reserve(n);
    for (int i = 0; i < n; ++i) {
        auto pair = make_call_pair(fx.alice_cfg, fx.bob_cfg);
        set_fixed_ts(*pair.alice, *pair.bob, fx.ts);
        init_ake(*pair.alice);
        init_ake(*pair.bob);

        Bytes req_bytes = ake_request(*pair.alice);
        ProtocolMessage req_msg = ProtocolMessage::deserialize(req_bytes);

        Bytes resp_bytes = ake_response(*pair.bob, req_msg);
        ProtocolMessage resp_msg = ProtocolMessage::deserialize(resp_bytes);

        Bytes complete_bytes = ake_complete(*pair.alice, resp_msg);
        ProtocolMessage complete_msg = ProtocolMessage::deserialize(complete_bytes);

        out.push_back(AkeFinalizeCtx{std::move(pair.bob), std::move(complete_msg)});
    }
    return out;
}

static std::vector<RuaRequestCtx> prepare_rua_request_ctxs(const Fixtures& fx, int n) {
    std::vector<RuaRequestCtx> out;
    out.reserve(n);
    for (int i = 0; i < n; ++i) {
        auto pair = make_call_pair(fx.alice_cfg, fx.bob_cfg);
        set_fixed_ts(*pair.alice, *pair.bob, fx.ts);

        pair.alice->apply_peer_session(fx.alice_peer);
        pair.bob->apply_peer_session(fx.bob_peer);

        out.push_back(RuaRequestCtx{std::move(pair.alice)});
    }
    return out;
}

static std::vector<RuaResponseCtx> prepare_rua_response_ctxs(const Fixtures& fx, int n) {
    std::vector<RuaResponseCtx> out;
    out.reserve(n);
    for (int i = 0; i < n; ++i) {
        auto pair = make_call_pair(fx.alice_cfg, fx.bob_cfg);
        set_fixed_ts(*pair.alice, *pair.bob, fx.ts);

        pair.alice->apply_peer_session(fx.alice_peer);
        pair.bob->apply_peer_session(fx.bob_peer);

        Bytes req_bytes = rua_request(*pair.alice);
        ProtocolMessage req_msg = ProtocolMessage::deserialize(req_bytes);

        out.push_back(RuaResponseCtx{std::move(pair.bob), std::move(req_msg)});
    }
    return out;
}

static std::vector<RuaFinalizeCtx> prepare_rua_finalize_ctxs(const Fixtures& fx, int n) {
    std::vector<RuaFinalizeCtx> out;
    out.reserve(n);
    for (int i = 0; i < n; ++i) {
        auto pair = make_call_pair(fx.alice_cfg, fx.bob_cfg);
        set_fixed_ts(*pair.alice, *pair.bob, fx.ts);

        pair.alice->apply_peer_session(fx.alice_peer);
        pair.bob->apply_peer_session(fx.bob_peer);

        Bytes req_bytes = rua_request(*pair.alice);
        ProtocolMessage req_msg = ProtocolMessage::deserialize(req_bytes);

        Bytes resp_bytes = rua_response(*pair.bob, req_msg);
        ProtocolMessage resp_msg = ProtocolMessage::deserialize(resp_bytes);

        out.push_back(RuaFinalizeCtx{std::move(pair.alice), std::move(resp_msg)});
    }
    return out;
}

static std::vector<OdaRequestCtx> prepare_oda_request_ctxs(const Fixtures& fx, int n) {
    std::vector<OdaRequestCtx> out;
    out.reserve(n);
    for (int i = 0; i < n; ++i) {
        auto pair = make_call_pair(fx.alice_cfg, fx.bob_cfg);
        set_fixed_ts(*pair.alice, *pair.bob, fx.ts);

        pair.alice->apply_peer_session(fx.alice_peer);
        pair.bob->apply_peer_session(fx.bob_peer);
        run_rua_handshake(*pair.alice, *pair.bob);

        out.push_back(OdaRequestCtx{std::move(pair.alice)});
    }
    return out;
}

static std::vector<OdaResponseCtx> prepare_oda_response_ctxs(const Fixtures& fx, int n) {
    std::vector<OdaResponseCtx> out;
    out.reserve(n);
    for (int i = 0; i < n; ++i) {
        auto pair = make_call_pair(fx.alice_cfg, fx.bob_cfg);
        set_fixed_ts(*pair.alice, *pair.bob, fx.ts);

        pair.alice->apply_peer_session(fx.alice_peer);
        pair.bob->apply_peer_session(fx.bob_peer);
        run_rua_handshake(*pair.alice, *pair.bob);

        std::vector<std::string> attrs = {"name"};
        Bytes req_bytes = oda_request(*pair.alice, attrs);
        ProtocolMessage req_msg = ProtocolMessage::deserialize(req_bytes);

        out.push_back(OdaResponseCtx{std::move(pair.bob), std::move(req_msg)});
    }
    return out;
}

static std::vector<OdaVerifyCtx> prepare_oda_verify_ctxs(const Fixtures& fx, int n) {
    std::vector<OdaVerifyCtx> out;
    out.reserve(n);
    for (int i = 0; i < n; ++i) {
        auto pair = make_call_pair(fx.alice_cfg, fx.bob_cfg);
        set_fixed_ts(*pair.alice, *pair.bob, fx.ts);

        pair.alice->apply_peer_session(fx.alice_peer);
        pair.bob->apply_peer_session(fx.bob_peer);
        run_rua_handshake(*pair.alice, *pair.bob);

        std::vector<std::string> attrs = {"name"};
        Bytes req_bytes = oda_request(*pair.alice, attrs);
        ProtocolMessage req_msg = ProtocolMessage::deserialize(req_bytes);

        Bytes resp_bytes = oda_response(*pair.bob, req_msg);
        ProtocolMessage resp_msg = ProtocolMessage::deserialize(resp_bytes);

        out.push_back(OdaVerifyCtx{std::move(pair.alice), std::move(resp_msg)});
    }
    return out;
}

static std::shared_ptr<Fixtures> build_fixtures() {
    ensure_crypto_init();

    auto fx = std::make_shared<Fixtures>();
    fx->ts = get_normalized_ts();
    fx->server = make_server_config();

    // Prepare a single enrollment request/response/keys triple for isolated benches.
    {
        auto [keys, req] = create_enrollment_request(
            "+1234567890",
            "Alice",
            "https://example.com/logo.png",
            1
        );
        fx->enrollment_keys = keys;
        fx->enrollment_request = req;
        fx->enrollment_response = process_enrollment(fx->server, fx->enrollment_request);
    }

    // Create enrolled configs for AKE/RUA/ODA fixtures.
    fx->alice_cfg = enroll_client(fx->server, "+1234567890", "Alice", "https://example.com/alice.png", 1);
    fx->bob_cfg = enroll_client(fx->server, "+1987654321", "Bob", "https://example.com/bob.png", 1);

    // Precompute cached peer state once (post-AKE) for RUA-only flows.
    {
        auto pair = make_call_pair(fx->alice_cfg, fx->bob_cfg);
        set_fixed_ts(*pair.alice, *pair.bob, fx->ts);
        run_ake_handshake(*pair.alice, *pair.bob);
        fx->alice_peer = pair.alice->export_peer_session();
        fx->bob_peer = pair.bob->export_peer_session();
    }

    return fx;
}

static std::vector<BenchCase> make_protocol_benchmarks_with_fixtures(const std::shared_ptr<Fixtures>& fx) {

    std::vector<BenchCase> cases;

    // Enrollment
    cases.push_back(BenchCase{
        "Enrollment client: create_request (tickets=1)",
        120,
        {},
        [fx]() {
            (void)create_enrollment_request(
                "+1234567890",
                "Alice",
                "https://example.com/logo.png",
                1
            );
        },
    });

    cases.push_back(BenchCase{
        "Enrollment server: process_request (tickets=1)",
        80,
        {},
        [fx]() {
            (void)process_enrollment(fx->server, fx->enrollment_request);
        },
    });

    cases.push_back(BenchCase{
        "Enrollment client: finalize (tickets=1)",
        900,
        {},
        [fx]() {
            (void)finalize_enrollment(
                fx->enrollment_keys,
                fx->enrollment_response,
                "+1234567890",
                "Alice",
                "https://example.com/logo.png"
            );
        },
    });

    // Delegation (owner-side signature)
    cases.push_back(BenchCase{
        "Delegation owner: sign (rules=0)",
        200,
        {},
        [fx]() {
            (void)create_delegation(
                fx->server.ci_private_key,
                fx->enrollment_keys.subscriber_public_key,
                30,
                fx->enrollment_request.telephone_number,
                {}
            );
        },
    });

    // Access token minting (OPRF) operations
    {
        cases.push_back(BenchCase{
            "AccessToken client: blind (count=1)",
            120,
            {},
            []() {
                (void)accesstoken::blind_access_token();
            },
        });
    }
    {
        struct State {
            Bytes at_sk;
            std::vector<Bytes> blinded;
            std::size_t idx = 0;
        };
        auto st = std::make_shared<State>();
        cases.push_back(BenchCase{
            "AccessToken server: evaluate (count=1)",
            2000,
            [fx, st](int n) {
                st->at_sk = fx->server.at_private_key;
                st->blinded.clear();
                st->blinded.reserve(static_cast<std::size_t>(n));
                auto toks = accesstoken::blind_access_tokens(static_cast<std::size_t>(n));
                for (auto& t : toks) {
                    st->blinded.push_back(std::move(t.blinded));
                }
                st->idx = 0;
            },
            [st]() {
                const Bytes& b = st->blinded[st->idx++];
                (void)accesstoken::evaluate_blinded_access_token(st->at_sk, b);
            },
        });
    }
    {
        struct State {
            Bytes at_sk;
            Bytes vk;
            std::vector<accesstoken::BlindedAccessToken> blinded;
            std::vector<Bytes> evaluated;
            std::size_t idx = 0;
        };
        auto st = std::make_shared<State>();
        cases.push_back(BenchCase{
            "AccessToken client: finalize (count=1)",
            600,
            [fx, st](int n) {
                st->at_sk = fx->server.at_private_key;
                st->vk = fx->server.at_public_key;
                st->blinded = accesstoken::blind_access_tokens(static_cast<std::size_t>(n));
                st->evaluated.clear();
                st->evaluated.reserve(st->blinded.size());
                for (const auto& bt : st->blinded) {
                    st->evaluated.push_back(accesstoken::evaluate_blinded_access_token(st->at_sk, bt.blinded));
                }
                st->idx = 0;
            },
            [st]() {
                const auto& bt = st->blinded[st->idx];
                const auto& ev = st->evaluated[st->idx];
                st->idx++;
                (void)accesstoken::finalize_access_token(bt, ev);
            },
        });
    }
    {
        struct State {
            Bytes vk;
            std::vector<accesstoken::AccessToken> tokens;
            std::size_t idx = 0;
        };
        auto st = std::make_shared<State>();
        cases.push_back(BenchCase{
            "AccessToken verifier: verify (count=1)",
            120,
            [fx, st](int n) {
                st->vk = fx->server.at_public_key;
                auto blinded = accesstoken::blind_access_tokens(static_cast<std::size_t>(n));
                st->tokens.clear();
                st->tokens.reserve(blinded.size());
                for (const auto& bt : blinded) {
                    Bytes ev = accesstoken::evaluate_blinded_access_token(fx->server.at_private_key, bt.blinded);
                    st->tokens.push_back(accesstoken::finalize_access_token(bt, ev));
                }
                st->idx = 0;
            },
            [st]() {
                const auto& t = st->tokens[st->idx++];
                (void)accesstoken::verify_access_token(t, st->vk);
            },
        });
    }

    // AKE operations
    {
        struct State {
            std::vector<AkeRequestCtx> ctxs;
            std::size_t idx = 0;
        };
        auto st = std::make_shared<State>();
        cases.push_back(BenchCase{
            "AKE caller: ake_request",
            50,
            [fx, st](int n) {
                st->ctxs = prepare_ake_request_ctxs(*fx, n);
                st->idx = 0;
            },
            [st]() {
                auto& c = st->ctxs[st->idx++];
                (void)ake_request(*c.caller);
            },
        });
    }
    {
        struct State {
            std::vector<AkeResponseCtx> ctxs;
            std::size_t idx = 0;
        };
        auto st = std::make_shared<State>();
        cases.push_back(BenchCase{
            "AKE recipient: ake_response",
            50,
            [fx, st](int n) {
                st->ctxs = prepare_ake_response_ctxs(*fx, n);
                st->idx = 0;
            },
            [st]() {
                auto& c = st->ctxs[st->idx++];
                (void)ake_response(*c.recipient, c.request_msg);
            },
        });
    }
    {
        struct State {
            std::vector<AkeCompleteCtx> ctxs;
            std::size_t idx = 0;
        };
        auto st = std::make_shared<State>();
        cases.push_back(BenchCase{
            "AKE caller: ake_complete",
            40,
            [fx, st](int n) {
                st->ctxs = prepare_ake_complete_ctxs(*fx, n);
                st->idx = 0;
            },
            [st]() {
                auto& c = st->ctxs[st->idx++];
                (void)ake_complete(*c.caller, c.response_msg);
            },
        });
    }
    {
        struct State {
            std::vector<AkeFinalizeCtx> ctxs;
            std::size_t idx = 0;
        };
        auto st = std::make_shared<State>();
        cases.push_back(BenchCase{
            "AKE recipient: ake_finalize",
            40,
            [fx, st](int n) {
                st->ctxs = prepare_ake_finalize_ctxs(*fx, n);
                st->idx = 0;
            },
            [st]() {
                auto& c = st->ctxs[st->idx++];
                ake_finalize(*c.recipient, c.complete_msg);
            },
        });
    }

    // RUA operations (subsequent-call flow via cached peer state)
    {
        struct State {
            std::vector<RuaRequestCtx> ctxs;
            std::size_t idx = 0;
        };
        auto st = std::make_shared<State>();
        cases.push_back(BenchCase{
            "RUA caller: rua_request (cached peer state)",
            120,
            [fx, st](int n) {
                st->ctxs = prepare_rua_request_ctxs(*fx, n);
                st->idx = 0;
            },
            [st]() {
                auto& c = st->ctxs[st->idx++];
                (void)rua_request(*c.caller);
            },
        });
    }
    {
        struct State {
            std::vector<RuaResponseCtx> ctxs;
            std::size_t idx = 0;
        };
        auto st = std::make_shared<State>();
        cases.push_back(BenchCase{
            "RUA recipient: rua_response (cached peer state)",
            40,
            [fx, st](int n) {
                st->ctxs = prepare_rua_response_ctxs(*fx, n);
                st->idx = 0;
            },
            [st]() {
                auto& c = st->ctxs[st->idx++];
                (void)rua_response(*c.recipient, c.request_msg);
            },
        });
    }
    {
        struct State {
            std::vector<RuaFinalizeCtx> ctxs;
            std::size_t idx = 0;
        };
        auto st = std::make_shared<State>();
        cases.push_back(BenchCase{
            "RUA caller: rua_finalize (cached peer state)",
            40,
            [fx, st](int n) {
                st->ctxs = prepare_rua_finalize_ctxs(*fx, n);
                st->idx = 0;
            },
            [st]() {
                auto& c = st->ctxs[st->idx++];
                rua_finalize(*c.caller, c.response_msg);
            },
        });
    }

    // ODA operations (after RUA)
    {
        struct State {
            std::unique_ptr<CallState> verifier;
            std::vector<std::string> attrs;
        };
        auto st = std::make_shared<State>();
        cases.push_back(BenchCase{
            "ODA verifier: oda_request (after RUA)",
            6000,
            [fx, st](int n) {
                auto pair = make_call_pair(fx->alice_cfg, fx->bob_cfg);
                set_fixed_ts(*pair.alice, *pair.bob, fx->ts);

                pair.alice->apply_peer_session(fx->alice_peer);
                pair.bob->apply_peer_session(fx->bob_peer);
                run_rua_handshake(*pair.alice, *pair.bob);

                st->verifier = std::move(pair.alice);
                st->attrs = {"name"};
            },
            [st]() {
                (void)oda_request(*st->verifier, st->attrs);
            },
        });
    }
    {
        struct State {
            std::unique_ptr<CallState> prover;
            std::unique_ptr<CallState> verifier;
            std::vector<ProtocolMessage> requests;
            std::size_t idx = 0;
            std::vector<std::string> attrs;
        };
        auto st = std::make_shared<State>();
        cases.push_back(BenchCase{
            "ODA prover: oda_response",
            170,
            [fx, st](int n) {
                auto pair = make_call_pair(fx->alice_cfg, fx->bob_cfg);
                set_fixed_ts(*pair.alice, *pair.bob, fx->ts);

                pair.alice->apply_peer_session(fx->alice_peer);
                pair.bob->apply_peer_session(fx->bob_peer);
                run_rua_handshake(*pair.alice, *pair.bob);

                st->verifier = std::move(pair.alice);
                st->prover = std::move(pair.bob);
                st->attrs = {"name"};
                st->requests.clear();
                st->requests.reserve(static_cast<std::size_t>(n));
                st->idx = 0;

                for (int i = 0; i < n; ++i) {
                    Bytes req_bytes = oda_request(*st->verifier, st->attrs);
                    st->requests.push_back(ProtocolMessage::deserialize(req_bytes));
                }
            },
            [st]() {
                auto& msg = st->requests[st->idx++];
                (void)oda_response(*st->prover, msg);
            },
        });
    }
    {
        struct State {
            std::unique_ptr<CallState> verifier;
            std::unique_ptr<CallState> prover;
            std::vector<ProtocolMessage> responses;
            std::vector<OdaMessage> pending;
            std::size_t idx = 0;
            std::vector<std::string> attrs;
        };
        auto st = std::make_shared<State>();
        cases.push_back(BenchCase{
            "ODA verifier: oda_verify",
            75,
            [fx, st](int n) {
                auto pair = make_call_pair(fx->alice_cfg, fx->bob_cfg);
                set_fixed_ts(*pair.alice, *pair.bob, fx->ts);

                pair.alice->apply_peer_session(fx->alice_peer);
                pair.bob->apply_peer_session(fx->bob_peer);
                run_rua_handshake(*pair.alice, *pair.bob);

                st->verifier = std::move(pair.alice);
                st->prover = std::move(pair.bob);
                st->attrs = {"name"};
                st->responses.clear();
                st->pending.clear();
                st->responses.reserve(static_cast<std::size_t>(n));
                st->pending.reserve(static_cast<std::size_t>(n));
                st->idx = 0;

                st->verifier->oda_verifications.clear();
                st->verifier->oda_verifications.reserve(static_cast<std::size_t>(n));

                for (int i = 0; i < n; ++i) {
                    Bytes req_bytes = oda_request(*st->verifier, st->attrs);
                    ProtocolMessage req_msg = ProtocolMessage::deserialize(req_bytes);

                    // Snapshot the pending request that oda_verify expects later.
                    if (!st->verifier->pending_oda_request.has_value()) {
                        throw std::runtime_error("benchmark: missing pending ODA request");
                    }
                    st->pending.push_back(st->verifier->pending_oda_request.value());

                    Bytes resp_bytes = oda_response(*st->prover, req_msg);
                    st->responses.push_back(ProtocolMessage::deserialize(resp_bytes));
                }
            },
            [st]() {
                const std::size_t i = st->idx++;
                st->verifier->pending_oda_request = st->pending[i];
                (void)oda_verify(*st->verifier, st->responses[i]);
            },
        });
    }

    return cases;
}

std::vector<BenchCase> make_protocol_benchmarks() {
    return make_protocol_benchmarks_with_fixtures(build_fixtures());
}

static std::vector<RawBench> run_cases_raw(const std::vector<BenchCase>& cases, const BenchOptions& opts) {
    const int samples = std::max(1, opts.samples);

    std::vector<RawBench> out;
    out.reserve(cases.size());

    for (const auto& c : cases) {
        const int iters = (opts.iters_override > 0) ? opts.iters_override : c.iters;

        std::vector<double> per_iter_ms;
        per_iter_ms.reserve(static_cast<std::size_t>(samples));

        for (int s = 0; s < samples; ++s) {
            if (c.setup) {
                c.setup(iters);
            }

            auto start = std::chrono::high_resolution_clock::now();
            for (int i = 0; i < iters; ++i) {
                c.run();
            }
            auto end = std::chrono::high_resolution_clock::now();
            std::chrono::duration<double, std::milli> elapsed = end - start;
            per_iter_ms.push_back(elapsed.count() / static_cast<double>(iters));
        }

        RawBench rb;
        rb.summary.name = c.name;
        rb.summary.iters = iters;
        rb.summary.samples = samples;
        rb.samples_ms = std::move(per_iter_ms);
        rb.summary.stats = compute_stats_ms(rb.samples_ms);
        out.push_back(std::move(rb));
    }

    return out;
}

std::vector<BenchResult> run_protocol_benchmarks(const BenchOptions& opts) {
    auto raw = run_cases_raw(make_protocol_benchmarks(), opts);
    std::vector<BenchResult> results;
    results.reserve(raw.size());
    for (auto& r : raw) {
        results.push_back(std::move(r.summary));
    }
    return results;
}

std::vector<RoleBenchResult> run_protocol_role_benchmarks(const BenchOptions& opts) {
    auto fx = build_fixtures();
    WireBytes wb = compute_wire_bytes(*fx);

    const auto cases = make_protocol_benchmarks_with_fixtures(fx);
    const auto raw = run_cases_raw(cases, opts);

    // Map per-op name -> sample vector.
    std::unordered_map<std::string, std::vector<double>> by_name;
    by_name.reserve(raw.size());
    for (const auto& r : raw) {
        by_name.emplace(r.summary.name, r.samples_ms);
    }

    const int samples = std::max(1, opts.samples);
    auto sum_samples = [samples, &by_name](const std::vector<std::string>& names) {
        std::vector<double> out(static_cast<std::size_t>(samples), 0.0);
        for (const auto& n : names) {
            auto it = by_name.find(n);
            if (it == by_name.end()) {
                throw std::runtime_error("role benchmarks: missing component case: " + n);
            }
            const auto& v = it->second;
            if (static_cast<int>(v.size()) != samples) {
                throw std::runtime_error("role benchmarks: sample count mismatch for case: " + n);
            }
            for (int i = 0; i < samples; ++i) {
                out[static_cast<std::size_t>(i)] += v[static_cast<std::size_t>(i)];
            }
        }
        return out;
    };

    auto join_components = [](const std::vector<std::string>& names) {
        std::ostringstream oss;
        for (std::size_t i = 0; i < names.size(); ++i) {
            if (i) oss << "+";
            oss << names[i];
        }
        return oss.str();
    };

    // Define role-level aggregations.
    struct RoleDef {
        std::string name;
        std::vector<std::string> components;
        std::size_t bytes_sent = 0;
        std::size_t bytes_received = 0;
    };

    const std::vector<RoleDef> roles = {
        {
            "AKE caller (request+complete)",
            {"AKE caller: ake_request", "AKE caller: ake_complete"},
            wb.ake_req + wb.ake_complete,
            wb.ake_resp,
        },
        {
            "AKE recipient (response+finalize)",
            {"AKE recipient: ake_response", "AKE recipient: ake_finalize"},
            wb.ake_resp,
            wb.ake_req + wb.ake_complete,
        },
        {
            "RUA caller (request+finalize, cached peer)",
            {"RUA caller: rua_request (cached peer state)", "RUA caller: rua_finalize (cached peer state)"},
            wb.rua_req,
            wb.rua_resp,
        },
        {
            "RUA recipient (response, cached peer)",
            {"RUA recipient: rua_response (cached peer state)"},
            wb.rua_resp,
            wb.rua_req,
        },
        {
            "ODA verifier (request+verify)",
            {"ODA verifier: oda_request (after RUA)", "ODA verifier: oda_verify"},
            wb.oda_req,
            wb.oda_resp,
        },
        {
            "ODA prover (response)",
            {"ODA prover: oda_response"},
            wb.oda_resp,
            wb.oda_req,
        },
        {
            "AccessToken client (blind+finalize)",
            {"AccessToken client: blind (count=1)", "AccessToken client: finalize (count=1)"},
            wb.token_blinded,
            wb.token_evaluated,
        },
        {
            "AccessToken server (evaluate)",
            {"AccessToken server: evaluate (count=1)"},
            wb.token_evaluated,
            wb.token_blinded,
        },
        {
            "AccessToken verifier (verify)",
            {"AccessToken verifier: verify (count=1)"},
            0,
            0,
        },
        {
            "Delegation owner (sign)",
            {"Delegation owner: sign (rules=0)"},
            wb.delegation_cert,
            0,
        },
    };

    std::vector<RoleBenchResult> out;
    out.reserve(roles.size());
    for (const auto& role : roles) {
        std::vector<double> combined = sum_samples(role.components);

        RoleBenchResult r;
        r.name = role.name;
        r.samples = samples;
        r.bytes_sent = role.bytes_sent;
        r.bytes_received = role.bytes_received;
        r.stats = compute_stats_ms(combined);
        r.components = join_components(role.components);
        out.push_back(std::move(r));
    }
    return out;
}

std::string protocol_benchmarks_to_csv(const std::vector<BenchResult>& results) {
    std::ostringstream out;
    out << "name,iters,samples,min_ms,max_ms,mean_ms,median_ms,stddev_ms,mad_ms\n";
    out << std::fixed << std::setprecision(9);
    for (const auto& r : results) {
        out << csv_escape(r.name) << ','
            << r.iters << ','
            << r.samples << ','
            << r.stats.min_ms << ','
            << r.stats.max_ms << ','
            << r.stats.mean_ms << ','
            << r.stats.median_ms << ','
            << r.stats.stddev_ms << ','
            << r.stats.mad_ms
            << '\n';
    }
    return out.str();
}

std::string protocol_role_benchmarks_to_csv(const std::vector<RoleBenchResult>& results) {
    std::ostringstream out;
    out << "name,samples,bytes_sent,bytes_received,min_ms,max_ms,mean_ms,median_ms,stddev_ms,mad_ms,components\n";
    out << std::fixed << std::setprecision(9);
    for (const auto& r : results) {
        out << csv_escape(r.name) << ','
            << r.samples << ','
            << r.bytes_sent << ','
            << r.bytes_received << ','
            << r.stats.min_ms << ','
            << r.stats.max_ms << ','
            << r.stats.mean_ms << ','
            << r.stats.median_ms << ','
            << r.stats.stddev_ms << ','
            << r.stats.mad_ms << ','
            << csv_escape(r.components)
            << '\n';
    }
    return out.str();
}

std::string run_protocol_benchmarks_csv(const BenchOptions& opts) {
    return protocol_benchmarks_to_csv(run_protocol_benchmarks(opts));
}

std::string run_protocol_role_benchmarks_csv(const BenchOptions& opts) {
    return protocol_role_benchmarks_to_csv(run_protocol_role_benchmarks(opts));
}

} // namespace bench
} // namespace protocol
