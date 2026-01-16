#ifndef DIA_PROTOCOL_BENCHMARK_HPP
#define DIA_PROTOCOL_BENCHMARK_HPP

#include <functional>
#include <string>
#include <vector>

namespace protocol {
namespace bench {

struct BenchCase {
    std::string name;
    int iters;
    // Optional: called once per sample (not timed) to prepare per-iteration state.
    // Receives the iteration count that will be executed for the sample.
    std::function<void(int)> setup;
    std::function<void()> run;
};

struct BenchOptions {
    // Number of timing samples per benchmark case.
    int samples = 30;
    // Optional override for per-case iteration count.
    // If <= 0, uses each case's default iters.
    int iters_override = 0;
};

struct Stats {
    double min_ms = 0.0;
    double max_ms = 0.0;
    double mean_ms = 0.0;
    double median_ms = 0.0;
    double stddev_ms = 0.0;
    double mad_ms = 0.0;
};

struct BenchResult {
    std::string name;
    int iters = 0;
    int samples = 0;
    Stats stats;
};

struct RoleBenchResult {
    std::string name;
    int samples = 0;
    std::size_t bytes_sent = 0;
    std::size_t bytes_received = 0;
    Stats stats;
    // Human-readable list of included per-op components.
    std::string components;
};

// Returns all protocol-operation benchmark cases.
std::vector<BenchCase> make_protocol_benchmarks();

// Runs all protocol benchmarks and returns results with summary statistics.
std::vector<BenchResult> run_protocol_benchmarks(const BenchOptions& opts = {});

// Runs role-aggregated protocol benchmarks (e.g. AKE caller = request+complete).
std::vector<RoleBenchResult> run_protocol_role_benchmarks(const BenchOptions& opts = {});

// Format results as CSV string.
std::string protocol_benchmarks_to_csv(const std::vector<BenchResult>& results);

// Format role-aggregated results as CSV string.
std::string protocol_role_benchmarks_to_csv(const std::vector<RoleBenchResult>& results);

// Convenience: run + CSV.
std::string run_protocol_benchmarks_csv(const BenchOptions& opts = {});

// Convenience: run role benchmarks + CSV.
std::string run_protocol_role_benchmarks_csv(const BenchOptions& opts = {});

} // namespace bench
} // namespace protocol

#endif // DIA_PROTOCOL_BENCHMARK_HPP
