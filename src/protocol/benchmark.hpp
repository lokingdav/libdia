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

// Returns all protocol-operation benchmark cases.
std::vector<BenchCase> make_protocol_benchmarks();

// Runs all protocol benchmarks and returns results with summary statistics.
std::vector<BenchResult> run_protocol_benchmarks(const BenchOptions& opts = {});

// Format results as CSV string.
std::string protocol_benchmarks_to_csv(const std::vector<BenchResult>& results);

// Convenience: run + CSV.
std::string run_protocol_benchmarks_csv(const BenchOptions& opts = {});

} // namespace bench
} // namespace protocol

#endif // DIA_PROTOCOL_BENCHMARK_HPP
