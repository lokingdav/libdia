#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <algorithm>
#include <chrono>

#include "protocol/benchmark.hpp"

static int parse_int_arg(int argc, char** argv, const std::string& flag, int default_value) {
    for (int i = 1; i + 1 < argc; ++i) {
        if (std::string(argv[i]) == flag) {
            try {
                return std::stoi(argv[i + 1]);
            } catch (...) {
                return default_value;
            }
        }
    }
    return default_value;
}

static bool has_flag(int argc, char** argv, const std::string& flag) {
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == flag) {
            return true;
        }
    }
    return false;
}

static void print_usage(const char* argv0) {
    std::cout << "Usage: " << argv0
              << " [--samples N] [--iters N] [--csv] [--csv-only]" << std::endl;
}

int main(int argc, char** argv) {
    const auto overall_start = std::chrono::high_resolution_clock::now();

    if (has_flag(argc, argv, "--help") || has_flag(argc, argv, "-h")) {
        print_usage(argv[0]);
        return 0;
    }

    const int samples = std::max(1, parse_int_arg(argc, argv, "--samples", 30));
    const int iters_override = parse_int_arg(argc, argv, "--iters", 0);
    const bool csv = has_flag(argc, argv, "--csv");
    const bool csv_only = has_flag(argc, argv, "--csv-only");

    if (!csv_only) {
        std::cout << "\n--- Protocol Operations ---" << std::endl;
    }

    protocol::bench::BenchOptions opts;
    opts.samples = samples;
    opts.iters_override = iters_override;

    auto results = protocol::bench::run_protocol_benchmarks(opts);
    if (!csv_only) {
        for (const auto& r : results) {
            std::cout << std::left << std::setw(44) << r.name
                      << " min=" << std::fixed << std::setprecision(6) << r.stats.min_ms
                      << " max=" << r.stats.max_ms
                      << " mean=" << r.stats.mean_ms
                      << " median=" << r.stats.median_ms
                      << " (ms/op)" << std::endl;
        }
    }

    if (csv || csv_only) {
        if (!csv_only) {
            std::cout << "\n";
        }
        std::cout << protocol::bench::protocol_benchmarks_to_csv(results);
    }

    const auto overall_end = std::chrono::high_resolution_clock::now();
    const std::chrono::duration<double> overall_elapsed = overall_end - overall_start;
    const std::chrono::duration<double, std::milli> overall_elapsed_ms = overall_end - overall_start;

    if (csv_only) {
        // Keep stdout parseable as pure CSV.
        std::cerr << "Total benchmark time: " << std::fixed << std::setprecision(3)
                  << overall_elapsed.count() << " s (" << overall_elapsed_ms.count() << " ms)" << std::endl;
    } else {
        std::cout << "\nTotal benchmark time: " << std::fixed << std::setprecision(3)
                  << overall_elapsed.count() << " s (" << overall_elapsed_ms.count() << " ms)" << std::endl;
    }

    return 0;
}
