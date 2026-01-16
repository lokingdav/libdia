#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <algorithm>
#include <chrono>

#include <sstream>

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
              << " [--samples N] [--iters N] [--ops] [--ops-only]" << std::endl;
}

static std::string fmt_ms(double v) {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(6) << v;
    return oss.str();
}

static std::string fmt_bytes(std::size_t b) {
    if (b < 1024) {
        return std::to_string(b) + " B";
    }
    if (b < 1024 * 1024) {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(2) << (static_cast<double>(b) / 1024.0) << " KiB";
        return oss.str();
    }
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2)
        << (static_cast<double>(b) / (1024.0 * 1024.0)) << " MiB";
    return oss.str();
}

static void print_ops_table(const std::vector<protocol::bench::BenchResult>& results) {
    std::size_t name_w = 4;
    for (const auto& r : results) {
        name_w = std::max(name_w, r.name.size());
    }
    name_w = std::min<std::size_t>(name_w, 72);

    std::cout << "\n--- Protocol Ops (ms/op) ---\n";
    std::cout << std::left << std::setw(static_cast<int>(name_w)) << "name" << "  "
              << std::right << std::setw(6) << "iters" << "  "
              << std::setw(7) << "samp" << "  "
              << std::setw(10) << "min" << "  "
              << std::setw(10) << "p50" << "  "
              << std::setw(10) << "mean" << "  "
              << std::setw(10) << "max" << "  "
              << std::setw(10) << "stdev" << "  "
              << std::setw(10) << "mad" << "\n";

    for (const auto& r : results) {
        std::string name = r.name;
        if (name.size() > name_w) {
            name = name.substr(0, name_w - 1) + "…";
        }
        std::cout << std::left << std::setw(static_cast<int>(name_w)) << name << "  "
                  << std::right << std::setw(6) << r.iters << "  "
                  << std::setw(7) << r.samples << "  "
                  << std::setw(10) << fmt_ms(r.stats.min_ms) << "  "
                  << std::setw(10) << fmt_ms(r.stats.median_ms) << "  "
                  << std::setw(10) << fmt_ms(r.stats.mean_ms) << "  "
                  << std::setw(10) << fmt_ms(r.stats.max_ms) << "  "
                  << std::setw(10) << fmt_ms(r.stats.stddev_ms) << "  "
                  << std::setw(10) << fmt_ms(r.stats.mad_ms) << "\n";
    }
}

static void print_role_table(const std::vector<protocol::bench::RoleBenchResult>& results) {
    std::size_t name_w = 4;
    for (const auto& r : results) {
        name_w = std::max(name_w, r.name.size());
    }
    name_w = std::min<std::size_t>(name_w, 48);

    std::cout << "\n--- Protocol Roles (ms/op, bytes on wire) ---\n";
    std::cout << std::left << std::setw(static_cast<int>(name_w)) << "role" << "  "
              << std::right << std::setw(7) << "samp" << "  "
              << std::setw(14) << "sent" << "  "
              << std::setw(14) << "recv" << "  "
              << std::setw(10) << "min" << "  "
              << std::setw(10) << "p50" << "  "
              << std::setw(10) << "mean" << "  "
              << std::setw(10) << "max" << "  "
              << std::setw(10) << "stdev" << "  "
              << std::setw(10) << "mad" << "\n";

    for (const auto& r : results) {
        std::string name = r.name;
        if (name.size() > name_w) {
            name = name.substr(0, name_w - 1) + "…";
        }

        std::cout << std::left << std::setw(static_cast<int>(name_w)) << name << "  "
                  << std::right << std::setw(7) << r.samples << "  "
                  << std::setw(14) << fmt_bytes(r.bytes_sent) << "  "
                  << std::setw(14) << fmt_bytes(r.bytes_received) << "  "
                  << std::setw(10) << fmt_ms(r.stats.min_ms) << "  "
                  << std::setw(10) << fmt_ms(r.stats.median_ms) << "  "
                  << std::setw(10) << fmt_ms(r.stats.mean_ms) << "  "
                  << std::setw(10) << fmt_ms(r.stats.max_ms) << "  "
                  << std::setw(10) << fmt_ms(r.stats.stddev_ms) << "  "
                  << std::setw(10) << fmt_ms(r.stats.mad_ms) << "\n";

        if (!r.components.empty()) {
            std::cout << std::string(2, ' ') << "components: " << r.components << "\n";
        }
    }
}

int main(int argc, char** argv) {
    const auto overall_start = std::chrono::high_resolution_clock::now();

    if (has_flag(argc, argv, "--help") || has_flag(argc, argv, "-h")) {
        print_usage(argv[0]);
        return 0;
    }

    const int samples = std::max(1, parse_int_arg(argc, argv, "--samples", 30));
    const int iters_override = parse_int_arg(argc, argv, "--iters", 0);
    const bool ops = has_flag(argc, argv, "--ops");
    const bool ops_only = has_flag(argc, argv, "--ops-only");

    protocol::bench::BenchOptions opts;
    opts.samples = samples;
    opts.iters_override = iters_override;

    if (ops && ops_only) {
        std::cerr << "Error: --ops and --ops-only are mutually exclusive." << std::endl;
        return 2;
    }

    if (ops_only || ops) {
        auto results = protocol::bench::run_protocol_benchmarks(opts);
        print_ops_table(results);
    }

    if (!ops_only) {
        auto role_results = protocol::bench::run_protocol_role_benchmarks(opts);
        print_role_table(role_results);
    }

    const auto overall_end = std::chrono::high_resolution_clock::now();
    const std::chrono::duration<double> overall_elapsed = overall_end - overall_start;
    const std::chrono::duration<double, std::milli> overall_elapsed_ms = overall_end - overall_start;

    std::cout << "\nTotal benchmark time: " << std::fixed << std::setprecision(3)
              << overall_elapsed.count() << " s (" << overall_elapsed_ms.count() << " ms)" << std::endl;

    return 0;
}
