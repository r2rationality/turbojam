/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025-2026 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include "test-vectors.hpp"
#include "fuzzer-runner.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jam;
    using namespace turbo::jam::fuzzer_runner;

    perf_stats_t test_sample(const std::string &sample_dir) {
        const file::tmp_directory tmp_dir{"turbo-jam-fuzzer"};
        impl_vs_trace_client_t<config_tiny, local_processor_t> client{std::make_unique<local_processor_t<config_tiny>>("dev", tmp_dir.path())};
        expect(client.test_sample(sample_dir));
        return client.stats();
    }
}

suite turbo_jam_traces_suite = [] {
    "turbo::jam::traces"_test = [] {
        static const auto test_prefix = test_vector_dir("traces/");
        static std::optional<std::filesystem::path> override_test{};
#if !defined(NDEBUG)
        //override_test.emplace(test_prefix + "fuzzy_light/00000002");
#endif
        if (!override_test) {
            std::map<std::string, perf_stats_t> stats{};
            std::set<std::filesystem::path> test_sets{};
            for (const auto &e: std::filesystem::directory_iterator{test_prefix}) {
                if (e.is_directory() && !e.path().filename().string().starts_with("."))
                    test_sets.emplace(e.path());
            }
            for (const auto &test_set: test_sets) {
                stats[test_set.filename().string()] = test_sample(test_set.string());
            }
            for (const auto &[group, st]: stats) {
                logger::info("{}: mean: {:.3f}s sd: {:.3f}s min: {:.3f}s max: {:.3f}s over {} tests",
                    group, st.mean, std::sqrt(st.variance), st.min, st.max, st.count);
            }
        } else {
            test_sample(override_test->string());
        }
    };
};
