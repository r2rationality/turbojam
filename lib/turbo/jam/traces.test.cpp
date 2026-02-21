/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include "traces-test.hpp"
#include "test-vectors.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jam;
    using namespace turbo::jam::traces;
}

suite turbo_jam_traces_suite = [] {
    "turbo::jam::traces"_test = [] {
        static const auto test_prefix = test_vector_dir("traces/");
        static std::optional<std::filesystem::path> override_test{};
        static const auto genesis = jam::load_obj<test_genesis_t<config_tiny>>(test_prefix + "safrole/genesis.bin");
        // correct rollback of state
        test_sequence(file::files_with_ext(file::install_path("test/jam-conformance/fuzz-reports/0.7.2/traces/1767895984_8315"), ".bin"), genesis.state.keyvals);
        //override_test.emplace(test_prefix + "fuzzy_light/00000002");
        if (!override_test) {
            set_t<test_res_t> perf{};
            std::set<std::filesystem::path> test_sets{};
            for (const auto &e: std::filesystem::directory_iterator{test_prefix}) {
                if (e.is_directory() && !e.path().filename().string().starts_with("."))
                    test_sets.emplace(e.path());
            }
            for (const auto &test_set: test_sets) {
                const auto test_dir = test_set.string();
                auto test_files_v = file::files_with_ext_path(test_dir, ".bin") | std::views::filter([](const auto &p) { return p.filename().stem() != "genesis"; });
                const auto test_files = std::vector<std::filesystem::path>(test_files_v.begin(), test_files_v.end());
                const timer t{fmt::format("Testing {} traces in {}", test_files.size(), test_set.filename().string()), logger::level::info};
                expect(genesis.state.keyvals.root() == genesis.state.state_root);
                for (const auto &path: test_files) {
                    const auto path_str = path.string();
                    perf.emplace(test_file(path_str.substr(0, path_str.size() - 4), genesis.state.keyvals));
                }
            }
            struct perf_stats_t {
                double min = 0.0;
                double max = 0.0;
                double mean = 0.0;
                double variance = 0.0;
                size_t count = 0;
            };
            std::map<std::string, perf_stats_t> stats{};
            for (const auto &r: perf) {
                const auto group = std::filesystem::path{r.path}.parent_path().stem().string();
                auto &st = stats[group];
                st.min = std::min(st.min, r.duration);
                st.max = std::max(st.max, r.duration);
                ++st.count;
                const auto delta = r.duration - st.mean;
                st.mean += delta / st.count;
                const auto delta2 = r.duration - st.mean;
                st.variance += delta * delta2;
                logger::trace("{}: {:.3f} {}", r.path, r.duration, r.success ? "SUCCESS" : "FAILURE");
            }
            for (const auto &[group, st]: stats) {
                logger::info("{}: mean: {:.3f}s sd: {:.3f}s min: {:.3f}s max: {:.3f}s over {} tests",
                    group, st.mean, std::sqrt(st.variance), st.min, st.max, st.count);
            }
        } else {
            test_file(override_test->string(), genesis.state.keyvals);
        }
    };
};
