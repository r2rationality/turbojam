/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/timer.hpp>
#include "chain.hpp"
#include "machine.hpp"
#include "traces.hpp"
#include "test-vectors.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jam;
    using namespace turbo::jam::traces;

    void test_file(const std::string &path, const state_snapshot_t &genesis_state)
    {
        try {
            const auto tc = jam::load_obj<test_case_t>(path + ".bin");
            {
                const auto j_tc = codec::json::load_obj<test_case_t>(path + ".json");
                expect(tc == j_tc) << "the json test case does not match the binary one" << path;
            }
            const file::tmp_directory data_dir { "test-jam-traces" };
            chain_t<config_tiny> chain {
                "dev",
                data_dir.path(),
                genesis_state,
                tc.pre.keyvals
            };
            chain.apply(tc.block);
            const auto &post_state = chain.state().snapshot();
            const auto state_matches = post_state.root() == tc.post.state_root;
            expect(state_matches) << path;
            if (!state_matches) {
                const auto act = chain.state().snapshot();
                const auto diff = act.diff(tc.post.keyvals);
                logger::info("{} diff:\n{}", path, diff);
                const auto exp_val = tc.post.keyvals.at(state_dict_t::make_key(0x0DU));
                const auto act_val = act.at(state_dict_t::make_key(0x0DU));
                const auto exp_stat = jam::from_bytes<statistics_t<config_tiny>>(exp_val);
                const auto act_stat = jam::from_bytes<statistics_t<config_tiny>>(act_val);
                logger::info("stat.current matches: {}", static_cast<bool>(exp_stat.current == act_stat.current));
                logger::info("stat.last matches: {}", static_cast<bool>(exp_stat.last == act_stat.last));
                logger::info("stat.cores matches: {}", static_cast<bool>(exp_stat.cores == act_stat.cores));
                logger::info("stat.services matches: {}", static_cast<bool>(exp_stat.services == act_stat.services));
            }
        } catch (const std::exception &ex) {
            expect(false) << path << ex.what();
        }
    }
}

suite turbo_jam_traces_suite = [] {
    "turbo::jam::traces"_test = [] {
        static std::optional<std::filesystem::path> override_test{};
        //override_test.emplace(test_vector_dir("traces/preimages/00000019"));
        if (!override_test) {
            std::set<std::filesystem::path> test_sets{};
            for (const auto &e: std::filesystem::directory_iterator{test_vector_dir("traces")}) {
                if (e.is_directory() && !e.path().filename().string().starts_with("."))
                    test_sets.emplace(e.path());
            }
            for (const auto &test_set: test_sets) {
                const auto test_dir = test_set.string();
                auto test_files_v = file::files_with_ext_path(test_dir, ".bin") | std::views::filter([](const auto &p) { return p.filename().stem() != "genesis"; });
                const auto test_files = std::vector<std::filesystem::path>(test_files_v.begin(), test_files_v.end());
                const timer t{fmt::format("Testing {} traces in {}", test_files.size(), test_set.filename().string()), logger::level::info};
                const auto genesis = codec::json::load_obj<test_genesis_t<config_tiny>>(fmt::format("{}/genesis.json", test_dir));
                expect(genesis.state.keyvals.root() == genesis.state.state_root);
                for (const auto &path: test_files) {
                    const auto path_str = path.string();
                    test_file(path_str.substr(0, path_str.size() - 4), genesis.state.keyvals);
                }
            }
        } else {
            const auto genesis = codec::json::load_obj<test_genesis_t<config_tiny>>((override_test->parent_path() / "genesis.json").string());
            test_file(override_test->string(), genesis.state.keyvals);
        }
    };
};
