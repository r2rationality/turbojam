/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/test.hpp>
#include <turbo/common/timer.hpp>
#include "chain.hpp"
#include "machine.hpp"
#include "traces.hpp"

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
            const auto &post_state = *chain.state().triedb->trie().get();
            const auto state_matches = post_state.root() == tc.post.state_root;
            expect(state_matches) << path;
        } catch (const std::exception &ex) {
            expect(false) << path << ex.what();
        }
    }
}

suite turbo_jam_traces_suite = [] {
    "turbo::jam::traces"_test = [] {
        /*const auto test_dir = file::install_path("test/jam-test-vectors/traces/reports-l0");
        const auto genesis = codec::json::load_obj<test_genesis_t<config_tiny>>(fmt::format("{}/genesis.json", test_dir));
        test_file(fmt::format("{}/00000005", test_dir), genesis.state.keyvals);*/
        for (const auto testset: { "fallback", "safrole", "reports-l0", "reports-l1" }) {
            const auto test_dir = file::install_path(fmt::format("test/jam-test-vectors/traces/{}", testset));
            auto test_files_v = file::files_with_ext_path(test_dir, ".bin") | std::views::filter([](const auto &p) { return p.filename().stem() != "genesis"; });
            const auto test_files = std::vector<std::filesystem::path>(test_files_v.begin(), test_files_v.end());
            const timer t { fmt::format("Testing {} traces in {}", test_files.size(), testset), logger::level::info };
            const auto genesis = codec::json::load_obj<test_genesis_t<config_tiny>>(fmt::format("{}/genesis.json", test_dir));
            expect(genesis.state.keyvals.root() == genesis.state.state_root);
            for (const auto &path: test_files) {
                const auto path_str = path.string();
                test_file(path_str.substr(0, path_str.size() - 4), genesis.state.keyvals);
            }
        }
    };
};
