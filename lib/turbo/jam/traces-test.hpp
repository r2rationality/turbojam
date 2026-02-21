#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/test.hpp>
#include "traces.hpp"

namespace turbo::jam::traces {
    inline test_res_t test_file(const std::string &path, const state_snapshot_t &genesis_state)
    {
        static constexpr bool compare_with_json = false;
        timer t{path};
        bool success = false;
        try {
            const auto tc = jam::load_obj<test_case_t>(path + ".bin");
            if (compare_with_json) {
                const auto j_tc = codec::json::load_obj<test_case_t>(path + ".json");
                expect(tc == j_tc) << "the json test case does not match the binary one" << path;
            }
            const file::tmp_directory data_dir{"test-jam-traces"};
            chain_t<config_tiny> chain {
                "dev",
                data_dir.path(),
                genesis_state,
                tc.pre.keyvals
            };
            try {
                chain.apply(tc.block);
            } catch (const std::exception &ex) {
                logger::debug("apply block failed: {}", ex.what());
            }
            const auto &post_state = chain.state().snapshot();
            const auto state_matches = post_state.root() == tc.post.state_root;
            expect(state_matches) << path;
            if (!state_matches) {
                const auto act = chain.state().snapshot();
                logger::trace("{} diff:\n{}", path, act.diff(tc.post.keyvals));
                const auto exp_val = tc.post.keyvals.at(state_dict_t::make_key(0x0DU));
                const auto act_val = act.at(state_dict_t::make_key(0x0DU));
                const auto exp_stat = jam::from_bytes<statistics_t<config_tiny>>(exp_val);
                const auto act_stat = jam::from_bytes<statistics_t<config_tiny>>(act_val);
            }
            success = true;
        } catch (const std::exception &ex) {
            expect(false) << path << ex.what();
        }
        return {path, t.stop(false), success};
    }

    inline void test_sequence(const std::span<const std::string> &paths, const state_snapshot_t &genesis_state)
    {
        if (paths.empty()) [[unlikely]] {
            expect(false);
            return;
        }
        try {
            std::vector<test_case_t> test_cases{};
            test_cases.reserve(paths.size());
            for (const auto &p: paths)
                test_cases.emplace_back(jam::load_obj<test_case_t>(p));
            const file::tmp_directory data_dir{"test-jam-traces"};
            chain_t<config_tiny> chain{
                "dev",
                data_dir.path(),
                genesis_state,
                test_cases[0].pre.keyvals
            };
            for (size_t i = 0; i < test_cases.size(); ++i) {
                const auto &path = paths[i];
                const auto &tc = test_cases[i];
                try {
                    chain.apply(tc.block);
                    const auto &post_state = chain.state().snapshot();
                    const auto state_matches = post_state.root() == tc.post.state_root;
                    expect(state_matches) << path;
                    if (!state_matches) {
                        const auto act = chain.state().snapshot();
                        logger::trace("{} diff:\n{}", path, act.diff(tc.post.keyvals));
                    }
                } catch (const std::exception &ex) {
                    expect(false) << path << ex.what();
                }
            }
        } catch (const std::exception &ex) {
            expect(false) << paths[0] << ex.what();
        }
    }
}
