#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/timer.hpp>
#include <turbo/common/test.hpp>
#include "types/header.hpp"
#include "types/state-dict.hpp"
#include "chain.hpp"

namespace turbo::jam::traces {
    struct raw_state_t {
        state_root_t state_root;
        state_snapshot_t keyvals;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("state_root"sv, state_root);
            archive.process("keyvals"sv, keyvals);
        }

        bool operator==(const raw_state_t &o) const
        {
            if (state_root != o.state_root)
                return false;
            if (keyvals != o.keyvals)
                return false;
            return true;
        }
    };

    struct test_genesis_state_t {
        state_root_t state_root;
        state_snapshot_t keyvals;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("state_root"sv, state_root);
            archive.process("keyvals"sv, keyvals);
        }
    };

    template<typename CFG>
    struct test_genesis_t {
        header_t<CFG> header;
        test_genesis_state_t state;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("header"sv, header);
            archive.process("state"sv, state);
        }
    };

    struct test_case_t {
        raw_state_t pre;
        block_t<config_tiny> block;
        raw_state_t post;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("pre_state"sv, pre);
            archive.process("block"sv, block);
            archive.process("post_state"sv, post);
        }

        bool operator==(const test_case_t &o) const
        {
            if (pre != o.pre)
                return false;
            if (block != o.block)
                return false;
            if (post != o.post)
                return false;
            return true;
        }
    };

    struct test_res_t {
        std::string path;
        double duration;
        bool success;

        bool operator<(const test_res_t &o) const {
            return duration > o.duration;
        }
    };

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
}
