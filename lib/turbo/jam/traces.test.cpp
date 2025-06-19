/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/test.hpp>
#include "chain.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jam;

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
            expect(chain.state().state_dict->root() == tc.post.state_root) << path;
            //expect(*chain.state().state_dict == tc.post.keyvals) << path;
            /*const auto k = merkle::trie::key_t::from_hex<merkle::trie::key_t>("0D000000000000000000000000000000000000000000000000000000000000");
            using ET = std::decay_t<decltype(chain.state().pi.get())>;
            logger::info("L: {} {}",
                chain.state().state_dict->get(k),
                from_bytes<ET>(encode(chain.state().pi.get())));
            logger::info("R: {} {}",
                chain.state().state_dict->make_value(tc.post.keyvals.at(k)),
                from_bytes<ET>(tc.post.keyvals.at(k)));*/
        } catch (const std::exception &ex) {
            expect(false) << path << ex.what();
        }
    }
}

suite turbo_jam_traces_suite = [] {
    "turbo::jam::traces"_test = [] {
        //test_file(file::install_path("test/jam-test-vectors/traces/fallback/00000001"), genesis.state.keyvals);
        //for (const auto testset: { "fallback", "safrole", "reports-l0", "reports-l1" }) {
        for (const auto testset: { "reports-l0" }) {
            const auto test_dir = file::install_path(fmt::format("test/jam-test-vectors/traces/{}", testset));
            const auto genesis = codec::json::load_obj<test_genesis_t<config_tiny>>(fmt::format("{}/genesis.json", test_dir));
            expect(genesis.state.keyvals.root() == genesis.state.state_root);
            for (const auto &path: file::files_with_ext_path(test_dir, ".bin")) {
                if (path.filename().stem() == "genesis")
                    continue;
                const auto path_str = path.string();
                test_file(path_str.substr(0, path_str.size() - 4), genesis.state.keyvals);
            }
        }
    };
};
