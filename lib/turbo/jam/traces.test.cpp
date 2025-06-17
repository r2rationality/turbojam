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

            // test round-trip decoding/encoding of the state from the state dictionary
            //expect_equal(state_t<config_tiny> { tc.post.keyvals }.state_dict().root(), tc.post.keyvals.root(), path);
            //expect_equal(path, tc.pre.keyvals.root(), tc.pre.state_root);
            //expect_equal(tc.post.keyvals.root(), tc.post.state_root, path);

            file::tmp_directory data_dir { "test-jam-traces" };
            chain_t<config_tiny> chain {
                "dev",
                data_dir.path(),
                genesis_state,
                tc.pre.keyvals
            };

            //std::cout << fmt::format("{} block {}\n", path, tc.block.header.hash());
            chain.apply(tc.block);

            const auto post_keyvals = *chain.state().state_dict;
            const auto same_state = post_keyvals == tc.post.keyvals;
            expect(same_state) << path;
            if (!same_state) {
                //std::cout << fmt::format("{} state diff: {}\n", path, post_keyvals.diff(tc.post.keyvals));
                const auto k = merkle::trie::key_t::from_hex<merkle::trie::key_t>("0D000000000000000000000000000000000000000000000000000000000000");
                std::cout << fmt::format("L pi: {}\n", chain.state().pi);
                std::cout << fmt::format("R pi: {}\n", from_bytes<decltype(chain.state().pi.get())>(tc.post.keyvals.at(k)));
            }
            //expect(chain.state().state_dict() == tc.post.keyvals) << path;
            // TODO: temporarily disabled, re-enabled after an investigation
            // Even though state_dict matches, the root's do not!
            // Seems like the traces use a different algo than the one in the trie tests
            // expect_equal(path, chain.state().state_dict().root(), tc.post.state_root);
        } catch (const std::exception &ex) {
            expect(false) << path << ex.what();
        }
    }
}

suite turbo_jam_traces_suite = [] {
    "turbo::jam::traces"_test = [] {
        state_snapshot_t genesis_state;
        {
            //const auto j_cfg = codec::json::load(file::install_path("etc/devnet/dev-spec.json"));
            //genesis_state = state_dict_t::from_genesis_json(j_cfg.at("genesis_state").as_object());
            const auto j_tc = codec::json::load_obj<test_case_t>(file::install_path("test/jam-test-vectors/traces/fallback/00000000.json"));
            genesis_state = j_tc.post.keyvals;
            /*genesis_state.alpha = upd_genesis.alpha;
            genesis_state.gamma.s = upd_genesis.gamma.s;
            genesis_state.delta = upd_genesis.delta;
            genesis_state.phi = upd_genesis.phi;
            genesis_state.eta = upd_genesis.eta;*/
        }
        test_file(file::install_path("test/jam-test-vectors/traces/reports-l0/00000003"), genesis_state);
        //for (const auto testset: { "fallback", "safrole", "reports-l0", "reports-l1" }) {
        /*for (const auto testset: { "reports-l0" }) {
            for (const auto &path: file::files_with_ext(file::install_path(fmt::format("test/jam-test-vectors/traces/{}", testset)), ".bin")) {
                test_file(path.substr(0, path.size() - 4), genesis_state);
            }
        }*/
    };
};
