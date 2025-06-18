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

    void test_roots(const std::string &path)
    {
        try {
            const auto tc = jam::load_obj<test_case_t>(path);
            struct test_vector {
                const char *name;
                const state_snapshot_t &keyvals;
                const state_root_t &root;
            };
            for (const auto &[name, keyvals, root]: std::initializer_list<test_vector> {
                { "pre", tc.pre.keyvals, tc.pre.state_root },
                { "post", tc.post.keyvals, tc.post.state_root }
            }) {
                expect(keyvals.root() == root) << path << name;
                expect(state_dict_t { keyvals }.root() == root) << path << name;
            }
        } catch (const std::exception &ex) {
            expect(false) << path << ex.what();
        }
    }

    void test_transition(const std::string &path, const state_snapshot_t &genesis_state)
    {
        try {
            const auto tc = jam::load_obj<test_case_t>(path + ".bin");
            {
                const auto j_tc = codec::json::load_obj<test_case_t>(path + ".json");
                expect(tc == j_tc) << "the json test case does not match the binary one" << path;
            }

            file::tmp_directory data_dir { "test-jam-traces" };
            chain_t<config_tiny> chain {
                "dev",
                data_dir.path(),
                genesis_state,
                tc.pre.keyvals
            };
            if (!tc.pre.keyvals.empty())
                expect(*chain.state().state_dict == tc.pre.keyvals) << path;
            chain.apply(tc.block);
            expect(*chain.state().state_dict == tc.post.keyvals) << path;
            /*const auto k = merkle::trie::key_t::from_hex<merkle::trie::key_t>("03000000000000000000000000000000000000000000000000000000000000");
            using ET = std::decay_t<decltype(chain.state().beta.get())>;
            std::cout << fmt::format("L: {} {}\n",
                chain.state().state_dict->get(k),
                from_bytes<ET>(encode(chain.state().beta.get())));
            std::cout << fmt::format("R: {} {}\n",
                chain.state().state_dict->make_value(tc.post.keyvals.at(k)),
                from_bytes<ET>(tc.post.keyvals.at(k)));*/
        } catch (const std::exception &ex) {
            expect(false) << path << ex.what();
        }
    }
}

suite turbo_jam_traces_suite = [] {
    "turbo::jam::traces"_test = [] {
        "state roots"_test = [] {
            /*for (const auto testset: { "fallback", "safrole", "reports-l0", "reports-l1" }) {
                for (const auto &path: file::files_with_ext(file::install_path(fmt::format("test/jam-test-vectors/traces/{}", testset)), ".bin")) {
                    test_roots(path);
                }
            }*/
            test_roots(file::install_path("test/jam-test-vectors/traces/fallback/00000000.bin"));
        };
        "state transitions"_test = [] {
            state_snapshot_t genesis_state;
            {
                const auto j_tc = codec::json::load_obj<test_case_t>(file::install_path("test/jam-test-vectors/traces/fallback/00000000.json"));
                genesis_state = j_tc.post.keyvals;
                const auto j_cfg = codec::json::load(file::install_path("etc/devnet/dev-spec.json"));
                auto orig_genesis = state_dict_t::from_genesis_json(j_cfg.at("genesis_state").as_object());
            }
            test_transition(file::install_path("test/jam-test-vectors/traces/reports-l0/00000002"), genesis_state);
            //for (const auto testset: { "fallback", "safrole", "reports-l0", "reports-l1" }) {
            /*for (const auto testset: { "reports-l0" }) {
                for (const auto &path: file::files_with_ext(file::install_path(fmt::format("test/jam-test-vectors/traces/{}", testset)), ".bin")) {
                    test_file(path.substr(0, path.size() - 4), genesis_state);
                }
            }*/
        };
    };
};
