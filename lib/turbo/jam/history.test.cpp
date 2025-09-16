/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include "state.hpp"
#include "test-vectors.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jam;

    template<typename CFG>
    struct test_input_t {
        header_hash_t header_hash;
        state_root_t parent_state_root;
        opaque_hash_t accumulate_root;
        reported_work_seq_t<CFG> work_packages;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("header_hash"sv, header_hash);
            archive.process("parent_state_root"sv, parent_state_root);
            archive.process("accumulate_root"sv, accumulate_root);
            archive.process("work_packages"sv, work_packages);
        }

        bool operator==(const test_input_t &o) const = default;
    };

    template<typename CFG>
    struct test_state_t {
        recent_blocks_t<CFG> beta;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("beta"sv, beta);
        }

        bool operator==(const test_state_t &o) const = default;
    };

    template<typename CFG>
    struct test_case_t {
        test_input_t<CFG> in;
        test_state_t<CFG> pre;
        test_state_t<CFG> post;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("input"sv, in);
            archive.process("pre_state"sv, pre);
            archive.process("post_state"sv, post);
        }

        bool operator==(const test_case_t &o) const = default;
    };

    template<typename CFG>
    void test_file(const std::string &path)
    {
        const auto tc = jam::load_obj<test_case_t<CFG>>(path + ".bin");
        {
            const auto j_tc = codec::json::load_obj<test_case_t<CFG>>(path + ".json");
            expect(tc == j_tc) << "json test case does not match the binary one" << path;
        }
        auto new_beta = tc.pre.beta;
        state_t<CFG>::beta_dagger(new_beta, tc.in.parent_state_root);
        state_t<CFG>::beta_prime(new_beta, tc.in.header_hash, tc.in.accumulate_root, tc.in.work_packages);
        expect(new_beta == tc.post.beta) << path;
    }
}

suite turbo_jam_history_suite = [] {
    "turbo::jam::history"_test = [] {
        static const auto test_prefix = test_vector_dir("stf/history/");
        static std::optional<std::string> override_test{};
        //override_test.emplace("tiny/progress_blocks_history-2");
        if (!override_test) {
            for (const auto &path: file::files_with_ext(test_prefix + "tiny", ".bin")) {
                test_file<config_tiny>(path.substr(0, path.size() - 4));
            }
            for (const auto &path: file::files_with_ext(test_prefix + "full", ".bin")) {
                test_file<config_prod>(path.substr(0, path.size() - 4));
            }
        } else {
            test_file<config_tiny>(test_prefix + *override_test);
        }
    };
};
