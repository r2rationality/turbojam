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
        time_slot_t<CFG> slot;
        core_authorizers_t auths;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("slot"sv, slot);
            archive.process("auths"sv, auths);
        }

        bool operator==(const test_input_t &o) const = default;
    };

    template<typename CFG>
    struct test_state_t {
        auth_pools_t<CFG> alpha;
        auth_queues_t<CFG> phi;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("auth_pools"sv, alpha);
            archive.process("auth_queues"sv, phi);
        }

        bool operator==(const test_state_t &o) const = default;
    };

    template<typename CFG=config_prod>
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
        try {
            auto new_st = tc.pre;
            new_st.alpha = state_t<CFG>::alpha_prime(tc.in.slot, tc.in.auths, new_st.phi, new_st.alpha);
            expect(new_st == tc.post) << path;
        } catch (...) {
            expect(false) << path;
        }
    }
}

suite turbo_jam_authorizations_suite = [] {
    "turbo::jam::authorizations"_test = [] {
        "tiny"_test = [] {
            for (const auto &path: file::files_with_ext(test_vector_dir("stf/authorizations/tiny"), ".bin")) {
                test_file<config_tiny>(path.substr(0, path.size() - 4));
            }
        };
        "full"_test = [] {
            for (const auto &path: file::files_with_ext(test_vector_dir("stf/authorizations/full"), ".bin")) {
                test_file<config_prod>(path.substr(0, path.size() - 4));
            }
        };
    };
};
