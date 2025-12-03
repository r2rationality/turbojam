/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include "state.hpp"
#include "test-vectors.hpp"

namespace turbo_jam_statistics_test {
    using namespace turbo;
    using namespace turbo::jam;

    template<typename CFG>
    struct test_input_t {
        time_slot_t<CFG> slot;
        validator_index_t author_index;
        extrinsic_t<CFG> extrinsic;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("slot"sv, slot);
            archive.process("author_index"sv, author_index);
            archive.process("extrinsic"sv, extrinsic);
        }

        bool operator==(const test_input_t &o) const = default;
    };

    template<typename CFG>
    struct test_state_t {
        validators_statistics_t<CFG> pi_vals_curr;
        validators_statistics_t<CFG> pi_vals_last;
        time_slot_t<CFG> tau;
        validators_data_t<CFG> kappa;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("vals_curr_stats"sv, pi_vals_curr);
            archive.process("vals_last_stats"sv, pi_vals_last);
            archive.process("slot"sv, tau);
            archive.process("curr_validators"sv, kappa);
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
            expect(tc == j_tc) << "the json test case does not match the binary one" << path;
        }
        const file::tmp_directory state_dir { "test-jam-statistics" };
        auto new_st = tc.pre;
        reports_output_data_t reports_res{};
        for (const auto &g: tc.in.extrinsic.guarantees) {
            for (const auto &s: g.signatures)
                reports_res.reporters.emplace(tc.pre.kappa[s.validator_index].ed25519);
        }
        state_t<CFG>::pi_prime(new_st.pi_vals_curr, new_st.pi_vals_last, reports_res,
            new_st.kappa, tc.pre.tau, tc.in.slot, tc.in.author_index, tc.in.extrinsic);
        expect(new_st == tc.post) << path;
    }
}

namespace {
    using namespace turbo_jam_statistics_test;
}

suite turbo_jam_statistics_suite = [] {
    "turbo::jam::statistics"_test = [] {
        for (const auto &path: file::files_with_ext(test_vector_dir("stf/statistics/tiny"), ".bin")) {
            test_file<config_tiny>(path.substr(0, path.size() - 4));
        }
        for (const auto &path: file::files_with_ext(test_vector_dir("stf/statistics/full"), ".bin")) {
            test_file<config_prod>(path.substr(0, path.size() - 4));
        }
    };
};
