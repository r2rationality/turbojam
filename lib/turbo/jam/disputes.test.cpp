/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include "types/errors.hpp"
#include "state.hpp"
#include "test-vectors.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jam;

    template<typename CFG>
    struct test_input_t {
        disputes_extrinsic_t<CFG> disputes;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("disputes"sv, disputes);
        }

        bool operator==(const test_input_t &o) const = default;
    };

    using err_code_base_t = std::variant<
        err_already_judged_t,
        err_bad_vote_split_t,
        err_verdicts_not_sorted_unique_t,
        err_judgements_not_sorted_unique_t,
        err_culprits_not_sorted_unique_t,
        err_faults_not_sorted_unique_t,
        err_not_enough_culprits_t,
        err_not_enough_faults_t,
        err_culprits_verdict_not_bad_t,
        err_fault_verdict_wrong_t,
        err_offender_already_reported_t,
        err_bad_judgement_age_t,
        err_bad_validator_index_t,
        err_bad_signature_t,
        err_bad_guarantor_key_t,
        err_bad_auditor_key_t
    >;

    struct err_code_t: err_group_t<err_code_t, err_code_base_t> {
        using base_type = err_group_t;
        using base_type::base_type;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            static_assert(std::variant_size_v<err_code_base_t> > 0);
            static codec::variant_names_t<err_code_base_t> names {
                "already_judged"sv,
                "bad_vote_split"sv,
                "verdicts_not_sorted_unique"sv,
                "judgements_not_sorted_unique"sv,
                "culprits_not_sorted_unique"sv,
                "faults_not_sorted_unique"sv,
                "not_enough_culprits"sv,
                "not_enough_faults"sv,
                "culprits_verdict_not_bad"sv,
                "fault_verdict_wrong"sv,
                "offender_already_reported"sv,
                "bad_judgement_age"sv,
                "bad_validator_index"sv,
                "bad_signature"sv,
                "bad_guarantor_key"sv,
                "bad_auditor_key"sv
            };
            archive.template process_variant<err_code_base_t>(*this, names);
        }
    };

    struct test_output_data_t {
        offenders_mark_t offenders_mark;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("offenders_mark"sv, offenders_mark);
        }

        bool operator==(const test_output_data_t &o) const = default;
    };

    using test_output_base_t = std::variant<test_output_data_t, err_code_t>;
    struct test_output_t: test_output_base_t {
        using base_type = test_output_base_t;
        using base_type::base_type;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            static_assert(std::variant_size_v<base_type> > 0);
            static codec::variant_names_t<base_type> names {
                "ok"sv,
                "err"sv
            };
            archive.template process_variant<base_type>(*this, names);
        }
    };

    template<typename CFG>
    struct test_state_t {
        disputes_records_t psi;
        availability_assignments_t<CFG> rho;
        time_slot_t<CFG> tau;
        validators_data_t<CFG> kappa;
        validators_data_t<CFG> lambda;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("psi"sv, psi);
            archive.process("rho"sv, rho);
            archive.process("tau"sv, tau);
            archive.process("kappa"sv, kappa);
            archive.process("lambda"sv, lambda);
        }

        bool operator==(const test_state_t &) const = default;
    };

    template<typename CFG>
    struct test_case_t {
        test_input_t<CFG> in;
        test_state_t<CFG> pre;
        test_output_t out;
        test_state_t<CFG> post;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("input"sv, in);
            archive.process("pre_state"sv, pre);
            archive.process("output"sv, out);
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
        std::optional<test_output_t> out{};
        auto new_st = tc.pre;
        err_code_t::catch_into(
            [&] {
                 {};
                auto new_offenders = state_t<CFG>::psi_prime(new_st.psi, new_st.rho,
                    tc.pre.kappa, tc.pre.lambda, tc.pre.tau, tc.in.disputes
                );
                out.emplace(test_output_data_t{ .offenders_mark=std::move(new_offenders) });
            },
            [&](err_code_t err) {
                out.emplace(std::move(err));
                new_st = tc.pre;
            }
        );
        if (out.has_value()) {
            expect(out == tc.out) << path;
            expect(new_st == tc.post) << path;
        } else {
            expect(false) << path;
        }
    }
}

suite turbo_jam_disputes_suite = [] {
    "turbo::jam::disputes"_test = [] {
        //test_file<config_tiny>(file::install_path("test/jam-test-vectors/stf/disputes/tiny/progress_invalidates_avail_assignments-1"));
        "tiny test vectors"_test = [] {
            for (const auto &path: file::files_with_ext(test_vector_dir("stf/disputes/tiny"), ".bin")) {
                test_file<config_tiny>(path.substr(0, path.size() - 4));
            }
        };
        "full test vectors"_test = [] {
            for (const auto &path: file::files_with_ext(test_vector_dir("stf/disputes/full"), ".bin")) {
                test_file<config_prod>(path.substr(0, path.size() - 4));
            }
        };
    };
};
