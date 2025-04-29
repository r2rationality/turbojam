/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/test.hpp>
#include "errors.hpp"
#include "types.hpp"
#include "state.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jam;

    template<typename CONSTANTS>
    struct input_t: codec::serializable_t<input_t<CONSTANTS>> {
        disputes_extrinsic_t<CONSTANTS> disputes;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("disputes"sv, disputes);
        }

        bool operator==(const input_t &o) const
        {
            if (disputes != o.disputes)
                return false;
            return true;
        }
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

    struct err_code_t final: err_code_base_t, codec::serializable_t<err_code_t> {
        using base_type = err_code_base_t;
        using base_type::base_type;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            static_assert(std::variant_size_v<err_any_t> > 0);
            static codec::variant_names_t<base_type> names {
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
            archive.template process_variant<base_type>(*this, names);
        }

        static void catch_into(const std::function<void()> &action, const std::function<void(err_code_t)> &on_error)
        {
            if constexpr (std::variant_size_v<base_type> > 0) {
                catch_into_impl<std::variant_size_v<base_type> - 1>(action, on_error);
            }
        }
    private:
        template<size_t I>
        static void catch_into_impl(const std::function<void()> &action, const std::function<void(err_code_t)> &on_error)
        {
            if constexpr (I == 0) {
                try {
                    action();
                } catch (std::variant_alternative_t<I, base_type> &err) {
                    on_error(std::move(err));
                }
            } else {
                try {
                    catch_into_impl<I - 1>(action, on_error);
                } catch (std::variant_alternative_t<I, base_type> &err) {
                    on_error(std::move(err));
                }
            }
        }
    };

    struct output_data_t: codec::serializable_t<output_data_t> {
        offenders_mark_t offenders_mark;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("offenders_mark"sv, offenders_mark);
        }

        bool operator==(const output_data_t &o) const
        {
            if (offenders_mark != o.offenders_mark)
                return false;
            return true;
        }
    };

    using output_base_t = std::variant<output_data_t, err_code_t>;
    struct output_t: output_base_t, codec::serializable_t<output_t> {
        using base_type = output_base_t;
        using base_type::base_type;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            static_assert(std::variant_size_v<err_any_t> > 0);
            static codec::variant_names_t<base_type> names {
                "ok"sv,
                "err"sv
            };
            archive.template process_variant<base_type>(*this, names);
        }
    };

    template<typename CONSTANTS>
    struct test_case_t: codec::serializable_t<test_case_t<CONSTANTS>> {
        input_t<CONSTANTS> in;
        state_t<CONSTANTS> pre;
        output_t out;
        state_t<CONSTANTS> post;

        static void serialize_state(auto &archive, state_t<CONSTANTS> &st)
        {
            using namespace std::string_view_literals;
            archive.process("psi"sv, st.psi);
            archive.process("rho"sv, st.rho);
            archive.process("tau"sv, st.tau);
            archive.process("kappa"sv, st.kappa);
            archive.process("lambda"sv, st.lambda);
        }

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("input"sv, in);
            archive.push("pre_state"sv);
            serialize_state(archive, pre);
            archive.pop();
            archive.process("output"sv, out);
            archive.push("post_state"sv);
            serialize_state(archive, post);
            archive.pop();
        }

        bool operator==(const test_case_t &o) const
        {
            if (in != o.in)
                return false;
            if (pre != o.pre)
                return false;
            if (out != o.out)
                return false;
            if (post != o.post)
                return false;
            return true;
        }
    };

    template<typename CFG>
    void test_file(const std::string &path)
    {
        const auto j_tc = codec::json::load_obj<test_case_t<CFG>>(path + ".json");
        const auto tc = jam::load_obj<test_case_t<CFG>>(path + ".bin");
        expect(tc == j_tc) << "json test case does not match the binary one" << path;
        std::optional<output_t> out {};
        state_t<CFG> res_st = tc.pre;
        err_code_t::catch_into(
            [&] {
                auto tmp_st = tc.pre;
                out.emplace(output_data_t { .offenders_mark=tmp_st.update_disputes(tc.in.disputes) });
                res_st = std::move(tmp_st);
            },
            [&](err_code_t err) {
                out.emplace(std::move(err));
            }
        );
        if (out.has_value()) {
            expect(out == tc.out) << path;
            expect(res_st == tc.post) << path;
        } else {
            expect(false) << path;
        }
    }
}

suite turbo_jam_disputes_suite = [] {
    "turbo::jam::disputes"_test = [] {
        test_file<config_tiny>(file::install_path("test/jam-test-vectors/disputes/tiny/progress_with_faults-7"));
        "tiny test vectors"_test = [] {
            for (const auto &path: file::files_with_ext(file::install_path("test/jam-test-vectors/disputes/tiny"), ".bin")) {
                test_file<config_tiny>(path.substr(0, path.size() - 4));
            }
        };
        "full test vectors"_test = [] {
            for (const auto &path: file::files_with_ext(file::install_path("test/jam-test-vectors/disputes/full"), ".bin")) {
                test_file<config_prod>(path.substr(0, path.size() - 4));
            }
        };
    };
};
