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

    struct tmp_account_t: codec::serializable_t<tmp_account_t> {
        service_info_t service;
        preimages_t preimages;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("service"sv, service);
            archive.process("preimages"sv, preimages);
        }
    };

    using tmp_accounts_t = map_t<service_id_t, tmp_account_t, accounts_config_t>;

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

    struct err_code_t final: err_any_t {
        using err_any_t::err_any_t;

        static err_code_t from_bytes(decoder &dec)
        {
            switch (const auto typ = dec.decode<uint8_t>(); typ) {
                case 0: return { err_already_judged_t {} };
                case 1: return { err_bad_vote_split_t {} };
                case 2: return { err_verdicts_not_sorted_unique_t {} };
                case 3: return { err_judgements_not_sorted_unique_t {} };
                case 4: return { err_culprits_not_sorted_unique_t {} };
                case 5: return { err_faults_not_sorted_unique_t {} };
                case 6: return { err_not_enough_culprits_t {} };
                case 7: return { err_not_enough_faults_t {} };
                case 8: return { err_culprits_verdict_not_bad_t {} };
                case 9: return { err_fault_verdict_wrong_t {} };
                case 10: return { err_offender_already_reported_t {} };
                case 11: return { err_bad_judgement_age_t {} };
                case 12: return { err_bad_validator_index_t {} };
                case 13: return { err_bad_signature_t {} };
                case 14: return { err_bad_guarantor_key_t {} };
                case 15: return { err_bad_auditor_key_t {} };
                [[unlikely]] default: throw error(fmt::format("unsupported output_t error type: {}", typ));
            }
        }
    };

    using output_base_t = std::variant<offenders_mark_t, err_code_t>;
    struct output_t: output_base_t {
        using base_type = output_base_t;
        using base_type::base_type;

        static output_t from_bytes(decoder &dec)
        {
            const auto typ = dec.decode<uint8_t>();
            switch (typ) {
                case 0: return { offenders_mark_t::from(dec) };
                case 1: return { err_code_t::from_bytes(dec) };
                [[unlikely]] default: throw error(fmt::format("unsupported output_t type: {}", typ));
            }
        }
    };

    template<typename CONSTANTS>
    struct test_case_t: codec::serializable_t<test_case_t<CONSTANTS>> {
        input_t<CONSTANTS> in;
        state_t<CONSTANTS> pre;
        output_t out;
        state_t<CONSTANTS> post;

        static void serialize_state(auto &archive, const std::string_view, state_t<CONSTANTS> &st)
        {
            using namespace std::string_view_literals;
            archive.process("psu"sv, st.psi);
            archive.process("rho"sv, st.rho);
            archive.process("tau"sv, st.tau);
            archive.process("kappa"sv, st.kappa);
            archive.process("lambda"sv, st.lambda);
        }

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("input"sv, in);
            serialize_state(archive, "pre_state"sv, pre);
            archive.process("output"sv, out);
            serialize_state(archive, "post_state"sv, post);
        }
    };

    template<typename CFG>
    void test_file(const std::string &path)
    {
        const auto tc = jam::load<test_case_t<CFG>>(path);
        /*std::optional<output_t> out {};
        state_t<CFG> res_st = tc.pre;
        try {
            auto tmp_st = tc.pre;
            out.emplace(tmp_st.accumulate(tc.in.slot, tc.in.reports));
            res_st = std::move(tmp_st);
        } catch (const error &) {
            out.emplace(err_code_t {});
        }
        if (out.has_value()) {
            expect(out == tc.out) << path;
            expect(res_st == tc.post) << path;
        } else {
            expect(false) << path;
        }*/
        expect(false) << path;
    }
}

suite turbo_jam_disputes_suite = [] {
    "turbo::jam::disputes"_test = [] {
        "tiny test vectors"_test = [] {
            for (const auto &path: file::files_with_ext(file::install_path("test/jam-test-vectors/disputes/tiny"), ".bin")) {
                test_file<config_tiny>(path);
            }
        };
        "full test vectors"_test = [] {
            for (const auto &path: file::files_with_ext(file::install_path("test/jam-test-vectors/disputes/full"), ".bin")) {
                test_file<config_prod>(path);
            }
        };
    };
};
