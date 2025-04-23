/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/test.hpp>
#include "errors.hpp"
#include "types.hpp"
#include "state.hpp"

namespace {
    using namespace std::string_view_literals;
    using namespace turbo;
    using namespace turbo::jam;

    struct tmp_account_t {
        service_info_t service;

        static tmp_account_t from_bytes(decoder &dec)
        {
            return {
                dec.decode<decltype(service)>()
            };
        }
    };

    using tmp_accounts_t = map_t<service_id_t, tmp_account_t, accounts_config_t>;

    template<typename CONSTANTS>
    struct input_t {
        guarantees_extrinsic_t<CONSTANTS> guarantees;
        time_slot_t<CONSTANTS> slot;

        static input_t from_bytes(decoder &dec)
        {
            return {
                dec.decode<decltype(guarantees)>(),
                dec.decode<decltype(slot)>()
            };
        }

        bool operator==(const input_t &o) const
        {
            if (guarantees != o.guarantees)
                return false;
            if (slot != o.slot)
                return false;
            return true;
        }
    };

    struct err_code_t: err_any_t {
        using base_type = err_any_t;
        using base_type::base_type;

        static err_code_t from_err_any(err_any_t &&err)
        {
            return std::visit([&](auto &&e) -> err_code_t {
                return { std::move(e) };
            }, std::move(err));
        }

        static err_code_t from_bytes(decoder &dec)
        {
            switch (const auto typ = dec.decode<uint8_t>(); typ) {
                case 0: return { err_bad_core_index_t {} };
                case 1: return { err_future_report_slot_t {} };
                case 2: return { err_report_epoch_before_last_t {} };
                case 3: return { err_insufficient_guarantees_t {} };
                case 4: return { err_out_of_order_guarantee_t {} };
                case 5: return { err_not_sorted_or_unique_guarantors_t {} };
                case 6: return { err_wrong_assignment_t {} };
                case 7: return { err_core_engaged_t {} };
                case 8: return { err_anchor_not_recent_t {} };
                case 9: return { err_bad_service_id_t {} };
                case 10: return { err_bad_code_hash_t {} };
                case 11: return { err_dependency_missing_t {} };
                case 12: return { err_duplicate_package_t {} };
                case 13: return { err_bad_state_root_t {} };
                case 14: return { err_bad_beefy_mmr_root_t {} };
                case 15: return { err_core_unauthorized_t {} };
                case 16: return { err_bad_validator_index_t {} };
                case 17: return { err_work_report_gas_too_high_t {} };
                case 18: return { err_service_item_gas_too_low_t {} };
                case 19: return { err_too_many_dependencies_t {} };
                case 20: return { err_segment_root_lookup_invalid_t {} };
                case 21: return { err_bad_signature_t {} };
                case 22: return { err_work_report_too_big_t {} };
                [[unlikely]] default: throw error(fmt::format("unsupported err_code_t type: {}", typ));
            }
        }
    };

    using output_base_t = std::variant<reports_output_data_t, err_code_t>;
    struct output_t: output_base_t {
        using base_type = output_base_t;
        using base_type::base_type;

        static output_t from_bytes(decoder &dec)
        {
            const auto typ = dec.decode<uint8_t>();
            switch (typ) {
                case 0: return { reports_output_data_t::from_bytes(dec) };
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

        static void serialize_accounts(auto &archive, const std::string_view name, accounts_t<CONSTANTS> &self)
        {
            tmp_accounts_t taccs;
            archive.process(name, taccs);
            self.clear();
            for (auto &&[id, tacc]: taccs) {
                account_t<CONSTANTS> acc {
                    .info=std::move(tacc.service)
                };
                self.try_emplace(std::move(id), std::move(acc));
            }
        }

        static void serialize_state(auto &archive, const std::string_view, state_t<CONSTANTS> &self)
        {
            archive.process("avail_assignments"sv, self.rho);
            archive.process("curr_validators"sv, self.kappa);
            archive.process("prev_validators"sv, self.lambda);
            archive.process("entropy"sv, self.eta);
            archive.process("offenders"sv, self.psi.offenders);
            archive.process("recent_blocks"sv, self.beta);
            archive.process("auth_pools"sv, self.alpha);
            serialize_accounts(archive, "accounts"sv, self.delta);
            archive.process("cores_statistics"sv, self.pi.cores);
            archive.process("services_statistics"sv, self.pi.services);
        }

        void serialize(auto &archive)
        {
            archive.process("input"sv, in);
            serialize_state(archive, "pre_state"sv, pre);
            archive.process("output"sv, out);
            serialize_state(archive, "post_state"sv, post);
        }

        static test_case_t from_bytes(decoder &dec)
        {
            return test_case_t::from(dec);
        }
    };

    template<typename CFG>
    void test_file(const std::string &path)
    {
        const auto tc = jam::load_obj<test_case_t<CFG>>(path);
        std::optional<output_t> out {};
        state_t<CFG> res_st = tc.pre;
        err_any_t::catch_into(
            [&] {
                auto tmp_st = tc.pre;
                out.emplace(tmp_st.update_reports(tc.in.slot, tc.in.guarantees));
                res_st = std::move(tmp_st);
            },
            [&](err_any_t err) {
                out.emplace(err_code_t::from_err_any(std::move(err)));
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

suite turbo_jam_reports_suite = [] {
    "turbo::jam::reports"_test = [] {
        test_file<config_tiny>(file::install_path("test/jam-test-vectors/reports/tiny/bad_code_hash-1.bin"));
        "tiny"_test = [] {
            for (const auto &path: file::files_with_ext(file::install_path("test/jam-test-vectors/reports/tiny"), ".bin")) {
                test_file<config_tiny>(path);
            }
        };
        "full"_test = [] {
            for (const auto &path: file::files_with_ext(file::install_path("test/jam-test-vectors/reports/full"), ".bin")) {
                test_file<config_prod>(path);
            }
        };
    };
};
