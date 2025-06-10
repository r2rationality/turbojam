/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/test.hpp>
#include "types/errors.hpp"
#include "types.hpp"

namespace {
    using namespace std::string_view_literals;
    using namespace turbo;
    using namespace turbo::jam;

    struct tmp_account_t {
        service_info_t service;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("service"sv, service);
        }
    };

    using tmp_accounts_t = map_t<service_id_t, tmp_account_t, accounts_config_t>;
    using known_packages_t = sequence_t<work_package_hash_t>;

    template<typename CONSTANTS>
    struct input_t {
        guarantees_extrinsic_t<CONSTANTS> guarantees;
        time_slot_t<CONSTANTS> slot;
        known_packages_t known_packages;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("guarantees"sv, guarantees);
            archive.process("slot"sv, slot);
            archive.process("known_packages"sv, known_packages);
        }

        bool operator==(const input_t &o) const
        {
            if (guarantees != o.guarantees)
                return false;
            if (slot != o.slot)
                return false;
            if (known_packages != o.known_packages)
                return false;
            return true;
        }
    };

    using err_code_base_t = std::variant<
        err_bad_core_index_t,
        err_future_report_slot_t,
        err_report_epoch_before_last_t,
        err_insufficient_guarantees_t,
        err_out_of_order_guarantee_t,
        err_not_sorted_or_unique_guarantors_t,
        err_wrong_assignment_t,
        err_core_engaged_t,
        err_anchor_not_recent_t,
        err_bad_service_id_t,
        err_bad_code_hash_t,
        err_dependency_missing_t,
        err_duplicate_package_t,
        err_bad_state_root_t,
        err_bad_beefy_mmr_root_t,
        err_core_unauthorized_t,
        err_bad_validator_index_t,
        err_work_report_gas_too_high_t,
        err_service_item_gas_too_low_t,
        err_too_many_dependencies_t,
        err_segment_root_lookup_invalid_t,
        err_bad_signature_t,
        err_work_report_too_big_t
    >;

    struct err_code_t: err_group_t<err_code_t, err_code_base_t> {
        using base_type = err_group_t;
        using base_type::base_type;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            static_assert(std::variant_size_v<err_code_base_t> > 0);
            static codec::variant_names_t<err_code_base_t> names {
                "bad_core_index"sv,
                "future_report_slot"sv,
                "report_epoch_before_last"sv,
                "insufficient_guarantees"sv,
                "out_of_order_guarantee"sv,
                "not_sorted_or_unique_guarantors"sv,
                "wrong_assignment"sv,
                "core_engaged"sv,
                "anchor_not_recent"sv,
                "bad_service_id"sv,
                "bad_code_hash"sv,
                "dependency_missing"sv,
                "duplicate_package"sv,
                "bad_state_root"sv,
                "bad_beefy_mmr_root"sv,
                "core_unauthorized"sv,
                "bad_validator_index"sv,
                "work_report_gas_too_high"sv,
                "service_item_gas_too_low"sv,
                "too_many_dependencies"sv,
                "segment_root_lookup_invalid"sv,
                "bad_signature"sv,
                "work_report_too_big"sv
            };
            archive.template process_variant<err_code_base_t>(*this, names);
        }
    };

    using output_base_t = std::variant<reports_output_data_t, err_code_t>;
    struct output_t: output_base_t {
        using base_type = output_base_t;
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

    template<typename CONSTANTS>
    struct test_case_t {
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

        static void serialize_state(auto &archive, state_t<CONSTANTS> &self)
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
        try {
            const auto tc = jam::load_obj<test_case_t<CFG>>(path + ".bin");
            {
                const auto j_tc = codec::json::load_obj<test_case_t<CFG>>(path + ".json");
                expect(tc == j_tc) << "the json test case does not match the binary one" << path;
            }
            std::optional<output_t> out {};
            state_t<CFG> res_st = tc.pre;
            err_code_t::catch_into(
                [&] {
                    auto tmp_st = tc.pre;
                    out.emplace(tmp_st.update_reports(tc.in.slot, tc.in.guarantees));
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
        } catch (const std::exception &ex) {
            expect(false) << path << ex.what();
        }
    }
}

suite turbo_jam_reports_suite = [] {
    "turbo::jam::reports"_test = [] {
        "tiny"_test = [] {
            for (const auto &path: file::files_with_ext(file::install_path("test/jam-test-vectors/stf/reports/tiny"), ".bin")) {
                test_file<config_tiny>(path.substr(0, path.size() - 4));
            }
        };
        "full"_test = [] {
            for (const auto &path: file::files_with_ext(file::install_path("test/jam-test-vectors/stf/reports/full"), ".bin")) {
                test_file<config_prod>(path.substr(0, path.size() - 4));
            }
        };
    };
};
