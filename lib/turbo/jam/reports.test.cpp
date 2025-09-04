/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/storage/memory.hpp>
#include "types/errors.hpp"
#include "state.hpp"
#include "test-vectors.hpp"

namespace {
    using namespace std::string_view_literals;
    using namespace turbo;
    using namespace turbo::jam;

    template<typename CFG>
    struct test_account_t {
        service_info_t<CFG> service;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("service"sv, service);
        }

        bool operator==(const test_account_t &) const = default;
    };

    template<typename CFG>
    struct test_accounts_t: map_t<service_id_t, test_account_t<CFG>, accounts_config_t> {
        using base_type = map_t<service_id_t, test_account_t<CFG>, accounts_config_t>;
        using base_type::base_type;

        [[nodiscard]] accounts_t<CFG> get(storage::db_ptr_t db) const
        {
            accounts_t<CFG> res{std::move(db)};
            for (auto &&[id, tacc]: *this) {
                res.info_set(id, tacc.service);
            }
            return res;
        }

        void set(accounts_t<CFG> &&o)
        {
            this->clear();
            o.foreach([&](auto id, auto info) {
                this->try_emplace(std::move(id), std::move(info));
            });
        }
    };

    using known_packages_t = sequence_t<work_package_hash_t>;

    template<typename CFG>
    struct test_input_t {
        guarantees_extrinsic_t<CFG> guarantees;
        time_slot_t<CFG> slot;
        known_packages_t known_packages;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("guarantees"sv, guarantees);
            archive.process("slot"sv, slot);
            archive.process("known_packages"sv, known_packages);
        }

        bool operator==(const test_input_t &o) const = default;
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
        err_work_report_too_big_t,
        err_banned_validator_t,
        err_lookup_anchor_not_recent_t
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
                "work_report_too_big"sv,
                "banned_validator"sv,
                "lookup-anchor-not-recept"sv
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

    template<typename CFG>
    struct test_state_t {
        availability_assignments_t<CFG> rho;
        validators_data_t<CFG> kappa;
        validators_data_t<CFG> lambda;
        entropy_buffer_t eta;
        ed25519_keys_set_t offenders;
        recent_blocks_t<CFG> beta;
        auth_pools_t<CFG> alpha;
        test_accounts_t<CFG> accounts;
        cores_statistics_t<CFG> pi_cores;
        services_statistics_t pi_services;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("avail_assignments", rho);
            archive.process("curr_validators", kappa);
            archive.process("prev_validators", lambda);
            archive.process("entropy", eta);
            archive.process("offenders", offenders);
            archive.process("recent_blocks", beta);
            archive.process("auth_pools", alpha);
            archive.process("accounts", accounts);
            archive.process("cores_statistics", pi_cores);
            archive.process("services_statistics", pi_services);
        }

        bool operator==(const test_state_t &o) const = default;
    };

    template<typename CFG>
    struct test_case_t {
        test_input_t<CFG> in;
        test_state_t<CFG> pre;
        output_t out;
        test_state_t<CFG> post;

        void serialize(auto &archive)
        {
            archive.process("input"sv, in);
            archive.process("pre_state"sv, pre);
            archive.process("output"sv, out);
            archive.process("post_state"sv, post);
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
            std::optional<output_t> out{};
            auto new_st = tc.pre;
            err_code_t::catch_into(
                [&] {
                    auto delta = tc.pre.accounts.get(std::make_shared<storage::memory::db_t>());
                    out.emplace(
                        state_t<CFG>::update_reports(
                            new_st.rho, new_st.pi_cores, new_st.pi_services,
                            new_st.beta.history,
                            new_st.eta, new_st.offenders,
                            new_st.kappa, new_st.lambda,
                            new_st.alpha,
                            delta,
                            tc.in.slot, tc.in.guarantees
                        )
                    );
                    new_st.accounts.set(std::move(delta));
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
        } catch (const std::exception &ex) {
            expect(false) << path << ex.what();
        }
    }
}

suite turbo_jam_reports_suite = [] {
    "turbo::jam::reports"_test = [] {
        static const std::string test_prefix = "stf/reports/";
        static std::optional<std::string> override_test{};
        //override_test.emplace("tiny/anchor_not_recent-1");
        if (!override_test) {
            "tiny"_test = [] {
                for (const auto &path: file::files_with_ext(test_vector_dir(test_prefix + "tiny"), ".bin")) {
                    test_file<config_tiny>(path.substr(0, path.size() - 4));
                }
            };
            "full"_test = [] {
                for (const auto &path: file::files_with_ext(test_vector_dir(test_prefix + "full"), ".bin")) {
                    test_file<config_prod>(path.substr(0, path.size() - 4));
                }
            };
        } else {
            test_file<config_tiny>(test_vector_dir(test_prefix + *override_test));
        }
    };
};
