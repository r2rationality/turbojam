#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <functional>
#include <variant>
#include <turbo/common/error.hpp>

namespace turbo::jam {
    struct error_t: error {
        explicit error_t(auto &self): error(typeid(std::remove_cvref_t<decltype(self)>).name()) {}
        friend bool operator==(const error_t& a, const error_t& b) noexcept {
            return std::string_view(a.what()) == std::string_view(b.what());
        }
        void serialize(auto &) {}
    };
    struct err_bad_attestation_parent_t final: error_t {
        explicit err_bad_attestation_parent_t(): error_t{*this} {}
    };
    struct err_bad_validator_index_t final: error_t {
        explicit err_bad_validator_index_t(): error_t{*this} {}
    };
    struct err_core_not_engaged_t final: error_t {
        explicit err_core_not_engaged_t(): error_t{*this} {}
    };
    struct err_bad_signature_t final: error_t {
        explicit err_bad_signature_t(): error_t{*this} {}
    };
    struct err_not_sorted_or_unique_assurers final: error_t {
        explicit err_not_sorted_or_unique_assurers(): error_t{*this} {}
    };
    struct err_bad_slot_t final: error_t {
        explicit err_bad_slot_t(): error_t{*this} {}
    };
    struct err_future_slot_t final: error_t {
        explicit err_future_slot_t(): error_t{*this} {}
    };
    struct err_bad_extrinsic_hash_t final: error_t {
        explicit err_bad_extrinsic_hash_t(): error_t{*this} {}
    };
    struct err_unexpected_ticket_t final: error_t {
        explicit err_unexpected_ticket_t(): error_t{*this} {}
    };
    struct err_unknown_parent_t final: error_t {
        explicit err_unknown_parent_t(): error_t{*this} {}
    };
    struct err_bad_ticket_order_t final: error_t {
        explicit err_bad_ticket_order_t(): error_t{*this} {}
    };
    struct err_bad_ticket_proof_t final: error_t {
        explicit err_bad_ticket_proof_t(): error_t{*this} {}
    };
    struct err_bad_ticket_attempt_t final: error_t {
        explicit err_bad_ticket_attempt_t(): error_t{*this} {}
    };
    struct err_bad_offenders_mark_t final: error_t {
        explicit err_bad_offenders_mark_t(): error_t{*this} {}
    };
    struct err_reserved_t final: error_t {
        explicit err_reserved_t(): error_t{*this} {}
    };
    struct err_duplicate_ticket_t final: error_t {
        explicit err_duplicate_ticket_t(): error_t{*this} {}
    };
    struct err_bad_core_index_t final: error_t {
        explicit err_bad_core_index_t(): error_t{*this} {}
    };
    struct err_future_report_slot_t final: error_t {
        explicit err_future_report_slot_t(): error_t{*this} {}
    };
    struct err_report_epoch_before_last_t final: error_t {
        explicit err_report_epoch_before_last_t(): error_t{*this} {}
    };
    struct err_insufficient_guarantees_t final: error_t {
        explicit err_insufficient_guarantees_t(): error_t{*this} {}
    };
    struct err_out_of_order_guarantee_t final: error_t {
        explicit err_out_of_order_guarantee_t(): error_t{*this} {}
    };
    struct err_not_sorted_or_unique_guarantors_t final: error_t {
        explicit err_not_sorted_or_unique_guarantors_t(): error_t{*this} {}
    };
    struct err_wrong_assignment_t final: error_t {
        explicit err_wrong_assignment_t(): error_t{*this} {}
    };
    struct err_core_engaged_t final: error_t {
        explicit err_core_engaged_t(): error_t{*this} {}
    };
    struct err_anchor_not_recent_t final: error_t {
        explicit err_anchor_not_recent_t(): error_t{*this} {}
    };
    struct err_bad_service_id_t final: error_t {
        explicit err_bad_service_id_t(): error_t{*this} {}
    };
    struct err_bad_code_hash_t final: error_t {
        explicit err_bad_code_hash_t(): error_t{*this} {}
    };
    struct err_dependency_missing_t final: error_t {
        explicit err_dependency_missing_t(): error_t{*this} {}
    };
    struct err_duplicate_package_t final: error_t {
        explicit err_duplicate_package_t(): error_t{*this} {}
    };
    struct err_bad_state_root_t final: error_t {
        explicit err_bad_state_root_t(): error_t{*this} {}
    };
    struct err_bad_beefy_mmr_root_t final: error_t {
        explicit err_bad_beefy_mmr_root_t(): error_t{*this} {}
    };
    struct err_core_unauthorized_t final: error_t {
        explicit err_core_unauthorized_t(): error_t{*this} {}
    };
    struct err_work_report_gas_too_high_t final: error_t {
        explicit err_work_report_gas_too_high_t(): error_t{*this} {}
    };
    struct err_service_item_gas_too_low_t final: error_t {
        explicit err_service_item_gas_too_low_t(): error_t{*this} {}
    };
    struct err_too_many_dependencies_t final: error_t {
        explicit err_too_many_dependencies_t(): error_t{*this} {}
    };
    struct err_segment_root_lookup_invalid_t final: error_t {
        explicit err_segment_root_lookup_invalid_t(): error_t{*this} {}
    };
    struct err_work_report_too_big_t final: error_t {
        explicit err_work_report_too_big_t(): error_t{*this} {}
    };
    struct err_banned_validator_t final: error_t {
        explicit err_banned_validator_t(): error_t{*this} {}
    };
    struct err_lookup_anchor_not_recent_t final: error_t {
        explicit err_lookup_anchor_not_recent_t(): error_t{*this} {}
    };
    struct err_preimage_unneeded_t final: error_t{
        explicit err_preimage_unneeded_t(): error_t{*this} {}
    };
    struct err_preimages_not_sorted_or_unique_t final: error_t {
        explicit err_preimages_not_sorted_or_unique_t(): error_t{*this} {}
    };
    struct err_already_judged_t final: error_t {
        explicit err_already_judged_t(): error_t{*this} {}
    };
    struct err_bad_vote_split_t final: error_t {
        explicit err_bad_vote_split_t(): error_t{*this} {}
    };
    struct err_verdicts_not_sorted_unique_t final: error_t {
        explicit err_verdicts_not_sorted_unique_t(): error_t{*this} {}
    };
    struct err_judgements_not_sorted_unique_t final: error_t {
        explicit err_judgements_not_sorted_unique_t(): error_t{*this} {}
    };
    struct err_culprits_not_sorted_unique_t final: error_t {
        explicit err_culprits_not_sorted_unique_t(): error_t{*this} {}
    };
    struct err_faults_not_sorted_unique_t final: error_t {
        explicit err_faults_not_sorted_unique_t(): error_t{*this} {}
    };
    struct err_not_enough_culprits_t final: error_t {
        explicit err_not_enough_culprits_t(): error_t{*this} {}
    };
    struct err_not_enough_faults_t final: error_t {
        explicit err_not_enough_faults_t(): error_t{*this} {}
    };
    struct err_culprits_verdict_not_bad_t final: error_t {
        explicit err_culprits_verdict_not_bad_t(): error_t{*this} {}
    };
    struct err_fault_verdict_wrong_t final: error_t {
        explicit err_fault_verdict_wrong_t(): error_t{*this} {}
    };
    struct err_offender_already_reported_t final: error_t {
        explicit err_offender_already_reported_t(): error_t{*this} {}
    };
    struct err_bad_judgement_age_t final: error_t {
        explicit err_bad_judgement_age_t(): error_t{*this} {}
    };
    struct err_bad_guarantor_key_t final: error_t {
        explicit err_bad_guarantor_key_t(): error_t{*this} {}
    };
    struct err_bad_auditor_key_t final: error_t {
        explicit err_bad_auditor_key_t(): error_t{*this} {}
    };
    struct err_missing_work_results_t final: error_t {
        explicit err_missing_work_results_t(): error_t{*this} {}
    };

    template<typename BASE_T, typename BASE_V>
    struct err_group_t: BASE_V {
        using base_type = BASE_V;
        using base_type::base_type;

        static void catch_into(const std::function<void()> &action, const std::function<void(BASE_T)> &on_error)
        {
            if constexpr (std::variant_size_v<BASE_V> > 0) {
                catch_into_impl<std::variant_size_v<BASE_V> - 1>(action, on_error);
            }
        }
    private:
        template<size_t I>
        static void catch_into_impl(const std::function<void()> &action, const std::function<void(BASE_T)> &on_error)
        {
            if constexpr (I == 0) {
                try {
                    action();
                } catch (std::variant_alternative_t<I, BASE_V> &err) {
                    on_error(std::move(err));
                }
            } else {
                try {
                    catch_into_impl<I - 1>(action, on_error);
                } catch (std::variant_alternative_t<I, BASE_V> &err) {
                    on_error(std::move(err));
                }
            }
        }
    };
}