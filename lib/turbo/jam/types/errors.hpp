#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <functional>
#include <variant>
#include <turbo/common/error.hpp>

namespace turbo::jam {
    struct err_bad_attestation_parent_t final: error {
        err_bad_attestation_parent_t(): error { "err_bad_attestation_parent_t" } {}
        bool operator==(const err_bad_attestation_parent_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_bad_validator_index_t final: error {
        err_bad_validator_index_t(): error { "err_bad_validator_index_t" } {}
        bool operator==(const err_bad_validator_index_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_core_not_engaged_t final: error {
        err_core_not_engaged_t(): error { "err_core_not_engaged_t" } {}
        bool operator==(const err_core_not_engaged_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_bad_signature_t final: error {
        err_bad_signature_t(): error { "err_bad_signature_t" } {}
        bool operator==(const err_bad_signature_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_not_sorted_or_unique_assurers final: error {
        err_not_sorted_or_unique_assurers(): error { "err_not_sorted_or_unique_assurers" } {}
        bool operator==(const err_not_sorted_or_unique_assurers &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_bad_slot_t final: error {
        err_bad_slot_t(): error { "err_bad_slot_t" } {}
        bool operator==(const err_bad_slot_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_unexpected_ticket_t final: error {
        err_unexpected_ticket_t(): error { "err_unexpected_ticket_t" } {}
        bool operator==(const err_unexpected_ticket_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_bad_ticket_order_t final: error {
        err_bad_ticket_order_t(): error { "err_bad_ticket_order_t" } {}
        bool operator==(const err_bad_ticket_order_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_bad_ticket_proof_t final: error {
        err_bad_ticket_proof_t(): error { "err_bad_ticket_proof_t" } {}
        bool operator==(const err_bad_ticket_proof_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_bad_ticket_attempt_t final: error {
        err_bad_ticket_attempt_t(): error { "err_bad_ticket_attempt_t" } {}
        bool operator==(const err_bad_ticket_attempt_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_reserved_t final: error {
        err_reserved_t(): error { "err_reserved_t" } {}
        bool operator==(const err_reserved_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_duplicate_ticket_t final: error {
        err_duplicate_ticket_t(): error { "err_duplicate_ticket_t" } {}
        bool operator==(const err_duplicate_ticket_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_bad_core_index_t final: error {
        err_bad_core_index_t(): error { "err_bad_core_index_t" } {}
        bool operator==(const err_bad_core_index_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_future_report_slot_t final: error {
        err_future_report_slot_t(): error { "err_future_report_slot_t" } {}
        bool operator==(const err_future_report_slot_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_report_epoch_before_last_t final: error {
        err_report_epoch_before_last_t(): error { "err_report_epoch_before_last_t" } {}
        bool operator==(const err_report_epoch_before_last_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_insufficient_guarantees_t final: error {
        err_insufficient_guarantees_t(): error { "err_insufficient_guarantees_t" } {}
        bool operator==(const err_insufficient_guarantees_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_out_of_order_guarantee_t final: error {
        err_out_of_order_guarantee_t(): error { "err_out_of_order_guarantee_t" } {}
        bool operator==(const err_out_of_order_guarantee_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_not_sorted_or_unique_guarantors_t final: error {
        err_not_sorted_or_unique_guarantors_t(): error { "err_not_sorted_or_unique_guarantors_t" } {}
        bool operator==(const err_not_sorted_or_unique_guarantors_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_wrong_assignment_t final: error {
        err_wrong_assignment_t(): error { "err_wrong_assignment_t" } {}
        bool operator==(const err_wrong_assignment_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_core_engaged_t final: error {
        err_core_engaged_t(): error { "err_core_engaged_t" } {}
        bool operator==(const err_core_engaged_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_anchor_not_recent_t final: error {
        err_anchor_not_recent_t(): error { "err_anchor_not_recent_t" } {}
        bool operator==(const err_anchor_not_recent_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_bad_service_id_t final: error {
        err_bad_service_id_t(): error { "err_bad_service_id_t" } {}
        bool operator==(const err_bad_service_id_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_bad_code_hash_t final: error {
        err_bad_code_hash_t(): error { "err_bad_code_hash_t" } {}
        bool operator==(const err_bad_code_hash_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_dependency_missing_t final: error {
        err_dependency_missing_t(): error { "err_dependency_missing_t" } {}
        bool operator==(const err_dependency_missing_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_duplicate_package_t final: error {
        err_duplicate_package_t(): error { "err_duplicate_package_t" } {}
        bool operator==(const err_duplicate_package_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_bad_state_root_t final: error {
        err_bad_state_root_t(): error { "err_bad_state_root_t" } {}
        bool operator==(const err_bad_state_root_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_bad_beefy_mmr_root_t final: error {
        err_bad_beefy_mmr_root_t(): error { "err_bad_beefy_mmr_root_t" } {}
        bool operator==(const err_bad_beefy_mmr_root_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_core_unauthorized_t final: error {
        err_core_unauthorized_t(): error { "err_core_unauthorized_t" } {}
        bool operator==(const err_core_unauthorized_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_work_report_gas_too_high_t final: error {
        err_work_report_gas_too_high_t(): error { "err_work_report_gas_too_high_t" } {}
        bool operator==(const err_work_report_gas_too_high_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_service_item_gas_too_low_t final: error {
        err_service_item_gas_too_low_t(): error { "err_service_item_gas_too_low_t" } {}
        bool operator==(const err_service_item_gas_too_low_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_too_many_dependencies_t final: error {
        err_too_many_dependencies_t(): error { "err_too_many_dependencies_t" } {}
        bool operator==(const err_too_many_dependencies_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_segment_root_lookup_invalid_t final: error {
        err_segment_root_lookup_invalid_t(): error { "err_segment_root_lookup_invalid_t" } {}
        bool operator==(const err_segment_root_lookup_invalid_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_work_report_too_big_t final: error {
        err_work_report_too_big_t(): error { "err_work_report_too_big_t" } {}
        bool operator==(const err_work_report_too_big_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_banned_validator_t final: error {
        err_banned_validator_t(): error { "err_banned_validator_t" } {}
        bool operator==(const err_banned_validator_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_lookup_anchor_not_recent_t final: error {
        err_lookup_anchor_not_recent_t(): error { "err_lookup_anchor_not_recent_t" } {}
        bool operator==(const err_lookup_anchor_not_recent_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_preimage_unneeded_t final: error{
        err_preimage_unneeded_t(): error { "err_preimage_unneeded_t" } {}
        bool operator==(const err_preimage_unneeded_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_preimages_not_sorted_or_unique_t final: error {
        err_preimages_not_sorted_or_unique_t(): error { "err_preimages_not_sorted_or_unique_t" } {}
        bool operator==(const err_preimages_not_sorted_or_unique_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_already_judged_t final: error {
        err_already_judged_t(): error { "err_already_judged_t" } {}
        bool operator==(const err_already_judged_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_bad_vote_split_t final: error {
        err_bad_vote_split_t(): error { "err_bad_vote_split_t" } {}
        bool operator==(const err_bad_vote_split_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_verdicts_not_sorted_unique_t final: error {
        err_verdicts_not_sorted_unique_t(): error { "err_verdicts_not_sorted_unique_t" } {}
        bool operator==(const err_verdicts_not_sorted_unique_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_judgements_not_sorted_unique_t final: error {
        err_judgements_not_sorted_unique_t(): error { "err_judgements_not_sorted_unique_t" } {}
        bool operator==(const err_judgements_not_sorted_unique_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_culprits_not_sorted_unique_t final: error {
        err_culprits_not_sorted_unique_t(): error { "err_culprits_not_sorted_unique_t" } {}
        bool operator==(const err_culprits_not_sorted_unique_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_faults_not_sorted_unique_t final: error {
        err_faults_not_sorted_unique_t(): error { "err_faults_not_sorted_unique_t" } {}
        bool operator==(const err_faults_not_sorted_unique_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_not_enough_culprits_t final: error {
        err_not_enough_culprits_t(): error { "err_not_enough_culprits_t" } {}
        bool operator==(const err_not_enough_culprits_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_not_enough_faults_t final: error {
        err_not_enough_faults_t(): error { "err_not_enough_faults_t" } {}
        bool operator==(const err_not_enough_faults_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_culprits_verdict_not_bad_t final: error {
        err_culprits_verdict_not_bad_t(): error { "err_culprits_verdict_not_bad_t" } {}
        bool operator==(const err_culprits_verdict_not_bad_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_fault_verdict_wrong_t final: error {
        err_fault_verdict_wrong_t(): error { "err_fault_verdict_wrong_t" } {}
        bool operator==(const err_fault_verdict_wrong_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_offender_already_reported_t final: error {
        err_offender_already_reported_t(): error { "err_offender_already_reported_t" } {}
        bool operator==(const err_offender_already_reported_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_bad_judgement_age_t final: error {
        err_bad_judgement_age_t(): error { "err_bad_judgement_age_t" } {}
        bool operator==(const err_bad_judgement_age_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_bad_guarantor_key_t final: error {
        err_bad_guarantor_key_t(): error { "err_bad_guarantor_key_t" } {}
        bool operator==(const err_bad_guarantor_key_t &) const { return true; }
        void serialize(auto &) {}
    };
    struct err_bad_auditor_key_t final: error {
        err_bad_auditor_key_t(): error { "err_bad_auditor_key_t" } {}
        bool operator==(const err_bad_auditor_key_t &) const { return true; }
        void serialize(auto &) {}
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