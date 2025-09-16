#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <cstddef>
#include <string_view>

namespace turbo::jam {
    // Constants that are the same in all configurations
    struct config_base {
        // JAM I.4.5 Signing Contexts
        static constexpr std::string_view jam_entropy{"jam_entropy"};
        static constexpr std::string_view jam_fallback_seal{"jam_fallback_seal"};
        static constexpr std::string_view jam_ticket_seal{"jam_ticket_seal"};
        static constexpr std::string_view jam_valid{"jam_valid"};
        static constexpr std::string_view jam_invalid{"jam_invalid"};
        static constexpr std::string_view jam_available{"jam_available"};
        static constexpr std::string_view jam_guarantee{"jam_guarantee"};
        static constexpr std::string_view jam_audit{"jam_audit"};
        static constexpr std::string_view jam_announce{"jam_announce"};
        static constexpr std::string_view jam_beefy{"jam_beefy"};

        static constexpr size_t A_audit_period = 8;
        static constexpr size_t BI_min_balance_per_item = 10;
        static constexpr size_t BL_min_balance_per_octet = 1;
        static constexpr size_t BS_min_balance_per_service = 100;
        static constexpr size_t C_core_count = 341;
        static constexpr size_t D_preimage_expunge_delay = 19'200;
        static constexpr size_t E_epoch_length = 600;
        static constexpr size_t F_audit_bias = 2;
        static constexpr size_t GA_max_accumulate_gas = 10'000'000;
        static constexpr size_t GI_max_is_authorized_gas = 50'000'000;
        static constexpr size_t GR_max_refine_gas = 5'000'000'000;
        static constexpr size_t GT_max_total_accumulation_gas = 3'500'000'000;
        static_assert(GT_max_total_accumulation_gas >= GA_max_accumulate_gas * C_core_count);
        static constexpr size_t H_max_blocks_history = 8;
        static constexpr size_t I_max_work_items = 16;
        static constexpr size_t J_max_report_dependencies = 8;
        static constexpr size_t K_max_tickets_per_block = 16;
        static constexpr size_t L_max_lookup_anchor_age = 14'400;
        static constexpr size_t N_ticket_attempts = 2;
        static constexpr size_t O_auth_pool_max_size = 8;
        static constexpr size_t P_slot_period = 6;
        static constexpr size_t Q_auth_queue_size = 80;
        static constexpr size_t R_core_assignment_rotation_period = 10;
        static constexpr size_t T_max_package_extrinsics = 128;
        static constexpr size_t U_reported_work_timeout = 5;
        static constexpr size_t validator_factor = 3;
        static constexpr size_t V_validator_count = C_core_count * validator_factor;
        static_assert(V_validator_count == 1023U);
        static constexpr size_t WA_max_is_authorized_code_size = 64'000;
        static constexpr size_t WB_max_work_package_size = 13'794'305;
        static constexpr size_t WC_max_service_code_size = 4'000'000;
        static constexpr size_t WP_segment_num_pieces = 6;
        static constexpr size_t WG_segment_size = 4'104U;
        static constexpr size_t WE_segment_piece_size = WG_segment_size / WP_segment_num_pieces;
        static_assert(WE_segment_piece_size == 684U);
        static constexpr size_t WM_max_work_package_imports = 3'072;
        static constexpr size_t WR_max_blobs_size = 48ULL << 10U;
        static constexpr size_t WT_transfer_memo_size = 128;
        static constexpr size_t WX_max_package_exports = 3'072;
        static constexpr size_t Y_ticket_submission_end = 500U;
        static_assert(Y_ticket_submission_end <=  E_epoch_length * 5 / 6);
        static constexpr size_t ZA_pvm_address_alignment_factor = 2;
        static constexpr size_t ZI_pvm_input_size = 1ULL << 24U;
        static constexpr size_t ZP_pvm_page_size = 1ULL << 12U;
        static constexpr size_t ZZ_pvm_init_zone_size = 1ULL << 16U;

        static constexpr size_t pvm_p_size(const size_t x)
        {
            return ((x + ZP_pvm_page_size - 1) / ZP_pvm_page_size) * ZP_pvm_page_size;
        }

        static constexpr size_t pvm_z_size(const size_t x)
        {
            return ((x + ZZ_pvm_init_zone_size - 1) / ZZ_pvm_init_zone_size) * ZZ_pvm_init_zone_size;
        }
    };

    // JAM paper: I.4.4
    struct config_prod: config_base {
        static constexpr size_t min_guarantors = validator_factor - 1;
        static constexpr size_t validator_super_majority = V_validator_count * 2 / 3 + 1;
        static constexpr size_t avail_bitfield_bytes = (C_core_count + 7) / 8;
    };

    struct config_tiny: config_prod {
        static constexpr size_t C_core_count = 2;
        static constexpr size_t D_preimage_expunge_delay = 32;
        static constexpr size_t E_epoch_length = 12;
        static constexpr size_t GR_max_refine_gas = 1'000'000'000;
        static constexpr size_t GT_max_total_accumulation_gas = 20'000'000;
        static constexpr size_t K_max_tickets_per_block = 3;
        static constexpr size_t L_max_lookup_anchor_age = 24;
        static constexpr size_t N_ticket_attempts = 3;
        static constexpr size_t R_core_assignment_rotation_period = 4;
        static constexpr size_t V_validator_count = C_core_count * validator_factor;
        static constexpr size_t Y_ticket_submission_end = 10;
        static_assert(Y_ticket_submission_end <=  E_epoch_length * 5 / 6);
        static constexpr size_t validator_super_majority = V_validator_count * 2 / 3 + 1;
        static constexpr size_t avail_bitfield_bytes = (C_core_count + 7) / 8;
        static_assert(WG_segment_size == 4'104U);
        static constexpr size_t WP_segment_num_pieces = 1026;
        static constexpr size_t WE_segment_piece_size = WG_segment_size / WP_segment_num_pieces;
        static_assert(V_validator_count == 6U);
        static_assert(WE_segment_piece_size == 4U);
    };
}