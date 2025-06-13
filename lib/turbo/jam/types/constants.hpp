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
        static constexpr std::string_view jam_entropy { "jam_entropy" };
        static constexpr std::string_view jam_fallback_seal { "jam_fallback_seal" };
        static constexpr std::string_view jam_ticket_seal { "jam_ticket_seal" };
        static constexpr std::string_view jam_valid { "jam_valid" };
        static constexpr std::string_view jam_invalid { "jam_invalid" };
        static constexpr std::string_view jam_available { "jam_available" };
        static constexpr std::string_view jam_guarantee { "jam_guarantee" };
        static constexpr std::string_view jam_audit { "jam_audit" };
        static constexpr std::string_view jam_announce { "jam_announce" };
        static constexpr std::string_view jam_beefy { "jam_beefy" };
        // JAM I.4.4: Z_A
        static constexpr size_t pvm_address_alignment_factor = 2;
        // JAM I.4.4: Z_I
        static constexpr size_t pvm_input_size = 1ULL << 24U;
        // JAM I.4.4: Z_P
        static constexpr size_t pvm_page_size = 1ULL << 12U;
        // JAM I.4.4: Z_Z
        static constexpr size_t pvm_init_zone_size = 1ULL << 16U;

        // B_I
        static constexpr size_t min_balance_per_item = 10;
        // B_L
        static constexpr size_t min_balance_per_octet = 1;
        // B_S
        static constexpr size_t min_balance_per_service = 100;

        static constexpr size_t pvm_p_size(const size_t x)
        {
            return ((x + pvm_page_size - 1) / pvm_page_size) * pvm_page_size;
        }

        static constexpr size_t pvm_z_size(const size_t x)
        {
            return ((x + pvm_init_zone_size - 1) / pvm_init_zone_size) * pvm_init_zone_size;
        }
    };

    // JAM paper: I.4.4
    struct config_prod: config_base {
        // JAM I.4.4: E
        static constexpr size_t epoch_length = 600;
        // JAM I.4.4: Y
        static constexpr size_t ticket_submission_end = epoch_length * 5 / 6;
        // JAM I.4.4: C
        static constexpr size_t core_count = 341;
        static constexpr size_t validator_multiple = 3;
        static constexpr size_t min_guarantors = validator_multiple - 1;
        // JAM I.4.4: V
        static constexpr size_t validator_count = core_count * validator_multiple;
        static constexpr size_t validator_super_majority = validator_count * 2 / 3 + 1;
        // JAM I.4.4: I
        static constexpr size_t max_work_items = 16;
        static constexpr size_t avail_bitfield_bytes = (core_count + 7) / 8;
        // JAM I.4.4: J
        static constexpr size_t max_report_dependencies = 8;
        // JAM I.4.4: L
        static constexpr size_t max_lookup_anchor_age = 400;
        // JAM I.4.4: K
        static constexpr size_t max_tickets_per_block = 16;
        // JAM I.4.4: N
        static constexpr size_t tickets_per_validator = 2;
        // JAM I.4.4: H
        static constexpr size_t max_blocks_history = 8;
        // JAM I.4.4: O
        static constexpr size_t auth_pool_max_size = 8;
        // JAM I.4.4: Q
        static constexpr size_t auth_queue_size = 80;
        // JAM I.4.4: R
        static constexpr size_t core_assignment_rotation_period = 10;
        static constexpr size_t ticket_attempts = 2;
        // JAM (11.9) W_B
        static constexpr size_t max_blobs_size = 48ULL << 10U;
        // JAM I.4.4: Q
        static constexpr size_t accumulation_queue_size = 1024;
        // JAM I.4.4: U
        static constexpr size_t reported_work_timeout = 5;
        // JAM I.4.4: G_A
        static constexpr size_t max_work_report_accumulate_gas = 10'000'000;
        // JAM I.4.4: G_I
        static constexpr size_t max_is_authorized_gas = 50'000'000;
        // JAM I.4.4: G_R
        static constexpr size_t max_refine_gas = 5'000'000'000;
        // JAM I.4.4: G_T
        static constexpr size_t max_total_accumulation_gas = 3'500'000'000;
    };

    struct config_tiny: config_prod {
        static constexpr size_t epoch_length = 12;
        static constexpr size_t ticket_submission_end = epoch_length * 5 / 6;
        static constexpr size_t core_count = 2;
        static constexpr size_t validator_count = core_count * validator_multiple;
        static constexpr size_t validator_super_majority = validator_count * 2 / 3 + 1;
        static constexpr size_t avail_bitfield_bytes = (core_count + 7) / 8;
        static constexpr size_t max_lookup_anchor_age = 14;
        static constexpr size_t core_assignment_rotation_period = 4;
        static constexpr size_t ticket_attempts = 3;
    };
}