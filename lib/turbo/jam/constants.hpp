#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <cstddef>

namespace turbo::jam {
    // JAM paper: I.4.4
    struct config_prod {
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
        static constexpr size_t max_accumulate_gas = 10'000'000;
        // JAM I.4.4: G_I
        static constexpr size_t max_is_authorized_gas = 50'000'000;
        // JAM I.4.4: G_R
        static constexpr size_t max_refine_gas = 5'000'000'000;
        // JAM I.4.4: G_T
        static constexpr size_t max_total_accumulation_gas = 3'500'000'000;
        // JAM I.4.4: Z_A
        static constexpr size_t pvm_address_alignment_factor = 2;
        // JAM I.4.4: Z_I
        static constexpr size_t pvm_input_size = 1ULL << 24U;
        // JAM I.4.4: Z_P
        static constexpr size_t pvm_page_size = 1ULL << 12U;
        // JAM I.4.4: Z_Z
        static constexpr size_t pvm_init_zone_size = 1ULL << 16U;
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