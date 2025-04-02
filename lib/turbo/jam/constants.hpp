#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <cstddef>

namespace turbo::jam {
    struct config_prod {
        static constexpr size_t epoch_length = 600;
        static constexpr size_t core_count = 341;
        static constexpr size_t validator_count = core_count * 3;
        static constexpr size_t validator_super_majority = validator_count * 2 / 3 + 1;
        static constexpr size_t avail_bitfield_bytes = (core_count + 7) / 8;
        static constexpr size_t max_tickets_per_block = 16;
        static constexpr size_t tickets_per_validator = 2;
        static constexpr size_t max_blocks_history = 8;
        static constexpr size_t auth_pool_max_size = 8;
        static constexpr size_t auth_queue_size = 80;
        static constexpr size_t core_assignment_rotation_period = 10;
        static constexpr size_t ticket_attempts = 2;
        static constexpr size_t max_blob_size = 48 << 10;
    };

    struct config_tiny: config_prod {
        static constexpr size_t core_count = 2;
        static constexpr size_t validator_count = core_count * 3;
        static constexpr size_t epoch_length = 12;
        static constexpr size_t validator_super_majority = validator_count * 2 / 3 + 1;
        static constexpr size_t avail_bitfield_bytes = (core_count + 7) / 8;
        static constexpr size_t core_assignment_rotation_period = 4;
        static constexpr size_t ticket_attempts = 3;
    };
}