#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2026 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/jam/types/common.hpp>

namespace turbo::jam::machine {
    using register_val_t = uint64_t;
    using register_val_signed_t = int64_t;
    using address_val_t = uint32_t;
    typedef uint8_t register_idx_t;
    // in contrast to GP gas_remaining is unsigned, with gas_consume implementing the set to 0 on overuse and throws an exception
    using gas_remaining_t = gas_t;

    static constexpr size_t max_skip_len = 24U;
}
