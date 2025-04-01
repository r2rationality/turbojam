#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include "types.hpp"

namespace turbo::jam {
    struct err_preimage_unneeded_t: error {
        using error::error;
    };
    struct err_preimages_not_sorted_or_unique_t: error {
        using error::error;
    };
}