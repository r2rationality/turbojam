#pragma once
/* Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com) */

#include <cstdlib>
#include <turbo/common/error.hpp>

namespace turbo::crypto::sodium
{
    typedef turbo::error error;

    extern "C" {
#       include <sodium.h>
    }

    extern void ensure_initialized();
}
