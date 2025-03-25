#pragma once
/* Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com) */

#include <turbo/common/bytes.hpp>

namespace turbo::crypto::keccak
{
    using hash_t = byte_array<32>;

    extern void digest(hash_t &out, const buffer &in);

    inline hash_t digest(const buffer &in)
    {
        hash_t out;
        digest(out, in);
        return out;
    }
}