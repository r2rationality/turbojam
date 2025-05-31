#pragma once
/* Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com) */

#include <turbo/common/bytes.hpp>

namespace turbo::crypto::blake2b
{
    using hash_t = byte_array<32>;
    using hash_span_t = std::span<uint8_t, sizeof(hash_t)>;

    extern void digest(const hash_span_t &out, const buffer &in);

    template<typename T=hash_t>
    T digest(const buffer &in)
    {
        static_assert(sizeof(T) == sizeof(hash_t));
        T out;
        digest(out, in);
        return out;
    }
}