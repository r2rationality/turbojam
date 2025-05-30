#pragma once
/* Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com) */

#include <turbo/common/bytes.hpp>

namespace turbo::crypto::ed25519
{
    using skey_t = secure_byte_array<64>;
    using seed_t = secure_byte_array<32>;
    using vkey_t = byte_array<32>;
    using signature_t = byte_array<64>;

    struct key_pair_t {
        skey_t sk;
        vkey_t vk;
    };

    extern bool verify(const signature_t &sig, const buffer &msg, const vkey_t &vk);
    extern key_pair_t create_from_seed(const seed_t &sd);
}