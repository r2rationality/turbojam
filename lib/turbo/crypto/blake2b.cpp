/* Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com) */

#include "blake2b.hpp"
#include "sodium.hpp"

namespace turbo::crypto::blake2b {
    void digest(hash_t &out, const buffer &in)
    {
        sodium::ensure_initialized();
        if (sodium::crypto_generichash(out.data(), out.size(), in.data(), in.size(), nullptr, 0) != 0)
            throw error("libsodium error: can't compute hash!");
    }
}
