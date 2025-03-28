/* Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com) */

#include "ed25519.hpp"
#include "sodium.hpp"

namespace turbo::crypto::ed25519 {
    bool verify(const signature_t &sig, const buffer &msg, const vkey_t &vk)
    {
        sodium::ensure_initialized();
        return sodium::crypto_sign_verify_detached(sig.data(), msg.data(), msg.size(), vk.data()) == 0;
    }
}
