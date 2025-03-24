/* Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com) */

#include "sodium.hpp"

namespace turbo::crypto::sodium {
    void ensure_initialized()
    {
        struct sodium_initializer {
            explicit sodium_initializer()
            {
                if (sodium_init() == -1) [[unlikely]]
                    throw error("Failed to initialize libsodium!");
            }
        };
        // will be initialized on the first call, after that does nothing
        static sodium_initializer init {};
    }
}