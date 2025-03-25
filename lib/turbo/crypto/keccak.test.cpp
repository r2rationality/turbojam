/* Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com) */

#include <turbo/common/test.hpp>
#include "keccak.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::crypto;
}

suite turbo_crypto_keccak_suite = [] {
    "turbo::crypto::keccak"_test = [] {
        using test_vector = std::pair<std::string_view, uint8_vector>;
        static std::vector test_vectors = {
            test_vector { "C5D2460186F7233C927E7DB2DCC703C0E500B653CA82273B7BFAD8045D85A470", uint8_vector::from_hex("") },
            test_vector { "6FFFA070B865BE3EE766DC2DB49B6AA55C369F7DE3703ADA2612D754145C01E6", uint8_vector::from_hex("AAFDC9243D3D4A096558A360CC27C8D862F0BE73DB5E88AA55") }
        };
        for (const auto &[exp_hex, input]: test_vectors) {
            const auto exp_hash = uint8_vector::from_hex(exp_hex);
            const auto hash = keccak::digest(input);
            expect_equal(static_cast<buffer>(exp_hash), hash);
        }
    };
};