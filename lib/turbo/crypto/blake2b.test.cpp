/* Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com) */

#include <turbo/common/test.hpp>
#include "blake2b.hpp"

namespace {
    using namespace turbo;
    using namespace crypto::blake2b;
}

suite turbo_crypto_blake2b_suite = [] {
    "turbo::crypto::blake2b"_test = [] {
        using test_vector = std::pair<std::string_view, uint8_vector>;
        static std::vector test_vectors = {
            test_vector { "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8", uint8_vector {} },
            test_vector { "EF72A2CDE2A485B61F25762073155CC857A3D1B3FFD07B9C9B1993C75E07879D", uint8_vector::from_hex("000102030405060708090A0B0C0E0F") }
        };
        for (const auto &[exp_hex, input]: test_vectors) {
            const auto exp = uint8_vector::from_hex(exp_hex);
            const auto act = digest(input);
            expect_equal(exp, act);
        }
    };
};
