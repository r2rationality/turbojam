/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025-2026 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/test.hpp>
#include "cert.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jamnp;
}

suite turbo_jamnp_cert_suite = [] {
    "turbo::jamnp::cert"_test = [] {
        using crypto::ed25519::vkey_t;

        struct test_vector_t {
            const char *exp;
            const char *input;
        };

        const std::array<test_vector_t, 5> varlen_test_vectors{{
            {"", ""},
            {"ba", "01"},
            {"ae", "80"},
            {"aiaa", "0001"},
            {"byikutfrlnt7o", "0123456789abcdef"},
        }};
        for (const auto &[exp, input]: varlen_test_vectors)
            expect_equal(exp, alternative_name_varlen(uint8_vector::from_hex(input)));

        const std::array<test_vector_t, 7> test_vectors{{
            {"eaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "0000000000000000000000000000000000000000000000000000000000000000"},
            {"e777777777777777777777777777777777777777777777777777b", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"},
            {"e3r2oc62zwfj3crnuifuvsxvbtlzetk4o5qyhetkhagsc2fgl2oka", "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"},
            {"ebaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "0100000000000000000000000000000000000000000000000000000000000000"},
            {"eaeaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "8000000000000000000000000000000000000000000000000000000000000000"},
            {"eaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaiaa", "0000000000000000000000000000000000000000000000000000000000000001"},
            {"eaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab", "0000000000000000000000000000000000000000000000000000000000000080"},
        }};
        for (const auto &[exp, input]: test_vectors)
            expect_equal(exp, alternative_name(vkey_t::from_hex(input)));
    };
};
