/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/test.hpp>
#include "encoding.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jam;

    void test_varint(const buffer exp, const uint64_t x, const std::source_location& loc=std::source_location::current())
    {
        encoder enc{};
        enc.uint_varlen(x);
        expect_equal(exp, enc.bytes(), loc);
        decoder dec{exp};
        expect_equal(x, dec.uint_varlen(), loc);
    }
}

suite turbo_jam_encoding_suite = [] {
    "turbo::jam::encoding"_test = [] {
        // C.1
        "empty"_test = [] {
            encoder enc{};
            expect_equal(0, enc.bytes().size());
        };
        // C.2
        "octect"_test = [] {
            {
                const auto octet = uint8_vector::from_hex("83FF");
                const encoder enc{static_cast<buffer>(octet)};
                expect_equal(octet, enc.bytes());
            }
            {
                const auto octet = byte_array<4>::from_hex("DEADBEEF");
                const encoder enc{octet};
                expect_equal(octet, enc.bytes());
            }
        };
        // C.5: general naturals
        "uint_varlen"_test = [] {
            test_varint(uint8_vector::from_hex("00"), 0ULL);
            test_varint(uint8_vector::from_hex("01"), 1ULL);
            test_varint(uint8_vector::from_hex("7F"), 127ULL);
            test_varint(uint8_vector::from_hex("8080"), 128ULL);
            test_varint(uint8_vector::from_hex("BFFF"), 16383ULL);
            test_varint(uint8_vector::from_hex("C00040"), 16384ULL);
            test_varint(uint8_vector::from_hex("DFFFFF"), 2097151ULL);
            test_varint(uint8_vector::from_hex("E0000020"), 2097152ULL);
            test_varint(uint8_vector::from_hex("EFFFFFFF"), 268435455ULL);
            test_varint(uint8_vector::from_hex("F000000010"), 268435456ULL);
            test_varint(uint8_vector::from_hex("F7FFFFFFFF"), 34359738367ULL);
            test_varint(uint8_vector::from_hex("F80000000008"), 34359738368ULL);
            test_varint(uint8_vector::from_hex("FBFFFFFFFFFF"), 4398046511103ULL);
            test_varint(uint8_vector::from_hex("FC000000000004"), 4398046511104ULL);
            test_varint(uint8_vector::from_hex("FDFFFFFFFFFFFF"), 562949953421311ULL);
            test_varint(uint8_vector::from_hex("FE00000000000002"), 562949953421312ULL);
            test_varint(uint8_vector::from_hex("FEFFFFFFFFFFFFFF"), 72057594037927935ULL);
            test_varint(uint8_vector::from_hex("FF0000000000000001"), 72057594037927936ULL);
            test_varint(uint8_vector::from_hex("FFFFFFFFFFFFFFFFFF"), 18446744073709551615ULL);
            test_varint(uint8_vector::from_hex("2A"), 42ULL);
            test_varint(uint8_vector::from_hex("9234"), 0x1234ULL);
            test_varint(uint8_vector::from_hex("E0785634"), 0x345678ULL);
            test_varint(uint8_vector::from_hex("F078563412"), 0x12345678ULL);
        };
    };
};
