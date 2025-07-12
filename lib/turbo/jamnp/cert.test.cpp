/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
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

        expect_equal("", cert_name_base32(uint8_vector::from_hex("")));
        expect_equal("aa", cert_name_base32(uint8_vector::from_hex("00")));
        expect_equal("7ara", cert_name_base32(uint8_vector::from_hex("1F44")));
        expect_equal("vkva", cert_name_base32(uint8_vector::from_hex("5555")));
        expect_equal("kvkb", cert_name_base32(uint8_vector::from_hex("aaaa")));

        expect_equal("eaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", cert_name_from_vk(vkey_t::from_hex("0000000000000000000000000000000000000000000000000000000000000000")));
        expect_equal("e777777777777777777777777777777777777777777777777777b", cert_name_from_vk(vkey_t::from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")));
        expect_equal("e3r2oc62zwfj3crnuifuvsxvbtlzetk4o5qyhetkhagsc2fgl2oka", cert_name_from_vk(vkey_t::from_hex("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29")));
        expect_equal("eaieeszqivszohegtk5oz4o357hacbrmgekvmw3brzukxlgx3o77b", cert_name_from_vk(vkey_t::from_hex("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF")));
    };
};
