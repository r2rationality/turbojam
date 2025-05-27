/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/test.hpp>
#include "state-dict.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jam;
}

suite turbo_jam_state_dict_suite = [] {
    "turbo::jam::state_dict"_test = [] {
        expect_equal(
            state_key_t::from_hex("0a000000000000000000000000000000000000000000000000000000000000"),
            state_dict_t::make_key(10)
        );
        expect_equal(
            state_key_t::from_hex("37AF00BE00AD00DE0000000000000000000000000000000000000000000000"),
            state_dict_t::make_key(55, 0xDEADBEAF)
        );
        expect_equal(
            state_key_t::from_hex("FE00CA01AF02DE030405060708090a0b0c0d0e0f101112131415161718191a"),
            state_dict_t::make_key(0xDEAFCAFE, state_key_subhash_t::from_hex<state_key_subhash_t>("000102030405060708090a0b0c0d0e0f101112131415161718191a"))
        );
    };
};
