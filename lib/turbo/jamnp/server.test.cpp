/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/test.hpp>
#include "server.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jamnp;
}

suite turbo_jamnp_server_suite = [] {
    "turbo::jamnp::server"_test = [] {
        "trivial_seed"_test = [] {
            expect_equal(
                byte_array<32>::from_hex("0403020104030201040302010403020104030201040302010403020104030201"),
                dev_trivial_seed(0x01020304U)
            );
        };
        "dev_ed25519"_test = [] {
            const auto kp = dev_ed25519(dev_trivial_seed(0U));
            expect_equal(
                byte_array<32>::from_hex("4418fb8c85bb3985394a8c2756d3643457ce614546202a2f50b093d762499ace"),
                kp.vk
            );
        };
    };
};
