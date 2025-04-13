/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/test.hpp>
#include "encoding.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jam;
}

suite turbo_jam_codec_suite = [] {
    "turbo::jam::codec"_test = [] {
        "uint_general"_test = [] {
            static const auto exp = uint8_vector::from_hex("83FF");
            {
                encoder enc {};
                enc.uint_general(1023ULL);
                expect_equal(exp, enc.bytes());
            }
            {
                decoder dec { exp };
                expect_equal(1023ULL, dec.uint_general());
            }
        };
    };
};
