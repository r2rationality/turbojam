/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/test.hpp>
#include "types.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jam;
}

suite turbo_jam_mmr_suite = [] {
    "turbo::jam::mmr"_test = [] {
        "append to empty"_test = [] {
            const mmr_t empty {};
            const auto mmr1 = empty.append(opaque_hash_t {});
            expect_equal(1, mmr1.size());
            expect_equal(mmr_peak_t { opaque_hash_t {} }, mmr1.at(0));
        };
    };
};
