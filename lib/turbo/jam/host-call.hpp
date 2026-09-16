#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025-2026 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <cstdint>

namespace turbo::jam {
    enum class host_call_t: uint8_t {
        gas = 0,
        fetch = 1,
        lookup = 2,
        read = 3,
        write = 4,
        info = 5,

        historical_lookup = 6,
        export_ = 7,
        machine = 8,
        peek = 9,
        poke = 10,
        pages = 11,
        invoke = 12,
        expunge = 13,

        bless = 14,
        assign = 15,
        designate = 16,
        checkpoint = 17,
        new_ = 18,
        upgrade = 19,
        transfer = 20,
        eject = 21,
        query = 22,
        solicit = 23,
        forget = 24,
        yield = 25,
        provide = 26,
        log = 100
    };
}
