#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025-2026 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <cstdint>

namespace turbo::jam {
    enum class host_call_t: uint64_t {
        gas = 0,
        grow_heap = 1,
        fetch = 2,
        lookup = 3,
        read = 4,
        write = 5,
        info = 6,

        historical_lookup = 7,
        export_ = 8,
        machine = 9,
        peek = 10,
        poke = 11,
        pages = 12,
        invoke = 13,
        expunge = 14,

        bless = 15,
        assign = 16,
        designate = 17,
        checkpoint = 18,
        new_ = 19,
        upgrade = 20,
        transfer = 21,
        eject = 22,
        query = 23,
        solicit = 24,
        forget = 25,
        yield = 26,
        provide = 27,
        log = 100
    };
}
