/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include "state.hpp"

namespace turbo::jam {
    template<typename CONSTANTS>
    statistics_t<CONSTANTS> statistics_t<CONSTANTS>::from_bytes(codec::decoder &dec)
    {
        return {
            dec.decode<decltype(current)>(),
            dec.decode<decltype(last)>()
        };
    }

    template<typename CONSTANTS>
    bool statistics_t<CONSTANTS>::operator==(const statistics_t &o) const
    {
        return current == o.current && last == o.last;
    }

    template struct statistics_t<config_prod>;
    template struct statistics_t<config_tiny>;
}
