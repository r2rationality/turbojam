/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include "state.hpp"

namespace turbo::jam {
    template<typename CONSTANTS>
    state_t<CONSTANTS> state_t<CONSTANTS>::apply(const block_info_t &blk) const
    {
        state_t new_st = *this;
        // assurances must be processed before guarantees

        // new_st.beta = this->beta.apply(blk.header_hash, blk.state_root)

        // alpha is processed after phi
        return new_st;
    }

    template<typename CONSTANTS>
    bool state_t<CONSTANTS>::operator==(const state_t &o) const noexcept
    {
        return alpha == o.alpha
            && beta == o.beta
            && phi == o.phi;
    }

    template struct state_t<config_prod>;
    template struct state_t<config_tiny>;
}
