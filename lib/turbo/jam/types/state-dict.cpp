/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include "state-dict.hpp"

namespace turbo::jam {
    state_key_t state_dict_t::make_key(const uint8_t id)
    {
        state_key_t res {};
        res[0] = id;
        return res;
    }

    state_key_t state_dict_t::make_key(const uint8_t id, const service_id_t service_id)
    {
        encoder enc {};
        enc.uint_fixed(4, service_id);
        const auto n = static_cast<buffer>(enc.bytes());
        state_key_t res {};
        res[0] = id;
        res[1] = n[0];
        res[3] = n[1];
        res[5] = n[2];
        res[7] = n[3];
        return res;
    }

    state_key_t state_dict_t::make_key(const service_id_t service_id, const state_key_subhash_t &h)
    {
        encoder enc {};
        enc.uint_fixed(4, service_id);
        const auto n = static_cast<buffer>(enc.bytes());
        state_key_t res {};
        res[0] = n[0];
        res[1] = h[0];
        res[2] = n[1];
        res[3] = h[1];
        res[4] = n[2];
        res[5] = h[2];
        res[6] = n[3];
        res[7] = h[3];
        static_assert(sizeof(res) - 8 == sizeof(h) - 4);
        memcpy(res.data() + 8, h.data() + 4, h.size() - 4);
        return res;
    }
}