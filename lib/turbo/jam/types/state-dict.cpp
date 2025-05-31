/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/jam/encoding.hpp>
#include "state-dict.hpp"

namespace turbo::jam {
    state_dict_t state_dict_t::from_genesis_json(const boost::json::value &j)
    {
        const auto &j_state = j.as_object();
        state_dict_t st {};
        for (const auto &[jk, jv]: j_state) {
            st[state_key_t::from_hex<state_key_t>(jk)] = uint8_vector::from_hex(boost::json::value_to<std::string_view>(jv));
        }
        return st;
    }

    state_key_t state_dict_t::make_key(const uint8_t id)
    {
        state_key_t res {};
        res[0] = id;
        return res;
    }

    state_key_t state_dict_t::make_key(const uint8_t id, const uint32_t service_id)
    {
        byte_array<4> n;
        encoder::uint_fixed(n, sizeof(service_id), service_id);
        state_key_t res {};
        res[0] = id;
        res[1] = n[0];
        res[3] = n[1];
        res[5] = n[2];
        res[7] = n[3];
        return res;
    }

    state_key_t state_dict_t::make_key(const uint32_t service_id, const state_key_subhash_t &h)
    {
        byte_array<4> n;
        encoder::uint_fixed(n, sizeof(service_id), service_id);
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