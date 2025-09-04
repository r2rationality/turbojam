/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/jam/encoding.hpp>
#include <turbo/jam/state.hpp>
#include "state-dict.hpp"

namespace turbo::jam {
    std::string state_snapshot_t::diff(const state_snapshot_t &o) const
    {
        std::string diff {};
        auto diff_it = std::back_inserter(diff);
        size_t key_matches = 0;
        for (const auto &[o_k, o_v]: o) {
            const auto my_it = find(o_k);
            if (my_it == end()) [[unlikely]] {
                diff_it = fmt::format_to(diff_it, "missing key: {}\n", o_k);
                continue;
            }
            ++key_matches;
            if (my_it->second != o_v) [[unlikely]] {
                diff_it = fmt::format_to(diff_it, "key {}: exp {} act {}\n", o_k, o_v, my_it->second);
                diff_it = fmt::format_to(diff_it, "key {}: decoded exp:\n{}\n", o_k, state_t<config_tiny>::decode_val(o_k, o_v));
                diff_it = fmt::format_to(diff_it, "key {}: decoded act:\n{}\n", o_k, state_t<config_tiny>::decode_val(o_k, my_it->second));
            }
        }
        if (key_matches != size()) [[unlikely]] {
            for (const auto &[k, v]: *this) {
                if (const auto o_it = o.find(k); o_it == o.end()) [[unlikely]] {
                    diff_it = fmt::format_to(diff_it, "extra key: {}\n", k);
                }
            }
        }
        return diff;
    }

    state_snapshot_t state_dict_t::from_genesis_json(const boost::json::value &j)
    {
        const auto &j_state = j.as_object();
        state_snapshot_t st {};
        for (const auto &[jk, jv]: j_state) {
            st.emplace(state_key_t::from_hex<state_key_t>(jk), uint8_vector::from_hex(boost::json::value_to<std::string_view>(jv)));
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

    state_key_t state_dict_t::make_key(const uint32_t service_id, const buffer k)
    {
        const auto a = crypto::blake2b::digest(k);
        byte_array<4> n;
        encoder::uint_fixed(n, sizeof(service_id), service_id);
        state_key_t res;
        res[0] = n[0];
        res[1] = a[0];
        res[2] = n[1];
        res[3] = a[1];
        res[4] = n[2];
        res[5] = a[2];
        res[6] = n[3];
        res[7] = a[3];
        static_assert(sizeof(a) >= sizeof(res) - 4);
        memcpy(res.data() + 8, a.data() + 4, sizeof(res) - 8);
        return res;
    }

    key_info_t state_dict_t::key_info(const buffer key)
    {
        const auto ksum = std::accumulate(key.begin() + 1U, key.end(), size_t{0});
        const auto ssum = key[2] + key[4] + key[6] + std::accumulate(key.begin() + 8U, key.end(), size_t{0});
        if (key[0] == 0xFFU && ssum == 0U) {
            return key_service_info_t{decoder::uint_fixed<service_id_t>(byte_array<4>{key[1], key[3], key[5], key[7]})};
        }
        if (ksum == 0) {
            return key_state_var_t{key[0]};
        }
        return key_service_data_t{decoder::uint_fixed<service_id_t>(byte_array<4>{key[0], key[2], key[4], key[6]})};
    }
}