#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/logger.hpp>
#include <turbo/jam/merkle.hpp>

namespace turbo::jam {
    // JAM D.1
    using state_key_t = merkle::key_t;
    using state_key_subhash_t = byte_array_t<27>;
    using state_dict_base_t = merkle::trie_t;

    struct state_snapshot_t: merkle::trie::input_map_t
    {
        using base_type = merkle::trie::input_map_t;
        using base_type::base_type;

        [[nodiscard]] merkle::hash_t root() const
        {
            return merkle::trie_t { *this }.root();
        }

        [[nodiscard]] std::string diff(const state_snapshot_t &o) const
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
                    diff_it = fmt::format_to(diff_it, "key {}: expected {}, got {}\n", o_k, o_v, my_it->second);
                } else {
                    diff_it = fmt::format_to(diff_it, "key {}: ok\n", o_k);
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
    };

    struct state_dict_t: state_dict_base_t {
        using base_type = state_dict_base_t;
        using base_type::base_type;

        static state_key_t make_key(uint8_t id);
        static state_key_t make_key(uint8_t id, uint32_t service_id);
        static state_key_t make_key(uint32_t service_id, const buffer &k);
        static state_snapshot_t from_genesis_json(const boost::json::value &);

        state_dict_t(const state_snapshot_t &o)
        {
            *this = o;
        }

        state_dict_t &operator=(const state_snapshot_t &o)
        {
            clear();
            for (const auto &[k, v]: o)
                set(k, v);
            return *this;
        }

        const value_t &emplace(const state_key_t &k, const buffer &v)
        {
            return set(k, v);
        }

        bool operator==(const state_dict_t &o) const
        {
            return root() == o.root();
        }
    };
    using state_dict_ptr_t = std::shared_ptr<state_dict_t>;
    using state_dict_cptr_t = std::shared_ptr<const state_dict_t>;
}
