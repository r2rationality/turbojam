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
            return merkle::trie::compute_root(*this);
        }
    };

    struct state_dict_t: state_dict_base_t {
        using base_type = state_dict_base_t;
        using base_type::base_type;

        static state_key_t make_key(uint8_t id);
        static state_key_t make_key(uint8_t id, uint32_t service_id);
        static state_key_t make_key(uint32_t service_id, const state_key_subhash_t &subhash);
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

        bool operator==(const state_snapshot_t &o) const
        {
            //if (size() != o.size()) [[unlikely]]
            //    return false;
            size_t key_matches = 0;
            for (const auto &[k, v]: o) {
                auto ov = make_value(v);
                auto my_v = get(k);
                if (!my_v) [[unlikely]] {
                    logger::info("missing key: {}", k);
                    return false;
                }
                ++key_matches;
                if (my_v != ov) [[unlikely]] {
                    logger::info("key {}: expected {}, got {}", k, ov, my_v);
                    return false;
                }
            }
            if (key_matches != size()) [[unlikely]] {
                foreach([&](const auto &k, const auto &) {
                    logger::info("extra key: {}", k);
                });
            }
            return true;
        }

        bool operator==(const state_dict_t &o) const
        {
            return root() == o.root();
        }
    };
    using state_dict_ptr_t = std::shared_ptr<state_dict_t>;
    using state_dict_cptr_t = std::shared_ptr<const state_dict_t>;
}
