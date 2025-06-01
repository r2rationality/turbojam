#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/jam/merkle.hpp>

namespace turbo::jam {
    // JAM D.1
    using state_key_t = merkle::trie::key_t;
    using state_key_subhash_t = byte_array_t<27>;
    using state_dict_base_t = merkle::trie::input_map_t;

    struct state_dict_t: state_dict_base_t {
        using base_type = state_dict_base_t;
        using base_type::base_type;

        static state_key_t make_key(uint8_t id);
        static state_key_t make_key(uint8_t id, uint32_t service_id);
        static state_key_t make_key(uint32_t service_id, const state_key_subhash_t &subhash);

        static state_dict_t from_genesis_json(const boost::json::value &);

        [[nodiscard]] state_root_t root() const
        {
            state_root_t root {};
            if (!empty()) [[likely]]
                merkle::trie::encode_blake2b(root, *this);
            return root;
        }
    };
}
