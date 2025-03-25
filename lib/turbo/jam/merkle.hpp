#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/bytes.hpp>
#include "types.hpp"

namespace turbo::jam::merkle {
    using hash_t = byte_array<32>;

    struct node_t {
        hash_t left;
        hash_t right;

        operator buffer() const
        {
            return { reinterpret_cast<const uint8_t *>(this), sizeof(*this) };
        }
    };

    namespace trie {
        struct key_val_t {
            hash_t key;
            uint8_vector val;
        };
        using flat_tree_t = std::vector<key_val_t>;

        extern hash_t encode_blake2b(const flat_tree_t &tree);
        extern hash_t encode_keccak(const flat_tree_t &tree);
    }

    namespace binary {
        using value_list = std::vector<hash_t>;

        extern hash_t encode_blake2b(const value_list &items);
        extern hash_t encode_keccak(const value_list &items);
    }
}
