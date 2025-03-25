#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/bytes.hpp>

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

    struct key_val_t {
        hash_t key;
        uint8_vector val;
    };
    using flat_tree_t = std::vector<key_val_t>;

    extern hash_t encode(const flat_tree_t &tree);
}
