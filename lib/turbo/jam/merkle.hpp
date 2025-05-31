#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/jam/types/common.hpp>

namespace turbo::jam::merkle {
    using hash_t = byte_array_t<32>;
    using hash_span_t = std::span<uint8_t, sizeof(hash_t)>;

    struct node_t {
        hash_t left;
        hash_t right;

        operator buffer() const
        {
            return { reinterpret_cast<const uint8_t *>(this), sizeof(*this) };
        }
    };

    struct input_map_config_t {
        std::string key_name = "key";
        std::string val_name = "value";
    };

    namespace trie {
        using key_t = byte_array_t<31>;
        using input_map_t = map_t<key_t, byte_sequence_t, input_map_config_t>;

        extern void encode_blake2b(const hash_span_t &out, const input_map_t &tree);
        extern void encode_keccak(const hash_span_t &out, const input_map_t &tree);

        inline hash_t encode_blake2b(const input_map_t &tree)
        {
            hash_t res;
            encode_blake2b(res, tree);
            return res;
        }

        inline hash_t encode_keccak(const input_map_t &tree)
        {
            hash_t res;
            encode_keccak(res, tree);
            return res;
        }
    }

    namespace binary {
        using value_list = std::vector<hash_t>;

        extern hash_t encode_blake2b(const value_list &items);
        extern hash_t encode_keccak(const value_list &items);
    }
}
