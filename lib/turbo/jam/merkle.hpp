#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <boost/container/static_vector.hpp>
#include <turbo/crypto/keccak.hpp>
#include <turbo/jam/types/common.hpp>

namespace turbo::jam::merkle {
    using hash_t = byte_array_t<32>;
    using hash_span_t = crypto::blake2b::hash_span_t;
    using hash_func = std::function<void(const hash_span_t &, const buffer &)>;

    static constexpr auto blake2b_hash_func = static_cast<void(*)(const hash_span_t &, const buffer &)>(crypto::blake2b::digest);
    static constexpr auto keccak_hash_func = static_cast<void(*)(const hash_span_t &, const buffer &)>(crypto::keccak::digest);

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

    struct trie_t {
        using key_t = byte_array_t<31>;
        using value_inplace_t = boost::container::static_vector<uint8_t, 32>;

        using value_base_t = std::variant<value_inplace_t, hash_t>;
        struct value_t: value_base_t {
            using base_type = value_base_t;

            value_t(const buffer &val, const hash_func &hf):
                base_type { from_byte_sequence(val, hf) }
            {
            }
        private:
            static value_base_t from_byte_sequence(const buffer &v, const hash_func &hf)
            {
                if (v.size() <= sizeof(hash_t))
                    return value_inplace_t { v.begin(), v.end() };
                hash_t h;
                hf(h, v);
                return { h };
            }
        };
        using opt_value_t = std::optional<value_t>;

        trie_t(trie_t &&o);
        trie_t(const hash_func &hf=blake2b_hash_func);
        ~trie_t();

        void clear();
        bool empty() const;
        void erase(const key_t& key);
        const opt_value_t& get(const key_t& key) const;
        void set(const key_t &key, const buffer &value);
        [[nodiscard]] hash_t root() const;
    private:
        struct impl;
        std::unique_ptr<impl> _impl;
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
        using value_list = std::span<const hash_t>;

        extern hash_t encode_blake2b(value_list items);
        extern hash_t encode_keccak(value_list items);
    }
}
