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
    using key_t = byte_array_t<31>;

    static constexpr auto blake2b_hash_func = static_cast<void(*)(const hash_span_t &, const buffer &)>(crypto::blake2b::digest);
    static constexpr auto keccak_hash_func = static_cast<void(*)(const hash_span_t &, const buffer &)>(crypto::keccak::digest);

    namespace trie {
        struct input_map_config_t {
            std::string key_name = "key";
            std::string val_name = "value";
        };

        using key_t = byte_array_t<31>;
        using input_map_t = map_t<key_t, byte_sequence_t, input_map_config_t>;

        static constexpr size_t max_in_place_value_size = 32;

        struct value_inplace_t: boost::container::static_vector<uint8_t, max_in_place_value_size> {
            using base_type = boost::container::static_vector<uint8_t, max_in_place_value_size>;
            using base_type::base_type;

            void serialize(auto &archive)
            {
                archive.process_array(*this, 0, max_in_place_value_size);
            }
        };

        using value_hash_t = hash_t;

        using value_base_t = std::variant<value_inplace_t, value_hash_t>;
        struct value_t: value_base_t {
            using base_type = value_base_t;

            value_t(const buffer &val, const hash_func &hf):
                base_type { from_byte_sequence(val, hf) }
            {
            }

            void serialize(auto &archive)
            {
                using namespace std::string_view_literals;
                static std::array<std::string_view, 2> names {
                    "inplace_value"sv,
                    "hash"
                };
                archive.template process_variant<base_type>(*this, names);
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

        struct node_t {
            hash_t left;
            hash_t right;

            operator buffer() const
            {
                return { reinterpret_cast<const uint8_t *>(this), sizeof(*this) };
            }
        };

        // JAM Paper D.2.1 "Bit encoding": The bit order is the least significant first.
        struct compact_node_t: node_t {
            compact_node_t(const key_t &k, const buffer &v, const hash_func &hf)
            {
                static_assert(sizeof(left) == sizeof(k) + 1);
                static constexpr size_t max_inplace_value = sizeof(right);
                if (v.size() <= max_inplace_value) {
                    memcpy(right.data(), v.data(), v.size());
                    memset(right.data() + v.size(), 0, right.size() - v.size());
                    //left[0] = 0x01 | v.size() << 2;
                    left[0] = 0b10000000 | v.size();
                    memcpy(left.data() + 1, k.data(), k.size());
                } else {
                    //left[0] = 0x03;
                    left[0] = 0b11000000;
                    memcpy(left.data() + 1, k.data(), k.size());
                    hf(right, v);
                }
            }

            compact_node_t(const key_t &k, const value_t &v)
            {
                std::visit([&](const auto &sv) {
                    using T = std::decay_t<decltype(sv)>;
                    if constexpr (std::is_same_v<T, value_inplace_t>) {
                        memcpy(right.data(), sv.data(), sv.size());
                        memset(right.data() + sv.size(), 0, right.size() - sv.size());
                        //left[0] = 0x01 | sv.size() << 2;
                        left[0] = 0b10000000 | sv.size();
                        memcpy(left.data() + 1, k.data(), k.size());
                    } else {
                        // left[0] = 0x03;
                        left[0] = 0b11000000;
                        memcpy(left.data() + 1, k.data(), k.size());
                        right = sv;
                    }
                }, v);
            }

            compact_node_t(const hash_t &l, const hash_t &r):
                node_t { l, r }
            {
                //left[0] &= 0xFE;
                left[0] &= 0x7F;
            }

            bool is_branch() const
            {
                return !is_leaf();
            }

            bool is_leaf() const
            {
                return left[0] & 1;
            }

            hash_t hash(const hash_func &hf) const
            {
                hash_t res;
                hf(res, *this);
                return res;
            }

            bool bit(const size_t i) const
            {
                // the metadata byte is excluded from the comparison!
                if (i >= (sizeof(*this) - 1) * 8) [[unlikely]]
                    throw error(fmt::format("bit index {} is beyond the num bits: {}", i, sizeof(*this) * 8));
                if (i < (sizeof(left) - 1) * 8)
                    return left.bit(8 + i);
                return right.bit(i - (sizeof(left) - 1) * 8);
            }

            bool operator<(const compact_node_t &o) const noexcept
            {
                // the metadata byte is excluded from the comparison!
                for (size_t i = 8; i < sizeof(left) * 8; ++i) {
                    if (const auto cmp = left.bit(i) <=> o.left.bit(i); cmp != std::strong_ordering::equal)
                        return cmp == std::strong_ordering::less;
                }
                for (size_t i = 0; i < sizeof(right) * 8; ++i) {
                    if (const auto cmp = right.bit(i) <=> o.right.bit(i); cmp != std::strong_ordering::equal)
                        return cmp == std::strong_ordering::less;
                }
                return false;
            }
        };
        static_assert(sizeof(node_t) == 64U);
    }

    struct trie_t {
        using value_t = trie::value_t;
        using value_hash_t = trie::value_hash_t;
        using opt_value_t = std::optional<value_t>;
        using observer_t = std::function<void(const key_t &, const value_t &)>;

        trie_t(const trie::input_map_t &inputs, const hash_func &hf=blake2b_hash_func);
        trie_t(const hash_func &hf=blake2b_hash_func);
        trie_t(const trie_t &o);
        trie_t(trie_t &&o);
        ~trie_t();

        trie_t &operator=(const trie_t &o);
        trie_t &operator=(trie_t &&o);

        void clear();
        size_t size() const;
        bool empty() const;
        void erase(const key_t& key);
        void foreach(const observer_t &obs) const;
        const opt_value_t& get(const key_t& key) const;
        value_t make_value(const buffer &value) const;
        const value_t &set(const key_t &key, const buffer &val);
        const value_t &set(const key_t &key, value_t val);
        [[nodiscard]] hash_t root() const;
    private:
        struct impl;
        std::unique_ptr<impl> _impl;
    };

    namespace binary {
        using value_list = std::vector<uint8_vector>;
        using value_span = std::span<const uint8_vector>;

        extern hash_t encode_blake2b(value_span items);
        extern hash_t encode_keccak(value_span items);
    }
}
