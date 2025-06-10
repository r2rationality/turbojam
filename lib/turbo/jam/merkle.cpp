/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <functional>
#include <turbo/crypto/blake2b.hpp>
#include <turbo/crypto/keccak.hpp>
#include "merkle.hpp"

namespace turbo::jam::merkle {
    using hash_func = std::function<void(const hash_span_t &, buffer bytes)>;

    namespace trie {
        // JAM Paper D.2.1 "Bit encoding": The bit order is the least significant first.
        static node_t encode(const hash_t &l, const hash_t &r)
        {
            node_t res { l, r };
            res.left[0] &= 0xFE;
            return res;
        }

        static node_t encode(const key_t &k, const buffer &v, const hash_func &hash_f)
        {
            node_t res;
            static_assert(sizeof(res.left) == sizeof(k) + 1);
            static_assert(sizeof(res.right) == 32);
            if (v.size() <= sizeof(res.right)) {
                // embedded value leaf
                memcpy(res.right.data(), v.data(), v.size());
                memset(res.right.data() + v.size(), 0, res.right.size() - v.size());
                res.left[0] = 0x01 | v.size() << 2;
                memcpy(res.left.data() + 1, k.data(), k.size());
            } else {
                // regular leaf
                res.left[0] = 0x03;
                memcpy(res.left.data() + 1, k.data(), k.size());
                hash_f(res.right, v);
            }
            return res;
        }

        using tree_copy_t = std::vector<const input_map_t::value_type *>;

        inline hash_t encode(const tree_copy_t &nodes, const size_t bit_no, const hash_func &hash_f);

        static void encode(const hash_span_t &out, const tree_copy_t &nodes, const size_t bit_no, const hash_func &hash_f)
        {
            switch (nodes.size()) {
                case 0: {
                    memset(out.data(), 0, out.size());
                    break;
                }
                case 1: {
                    hash_f(out, encode(nodes[0]->first, nodes[0]->second, hash_f));
                    break;
                }
                default: {
                    tree_copy_t l {};
                    l.reserve(nodes.size() / 2 + 1);
                    tree_copy_t r {};
                    r.reserve(nodes.size() / 2 + 1);
                    for (const auto *n: nodes) {
                        auto &list = n->first.bit(bit_no) ? r : l;
                        list.emplace_back(n);
                    }
                    hash_f(out, encode(encode(l, bit_no + 1, hash_f), encode(r, bit_no + 1, hash_f)));
                    break;
                }
            }
        }

        inline hash_t encode(const tree_copy_t &nodes, const size_t bit_no, const hash_func &hash_f)
        {
            hash_t out;
            encode(out, nodes, bit_no, hash_f);
            return out;
        }

        void encode_any(const hash_span_t &out, const input_map_t &tree, const hash_func &hash_f)
        {
            tree_copy_t copy {};
            copy.reserve(tree.size());
            for (const auto &n: tree)
                copy.emplace_back(&n);
            encode(out, copy, 0, hash_f);
        }

        void encode_blake2b(const hash_span_t &out, const input_map_t &tree)
        {
            encode_any(out, tree, [](const hash_span_t &out, const buffer bytes) { crypto::blake2b::digest(out, bytes); });
        }

        void encode_keccak(const hash_span_t &out, const input_map_t &tree)
        {
            encode_any(out, tree, [](const hash_span_t &out, const buffer bytes) { crypto::keccak::digest(out, bytes); });
        }
    }

    namespace binary {
        static hash_t encode(const value_list items, const hash_func &hash_f)
        {
            const auto sz = items.size();
            if (sz == 0)
                return {};
            if (sz == 1)
                return items.front();
            const auto mid_i = sz / 2;
            std::array<hash_t, 2> hashes;
            hashes[0] = encode(items.subspan(0, mid_i), hash_f);
            hashes[1] = encode(items.subspan(mid_i), hash_f);
            hash_t res;
            hash_f(res, buffer { reinterpret_cast<const uint8_t *>(hashes.data()), sizeof(hashes) });
            return res;
        }

        hash_t encode_blake2b(const value_list items)
        {
            return encode(items, [](const hash_span_t &out, const buffer bytes) { crypto::blake2b::digest(out, bytes); });
        }

        hash_t encode_keccak(const value_list items)
        {
            return encode(items, [](const hash_span_t &out,const buffer bytes) { crypto::keccak::digest(out, bytes); });
        }
    }
}
