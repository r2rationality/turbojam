/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <functional>
#include <turbo/crypto/blake2b.hpp>
#include <turbo/crypto/keccak.hpp>
#include "merkle.hpp"

namespace turbo::jam::merkle {
    using hash_func = std::function<void(hash_t &, buffer bytes)>;

    namespace trie {
        // JAM Paper C.1.5 "Bit encoding": The bit order is least significant first.
        static node_t encode(const hash_t &l, const hash_t &r)
        {
            node_t res { l, r };
            res.left[0] &= 0xFE;
            return res;
        }

        static node_t encode(const hash_t &k, const buffer v, const hash_func &hash_f)
        {
            node_t res;
            static_assert(sizeof(res.right) == 32);
            if (v.size() <= sizeof(res.right)) {
                memcpy(res.right.data(), v.data(), v.size());
                memset(res.right.data() + v.size(), 0, res.right.size() - v.size());
                res.left[0] = 0x01 | v.size() << 2;
                static_assert(sizeof(k) == sizeof(res.left));
                memcpy(res.left.data() + 1, k.data(), k.size() - 1);
            } else {
                res.left[0] = 0x03;
                memcpy(res.left.data() + 1, k.data(), k.size() - 1);
                hash_f(res.right, v);
            }
            return res;
        }

        using tree_copy_t = std::vector<const key_val_t *>;

        static hash_t encode(const tree_copy_t &nodes, const size_t bit_no, const hash_func &hash_f)
        {
            switch (nodes.size()) {
                case 0: return {};
                case 1: {
                    hash_t res;
                    hash_f(res, encode(nodes[0]->key, nodes[0]->val, hash_f));
                    return res;
                }
                default: {
                    tree_copy_t l {};
                    l.reserve(nodes.size() / 2 + 1);
                    tree_copy_t r {};
                    r.reserve(nodes.size() / 2 + 1);
                    for (const auto *n: nodes) {
                        if (n->key.bit(bit_no))
                            r.emplace_back(n);
                        else
                            l.emplace_back(n);
                    }
                    hash_t res;
                    hash_f(res, encode(encode(l, bit_no + 1, hash_f), encode(r, bit_no + 1, hash_f)));
                    return res;
                }
            }
        }

        hash_t encode_any(const flat_tree_t &tree, const hash_func &hash_f)
        {
            tree_copy_t copy {};
            copy.reserve(tree.size());
            for (const auto &n: tree)
                copy.emplace_back(&n);
            return encode(copy, 0, hash_f);
        }

        hash_t encode_blake2b(const flat_tree_t &tree)
        {
            return encode_any(tree, [](hash_t &out, const buffer bytes) { crypto::blake2b::digest(out, bytes); });
        }

        hash_t encode_keccak(const flat_tree_t &tree)
        {
            return encode_any(tree, [](hash_t &out, const buffer bytes) { crypto::keccak::digest(out, bytes); });
        }
    }

    namespace binary {
        static hash_t encode(const value_list::const_iterator first, const value_list::const_iterator last, const hash_func &hash_f)
        {
            const auto sz = last - first;
            if (sz == 0)
                return {};
            if (sz == 1)
                return *first;
            const auto mid = first + (sz / 2);
            std::array<hash_t, 2> hashes;
            hashes[0] = encode(first, mid, hash_f);
            hashes[1] = encode(mid, last, hash_f);
            hash_t res;
            hash_f(res, buffer { reinterpret_cast<const uint8_t *>(hashes.data()), sizeof(hashes) });
            return res;
        }

        static hash_t encode(const value_list &items, const hash_func &hash_f)
        {
            return encode(items.begin(), items.end(), hash_f);
        }

        hash_t encode_blake2b(const value_list &items)
        {
            return encode(items, [](hash_t &out, const buffer bytes) { crypto::blake2b::digest(out, bytes); });
        }

        hash_t encode_keccak(const value_list &items)
        {
            return encode(items, [](hash_t &out, const buffer bytes) { crypto::keccak::digest(out, bytes); });
        }
    }
}
