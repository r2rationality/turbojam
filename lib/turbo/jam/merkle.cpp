/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/crypto/blake2b.hpp>
#include "merkle.hpp"

namespace turbo::jam::merkle {
    // JAM Paper C.1.5 "Bit encoding": The bit order is least significant first.

    static node_t encode(const hash_t &l, const hash_t &r)
    {
        node_t res { l, r };
        res.left[0] &= 0xFE;
        return res;
    }

    static node_t encode(const hash_t &k, const buffer v)
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
            crypto::blake2b::digest(res.right, v);
        }
        return res;
    }

    using tree_copy_t = std::vector<const key_val_t *>;

    static hash_t encode(const tree_copy_t &nodes, const size_t bit_no)
    {
        switch (nodes.size()) {
            case 0: return {};
            case 1: return crypto::blake2b::digest(encode(nodes[0]->key, nodes[0]->val));
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
                return crypto::blake2b::digest(encode(encode(l, bit_no + 1), encode(r, bit_no + 1)));
            }
        }
    }

    hash_t encode(const flat_tree_t &tree)
    {
        tree_copy_t copy {};
        copy.reserve(tree.size());
        for (const auto &n: tree)
            copy.emplace_back(&n);
        return encode(copy, 0);
    }
}
