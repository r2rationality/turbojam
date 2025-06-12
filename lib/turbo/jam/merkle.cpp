/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <functional>
#include <turbo/crypto/blake2b.hpp>
#include <turbo/crypto/keccak.hpp>
#include "merkle.hpp"

namespace turbo::jam::merkle {
    namespace trie {
        // JAM Paper D.2.1 "Bit encoding": The bit order is the least significant first.
        static hash_t encode(const hash_t &l, const hash_t &r, const hash_func &hf)
        {
            node_t res { l, r };
            res.left[0] &= 0xFE;
            hash_t res_hash;
            hf(res_hash, res);
            return res_hash;
        }

        static hash_t encode(const key_t &k, const trie_t::value_t &v, const hash_func &hf)
        {
            node_t res;
            static_assert(sizeof(res.left) == sizeof(k) + 1);
            static_assert(sizeof(res.right) == 32);
            std::visit([&](const auto &vv) {
                using T = std::decay_t<decltype(vv)>;
                if constexpr (std::is_same_v<T, hash_t>) {
                    res.left[0] = 0x03;
                    memcpy(res.left.data() + 1, k.data(), k.size());
                    res.right = vv;
                } else {
                    memcpy(res.right.data(), vv.data(), vv.size());
                    memset(res.right.data() + vv.size(), 0, res.right.size() - vv.size());
                    res.left[0] = 0x01 | vv.size() << 2;
                    memcpy(res.left.data() + 1, k.data(), k.size());
                }
            }, v);
            hash_t res_hash;
            hf(res_hash, res);
            return res_hash;
        }

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
                    const auto h_l = encode(l, bit_no + 1, hash_f);
                    const auto h_r = encode(r, bit_no + 1, hash_f);
                    hash_f(out, encode(h_l, h_r));
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

    struct trie_t::impl {
        explicit impl(const hash_func &hf):
            _hash_func { hf }
        {
        }

        void clear()
        {
            _root.reset();
        }

        const std::optional<value_t> &get(const key_t &k) const
        {
            static std::optional<value_t> empty {};
            auto [shared_sz, node_ptr] = _find(const_cast<node_ptr_t &>(_root), k);
            if (shared_sz == prefix_max && *node_ptr) {
                if (!(*node_ptr)->value) [[unlikely]]
                    throw error("internal error: a trie leaf without a value!");
                return (*node_ptr)->value;
            }
            return empty;
        }

        bool empty() const
        {
            return !_root;
        }

        void erase(const key_t &key)
        {
            _erase(_root, key);
        }

        void set(const key_t &key, const buffer &val_bytes)
        {
            auto new_node = std::make_unique<node_t>(key, prefix_max, value_t { val_bytes, _hash_func });
            if (!_root) {
                _root = std::move(new_node);
                return;
            }
            auto [shared_sz, node_ptr] = _find(_root, key, true);
            auto &node = *node_ptr;
            if (shared_sz < prefix_max) {
                auto split_node = std::make_unique<node_t>(node->key, node->prefix_sz, std::move(node->value), std::move(node->left), std::move(node->right));
                node->prefix_sz = shared_sz;
                node->value.reset();
                if (key.bit(shared_sz)) {
                    node->left = std::move(split_node);
                    node->right = std::move(new_node);
                } else {
                    node->left = std::move(new_node);
                    node->right = std::move(split_node);
                }
            } else {
                if (node->value != new_node->value) {
                    node->value = std::move(new_node->value);
                }
            }
        }

        [[nodiscard]] const hash_t &root() const
        {
            if (_root)
                return _root->hash(_hash_func);
            return _empty_hash();
        }
    private:
        struct node_t;
        using node_ptr_t = std::unique_ptr<node_t>;
        struct node_t {
            key_t key;
            uint8_t prefix_sz;
            std::optional<value_t> value;
            node_ptr_t left;
            node_ptr_t right;
            mutable std::optional<hash_t> _hash {};

            [[nodiscard]] const hash_t &hash(const hash_func &hf)
            {
                if (!_hash)
                    branch_hash(this, hf, 0);
                return _hash.value();
            }
        private:
            static [[nodiscard]] const hash_t &branch_hash(const node_t *ptr, const hash_func &hf, const uint8_t bit_start)
            {
                if (!ptr)
                    return _empty_hash();
                if (!ptr->_hash) {
                    if (ptr->value) {
                        ptr->_hash = trie::encode(ptr->key, ptr->value.value(), hf);
                    } else {
                        const auto item_hash = trie::encode(
                            branch_hash(ptr->left.get(), hf, ptr->prefix_sz + 1),
                            branch_hash(ptr->right.get(), hf, ptr->prefix_sz + 1),
                            hf
                        );
                        hash_t res = item_hash;
                        for (uint8_t bit = ptr->prefix_sz; bit > bit_start; --bit) {
                            if (ptr->key.bit(bit - 1)) {
                                res = trie::encode(_empty_hash(), res, hf);
                            } else {
                                res = trie::encode(res, _empty_hash(), hf);
                            }
                        }
                        ptr->_hash = res;
                    }
                }
                return *ptr->_hash;
            }
        };

        const hash_func _hash_func;
        node_ptr_t _root {};

        static constexpr auto prefix_max = numeric_cast<uint8_t>(key_t::num_bits());
        static_assert(key_t::num_bits() <= std::numeric_limits<uint8_t>::max());

        struct find_res_t {
            uint8_t shared_sz;
            node_ptr_t *node;
        };

        static [[nodiscard]] find_res_t _find(node_ptr_t &root, const key_t& key, const bool reset_hashes=false)
        {
            find_res_t res { 0, &root };
            while (*res.node) {
                if (reset_hashes)
                    (*res.node)->_hash.reset();
                node_t* node = res.node->get();
                res.shared_sz = _shared_prefix_size(node->key, key);
                if (res.shared_sz < node->prefix_sz || node->prefix_sz == prefix_max)
                    break;
                const bool right = key.bit(node->prefix_sz);
                res.node = right ? &node->right : &node->left;
            }
            return res;
        }

        static bool _erase(std::unique_ptr<node_t> &root, const key_t &key)
        {
            if (!root)
                return false;
            auto [shared_sz, node_ptr] = _find(root, key, true);
            auto &node = *node_ptr;

            // Check if this node is the matching key
            if (node->prefix_sz != prefix_max) {
                if (shared_sz < node->prefix_sz)
                    return false;
                const bool right = key.bit(node->prefix_sz);
                auto &child = right ? node->right : node->left;
                if (!_erase(child, key))
                    return false;
            }

            if (!node->value) [[unlikely]]
                throw error("a trie leaf without a value!");
            node.reset();
            return true;
        }

        static [[nodiscard]] uint8_t _shared_prefix_size(const key_t &a, const key_t &b)
        {
            for (uint8_t i = 0; i < prefix_max; ++i) {
                if (a.bit(i) != b.bit(i))
                    return i;
            }
            return prefix_max;
        }

        static const hash_t &_empty_hash()
        {
            static hash_t empty {};
            return empty;
        }
    };

    trie_t::trie_t(const hash_func &hf):
        _impl { std::make_unique<impl>(hf) }
    {
    }

    trie_t::trie_t(trie_t &&o):
        _impl { std::move(o._impl) }
    {
    }

    trie_t::~trie_t() = default;

    void trie_t::clear()
    {
        _impl->clear();
    }

    bool trie_t::empty() const
    {
        return _impl->empty();
    }

    void trie_t::erase(const key_t &key)
    {
        _impl->erase(key);
    }

    const trie_t::opt_value_t &trie_t::get(const key_t &key) const
    {
        return _impl->get(key);
    }

    void trie_t::set(const key_t &key, const buffer &value)
    {
        _impl->set(key, value);
    }

    hash_t trie_t::root() const
    {
        return _impl->root();
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
