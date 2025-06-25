/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <functional>
#include <turbo/common/logger.hpp>
#include <turbo/crypto/blake2b.hpp>
#include <turbo/crypto/keccak.hpp>
#include "merkle.hpp"

namespace turbo::jam::merkle {
    namespace trie {
        static hash_t encode(const std::span<const compact_node_t> &nodes, const size_t bit_no, const hash_func &hf)
        {
            hash_t res;
            switch (nodes.size()) {
                case 0:
                    res = {};
                    break;
                case 1:
                    res = nodes.front().hash(hf);
                    break;
                default: {
                    auto edge_it = nodes.begin();
                    while (edge_it != nodes.end() && !edge_it->bit(bit_no))
                        ++edge_it;
                    const auto h_l = encode(std::span { nodes.begin(), edge_it }, bit_no + 1, hf);
                    const auto h_r = encode(std::span { edge_it, nodes.end() }, bit_no + 1, hf);
                    res = compact_node_t { h_l, h_r }.hash(hf);
                    break;
                }
            }
            //logger::info("encode v2: level={} nodes={} hash={}", bit_no, nodes.size(), static_cast<buffer>(res));
            return res;
        }

        hash_t compute_root(const node_map_t &nodes, const hash_func &hf)
        {
            return encode(nodes, 0, hf);
        }

        hash_t compute_root(const input_map_t &inputs, const hash_func &hf)
        {
            const node_map_t nodes { inputs, hf };
            return compute_root(nodes, hf);
        }
    }

    struct trie_t::impl {
        explicit impl(const hash_func &hf):
            _hash_func { hf }
        {
        }

        impl(const impl &o):
            _hash_func { o._hash_func }
        {
            o.foreach([&](const key_t &k, const value_t &v) {
                set(k, value_t { v });
            });
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
            if (_erase(_root, key))
                --_size;
        }

        void foreach(const observer_t &obs) const
        {
            std::vector<const node_t *> stack {};
            if (_root)
                stack.emplace_back(_root.get());
            size_t cnt = 0;
            while (!stack.empty()) {
                const auto *node = stack.back();
                stack.pop_back();
                if (node->value) {
                    ++cnt;
                    obs(node->key, *node->value);
                }
                if (node->right)
                    stack.emplace_back(node->right.get());
                if (node->left)
                    stack.emplace_back(node->left.get());
            }
            if (cnt != _size) [[unlikely]]
                throw error(fmt::format("internal error: the action trie size does not match the recorded one: {} != {}!", cnt, _size));
        }

        value_t make_value(const buffer &bytes) const
        {
            return { bytes, _hash_func };
        }

        const value_t &set(const key_t &key, const buffer &val_bytes)
        {
            return set(key, value_t { val_bytes, _hash_func });
        }

        const value_t &set(const key_t &key, value_t val)
        {
            auto new_node = std::make_shared<node_t>(key, prefix_max, std::move(val));
            if (!_root) {
                ++_size;
                _root = std::move(new_node);
                return _root->value.value();
            }
            auto [shared_sz, node_ptr] = _find(_root, key, true);
            auto &node = *node_ptr;
            if (node) {
                if (shared_sz < prefix_max) {
                    ++_size;
                    auto split_node = std::make_shared<node_t>(node->key, node->prefix_sz, std::move(node->value), std::move(node->left), std::move(node->right));
                    node->prefix_sz = shared_sz;
                    node->value.reset();
                    if (key.bit(shared_sz)) {
                        node->left = std::move(split_node);
                        node->right = std::move(new_node);
                        return node->right->value.value();
                    } else {
                        node->left = std::move(new_node);
                        node->right = std::move(split_node);
                        return node->left->value.value();
                    }
                }
                if (node->value != new_node->value) {
                    node->value = std::move(new_node->value);
                }
            } else {
                ++_size;
                node = std::move(new_node);
            }
            return node->value.value();
        }

        size_t size() const
        {
            return _size;
        }

        [[nodiscard]] const hash_t &root() const
        {
            if (_root)
                return _root->hash(_hash_func);
            return _empty_hash();
        }
    private:
        struct node_t;
        using node_ptr_t = std::shared_ptr<node_t>;
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
            static const hash_t &branch_hash(const node_t *ptr, const hash_func &hf, const uint8_t bit_start)
            {
                if (!ptr)
                    return _empty_hash();
                if (!ptr->_hash) {
                    if (ptr->value) {
                        ptr->_hash = trie::compact_node_t { ptr->key, ptr->value.value() }.hash(hf);
                    } else {
                        const auto item_hash = trie::compact_node_t {
                            branch_hash(ptr->left.get(), hf, ptr->prefix_sz + 1),
                            branch_hash(ptr->right.get(), hf, ptr->prefix_sz + 1)
                        }.hash(hf);
                        hash_t res = item_hash;
                        for (uint8_t bit = ptr->prefix_sz; bit > bit_start; --bit) {
                            if (ptr->key.bit(bit - 1)) {
                                res = trie::compact_node_t { _empty_hash(), res }.hash(hf);
                            } else {
                                res = trie::compact_node_t { res, _empty_hash() }.hash(hf);
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
        size_t _size = 0;

        static constexpr auto prefix_max = numeric_cast<uint8_t>(key_t::num_bits());
        static_assert(key_t::num_bits() <= std::numeric_limits<uint8_t>::max());

        struct find_res_t {
            uint8_t shared_sz;
            node_ptr_t *node;
        };

        [[nodiscard]] static find_res_t _find(node_ptr_t &root, const key_t& key, const bool reset_hashes=false)
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

        static bool _erase(std::shared_ptr<node_t> &root, const key_t &key)
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

        [[nodiscard]] static uint8_t _shared_prefix_size(const key_t &a, const key_t &b)
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

    trie_t::trie_t(const trie_t &o):
        _impl { std::make_unique<impl>(*o._impl) }
    {
    }

    trie_t::trie_t(trie_t &&o):
        _impl { std::move(o._impl) }
    {
    }

    trie_t::~trie_t() = default;

    trie_t &trie_t::operator=(trie_t &&o)
    {
        _impl = std::move(o._impl);
        return *this;
    }

    trie_t &trie_t::operator=(const trie_t &o)
    {
        _impl = std::make_unique<impl>(*o._impl);
        return *this;
    }

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

    void trie_t::foreach(const observer_t &obs) const
    {
        _impl->foreach(obs);
    }

    const trie_t::opt_value_t &trie_t::get(const key_t &key) const
    {
        return _impl->get(key);
    }

    trie_t::value_t trie_t::make_value(const buffer &bytes) const
    {
        return _impl->make_value(bytes);
    }

    const trie_t::value_t &trie_t::set(const key_t &key, const buffer &value)
    {
        const auto &res = _impl->set(key, value);
        return res;
    }

    const trie_t::value_t &trie_t::set(const key_t &key, value_t val)
    {
        const auto &res = _impl->set(key, std::move(val));
        return res;
    }

    size_t trie_t::size() const
    {
        return _impl->size();
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
