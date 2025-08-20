#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <functional>
#include <turbo/common/bytes.hpp>
#include <turbo/jam/types/state-dict.hpp>
#include <turbo/storage/file.hpp>
#include <turbo/storage/update.hpp>

#define MY_NDEBUG

namespace turbo::jam::triedb {
    using key_t = merkle::key_t;
    using value_t = storage::value_t;

    // Instances are:
    // - not thread safe
    // - each maintains its own copy of the data even when they share the same data directory
    // - a copy creates a physical copy on disk
    struct db_t: storage::db_t {
        using store_t = storage::db_t;
        using store_ptr_t = std::shared_ptr<store_t>;
        using observer_t = storage::observer_t;

        explicit db_t(store_ptr_t store, const db_t &o):
            _store{std::move(store)},
            _trie{std::make_shared<state_dict_t>(*o.trie())}
#if         !defined(NDEBUG)
                , _snapshot{o._snapshot}
#endif
        {
        }

        explicit db_t(const std::string_view db_dir):
            _store{std::make_shared<storage::file::db_t>(db_dir)}
        {
        }

        void clear() override
        {
            _trie->foreach([&](const auto &, const auto &v) {
                std::visit([&](const auto &vv) {
                    using T = std::decay_t<decltype(vv)>;
                    if constexpr (std::is_same_v<T, merkle::trie::value_hash_t>) {
                        _store->erase(vv);
                    }
                }, v);
            });
            _trie->clear();
#if         !defined(NDEBUG)
                _snapshot.clear();
#endif
        }

        void erase(const buffer key) override
        {
            const key_t k{key};
#if         !defined(NDEBUG)
                _snapshot.erase(k);
#endif
            if (auto val = _trie->get(k); val) {
                std::visit([&](const auto &vv) {
                    using T = std::decay_t<decltype(vv)>;
                    if constexpr (std::is_same_v<T, merkle::trie_t::value_hash_t>) {
                        _store->erase(vv);
                    }
                }, *val);
                _trie->erase(k);
            }
#if         !defined(NDEBUG)
                if (const auto cmp_root = _snapshot.root(); cmp_root != _trie->root()) [[unlikely]] {
                    /*_trie->foreach([&](const auto &k, const auto &v) {
                        logger::debug("trie new: {}", k);
                    });
                    merkle::trie_t cmp { _snapshot };
                    logger::debug("trie cmp root: {} (computed: {} new root: {}", cmp_root, cmp.root(), _trie->root());
                    cmp.foreach([&](const auto &k, const auto &v) {
                        logger::debug("trie cmp: {}", k);
                    });*/
                    throw error(fmt::format("internal error: trie root mismatch after erase key: {}!", k));
                }
#endif
        }

        void foreach(const observer_t &obs) const override
        {
            _trie->foreach([&](const auto &k, const auto &v) {
                std::visit([&](const auto &vv) {
                    using T = std::decay_t<decltype(vv)>;
                    if constexpr (std::is_same_v<T, merkle::trie::value_hash_t>) {
                        auto val = _store->get(vv);
                        if (!val) [[unlikely]]
                            throw error(fmt::format("internal error: failed to get value for key {} from the store", k));
                        obs(static_cast<buffer>(k), *val);
                    } else {
                        obs(static_cast<buffer>(k), buffer {vv.data(), vv.size()});
                    }
                }, v);
            });
        }

        value_t get(const buffer key) const override
        {
            const key_t k{key};
            if (auto val = _trie->get(k); val) {
                return std::visit([&](const auto &vv) {
                    using T = std::decay_t<decltype(vv)>;
                    if constexpr (std::is_same_v<T, merkle::trie_t::value_hash_t>) {
                        return _store->get(vv);
                    } else {
                        return value_t { buffer { vv.data(), vv.size() } };
                    }
                }, *val);
            }
            return {};
        }

        void set(const buffer key, const buffer val) override
        {
            const key_t k{key};
#           if !defined(NDEBUG)
                _snapshot[k] = byte_sequence_t { val };
#           endif
            merkle::trie::value_t v { val, merkle::blake2b_hash_func };
            _trie->set(k, std::move(v));
            std::visit([&](const auto &vv) {
                using T = std::decay_t<decltype(vv)>;
                if constexpr (std::is_same_v<T, merkle::trie_t::value_hash_t>) {
                    return _store->set(vv, std::move(val));
                }
            }, v);
#           if !defined(NDEBUG)
                if (_snapshot.root() != _trie->root()) [[unlikely]]
                    throw error(fmt::format("internal error: trie root mismatch after set key: {}!", k));
#           endif
        }

        [[nodiscard]] size_t size() const
        {
            return _trie->size();
        }

        [[nodiscard]] const store_ptr_t &store() const
        {
            return _store;
        }

        [[nodiscard]] const state_dict_ptr_t &trie() const
        {
            return _trie;
        }
    protected:
        store_ptr_t _store;
        state_dict_ptr_t _trie = std::make_shared<state_dict_t>();
#if !defined(NDEBUG)
        state_snapshot_t _snapshot{};
#endif
    };
    using db_ptr_t = std::shared_ptr<db_t>;
}
