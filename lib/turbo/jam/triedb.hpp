#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <functional>
#include <turbo/common/bytes.hpp>
#include <turbo/jam/types/state-dict.hpp>
#include <turbo/storage/update.hpp>
#include <turbo/storage/lmdb.hpp>

#define MY_NDEBUG

namespace turbo::jam::triedb {
    using key_t = merkle::key_t;
    using value_t = storage::value_t;

    // Instances are:
    // - not thread safe
    // - each maintains its own copy of the data even when they share the same data directory
    // - a copy creates a physical copy on disk
    struct db_t: storage::db_t {
        using store_t = storage::lmdb::db_t;
        using store_ptr_t = std::shared_ptr<store_t>;
        using observer_t = storage::observer_t;

        explicit db_t(store_ptr_t store, const bool load_existing=true):
            _store{std::move(store)}
        {
            if (load_existing)
                _rebuild_trie();
        }

        explicit db_t(store_ptr_t store, const db_t &o):
            _store{std::move(store)},
            _trie{std::make_shared<state_dict_t>(*o._trie)}
#if         !defined(NDEBUG) && !defined(MY_NDEBUG)
                , _snapshot{o._snapshot}
#endif
        {
            if (_store && _store != o._store) {
                _store->clear();
                o.foreach([&](const auto &k, const auto &v) {
                    _store->set(k, v);
                });
            }
        }

        explicit db_t(const std::string_view db_dir, const bool load_existing=true):
            _store{std::make_shared<store_t>(db_dir)}
        {
            if (load_existing)
                _rebuild_trie();
        }

        void foreach(const observer_t &obs) const override
        {
            _trie->foreach([&](const auto &k, const auto &v) {
                std::visit([&](const auto &vv) {
                    using T = std::decay_t<decltype(vv)>;
                    if constexpr (std::is_same_v<T, merkle::trie::value_hash_t>) {
                        auto val = _store->get(buffer{k});
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
            auto [val, trie_v] = _get(key);
            return val;
        }

        [[nodiscard]] size_t size() const override
        {
            return _trie->size();
        }

        [[nodiscard]] state_root_t root() const
        {
            return _trie->root();
        }

        void clear() override
        {
            _trie->foreach([&](auto &&k, auto &&v) {
                std::visit([&](const auto &vv) {
                    using T = std::decay_t<decltype(vv)>;
                    if constexpr (std::is_same_v<T, merkle::trie::value_hash_t>) {
                        auto val = _store->get(buffer{k});
                        if (!val) [[unlikely]]
                            throw error(fmt::format("internal error: failed to get value for key {} from the store", k));
                        _undo.emplace_back(k, std::move(val));
                    } else {
                        _undo.emplace_back(k, buffer {vv.data(), vv.size()});
                    }
                }, v);
                _store->erase(buffer{k});
            });
            _trie->clear();
#if         !defined(NDEBUG) && !defined(MY_NDEBUG)
                _snapshot.clear();
#endif
        }

        void erase(const buffer key) override
        {
            _erase(key);
        }

        void set(const buffer key, const buffer val) override
        {
            _set(key, val);
        }

        void apply(const buffer key, const value_t &val)
        {
            _apply(key, val);
        }

        storage::update::undo_list_t commit() {
            if (_undo.empty())
                return {};
            _store->commit();
            return std::exchange(_undo, {});
        }

        void rollback() {
            if (!_undo.empty()) {
                for (const auto &[k, v] : _undo) {
                    _apply(k, v, false);
                }
                _undo.clear();
                _store->rollback();
            }
        }
    protected:
        store_ptr_t _store;
        state_dict_ptr_t _trie = std::make_shared<state_dict_t>();
        storage::update::undo_list_t _undo{};
#if !defined(NDEBUG) && !defined(MY_NDEBUG)
        state_snapshot_t _snapshot{};
#endif
    private:
        struct get_res_t {
            value_t val;
            const merkle::trie_t::opt_value_t &trie_v;
        };

        void _apply(const buffer key, const value_t &val, const bool track_undo=true)
        {
            if (val) {
                _set(key, *val, track_undo);
            } else {
                _erase(key, track_undo);
            }
        }

        get_res_t _get(const buffer key) const
        {
            const key_t k{key};
            const auto &val = _trie->get(k);
            if (val) {
                return std::visit([&](const auto &vv) -> get_res_t {
                    using T = std::decay_t<decltype(vv)>;
                    if constexpr (std::is_same_v<T, merkle::trie_t::value_hash_t>) {
                        return {_store->get(key), val};
                    } else {
                        return {buffer{vv.data(), vv.size()}, val};
                    }
                }, *val);
            }
            return {value_t{}, val};
        }

        void _erase(const buffer key, const bool track_undo=true)
        {
            const key_t k{key};
#if         !defined(NDEBUG) && !defined(MY_NDEBUG)
                _snapshot.erase(k);
#endif
            auto [prev_v, trie_v] = _get(key);
            if (trie_v) {
                // capture undo data before erasing: prev_v is a buffer view that becomes
                // dangling once _store->erase or _trie->erase destroys the underlying data
                if (track_undo)
                    _undo.emplace_back(key, std::move(prev_v));
                _store->erase(key);
                _trie->erase(k);
            }
#if         !defined(NDEBUG) && !defined(MY_NDEBUG)
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

        void _set(const buffer key, const buffer val, const bool track_undo=true)
        {
            const key_t k{key};
#           if !defined(NDEBUG) && !defined(MY_NDEBUG)
                _snapshot[k] = byte_sequence_t{val};
#           endif
            
            merkle::trie::value_t v{val, merkle::blake2b_hash_func};
            if (auto prev_v = get(key); prev_v != val) {
                // capture undo data before modifying the trie: prev_v is a buffer view into
                // the trie node or LMDB memory that _trie->set may invalidate
                if (track_undo)
                    _undo.emplace_back(key, std::move(prev_v));
                _trie->set(k, std::move(v));
                _store->set(key, val);
            }
#           if !defined(NDEBUG) && !defined(MY_NDEBUG)
                if (_snapshot.root() != _trie->root()) [[unlikely]]
                    throw error(fmt::format("internal error: trie root mismatch after set key: {}!", k));
#           endif
        }

        void _rebuild_trie()
        {
            _trie->clear();
            _store->foreach([&](const auto &k, const auto &v) {
                _trie->set(key_t{k}, v);
            });
        }
    };
    using db_ptr_t = std::shared_ptr<db_t>;
}
