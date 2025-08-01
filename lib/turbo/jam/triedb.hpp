#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <functional>
#include <turbo/common/bytes.hpp>
#include <turbo/jam/types/state-dict.hpp>
#include <turbo/storage/filedb.hpp>

namespace turbo::jam::triedb {
    struct client_t {
        using store_t = storage::filedb::client_t;
        using store_ptr_t = std::shared_ptr<store_t>;
        using key_t = merkle::key_t;
        using value_t = std::optional<uint8_vector>;
        using observer_t = std::function<void(const merkle::key_t &, uint8_vector)>;

        client_t(const std::string &db_dir):
            _db_dir { db_dir }
        {
        }

        void clear()
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
        }

        [[nodiscard]] bool empty() const
        {
            return _trie->empty();
        }

        void erase(const merkle::key_t &k)
        {
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

        void foreach(const observer_t &obs) const
        {
            _trie->foreach([&](const auto &k, const auto &v) {
                std::visit([&](const auto &vv) {
                    using T = std::decay_t<decltype(vv)>;
                    if constexpr (std::is_same_v<T, merkle::trie::value_hash_t>) {
                        auto val = _store->get(vv);
                        if (!val) [[unlikely]]
                            throw error(fmt::format("internal error: failed to get value for key {} from the store", k));
                        obs(k, std::move(*val));
                    } else {
                        obs(k, buffer { vv.data(), vv.size() });
                    }
                }, v);
            });
        }

        value_t get(const key_t &k) const
        {
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

        void set(const key_t &k, uint8_vector val)
        {
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
    private:
        static state_dict_ptr_t load(const std::string &path)
        {
            auto trie = std::make_shared<state_dict_t>();
            if (std::filesystem::exists(path)) {
                throw error(fmt::format("triedb: trie loading from a file is not implemented yet!"));
            }
            return trie;
        }

        std::filesystem::path _db_dir;
        store_ptr_t _store = std::make_shared<store_t>((_db_dir / "db").string());
        state_dict_ptr_t _trie = load((_db_dir / "trie.bin").string());
#if !defined(NDEBUG)
        state_snapshot_t _snapshot {};
#endif
    };
    using client_ptr_t = std::shared_ptr<client_t>;
}
