#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include "file.hpp"

namespace turbo::storage::update {
    // Designed to support data loading from a json snapshot using the serialize method.
    // For that reason must be default-constructible.
    struct db_t final: storage::db_t {
        using update_map_t = std::map<uint8_vector, value_t>;
        using undo_item_t = typename update_map_t::value_type;
        using undo_list_t = std::vector<undo_item_t>;

        struct undo_redo_t {
            undo_list_t undo;
            update_map_t redo;
        };

        explicit db_t(const db_t &o):
            _base_db{o._base_db},
            _updates{o._updates},
            _num_added{o._num_added},
            _num_removed{o._num_removed}
        {
        }

        db_t(storage::db_ptr_t db):
            _base_db{std::move(db)}
        {}

        ~db_t() override = default;

        void clear() override {
            throw error("clear is not supported for update::db_t out of performance reasons!");
        }

        void erase(const buffer key) override {
            _set(key, {});
        }

        void foreach(const observer_t &obs) const override {
            std::set<uint8_vector> seen{};
            _base_db->foreach([&](const auto &k, const auto &v) {
                if (const auto it = _updates.find(k); it != _updates.end()) {
                    seen.emplace(k);
                    if (it->second)
                        obs(k, *it->second);
                } else {
                    obs(k, v);
                }
            });
            for (const auto &[k, v]: _updates) {
                if (!seen.contains(k) && v)
                    obs(k, *v);
            }
        }

        value_t get(const buffer k) const override {
            if (const auto it = _updates.find(k); it != _updates.end())
                return it->second;
            return _base_db->get(k);
        }

        void set(buffer key, buffer val) override {
            _set(key, val);
        }

        [[nodiscard]] size_t size() const override {
            return _base_db->size() + _num_added - _num_removed;
        }

        void consume_from(db_t &&src) {
            if (_base_db.get() != src._base_db.get()) [[unlikely]]
                throw error("update::db_t can consume only instances referencing the same base db!");
            for (auto &&[k, v]: src._updates) {
                auto [it, created] = _updates.try_emplace(std::move(k), std::move(v));
                if (!created)
                    it->second = std::move(v);
            }
            _num_added += src._num_added;
            _num_removed += src._num_removed;
            src._updates.clear();
            src._num_added = 0;
            src._num_removed = 0;
        }

        undo_redo_t commit() {
            undo_list_t undo{};
            undo.reserve(_updates.size());
            for (const auto &[k, v]: _updates) {
                auto prev_v = _base_db->get(k);
                if (prev_v != v) {
                    if (v)
                        _base_db->set(k, *v);
                    else
                        _base_db->erase(k);
                    undo.emplace_back(k, std::move(prev_v));
                }
            }
            auto redo = std::move(_updates);
            reset();
            return {std::move(undo), std::move(redo)};
        }

        void reset() {
            _updates.clear();
            _num_added = 0;
            _num_removed = 0;
        }

        [[nodiscard]] const update_map_t &updates() const noexcept {
            return _updates;
        }
    private:
        storage::db_ptr_t _base_db;
        update_map_t _updates{};
        size_t _num_added = 0;
        size_t _num_removed = 0;

        void _set(const buffer key, value_t val)
        {
            const auto prev_val = get(key);
            if (prev_val != val) {
                const auto parent_val = _base_db->get(key);
                if (parent_val != val) {
                    auto [it, created] = _updates.try_emplace(key, std::move(val));
                    if (!created) {
                        if (it->second)
                            --_num_added;
                        else
                            --_num_removed;
                        it->second = std::move(val);
                    }
                    if (it->second)
                        ++_num_added;
                    else
                        ++_num_removed;
                } else {
                    if (const auto it = _updates.find(key); it != _updates.end()) {
                        if (it->second)
                            --_num_added;
                        else
                            --_num_removed;
                        _updates.erase(it);
                    }
                }
            }
        }
    };
    using db_ptr_t = std::shared_ptr<db_t>;
}
