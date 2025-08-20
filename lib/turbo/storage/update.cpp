/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include "update.hpp"

namespace turbo::storage::update {
    struct db_t::impl {
        explicit impl(storage::db_ptr_t base_db):
            _base_db{std::move(base_db)}
        {
        }

        void commit()
        {
            for (const auto &[k, v]: _updates) {
                if (v)
                    _base_db->set(k, *v);
                else
                    _base_db->erase(k);
            }
            _updates.clear();
            _num_added = 0;
            _num_removed = 0;
        }

        void clear()
        {
            throw error("clear is not supported for update::db_t out of performance reasons!");
        }

        void erase(const buffer key)
        {
            _set(key, {});
        }

        void foreach(const observer_t &obs)
        {
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

        value_t get(const buffer k) const
        {
            if (const auto it = _updates.find(k); it != _updates.end())
                return it->second;
            return _base_db->get(k);
        }

        void set(const buffer key, const buffer val)
        {
            _set(key, val);
        }

        [[nodiscard]] size_t size() const
        {
            return _base_db->size() + _num_added - _num_removed;
        }
    private:
        storage::db_ptr_t _base_db;
        std::map<uint8_vector, value_t> _updates{};
        size_t _num_added = 0;
        size_t _num_removed = 0;

        void _set(const buffer key, value_t val)
        {
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
    };

    db_t::db_t(storage::db_ptr_t base_db):
        _impl{std::make_unique<impl>(std::move(base_db))}
    {
    }

    db_t::~db_t() = default;

    void db_t::clear()
    {
        _impl->clear();
    }

    size_t db_t::size() const
    {
        return _impl->size();
    }

    void db_t::commit()
    {
        _impl->commit();
    }

    void db_t::erase(const buffer key)
    {
        _impl->erase(key);
    }

    void db_t::foreach(const observer_t &obs) const
    {
        _impl->foreach(obs);
    }

    value_t db_t::get(const buffer key) const
    {
        return _impl->get(key);
    }

    void db_t::set(const buffer key, const buffer val)
    {
        _impl->set(key, val);
    }
}
