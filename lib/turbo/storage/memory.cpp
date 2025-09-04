/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include "memory.hpp"

namespace turbo::storage::memory {
    struct db_t::impl {
        void commit()
        {
            throw error("commit is not supported for memory::db_t!");
        }

        void clear()
        {
            _db.clear();
        }

        void erase(const buffer key)
        {
            _db.erase(key);
        }

        void foreach(const observer_t &obs)
        {
            for (const auto &[k, v]: _db) {
                obs(k, v);
            }
        }

        value_t get(const buffer k) const
        {
            if (const auto it = _db.find(k); it != _db.end())
                return it->second;
            return {};
        }

        void set(const buffer key, const buffer val)
        {
            auto [it, created] = _db.try_emplace(key, val);
            if (!created)
                it->second = val;
        }

        [[nodiscard]] size_t size() const
        {
            return _db.size();
        }
    private:
        std::map<uint8_vector, uint8_vector> _db{};
    };

    db_t::db_t():
        _impl{std::make_unique<impl>()}
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
