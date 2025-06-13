#pragma once
/* Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com) */

#include <map>
#include <ranges>
#include <turbo/common/error.hpp>

namespace turbo::container {
    template<typename M>
    concept has_get_erase_set_c = requires(M m, typename M::key_type k, typename M::mapped_type v)
    {
        { m.get(k) };
        { m.erase(k) };
        { m.set(k, v) };
    };

    template<typename M>
    concept has_begin_end_c = requires(M m)
    {
        { m.begin() };
        { m.end() };
    };

    template<typename T>
    concept has_empty_c = requires(T t)
    {
        { t.empty() };
    };

    template<typename M>
    struct std_map_update_api_t {
        using key_type = typename M::key_type;
        using mapped_type = typename M::mapped_type;
        using observer_t = std::function<void(const key_type &k, const mapped_type &v)>;

        std_map_update_api_t(M &base):
            _base { base }
        {
        }

        void erase(const key_type &k)
        {
            _base.erase(k);
        }

        void foreach(const observer_t & obs) const
        {
            for (const auto &[k, v] : _base)
                obs(k, v);
        }

        const mapped_type &get(const key_type &k) const
        {
            static mapped_type empty {};
            if (const auto it = _base.find(k); it != _base.end())
                return it->second;
            return empty;
        }

        void set(const key_type &k, mapped_type v)
        {
            if (auto [it, created] = _base.try_emplace(k, std::move(v)); !created)
                it->second = std::move(v);
        }
    private:
        M &_base;
    };

    /*
     * This container is designed to keep updates separately from the main map so that they can be easily discarded.
     */
    template<typename M>
    struct update_map_t {
        using base_map_api_type = M;
        using key_type = typename M::key_type;
        using mapped_type = typename M::mapped_type;
        using observer_t = std::function<void(const key_type &k, const mapped_type &v)>;
        static_assert(has_empty_c<mapped_type>);
        static_assert(has_get_erase_set_c<M>);

        update_map_t(base_map_api_type base):
            _base { std::move(base) }
        {
        }

        bool empty() const
        {
            return _updates.empty();
        }

        void erase(const key_type &k)
        {
            set(k, {});
        }

        void foreach(const observer_t &obs) const
        {
            for (auto it = _updates.begin(); it != _updates.end(); ++it) {
                if (!it->second.empty())
                    obs(it->first, it->second);
            }
            _base.foreach([&](const auto &k, const auto &v) {
                if (!v.empty() && !_updates.contains(k))
                    obs(k, v);
            });
        }

        const mapped_type &get(const key_type &k) const
        {
            static mapped_type empty_val {};
            if (const auto it = _updates.find(k); it != _updates.end())
                return it->second;
            return _base.get(k);
        }

        mapped_type &get_mutable(const key_type &k)
        {
            auto &v = get(k);
            if (v.empty()) [[unlikely]]
                throw error("update_map_t::get_mutable requested a missing element!");
            return const_cast<mapped_type &>(v);
        }

        void set(const key_type &k, mapped_type v)
        {
            if (auto [it, created] = _updates.try_emplace(k, std::move(v)); !created)
                it->second = std::move(v);
        }

        void consume_from(update_map_t &&o)
        {
            if (&_base != &o._base) [[unlikely]]
                throw error("update_map_t::merge_from requires the argument to have the same base!");
            for (auto &&[k, upd]: o._updates) {
                set(k, std::move(upd));
            }
        }

        void commit()
        {
            for (auto it = _updates.begin(); it != _updates.end(); ++it) {
                if (!it->second.empty()) {
                    _base.set(it->first, std::move(it->second));
                } else {
                    _base.erase(it->first);
                }
            }
            _updates.clear();
        }

        void rollback()
        {
            _updates.clear();
        }
    private:
        base_map_api_type _base;
        std::map<key_type, mapped_type> _updates {};
    };
}