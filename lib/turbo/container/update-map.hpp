#pragma once
/* Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com) */

#include <map>
#include <ranges>
#include <boost/container/static_vector.hpp>
#include <turbo/common/error.hpp>
#include <turbo/common/format.hpp>

namespace turbo::container {
    template<typename T>
    concept has_empty_c = requires(T t)
    {
        { t.empty() };
    };

    /*
     * This container is designed to keep updates separately from the main map so that they can be easily discarded.
     */
    template<typename BASE>
    struct update_map_t {
        using base_map_type = BASE;
        using key_type = typename BASE::key_type;
        using mapped_type = typename BASE::mapped_type;
        static_assert(has_empty_c<mapped_type>);

        update_map_t(base_map_type &base):
            _base { base }
        {
        }

        void set(const key_type &k, mapped_type v)
        {
            auto [it, created] = _updates.try_emplace(k, std::move(v));
            if (!created)
                it->second = std::move(v);
        }

        const mapped_type &get(const key_type &k) const
        {
            static mapped_type empty_val {};
            if (const auto it = _updates.find(k); it != _updates.end())
                return it->second;
            if (const auto b_it = _base.find(k); b_it != _base.end())
                return b_it->second;
            return empty_val;
        }

        void merge_from(update_map_t &&o)
        {
            if (&_base != &o._base) [[unlikely]]
                throw error("update_map_t::merge_from requires the argument to have the same base!");
            for (auto &&[k, upd]: o._updates) {
                set(k, std::move(upd));
            }
        }

        void merge()
        {
            for (auto it = _updates.begin(); it != _updates.end(); ++it) {
                if (!it->second.empty()) {
                    _base[it->first] = std::move(it->second);
                } else if (const auto b_it = _base.find(it->first); b_it != _base.end()) {
                    _base.erase(b_it);
                }
            }
            _updates.clear();
        }

        void revert()
        {
            _updates.clear();
        }
    private:
        base_map_type &_base;
        std::map<key_type, mapped_type> _updates {};
    };
}