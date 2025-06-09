#pragma once
/* Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com) */

#include <map>
#include <ranges>
#include <boost/container/static_vector.hpp>

namespace turbo::container {
    template<typename T>
    concept has_empty_c = requires(T t)
    {
        { t.empty() };
    };

    template<typename BASE, size_t MAX_UPDATES=1>
    struct update_map_t {
        static constexpr size_t max_updates = MAX_UPDATES;
        using base_map_type = BASE;
        using key_type = typename BASE::key_type;
        using mapped_type = typename BASE::mapped_type;
        using version_type = boost::container::static_vector<mapped_type, MAX_UPDATES>;

        update_map_t(base_map_type &base):
            _base { base }
        {
        }

        void set(const key_type &k, mapped_type v)
        {
            auto [it, created] = _updates.try_emplace(k);
            if (it->second.size() == max_updates) [[unlikely]]
                throw error(fmt::format("update_map_t: trying to provide an update for a key that already has {} versions: {}", it->second.size(), k));
            it->second.emplace_back(std::move(v));
        }

        const mapped_type &get(const key_type &k) const
        {
            static mapped_type empty_val {};
            if (const auto &updates = get_updates(k); !updates.empty())
                return updates.back();
            if (const auto b_it = _base.find(k); b_it != _base.end())
                return b_it->second;
            return empty_val;
        }

        const version_type &get_updates(const key_type &k) const
        {
            static version_type empty_val {};
            if (const auto it = _updates.find(k); it != _updates.end()) {
                return it->second;
            }
            return empty_val;
        }

        void merge()
        {
            for (auto it = _updates.begin(); it != _updates.end(); ++it) {
                if (!it->second.back().empty()) {
                    _base[it->first] = std::move(it->second.back());
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
        std::map<key_type, version_type> _updates {};
    };
}