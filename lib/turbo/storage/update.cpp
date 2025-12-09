/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/logger.hpp>
#include "update.hpp"

namespace turbo::storage::update {
    void db_t::_set(const buffer key, value_t val)
    {
        logger::debug("storage::update::db: key #{} set to: {}", key, val);
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
}
