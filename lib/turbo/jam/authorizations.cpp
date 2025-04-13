/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <boost/json.hpp>
#include "types.hpp"

namespace turbo::jam {
    template<typename CONSTANTS>
    auth_pools_t<CONSTANTS> auth_pools_t<CONSTANTS>::apply(const time_slot_t<CONSTANTS> &slot, const core_authorizers_t &cas, const auth_queues_t<CONSTANTS> &phi) const
    {
        auto new_pools = *this;

        for (const auto &ca: cas) {
            auto &pool = new_pools.at(ca.core);
            auto pool_it = std::find(pool.begin(), pool.end(), ca.auth_hash);
            if (pool_it == pool.end()) [[unlikely]]
                throw error(fmt::format("a work report for core {} mentions an unknown auth_hash: {}", ca.core, ca.auth_hash));
            // remove the element and shift all elements after to make the final slot free
            pool.erase(pool_it);
        }

        for (size_t core = 0; core < new_pools.size(); ++core) {
            auto &pool = new_pools.at(core);
            if (pool.size() == pool.max_size)
                pool.erase(pool.begin());
            const auto &queue = phi.at(core);
            pool.emplace_back(queue.at(slot.slot() % queue.size()));
        }

        return new_pools;
    }

    template struct auth_pools_t<config_prod>;
    template struct auth_pools_t<config_tiny>;
}
