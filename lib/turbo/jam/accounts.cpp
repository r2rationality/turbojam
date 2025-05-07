/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/numeric-cast.hpp>
#include "turbo/crypto/blake2b.hpp"
#include "types/errors.hpp"
#include "types.hpp"

namespace turbo::jam {
    template<typename CONSTANTS>
    accounts_t<CONSTANTS> accounts_t<CONSTANTS>::apply(const time_slot_t<CONSTANTS> &slot, const preimages_extrinsic_t &preimages) const
    {
        auto new_accounts = *this;
        const preimage_t *prev = nullptr;
        for (const auto &p: preimages) {
            if (prev && *prev >= p) [[unlikely]]
                throw err_preimages_not_sorted_or_unique_t {};
            prev = &p;
            auto &acc = new_accounts.at(p.requester);
            lookup_met_map_key_t key;
            key.length = numeric_cast<decltype(lookup_met_map_key_t::length)>(p.blob.size());
            static_assert(sizeof(key.hash) == sizeof(crypto::blake2b::hash_t));
            crypto::blake2b::digest(*reinterpret_cast<crypto::blake2b::hash_t *>(&key.hash), p.blob);
            const auto meta_it = acc.lookup_metas.find(key);
            if (meta_it == acc.lookup_metas.end()) [[unlikely]]
                throw err_preimage_unneeded_t {};
            const auto [it, created] = acc.preimages.try_emplace(key.hash, p.blob);
            if (!created) [[unlikely]]
                throw err_preimage_unneeded_t {};
            meta_it->second.emplace_back(slot);
        }
        return new_accounts;
    }

    template struct accounts_t<config_prod>;
    template struct accounts_t<config_tiny>;
}
