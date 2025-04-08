/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/numeric-cast.hpp>
#include "preimages.hpp"
#include "types.hpp"
#include "turbo/crypto/blake2b.hpp"

namespace turbo::jam {
    template<typename CONSTANTS>
    account_t<CONSTANTS> account_t<CONSTANTS>::from_bytes(codec::decoder &dec)
    {
        return {
            dec.decode<decltype(preimages)>(),
            dec.decode<decltype(lookup_metas)>()
        };
    }

    template<typename CONSTANTS>
    account_t<CONSTANTS> account_t<CONSTANTS>::from_json(const boost::json::value &j)
    {
        return {
            decltype(preimages)::from_json(j.at("preimages"), "hash", "blob"),
            decltype(lookup_metas)::from_json(j.at("lookup_metas"), "key", "value")
        };
    }

    template<typename CONSTANTS>
    bool account_t<CONSTANTS>::operator==(const account_t<CONSTANTS> &o) const
    {
        return preimages == o.preimages
            && lookup_metas == o.lookup_metas;
    }

    template struct account_t<config_prod>;
    template struct account_t<config_tiny>;

    template<typename CONSTANTS>
    accounts_t<CONSTANTS> accounts_t<CONSTANTS>::from_bytes(codec::decoder &dec)
    {
        return base_type::template from_bytes<accounts_t<CONSTANTS>>(dec);
    }

    template<typename CONSTANTS>
    accounts_t<CONSTANTS> accounts_t<CONSTANTS>::from_json(const boost::json::value &j)
    {
        return base_type::template from_json<accounts_t>(j, "id", "data");
    }

    template<typename CONSTANTS>
    accounts_t<CONSTANTS> accounts_t<CONSTANTS>::apply(const time_slot_t<CONSTANTS> &slot, const preimages_extrinsic_t &preimages) const
    {
        auto new_accounts = *this;
        const preimage_t *prev = nullptr;
        for (const auto &p: preimages) {
            if (prev && *prev >= p) [[unlikely]]
                throw err_preimages_not_sorted_or_unique_t("a preimage is out of order or not unique!");
            prev = &p;
            auto &acc = new_accounts.at(p.requester);
            lookup_met_map_key_t key;
            key.length = numeric_cast<decltype(lookup_met_map_key_t::length)>(p.blob.size());
            static_assert(sizeof(key.hash) == sizeof(crypto::blake2b::hash_t));
            crypto::blake2b::digest(*reinterpret_cast<crypto::blake2b::hash_t *>(&key.hash), p.blob);
            const auto meta_it = acc.lookup_metas.find(key);
            if (meta_it == acc.lookup_metas.end()) [[unlikely]]
                throw err_preimage_unneeded_t(fmt::format("a preimage for an unexpected hash {} and length {}", key.hash, key.length));
            const auto [it, created] = acc.preimages.try_emplace(key.hash, p.blob);
            if (!created) [[unlikely]]
                throw err_preimage_unneeded_t(fmt::format("a duplicate preimage for hash {} and length {}", key.hash, key.length));
            meta_it->second.emplace_back(slot);
        }
        return new_accounts;
    }

    template struct accounts_t<config_prod>;
    template struct accounts_t<config_tiny>;
}
