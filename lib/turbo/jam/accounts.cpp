/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/numeric-cast.hpp>
#include "preimages.hpp"
#include "types.hpp"
#include "turbo/crypto/blake2b.hpp"

namespace turbo::jam {
    account_t account_t::from_bytes(codec::decoder &dec)
    {
        return {
            dec.decode<decltype(preimages)>(),
            dec.decode<decltype(lookup_metas)>()
        };
    }

    account_t account_t::from_json(const boost::json::value &j)
    {
        return {
            decltype(preimages)::from_json(j.at("preimages"), "hash", "blob"),
            decltype(lookup_metas)::from_json(j.at("lookup_metas"), "key", "value")
        };
    }

    bool account_t::operator==(const account_t &o) const
    {
        return preimages == o.preimages
            && lookup_metas == o.lookup_metas;
    }

    accounts_t accounts_t::from_bytes(codec::decoder &dec)
    {
        return base_type::from_bytes<accounts_t>(dec);
    }

    accounts_t accounts_t::from_json(const boost::json::value &j)
    {
        return base_type::from_json<accounts_t>(j, "id", "data");
    }

    accounts_t accounts_t::apply(time_slot_t slot, const preimages_extrinsic_t &preimages) const
    {
        auto new_accounts = *this;
        const preimage_t *prev = nullptr;
        for (const auto &p: preimages) {
            if (prev && *prev >= p) [[unlikely]]
                throw err_preimages_not_sorted_or_unique_t("a preimage is out of order or not unique!");
            prev = &p;
            auto &acc = new_accounts.at(p.requester);
            lookup_met_map_key_t key { .length=numeric_cast<decltype(lookup_met_map_key_t::length)>(p.blob.size()) };
            static_assert(sizeof(key.hash) == sizeof(crypto::blake2b::hash_t));
            crypto::blake2b::digest(*reinterpret_cast<crypto::blake2b::hash_t *>(&key.hash), p.blob);
            if (const auto it = acc.lookup_metas.find(key); it == acc.lookup_metas.end()) [[unlikely]]
                throw err_preimage_unneeded_t(fmt::format("a preimage for an unexpected hash {} and length {}", key.hash, key.length));
            const auto [it, created] = acc.preimages.try_emplace(key.hash, p.blob);
            if (!created) [[unlikely]]
                throw err_preimage_unneeded_t(fmt::format("a duplicate preimage for hash {} and length {}", key.hash, key.length));
        }
        return new_accounts;
    }
}
