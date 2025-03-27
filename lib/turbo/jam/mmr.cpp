/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/crypto/keccak.hpp>
#include "types.hpp"

namespace turbo::jam {
    using hash_t = crypto::keccak::hash_t;

    mmr_t mmr_t::from_bytes(codec::decoder &dec)
    {
        return base_type::from_bytes<mmr_t>(dec);
    }

    mmr_t mmr_t::from_json(const boost::json::value &j)
    {
        return base_type::from_json<mmr_t>(j);
    }

    static mmr_t replace(const mmr_t &r, size_t i, const mmr_peak_t &v)
    {
        if (i >= r.size()) [[unlikely]]
            throw error(fmt::format("mmr_r: index {} is out of range [0;{})", i, r.size()));
        auto new_r = r;
        new_r[i] = v;
        return new_r;
    }

    // As defined in the JAM paper appendix E.2 but the ash function is hardcoded to be Blake2b.
    static mmr_t place(const mmr_t &r, const hash_t &l, const size_t n)
    {
        if (n > r.size()) [[unlikely]]
            throw error(fmt::format("unexpected index {} for the size of {}", n, r.size()));
        if (n == r.size()) {
            auto new_r = r;
            new_r.emplace_back(l);
            return new_r;
        }
        if (n < r.size() && !r[n]) {
            return replace(r, n, mmr_peak_t { l });
        }
        std::array<hash_t, 2> hashes {};
        hashes[0] = *r[n];
        hashes[1] = l;
        return place(replace(r, n, {}), crypto::keccak::digest(buffer { reinterpret_cast<const uint8_t*>(hashes.data()), sizeof(opaque_hash_t) * hashes.size() }), n + 1);
    }

    mmr_t mmr_t::append(const opaque_hash_t &l) const
    {
        return place(*this, l, 0);
    }
}
