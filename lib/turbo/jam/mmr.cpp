/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/crypto/keccak.hpp>
#include "types/common.hpp"

namespace turbo::jam {
    using hash_t = crypto::keccak::hash_t;

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

    static opaque_hash_t _subroot(const std::vector<opaque_hash_t> &peaks, const size_t sz)
    {
        if (sz == 0)
            return {};
        if (sz == 1)
            return peaks[0];
        byte_array<4 + 2 * sizeof(opaque_hash_t)> msg;
        memcpy(msg.data(), "peak", 4);
        const auto sh = _subroot(peaks, sz - 1);
        static_assert(sizeof(sh) == sizeof(opaque_hash_t));
        memcpy(msg.data() + 4, sh.data(), sh.size());
        const auto &lh = peaks[sz - 1];
        static_assert(sizeof(lh) == sizeof(opaque_hash_t));
        memcpy(msg.data() + 4 + sh.size(), lh.data(), lh.size());
        opaque_hash_t res;
        crypto::keccak::digest(res, msg);
        return res;
    }

    // JAM Paper (E.10)
    opaque_hash_t mmr_t::root() const
    {
        std::vector<opaque_hash_t> peaks {};
        peaks.reserve(size());
        for (const auto &p: *this) {
            if (p)
                peaks.emplace_back(*p);
        }
        return _subroot(peaks, peaks.size());
    }
}
