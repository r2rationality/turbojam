/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/crypto/keccak.hpp>
#include "types/common.hpp"

namespace turbo::jam {
    using hash_t = crypto::keccak::hash_t;

    // As defined in the JAM paper appendix E.2 but the hash function is hardcoded to be Keccak.
    void mmr_t::place(const size_t idx, const opaque_hash_t &h)
    {
        if (idx >= size()) {
            emplace_back(h);
        } else{
            auto &p = (*this)[idx];
            if (!p) {
                p.emplace(h);
            } else {
                const std::array<hash_t, 2U> hashes{*p, h};
                p.reset();
                place(idx + 1U, crypto::keccak::digest<opaque_hash_t>(buffer{reinterpret_cast<const uint8_t*>(&hashes), sizeof(hashes)}));
            }
        }
    }

    void mmr_t::append(const opaque_hash_t &h)
    {
        return place(0U, h);
    }

    static opaque_hash_t _superpeak(const std::span<const opaque_hash_t> peaks)
    {
        if (peaks.empty())
            return {};
        if (peaks.size() == 1U)
            return peaks.front();
        struct{
            char prefix[4];
            opaque_hash_t left;
            opaque_hash_t right;
        } const preimage{
            {'p', 'e', 'a', 'k'},
            _superpeak(peaks.subspan(0, peaks.size() - 1U)),
            peaks.back()
        };
        static_assert(sizeof(preimage) == 4U + 2U * sizeof(opaque_hash_t));
        opaque_hash_t res;
        crypto::keccak::digest(res, buffer{reinterpret_cast<const uint8_t*>(&preimage), sizeof(preimage)});
        return res;
    }

    // JAM Paper (E.10)
    opaque_hash_t mmr_t::root() const
    {
        std::vector<opaque_hash_t> h{};
        h.reserve(size());
        for (const auto &p: *this) {
            if (p)
                h.emplace_back(*p);
        }
        return _superpeak(h);
    }
}
