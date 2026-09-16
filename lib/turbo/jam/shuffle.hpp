#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <bit>
#include <optional>
#include <span>
#include <turbo/crypto/blake2b.hpp>

namespace turbo::jam::shuffle {
    static constexpr size_t entropy_size = 32;
    using entropy_t = std::span<const uint8_t, entropy_size>;

    struct digest_t {
        crypto::blake2b::hash_t digest;
        uint32_t segment_idx;
    };
    using digest_cache_t = std::optional<digest_t>;

    struct state_t {
        const entropy_t entropy;
        digest_cache_t cache{};
    };

    inline uint32_t uint32_from_entropy(state_t &st, const uint32_t i)
    {
        static_assert(std::endian::native == std::endian::little);
        static constexpr size_t uint_sz = sizeof(i);
        static_assert(uint_sz == 4, "uint must take 4 bytes");
        static constexpr size_t segment_sz = entropy_size / uint_sz;
        static_assert(segment_sz == 8, "segment size must be 8");
        const uint32_t seg_idx = i / segment_sz;
        if (!st.cache || st.cache->segment_idx != seg_idx) {
            byte_array<entropy_size + uint_sz> preimage;
            memcpy(preimage.data(), st.entropy.data(), st.entropy.size());
            memcpy(preimage.data() + st.entropy.size(), &seg_idx, sizeof(seg_idx));
            st.cache.emplace(crypto::blake2b::digest(preimage), seg_idx);
        }
        uint32_t res = 0;
        const size_t base = (i * uint_sz) % st.cache->digest.size();
        memcpy(&res, &st.cache->digest[base], uint_sz);
        return res;
    }

    inline uint32_t uint32_from_entropy(const entropy_t &entropy, const uint32_t i)
    {
        state_t st{entropy};
        return uint32_from_entropy(st, i);
    }

    template<typename T>
    void with_entropy_inplace(T &out, const entropy_t &entropy)
    {
        state_t st{entropy};
        for (size_t i = 0U; i + 1U < out.size(); ++i) {
            const auto tail_sz = out.size() - i;
            const auto next_idx = uint32_from_entropy(st, i) % tail_sz;
            std::swap(out[next_idx], out[tail_sz - 1]);
        }
        std::reverse(out.begin(), out.end());
    }

    template<typename T>
    T with_entropy(const T &in, const entropy_t &entropy)
    {
        T out { in };
        with_entropy_inplace(out, entropy);
        return out;
    }
}
