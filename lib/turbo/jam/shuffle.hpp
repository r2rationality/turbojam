#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <bit>
#include <span>
#include <turbo/crypto/blake2b.hpp>

namespace turbo::jam::shuffle {
    static constexpr size_t entropy_size = 32;
    using entropy_t = std::span<const uint8_t, entropy_size>;

    inline uint32_t uint32_from_entropy(const entropy_t &entropy, const uint32_t i)
    {
        static_assert(std::endian::native == std::endian::little);
        static constexpr size_t uint_sz = sizeof(i);
        static constexpr size_t segment_sz = entropy_size / uint_sz;
        byte_array<entropy_size + uint_sz> preimage;
        memcpy(preimage.data(), entropy.data(), entropy.size());
        const uint32_t seg_idx = i / segment_sz;
        memcpy(preimage.data() + entropy.size(), &seg_idx, sizeof(seg_idx));
        const auto entropy_i = crypto::blake2b::digest(preimage);
        uint32_t res = 0;
        const size_t base = (i * uint_sz) % entropy_i.size();
        for (size_t j = 0; j < uint_sz; ++j) {
            res |= static_cast<uint32_t>(entropy_i[base + j]) << (j * 8U);
        }
        return res;
    }

    template<typename T>
    T with_entropy(const T &in, const entropy_t &entropy)
    {
        T out { in };
        for (size_t i = 0; i < out.size(); ++i) {
            const auto tail_sz = out.size() - i;
            const auto next_idx = uint32_from_entropy(entropy, i) % tail_sz;
            std::swap(out[next_idx], out[tail_sz - 1]);
        }
        std::reverse(out.begin(), out.end());
        return out;
    }
}
