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

    uint32_t uint32_from_entropy(const entropy_t &entropy, const uint32_t i)
    {
        static_assert(std::endian::native == std::endian::little);
        static constexpr size_t uint_sz = sizeof(i);
        static constexpr size_t segment_sz = entropy_size / uint_sz;
        byte_array<entropy_size + uint_sz> preimage;
        memcpy(preimage.data(), entropy.data(), entropy.size());
        const auto seg_idx = i / segment_sz;
        memcpy(preimage.data() + entropy.size(), &seg_idx, sizeof(seg_idx));
        const auto entropy_i alignas(4) = crypto::blake2b::digest(preimage);
        const auto res_buf = static_cast<buffer>(entropy_i).subbuf((i * uint_sz) % entropy.size(), uint_sz);
        return res_buf.to<uint32_t>();
    }

    template<typename T>
    T with_entropy(const T &in, const entropy_t &entropy)
    {
        T out { in };
        for (size_t i = 0; i < out.size(); ++i) {
            const auto next_idx = uint32_from_entropy(entropy, i) % (out.size() - i);
            std::swap(out[i], out[i + next_idx]);
        }
        return out;
    }
}
