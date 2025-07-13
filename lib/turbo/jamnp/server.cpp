/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/crypto/blake2b.hpp>
#include "server.hpp"

namespace turbo::jamnp {
    using namespace std::string_view_literals;

    [[nodiscard]] byte_array<32> dev_trivial_seed(uint32_t i)
    {
        static_assert(std::endian::native == std::endian::little);
        byte_array<32> seed;
        for (size_t j = 0; j < sizeof(seed) / sizeof(i); ++j) {
            memcpy(seed.data() + j * sizeof(i), &i, sizeof(i));
        }
        return seed;
    }

    [[nodiscard]] secure_byte_array<32> dev_secret_seed(const buffer prefix, const buffer input_seed)
    {
        uint8_vector seed {};
        seed << prefix << input_seed;
        return crypto::blake2b::digest<secure_byte_array<32>>(seed);
    }

    [[nodiscard]] crypto::ed25519::key_pair_t dev_ed25519(const buffer input_seed)
    {
        const auto secret_seed = dev_secret_seed("jam_val_key_ed25519"sv, input_seed);
        return crypto::ed25519::create_from_seed(secret_seed);
    }
}