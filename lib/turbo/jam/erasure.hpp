#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <erasure-coding.hpp>
#include "types/common.hpp"

namespace turbo::jam::erasure {
    inline uint8_vector transpose(const size_t num_shards, const buffer data)
    {
        const auto num_pairs = (data.size() + 1U) >> 1U;
        const auto piece_size = num_shards / 3U + 1U; // # pairs
        const auto num_pieces = (num_pairs + piece_size - 1U) / piece_size;
        uint8_vector res(num_pieces * piece_size << 1U);
        for (size_t i = 0; i < data.size(); i += 2U) {
            const auto pair_idx = i >> 1U;
            const auto ci = pair_idx / piece_size;
            const auto ri = pair_idx % piece_size;
            const auto res_idx = ri * num_pieces + ci;
            const auto res_off = res_idx << 1U;
            res[res_off] = data[i];
            if (i + 1U < data.size()) [[likely]]
                res[res_off + 1U] = data[i + 1U];
        }
        return res;
    }
}
