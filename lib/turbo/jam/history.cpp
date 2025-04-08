/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include "types.hpp"

namespace turbo::jam {
    template<typename CONSTANTS>
    blocks_history_t<CONSTANTS> blocks_history_t<CONSTANTS>::from_bytes(codec::decoder &dec)
    {
        return base_type::template from_bytes<blocks_history_t<CONSTANTS>>(dec);
    }

    template<typename CONSTANTS>
    blocks_history_t<CONSTANTS> blocks_history_t<CONSTANTS>::from_json(const boost::json::value &j)
    {
        return base_type::template from_json<blocks_history_t<CONSTANTS>>(j);
    }

    template<typename CONSTANTS>
    blocks_history_t<CONSTANTS> blocks_history_t<CONSTANTS>::apply(const header_hash_t &hh, const state_root_t &sr, const opaque_hash_t &ar, const reported_work_seq_t &wp) const
    {
        static mmr_t empty_mmr {};
        const mmr_t &prev_mmr = base_type::empty() ? empty_mmr : base_type::at(base_type::size() - 1).mmr;
        block_info_t bi { hh, prev_mmr.append(ar), {}, wp };
        auto new_beta = *this;
        if (!new_beta.empty()) [[likely]]
            new_beta.back().state_root = sr;
        if (new_beta.size() == base_type::max_size) {
            for (size_t i = 1; i < new_beta.size(); ++i) {
                std::swap(new_beta[i - 1], new_beta[i]);
            }
            new_beta[base_type::max_size - 1] = std::move(bi);
        } else {
            new_beta.emplace_back(std::move(bi));
        }
        return new_beta;
    }

    template struct blocks_history_t<config_prod>;
    template struct blocks_history_t<config_tiny>;
}
