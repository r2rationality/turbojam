/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include "chain.hpp"

namespace turbo::jam {
    template<typename CONFIG>
    chain_t<CONFIG> chain_t<CONFIG>::from_json_spec(const std::string &spec_path)
    {
        const auto j_cfg = codec::json::load(spec_path);
        auto genesis_state = state_dict_t::from_genesis_json(j_cfg.at("genesis_state").as_object());
        return {
            boost::json::value_to<std::string_view>(j_cfg.at("id")),
            std::move(genesis_state)
        };
    }

    template<typename CONFIG>
    header_t<CONFIG> chain_t<CONFIG>::make_genesis_header(const state_t<CONFIG> &genesis_state)
    {
        // Genesis Block Header expectations from here: https://docs.jamcha.in/basics/genesis-config
        header_t<CONFIG> h {};
        h.epoch_mark.emplace(
            genesis_state.eta[1],
            genesis_state.eta[2],
            genesis_state.gamma.k
        );
        h.author_index = 0xFFFFU;
        return h;
    }

    template<typename CONFIG>
    chain_t<CONFIG>::chain_t(const std::string_view &id, state_t<CONFIG> genesis_state, std::optional<state_t<CONFIG>> prev_state):
        _id { id },
        _genesis_state { std::move(genesis_state) },
        _genesis_header { make_genesis_header(_genesis_state) },
        _state { std::move(prev_state) }
    {
    }

    template<typename CONFIG>
    const state_t<CONFIG> &chain_t<CONFIG>::state() const
    {
        if (!_state) [[unlikely]]
            throw error("can't access the state before the chain has been fully initialized!");
        return *_state;
    }

    template<typename CONFIG>
    void chain_t<CONFIG>::apply(const block_t<CONFIG> &blk)
    {
        if (!_state) [[unlikely]] {
            //if (blk.header != _genesis_header) [[unlikely]]
             //   throw error("the genesis header does not match the genesis state!");
            _state.emplace(_genesis_state);
            _state->beta.clear();
            _state->update_history(blk.header.hash(), blk.header.parent_state_root, {}, {});
        } else {
            _state->apply(blk);
        }
    }

    template struct chain_t<config_prod>;
    template struct chain_t<config_tiny>;
}