#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/jam/types/s04-overview.hpp>

namespace turbo::jam {
    template<typename CONFIG>
    struct chain_t {
        static chain_t from_json_spec(const std::string &spec_path);
        static header_t<CONFIG> make_genesis_header(const state_t<CONFIG> &genesis_state);

        chain_t(const std::string_view &id, state_t<CONFIG> genesis_state, std::optional<state_t<CONFIG>> prev_state={});
        [[nodiscard]] const std::string &id() const { return _id; }
        [[nodiscard]] const header_t<CONFIG> &genesis_header() const { return _genesis_header; }
        [[nodiscard]] const state_t<CONFIG> &genesis_state() const { return _genesis_state; }
        [[nodiscard]] const state_t<CONFIG> &state() const;
        void apply(const block_t<CONFIG> &blk);
    private:
        std::string _id;
        state_t<CONFIG> _genesis_state;
        header_t<CONFIG> _genesis_header;
        std::optional<state_t<CONFIG>> _state {};
    };
}