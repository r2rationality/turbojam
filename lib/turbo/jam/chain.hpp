#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <memory>
#include "state.hpp"

namespace turbo::jam {
    template<typename CONFIG>
    struct chain_t {
        static chain_t from_json_spec(const std::string_view &data_path, const std::string &spec_path);
        static header_t<CONFIG> make_genesis_header(const state_snapshot_t &genesis_state);

        chain_t(const std::string_view &id, const std::string_view &data_path, const state_snapshot_t &genesis_state, const state_snapshot_t &prev_state={});
        ~chain_t();
        [[nodiscard]] const std::string &id() const;
        [[nodiscard]] const std::string &path() const;
        [[nodiscard]] const header_t<CONFIG> &genesis_header() const;
        [[nodiscard]] const state_snapshot_t &genesis_state() const;
        [[nodiscard]] const state_t<CONFIG> &state() const;
        [[nodiscard]] state_root_t state_root() const;
        [[nodiscard]] header_hash_t parent() const;
        void apply(const block_t<CONFIG> &blk);
    private:
        struct impl;
        std::unique_ptr<impl> _impl;
    };
}