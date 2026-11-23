#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <memory>
#include "state.hpp"

namespace turbo::jam {
    template<typename CFG>
    struct genesis_t {
        state_snapshot_t state;
        header_t<CFG> header;

        genesis_t(state_snapshot_t snapshot, header_t<CFG> header):
            state{std::move(snapshot)},
            header{std::move(header)}
        {
        }

        genesis_t(state_snapshot_t snapshot):
            state{std::move(snapshot)},
            header{state_t<CFG>::make_genesis_header(state, 0)}
        {
        }
    };

    template<typename CFG>
    struct chain_t {
        struct reset_t {
            genesis_t<CFG> genesis;
            ancestry_t<CFG> ancestry{};
        };

        static chain_t from_json_spec(const std::string_view &data_path, const std::string &spec_path);

        explicit chain_t(const std::string_view &id, const std::string_view &data_path, std::optional<reset_t> reset={});
        ~chain_t();
        [[nodiscard]] const std::string &id() const;
        [[nodiscard]] const std::string &path() const;
        [[nodiscard]] const ancestry_item_triplet_t<CFG> &genesis() const;
        [[nodiscard]] const state_t<CFG> &state() const;
        [[nodiscard]] state_root_t state_root() const;
        [[nodiscard]] header_hash_t parent() const;
        [[nodiscard]] size_t trie_size() const;
        void apply(const block_t<CFG> &blk);
    private:
        struct impl;
        std::unique_ptr<impl> _impl;
    };
}
