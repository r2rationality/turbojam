/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/logger.hpp>
#include <turbo/storage/file.hpp>
#include "chain.hpp"

namespace turbo::jam {
    template<typename CFG>
    struct chain_t<CFG>::impl {
        explicit impl(const std::string_view &id, const std::string_view &path, const state_snapshot_t &genesis_state, const state_snapshot_t &prev_state):
            _id{id},
            _path{path},
            _genesis_state{genesis_state}
        {
            if (!prev_state.empty()) {
                _state.emplace(_triedb);
                *_state = prev_state;
            }
        }

        void add_to_ancestry(const time_slot_t<CFG> &blk_slot, const header_hash_t &blk_hash)
        {
            // a duplicate check for monotonicity to ensure even initialized data comes in sorted to make binary search work
            if (!_ancestry.empty() && _ancestry.back().slot >= blk_slot) [[unlikely]]
                throw error(fmt::format("out of order ancestry block: {} comes after {}", blk_slot, _ancestry.back().slot));
            _ancestry.emplace_back(blk_slot, blk_hash);
        }

        void add_to_ancestry(const ancestry_t<CFG> &ancestry)
        {
            _ancestry.reserve(_ancestry.size() + ancestry.size());
            for (const auto &[slot, hash]: ancestry)
                add_to_ancestry(slot, hash);
        }

        void apply(const block_t<CFG> &blk)
        {
            const auto blk_hash = blk.header.hash();
            if (!_state) [[unlikely]] {
                _state.emplace(_triedb);
                *_state = _genesis_state;
                const auto genesis_header = _state->make_genesis_header();
                if (blk_hash != genesis_header.hash()) [[unlikely]]
                   throw error("the genesis header does not match the genesis state!");
                logger::run_log_errors_rethrow([&] {
                    state_t<CFG>::beta_prime(_state->beta.update(), blk.header.hash(), {}, {});
                    _state->beta.commit();
                });
            } else {
                _state->apply(blk, _ancestry);
            }
            add_to_ancestry(blk.header.slot, blk_hash);
        }

        [[nodiscard]] const std::string &id() const
        {
            return _id;
        }

        [[nodiscard]] header_hash_t parent() const
        {
            if (_state) {
                if (const auto &beta = _state->beta.get(); !beta.history.empty())
                    return beta.history.back().header_hash;
            }
            return {};
        }

        [[nodiscard]] const std::string &path() const
        {
            return _path;
        }

        [[nodiscard]] const header_t<CFG> &genesis_header() const
        {
            return _genesis_header;
        }

        [[nodiscard]] const state_snapshot_t &genesis_state() const
        {
            return _genesis_state;
        }

        [[nodiscard]] const state_t<CFG> &state() const
        {
            if (!_state) [[unlikely]]
                throw error("chain is empty: no state is available!");
            return *_state;
        }

        [[nodiscard]] state_root_t state_root() const
        {
            if (_state) [[likely]]
                return _state->root();
            return {};
        }
    private:
        std::string _id;
        std::string _path;
        triedb::db_ptr_t _triedb = std::make_shared<triedb::db_t>((std::filesystem::path { _path } / "kv").string());
        state_snapshot_t _genesis_state;
        header_t<CFG> _genesis_header;
        std::optional<state_t<CFG>> _state{};
        ancestry_t<CFG> _ancestry{};
    };

    template<typename CFG>
    chain_t<CFG> chain_t<CFG>::from_json_spec(const std::string_view &path, const std::string &spec_path)
    {
        const auto j_cfg = codec::json::load(spec_path);
        auto genesis_state = state_dict_t::from_genesis_json(j_cfg.at("genesis_state").as_object());
        return {
            boost::json::value_to<std::string_view>(j_cfg.at("id")),
            path,
            std::move(genesis_state)
        };
    }

    template<typename CFG>
    chain_t<CFG>::chain_t(const std::string_view &id, const std::string_view &path, const state_snapshot_t &genesis_state, const state_snapshot_t &prev_state):
        _impl { std::make_unique<impl>(id, path, genesis_state, prev_state) }
    {
    }

    template<typename CFG>
    chain_t<CFG>::~chain_t() = default;

    template<typename CFG>
    void chain_t<CFG>::add_to_ancestry(const ancestry_t<CFG> &ancestry)
    {
        _impl->add_to_ancestry(ancestry);
    }

    template<typename CFG>
    const state_snapshot_t &chain_t<CFG>::genesis_state() const
    {
        return _impl->genesis_state();
    }

    template<typename CFG>
    const std::string &chain_t<CFG>::id() const
    {
        return _impl->id();
    }

    template<typename CFG>
    const std::string &chain_t<CFG>::path() const
    {
        return _impl->path();
    }

    template<typename CFG>
    header_hash_t chain_t<CFG>::parent() const
    {
        return _impl->parent();
    }

    template<typename CFG>
    const state_t<CFG> &chain_t<CFG>::state() const
    {
        return _impl->state();
    }

    template<typename CFG>
    state_root_t chain_t<CFG>::state_root() const
    {
        return _impl->state_root();
    }

    template<typename CFG>
    void chain_t<CFG>::apply(const block_t<CFG> &blk)
    {
        _impl->apply(blk);
    }

    template struct chain_t<config_prod>;
    template struct chain_t<config_tiny>;
}