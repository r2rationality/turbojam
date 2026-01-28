/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/logger.hpp>
#include <turbo/storage/file.hpp>
#include "chain.hpp"

#include "cli/fuzzer.hpp"

namespace turbo::jam {
    template<typename CFG>
    struct chain_t<CFG>::impl {
        explicit impl(const std::string_view &id, const std::string_view &path, const state_snapshot_t &genesis_state,
            const state_snapshot_t &prev_state, std::optional<ancestry_t<CFG>> ancestry):
            _id{id},
            _path{path},
            _genesis_state{genesis_state}
        {
            if (ancestry)
                _ancestry = std::move(*ancestry);
            if (!prev_state.empty()) {
                _state.emplace(_updatedb);
                *_state = prev_state;
                _updatedb->commit();
                const auto &beta = _state->beta.get();
                for (const auto &h: beta.history) {
                    _ancestry.add(h.header_hash);
                }
            }
        }

        void apply(const block_t<CFG> &blk)
        {
            const auto blk_hash = blk.header.hash();
            std::optional<storage::update::undo_redo_t> undo_redo{};
            if (!_state) [[unlikely]] {
                _state.emplace(_updatedb);
                *_state = _genesis_state;
                const auto genesis_header = _state->make_genesis_header();
                if (blk_hash != genesis_header.hash()) [[unlikely]]
                   throw error("the genesis header does not match the genesis state!");
                logger::run_log_errors_rethrow([&] {
                    state_t<CFG>::beta_prime(_state->beta.update(), blk.header.hash(), {}, {});
                    _state->beta.commit();
                });
                _updatedb->commit();
            } else {
                _updatedb->reset();
                const auto new_ancestry_end = _ancestry.known(blk.header.parent);
                for (auto &ancestor: std::views::reverse(std::span{new_ancestry_end, _ancestry.end()})) {
                    if (!ancestor.undo_redo) [[unlikely]]
                        throw error(fmt::format("can't rollback block {} due to missing undo record", ancestor.header_hash));
                    for (auto &&[k, v]: ancestor.undo_redo->undo)
                        _updatedb->apply(k, v);
                }
                _state->apply(blk, std::span{_ancestry.begin(), new_ancestry_end});
                undo_redo = _updatedb->commit();
                _ancestry.erase(new_ancestry_end, _ancestry.end());
            }
            _ancestry.add(blk.header.slot, blk_hash, std::move(undo_redo));
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
            return _triedb->root();
        }
    private:
        std::string _id;
        std::string _path;
        triedb::db_ptr_t _triedb = std::make_shared<triedb::db_t>((std::filesystem::path{_path} / "kv").string());
        storage::update::db_ptr_t _updatedb = std::make_shared<storage::update::db_t>(_triedb);
        state_snapshot_t _genesis_state;
        header_t<CFG> _genesis_header;
        std::optional<state_t<CFG>> _state{};
        std::map<header_hash_t, storage::update::update_map_t> _rollback_state{};
        ancestry_t<CFG> _ancestry{};
    };

    template<typename CFG>
    chain_t<CFG> chain_t<CFG>::from_json_spec(const std::string_view &path, const std::string &spec_path)
    {
        const auto j_cfg = codec::json::load(spec_path);
        auto genesis_state = state_dict_t::from_genesis_json(j_cfg.at("genesis_state").as_object());
        return chain_t{
            boost::json::value_to<std::string_view>(j_cfg.at("id")),
            path,
            std::move(genesis_state)
        };
    }

    template<typename CFG>
    chain_t<CFG>::chain_t(const std::string_view &id, const std::string_view &path, const state_snapshot_t &genesis_state,
        const state_snapshot_t &prev_state, std::optional<ancestry_t<CFG>> ancestry):
        _impl{std::make_unique<impl>(id, path, genesis_state, prev_state, std::move(ancestry))}
    {
    }

    template<typename CFG>
    chain_t<CFG>::~chain_t() = default;

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
