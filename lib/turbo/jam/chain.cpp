/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/storage/common.hpp>
#include "chain.hpp"
#include "triedb.hpp"

namespace turbo::jam {
    template<typename CFG>
    struct chain_t<CFG>::impl {
        explicit impl(const std::string_view &id, const std::string_view &path, genesis_t<CFG> genesis,
            std::optional<reset_t> reset):
            _id{id},
            _path{path},
            _triedb{std::make_shared<triedb::db_t>((std::filesystem::path{path} / "kv").string(), !reset)},
            _genesis_state{std::move(genesis.state)},
            _genesis_header{std::move(genesis.header)},
            _state{_triedb}
        {
            if (reset) {
                if (reset->state.empty() && !reset->ancestry.empty()) [[unlikely]]
                    throw error{"chain reset ancestry requires a state snapshot"};
                _triedb->replace_with(reset->empty() ? _genesis_state : reset->state);
                _ancestry = std::move(reset->ancestry);
            } else if (_triedb->size() == 0) {
                _triedb->replace_with(_genesis_state);
            }
            if (_ancestry.empty()) {
                const auto genesis_hash = _genesis_header.hash();
                _ancestry.add(_genesis_header.slot, genesis_hash, _genesis_state.root());
                const auto &beta = _state.beta.unmodified();
                const auto restored_root = state_root();
                // Beta's newest entry has a placeholder root until the next block.
                for (const auto &[i, h]: std::views::enumerate(beta.history)) {
                    if (h.header_hash != genesis_hash)
                        _ancestry.add(h.slot, h.header_hash, std::cmp_equal(i + 1, beta.history.size()) ? restored_root : h.state_root);
                }
            }
        }

        void apply(const block_t<CFG> &blk)
        {
            const auto blk_hash = blk.header.hash();
            try {
                const auto new_ancestry_end = _ancestry.known(blk.header.parent, blk.header.parent_state_root);
                const ancestry_range_t<CFG> retained_ancestry{_ancestry.begin(), new_ancestry_end};
                size_t undo_fork_point = 0;
                if (new_ancestry_end != _ancestry.end()) {
                    for (const auto &ancestor: std::views::reverse(ancestry_range_t<CFG>{new_ancestry_end, _ancestry.end()})) {
                        if (!ancestor.undo) [[unlikely]]
                            throw error{"can't rollback block {} due to missing undo record", ancestor.header_hash};
                        // Preserve the undo record if applying it fails.
                        for (const auto &[k, v]: *ancestor.undo | std::views::reverse)
                            _triedb->apply(k, v);
                    }
                    _state.reset_cache();
                    // Earlier writes restore ancestors; later writes belong to the new block.
                    undo_fork_point = _triedb->undo_size();
                } else {
                    const auto local_state_root = state_root();
                    if (local_state_root != blk.header.parent_state_root) [[unlikely]]
                        throw err_bad_state_root_t{};
                }
                _state.apply(blk, retained_ancestry);
                _state.stage();
                auto undo = _triedb->commit();
                _state.accept();
                if (undo_fork_point > 0)
                    undo.erase(undo.begin(), undo.begin() + static_cast<std::ptrdiff_t>(undo_fork_point));
                _ancestry.truncate(retained_ancestry.size());
                _ancestry.add(blk.header.slot, blk_hash, state_root(), std::move(undo));
            } catch (...) {
                _state.rollback();
                _triedb->rollback();
                throw;
            }
        }

        [[nodiscard]] const std::string &id() const
        {
            return _id;
        }

        [[nodiscard]] header_hash_t parent() const
        {
            if (const auto &beta = _state.beta.unmodified(); !beta.history.empty())
                return beta.history.back().header_hash;
            return _genesis_header.hash();
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
            return _state;
        }

        [[nodiscard]] state_root_t state_root() const
        {
            return _triedb->root();
        }

        [[nodiscard]] size_t trie_size() const
        {
            return _triedb->size();
        }
    private:
        std::string _id;
        std::string _path;
        triedb::db_ptr_t _triedb;
        state_snapshot_t _genesis_state;
        header_t<CFG> _genesis_header;
        state_t<CFG> _state;
        ancestry_t<CFG> _ancestry{};
    };

    template<typename CFG>
    chain_t<CFG> chain_t<CFG>::from_json_spec(const std::string_view &path, const std::string &spec_path)
    {
        const auto j_cfg = codec::json::load(spec_path);
        return chain_t{
            boost::json::value_to<std::string_view>(j_cfg.at("id")),
            path,
            genesis_t<CFG>{
                state_dict_t::from_genesis_json(j_cfg.at("genesis_state").as_object()),
                jam::from_bytes<header_t<CFG>>(uint8_vector::from_hex(j_cfg.at("genesis_header").as_string()))
            }
        };
    }

    template<typename CFG>
    chain_t<CFG>::chain_t(const std::string_view &id, const std::string_view &path, genesis_t<CFG> genesis,
        std::optional<reset_t> reset):
        _impl{std::make_unique<impl>(id, path, std::move(genesis), std::move(reset))}
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
    const header_t<CFG> &chain_t<CFG>::genesis_header() const
    {
        return _impl->genesis_header();
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
    size_t chain_t<CFG>::trie_size() const
    {
        return _impl->trie_size();
    }

    template<typename CFG>
    void chain_t<CFG>::apply(const block_t<CFG> &blk)
    {
        _impl->apply(blk);
    }

    template struct chain_t<config_prod>;
    template struct chain_t<config_tiny>;
    template struct chain_t<config_fuzz>;
}
