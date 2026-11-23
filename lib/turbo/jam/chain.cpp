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
        explicit impl(const std::string_view &id, const std::string_view &path, std::optional<reset_t> reset):
            _id{id},
            _path{path},
            _triedb{std::make_shared<triedb::db_t>(_triedb_path(path), !reset)},
            _state{_triedb}
        {
            if (reset) {
                _triedb->replace_with(reset->genesis.state);
                _genesis.slot = reset->genesis.header.slot;
                _genesis.header_hash = reset->genesis.header.hash();
                _genesis.state_root = reset->genesis.state.root();
                save_obj(_genesis_path(_path), _genesis);
                _ancestry = std::move(reset->ancestry);
                if (_ancestry.empty()) {
                    _ancestry.checks_enabled(false);
                    if (const auto &beta = _state.beta.unmodified(); !beta.history.empty()) {
                        const auto &tip = beta.history.back();
                        _ancestry.add(tip.slot, tip.header_hash, state_root());
                    } else {
                        _ancestry.add(reset->genesis.header.slot, reset->genesis.header.hash(), state_root());
                    }
                }
                _save_ancestry();
            } else {
                if (_triedb->size() == 0) [[unlikely]]
                    throw error{"an empty database must be initialized with a genesis state"};
                _genesis = load_obj<decltype(_genesis)>(_genesis_path(_path));
                _load_ancestry();
            }
        }

        ~impl() {
            logger::run_log_errors([&] {
                _save_ancestry();
            });
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
                _state.apply(blk, _ancestry.checks_enabled() ? retained_ancestry : ancestry_range_t<CFG>{});
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
            if (_ancestry.empty()) [[unlikely]]
                throw error{"internal error: the ancestry is empty!"};
            return _ancestry.view().back().header_hash;
        }

        [[nodiscard]] const std::string &path() const
        {
            return _path;
        }

        [[nodiscard]] const ancestry_item_triplet_t<CFG> &genesis() const
        {
            return _genesis;
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
        ancestry_item_triplet_t<CFG> _genesis;
        state_t<CFG> _state;
        ancestry_t<CFG> _ancestry{};

        static std::string _triedb_path(const std::filesystem::path &path) {
            return (std::filesystem::path{path} / "kv").string();
        }

        static std::string _ancestry_path(const std::filesystem::path &path) {
            return (std::filesystem::path{path} / "ancestry.bin").string();
        }

        static std::string _genesis_path(const std::filesystem::path &path) {
            return (std::filesystem::path{path} / "genesis.bin").string();
        }

        void _load_ancestry() {
            const auto path = _ancestry_path(_path);
            _ancestry = load_obj<decltype(_ancestry)>(path);
        }

        void _save_ancestry() {
            const auto path = _ancestry_path(_path);
            try {
                save_obj(path, _ancestry);
            } catch (...) {
                std::filesystem::remove(path);
                throw;
            }
        }
    };

    template<typename CFG>
    chain_t<CFG> chain_t<CFG>::from_json_spec(const std::string_view &path, const std::string &spec_path)
    {
        const auto j_cfg = codec::json::load(spec_path);
        auto state = state_dict_t::from_genesis_json(j_cfg.at("genesis_state").as_object());
        const auto state_root = state.root();
        auto header = jam::from_bytes<header_t<CFG>>(uint8_vector::from_hex(j_cfg.at("genesis_header").as_string()));
        ancestry_t<CFG> ancestry{};
        ancestry.add(header.slot, header.hash(), state_root);
        std::optional<reset_t> reset{};
        if (!std::filesystem::exists(path)) {
            reset.emplace(genesis_t{std::move(state), std::move(header)}, std::move(ancestry));
        }
        return chain_t{
            boost::json::value_to<std::string_view>(j_cfg.at("id")),
            path,
            std::move(reset)
        };
    }

    template<typename CFG>
    chain_t<CFG>::chain_t(const std::string_view &id, const std::string_view &path, std::optional<reset_t> reset):
        _impl{std::make_unique<impl>(id, path, std::move(reset))}
    {
    }

    template<typename CFG>
    chain_t<CFG>::~chain_t() = default;

    template<typename CFG>
    const ancestry_item_triplet_t<CFG> &chain_t<CFG>::genesis() const
    {
        return _impl->genesis();
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
