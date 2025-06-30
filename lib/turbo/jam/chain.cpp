/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/logger.hpp>
#include <turbo/storage/filedb.hpp>
#include "chain.hpp"

namespace turbo::jam {
    template<typename CONFIG>
    struct chain_t<CONFIG>::impl {
        explicit impl(const std::string_view &id, const std::string_view &path, const state_snapshot_t &genesis_state, const state_snapshot_t &prev_state):
            _id { id },
            _path { path },
            _genesis_state { genesis_state },
            _genesis_header { make_genesis_header(_genesis_state) }
        {
            if (!prev_state.empty()) {
                _state.emplace(_triedb);
                *_state = prev_state;
            }
        }

        void apply(const block_t<CONFIG> &blk)
        {
            if (!_state) [[unlikely]] {
                if (blk.header.hash() != _genesis_header.hash()) [[unlikely]]
                   throw error("the genesis header does not match the genesis state!");
                _state.emplace(_triedb);
                *_state = _genesis_state;
                logger::run_log_errors_rethrow([&] {
                    _state->beta.set(state_t<CONFIG>::beta_prime({}, blk.header.hash(), {}, {}));
                });
            } else {
                _state->apply(blk);
            }
        }

        [[nodiscard]] const std::string &id() const
        {
            return _id;
        }

        [[nodiscard]] header_hash_t parent() const
        {
            if (_state) {
                if (const auto &beta = _state->beta.get(); !beta.empty())
                    return beta.back().header_hash;
            }
            return {};
        }

        [[nodiscard]] const std::string &path() const
        {
            return _path;
        }

        [[nodiscard]] const header_t<CONFIG> &genesis_header() const
        {
            return _genesis_header;
        }

        [[nodiscard]] const state_snapshot_t &genesis_state() const
        {
            return _genesis_state;
        }

        [[nodiscard]] const state_t<CONFIG> &state() const
        {
            if (!_state) [[unlikely]]
                throw error("chain is empty: no state is available!");
            return *_state;
        }

        [[nodiscard]] state_root_t state_root() const
        {
            if (_state) [[likely]]
                return _state->triedb->trie()->root();
            return {};
        }
    private:
        std::string _id;
        std::string _path;
        triedb::client_ptr_t _triedb = std::make_shared<triedb::client_t>((std::filesystem::path { _path } / "kv").string());
        state_snapshot_t _genesis_state;
        header_t<CONFIG> _genesis_header;
        std::optional<state_t<CONFIG>> _state {};
    };

    template<typename CONFIG>
    chain_t<CONFIG> chain_t<CONFIG>::from_json_spec(const std::string_view &path, const std::string &spec_path)
    {
        const auto j_cfg = codec::json::load(spec_path);
        auto genesis_state = state_dict_t::from_genesis_json(j_cfg.at("genesis_state").as_object());
        return {
            boost::json::value_to<std::string_view>(j_cfg.at("id")),
            path,
            std::move(genesis_state)
        };
    }

    template<typename CONFIG>
    header_t<CONFIG> chain_t<CONFIG>::make_genesis_header(const state_snapshot_t &genesis_state)
    {
        const file::tmp_directory tmp_store { "make-genesis-header" };
        state_t<CONFIG> g_state { std::make_shared<triedb::client_t>(tmp_store.path()) };
        g_state = genesis_state;
        // Genesis Block Header expectations from here: https://docs.jamcha.in/basics/genesis-config
        header_t<CONFIG> h {};
        h.epoch_mark.emplace(
            g_state.eta.get()[1],
            g_state.eta.get()[2],
            g_state.gamma.get().k
        );
        h.author_index = 0xFFFFU;
        return h;
    }

    template<typename CONFIG>
    chain_t<CONFIG>::chain_t(const std::string_view &id, const std::string_view &path, const state_snapshot_t &genesis_state, const state_snapshot_t &prev_state):
        _impl { std::make_unique<impl>(id, path, genesis_state, prev_state) }
    {
    }

    template<typename CONFIG>
    chain_t<CONFIG>::~chain_t() = default;

    template<typename CONFIG>
    const header_t<CONFIG> &chain_t<CONFIG>::genesis_header() const
    {
        return _impl->genesis_header();
    }

    template<typename CONFIG>
    const state_snapshot_t &chain_t<CONFIG>::genesis_state() const
    {
        return _impl->genesis_state();
    }

    template<typename CONFIG>
    const std::string &chain_t<CONFIG>::id() const
    {
        return _impl->id();
    }

    template<typename CONFIG>
    const std::string &chain_t<CONFIG>::path() const
    {
        return _impl->path();
    }

    template<typename CONFIG>
    header_hash_t chain_t<CONFIG>::parent() const
    {
        return _impl->parent();
    }

    template<typename CONFIG>
    const state_t<CONFIG> &chain_t<CONFIG>::state() const
    {
        return _impl->state();
    }

    template<typename CONFIG>
    state_root_t chain_t<CONFIG>::state_root() const
    {
        return _impl->state_root();
    }

    template<typename CONFIG>
    void chain_t<CONFIG>::apply(const block_t<CONFIG> &blk)
    {
        _impl->apply(blk);
    }

    template struct chain_t<config_prod>;
    template struct chain_t<config_tiny>;
}