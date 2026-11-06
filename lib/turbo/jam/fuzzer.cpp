/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/memory.hpp>
#include <turbo/jam/chain.hpp>
#include "fuzzer.hpp"

namespace turbo::jam::fuzzer {
    template<typename CFG>
    initialize_t<CFG> initialize_t<CFG>::from_snapshot(const state_snapshot_t &snap, const genesis_t<CFG> &genesis)
    {
        ancestry_t<CFG> ancestry;
        const auto beta = jam::from_bytes<typename decltype(state_t<CFG>::beta)::element_type>(snap.at(state_dict_t::make_key(3)));
        const auto snapshot_root = snap.root();
        const auto genesis_hash = genesis.header.hash();
        if (genesis.header.slot != 0) [[unlikely]]
            throw error{"genesis header slot must be 0 but got: {}", genesis.header.slot};
        if (beta.history.empty()) {
            const auto genesis_root = genesis.state.root();
            if (snapshot_root != genesis_root) [[unlikely]]
                throw error{"initial snapshot with empty history does not match the supplied genesis state"};
            ancestry.add(genesis.header.slot, genesis_hash, genesis_root);
        } else {
            // current fuzzer configuration does not always provide a full genesis state, so the state_root check must be skipped in such cases
            if (beta.history.front().slot > 0)
                ancestry.add(genesis.header.slot, genesis_hash);
            else if (const auto beta0_hash = beta.history.front().header_hash; beta0_hash != genesis_hash) [[unlikely]]
                throw error{"beta provided genesis hash {} does not match the supplied genesis header's one {}", beta0_hash, genesis_hash};
        }
        for (const auto &[i, h]: std::views::enumerate(beta.history)) {
            ancestry.add(h.slot, h.header_hash, std::cmp_equal(i + 1, beta.history.size()) ? snapshot_root : h.state_root);
        }
        return {genesis.header, snap, std::move(ancestry)};
    }

    template struct initialize_t<config_prod>;
    template struct initialize_t<config_tiny>;

    template<typename CFG>
    struct local_processor_t<CFG>::impl_t {
        impl_t(std::string &&chain_id, const std::string_view chain_dir):
            _chain_id{std::move(chain_id)},
            _chain_dir{chain_dir}
        {
        }

        message_t<CFG> process(message_t<CFG> &&msg)
        {
            if (const auto now = std::chrono::steady_clock::now(); now >= _next_info) {
                _next_info = now + std::chrono::seconds{60};
                logger::info("Fuzzer API: RAM Used: {} MB Trie size: {}", memory::my_usage_mb(), _chain ? _chain->trie_size() : size_t{0});
            }
            return std::visit([&](auto &&m) -> message_t<CFG> {
                using T = std::decay_t<decltype(m)>;
                if constexpr (std::is_same_v<T, initialize_t<CFG>>) {
                    genesis_t genesis{m.state, std::move(m.header)};
                    _chain.emplace(_chain_id, _chain_dir, std::move(genesis),
                        typename chain_t<CFG>::reset_t{std::move(m.state), std::move(m.ancestry)});
                    return _chain->state_root();
                } else if constexpr (std::is_same_v<T, import_block_t<CFG>>) {
                    if (!_chain) [[unlikely]]
                        throw error("import_block is not allowed before set_state");
                    const auto pre_root = _chain->state_root();
                    try {
                        _chain->apply(m);
                        return _chain->state_root();
                    } catch (const std::exception &ex) {
                        if (const auto post_root = _chain->state_root(); post_root != pre_root) [[unlikely]]
                            throw error{"chain failed to rollback after an error: {}", ex.what()};
                        return fuzzer::error_t{ex.what()};
                    }
                } else if constexpr (std::is_same_v<T, get_state_t>) {
                    if (!_chain) [[unlikely]]
                        throw error("get_state is not allowed before set_state");
                    // the practical difference between closing a connection vs. returning a state for a non-matching header
                    // is that the fuzzer will generate a state diff, which is the preferable outcome.
                    // For this reason, the current state is always returned
                    return _chain->state().snapshot();
                } else {
                    throw error{"unexpected message type: {}", typeid(T).name()};
                }
            }, std::move(msg));
        }
    private:
        std::string _chain_id;
        std::string _chain_dir;
        std::optional<chain_t<CFG>> _chain{};
        std::chrono::steady_clock::time_point _next_info{std::chrono::steady_clock::now() + + std::chrono::seconds{60}};
    };

    template<typename CFG>
    local_processor_t<CFG>::local_processor_t(std::string chain_id, std::string_view chain_dir):
        _impl{std::make_unique<impl_t>(std::move(chain_id), std::move(chain_dir))}
    {
    }

    template<typename CFG>
    local_processor_t<CFG>::~local_processor_t() =default;

    template<typename CFG>
    boost::asio::awaitable<message_t<CFG>> local_processor_t<CFG>::process(message_t<CFG> msg)
    {
        co_return _impl->process(std::move(msg));
    }

    template struct local_processor_t<config_prod>;
    template struct local_processor_t<config_tiny>;
    template struct local_processor_t<config_fuzz>;
}
