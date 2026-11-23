/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/memory.hpp>
#include <turbo/jam/chain.hpp>
#include "fuzzer.hpp"

namespace turbo::jam::fuzzer {
    template<typename CFG>
    initialize_t<CFG> initialize_t<CFG>::from_snapshot(const state_snapshot_t &snap)
    {
        return {state_t<CFG>::make_genesis_header(snap), snap};
    }

    template struct initialize_t<config_prod>;
    template struct initialize_t<config_tiny>;

    template<typename CFG>
    struct local_processor_t<CFG>::impl_t {
        impl_t(std::string &&chain_id, const std::string_view chain_dir, const features_t feats):
            _chain_id{std::move(chain_id)},
            _chain_dir{chain_dir},
            _feats{feats}
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
                    partial_ancestry_t<CFG> passed_ancestry{};
                    if (_feats.ancestry())
                        passed_ancestry = std::move(m.ancestry);
                    _chain.emplace(_chain_id, _chain_dir, typename chain_t<CFG>::reset_t{{std::move(m.state), std::move(m.header)}, std::move(passed_ancestry)});
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
        features_t _feats;
        std::optional<chain_t<CFG>> _chain{};
        std::chrono::steady_clock::time_point _next_info{std::chrono::steady_clock::now() + + std::chrono::seconds{60}};
    };

    template<typename CFG>
    local_processor_t<CFG>::local_processor_t(std::string chain_id, std::string_view chain_dir, const features_t feats):
        _impl{std::make_unique<impl_t>(std::move(chain_id), std::move(chain_dir), feats)}
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
