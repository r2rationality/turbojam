/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include "fuzzer.hpp"
#include <turbo/jam/chain.hpp>

namespace turbo::jam::fuzzer {
    template<typename CFG>
    initialize_t<CFG> initialize_t<CFG>::from_snapshot(const state_snapshot_t &snap)
    {
        const file::tmp_directory data_dir{"jam-set-state-from-snapshot"};
        state_t<CFG> state{std::make_shared<triedb::db_t>(data_dir.path())};
        state = snap;
        auto hdr = state.make_genesis_header();
        const auto hdr_hash = hdr.hash();
        return {std::move(hdr), snap, {{0, hdr_hash}}};
    }

    template struct initialize_t<config_prod>;
    template struct initialize_t<config_tiny>;

    template<typename CFG>
    struct processor_t<CFG>::impl_t {
        impl_t(std::string &&chain_id, file::tmp_directory &&tmp_dir):
            _chain_id{std::move(chain_id)},
            _tmp_dir{std::move(tmp_dir)}
        {
        }

        message_t<CFG> process(message_t<CFG> &&msg)
        {
            return std::visit([&](auto &&m) -> message_t<CFG> {
                using T = std::decay_t<decltype(m)>;
                if constexpr (std::is_same_v<T, initialize_t<CFG>>) {
                    std::optional<ancestry_t<CFG>> ancestry{};
                    if (!m.ancestry.empty())
                        ancestry.emplace(std::move(m.ancestry));
                    _chain.emplace(_chain_id, _tmp_dir.path(), m.state, m.state, std::move(ancestry));
                    return _chain->state_root();
                } else if constexpr (std::is_same_v<T, import_block_t<CFG>>) {
                    if (!_chain) [[unlikely]]
                        throw error("import_block is not allowed before set_state");
                    try {
                        _chain->apply(m);
                        return _chain->state_root();
                    } catch (const std::exception &ex) {
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
                    throw error(fmt::format("unexpected message type: {}", typeid(T).name()));
                }
            }, std::move(msg));
        }
    private:
        std::string _chain_id;
        file::tmp_directory _tmp_dir;
        std::optional<chain_t<CFG>> _chain {};
    };

    template<typename CFG>
    processor_t<CFG>::processor_t(std::string chain_id, file::tmp_directory tmp_dir):
        _impl{std::make_unique<impl_t>(std::move(chain_id), std::move(tmp_dir))}
    {
    }

    template<typename CFG>
    processor_t<CFG>::~processor_t() =default;

    template<typename CFG>
    message_t<CFG> processor_t<CFG>::process(message_t<CFG> msg)
    {
        return _impl->process(std::move(msg));
    }

    template struct processor_t<config_prod>;
    template struct processor_t<config_tiny>;
}
