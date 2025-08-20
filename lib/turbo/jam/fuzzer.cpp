/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include "fuzzer.hpp"
#include <turbo/jam/chain.hpp>

namespace turbo::jam::fuzzer {
    template<typename CFG>
    set_state_t<CFG> set_state_t<CFG>::from_snapshot(const state_snapshot_t &snap)
    {
        const file::tmp_directory data_dir{"jam-set-state-from-snapshot"};
        state_t<CFG> state{std::make_shared<triedb::db_t>(data_dir.path())};
        state = snap;
        return {state.make_genesis_header(), snap};
    }

    template struct set_state_t<config_prod>;
    template struct set_state_t<config_tiny>;

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
                if constexpr (std::is_same_v<T, set_state_t<CFG>>) {
                    _chain.emplace(_chain_id, _tmp_dir.path(), m.state, m.state);
                    return _chain->state_root();
                } else if constexpr (std::is_same_v<T, import_block_t<CFG>>) {
                    if (!_chain) [[unlikely]]
                        throw error("import_block is not allowed before set_state");
                    logger::run_log_errors([&] {
                        _chain->apply(m);
                    });
                    return _chain->state_root();
                } else if constexpr (std::is_same_v<T, get_state_t>) {
                    if (!_chain) [[unlikely]]
                        throw error("get_state is not allowed before set_state");
                    const auto &beta = _chain->state().beta.get();
                    if (beta.history.empty() || beta.history.back().header_hash != m.header_hash) [[unlikely]]
                        throw error("get_state supports returning the state of only the latest valid block!");
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
