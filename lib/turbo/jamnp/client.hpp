#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/coro.hpp>
#include "jamnp.hpp"

namespace turbo::jamnp {
    using namespace jam;

    template<typename CFG>
    struct client_t {
        using block_list_t = sequence_t<block_t<CFG>>;

        client_t(address_t server_addr, const std::string &app_name, const std::string &alpn_id, cert_pair_t cert);
        ~client_t();

        [[nodiscard]] coro::task_t<block_list_t> fetch_blocks(const header_hash_t &hh, uint32_t max_blocks, direction_t direction=direction_t::ascending);
        [[nodiscard]] coro::task_t<state_resp_t> fetch_state(const header_hash_t &hh, const merkle::trie::key_t &key_start, const merkle::trie::key_t &key_end, const uint32_t max_size);
    private:
        struct impl_t;
        std::unique_ptr<impl_t> _impl;
    };
}

namespace fmt {
    template<>
    struct formatter<turbo::jamnp::address_t>: formatter<int> {
        template<typename FormatContext>
        auto format(const turbo::jamnp::address_t &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "host={} port={}", v.host, v.port);
        }
    };
}
