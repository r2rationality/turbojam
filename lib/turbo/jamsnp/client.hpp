#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/coro.hpp>
#include <turbo/jam/types/header.hpp>

namespace turbo::jamsnp {
    using namespace jam;

    struct address_t {
        std::string host;
        uint16_t port;
    };

    enum class direction_t: uint8_t {
        ascending = 0,
        descending = 1
    };

    template<typename CFG>
    struct client_t {
        using block_list_t = sequence_t<block_t<CFG>>;

        client_t(address_t server_addr, const std::string &app_name, const std::string &alpn_id, const std::string &cert_prefix);
        ~client_t();

        [[nodiscard]] coro::task_t<block_list_t> fetch_blocks(const header_hash_t &hh, uint32_t max_blocks, direction_t direction=direction_t::ascending);
    private:
        struct impl_t;
        std::unique_ptr<impl_t> _impl;
    };
}
