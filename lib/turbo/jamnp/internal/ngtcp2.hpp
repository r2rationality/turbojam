#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025-2026 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <cstdint>
#include <functional>
#include <memory>
#include <turbo/common/bytes.hpp>
#include <turbo/common/coro.hpp>
#include <turbo/jamnp/jamnp.hpp>

namespace turbo::jamnp::transport::ngtcp2 {
    struct transport_config_t {
        protocol_id_t protocol_id;
        cert_pair_t certificate;
    };

    struct client_t {
        client_t(address_t server_addr, transport_config_t cfg);
        ~client_t();
        client_t(client_t &&) noexcept;
        client_t &operator=(client_t &&) noexcept;

        client_t(const client_t &) = delete;
        client_t &operator=(const client_t &) = delete;

        [[nodiscard]] coro::task_t<uint8_vector> request(buffer payload);
    private:
        struct impl_t;
        std::unique_ptr<impl_t> _impl;
    };

    struct server_stream_t {
        struct impl_t;

        explicit server_stream_t(std::unique_ptr<impl_t> impl);
        ~server_stream_t();
        server_stream_t(server_stream_t &&) noexcept;
        server_stream_t &operator=(server_stream_t &&) noexcept;

        server_stream_t(const server_stream_t &) = delete;
        server_stream_t &operator=(const server_stream_t &) = delete;

        [[nodiscard]] coro::task_t<uint8_vector> read(size_t sz);
        [[nodiscard]] coro::task_t<uint8_vector> read_available();
        [[nodiscard]] coro::task_t<void> write(buffer bytes);
        [[nodiscard]] uint64_t id() const noexcept;
        [[nodiscard]] bool done() const noexcept;
    private:
        std::unique_ptr<impl_t> _impl;
    };

    using server_stream_handler_t = std::function<coro::task_t<void>(uint8_t, server_stream_t)>;

    struct server_t {
        explicit server_t(transport_config_t cfg);
        ~server_t();
        server_t(server_t &&) noexcept;
        server_t &operator=(server_t &&) noexcept;

        server_t(const server_t &) = delete;
        server_t &operator=(const server_t &) = delete;

        void run(address_t bind_addr, server_stream_handler_t default_handler);
    private:
        struct impl_t;
        std::unique_ptr<impl_t> _impl;
    };
}
