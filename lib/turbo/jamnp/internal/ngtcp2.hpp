#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025-2026 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <memory>
#include <string>

#include <turbo/common/bytes.hpp>
#include <turbo/common/coro.hpp>

namespace turbo::jamnp {
    struct address_t;
}

namespace turbo::jamnp::transport::ngtcp2 {
    struct transport_config_t {
        std::string app_name;
        std::string alpn_id;
        std::string private_key_path;
        std::string certificate_path;
    };

    class client_bootstrap_t {
    public:
        explicit client_bootstrap_t(transport_config_t cfg);
        ~client_bootstrap_t();
        client_bootstrap_t(client_bootstrap_t &&) noexcept;
        client_bootstrap_t &operator=(client_bootstrap_t &&) noexcept;

        client_bootstrap_t(const client_bootstrap_t &) = delete;
        client_bootstrap_t &operator=(const client_bootstrap_t &) = delete;

        [[nodiscard]] bool available() const noexcept;
        [[nodiscard]] std::string summary() const;
    private:
        struct impl_t;
        std::unique_ptr<impl_t> _impl;
    };

    class client_session_t {
    public:
        client_session_t(address_t server_addr, transport_config_t cfg);
        ~client_session_t();
        client_session_t(client_session_t &&) noexcept;
        client_session_t &operator=(client_session_t &&) noexcept;

        client_session_t(const client_session_t &) = delete;
        client_session_t &operator=(const client_session_t &) = delete;

        [[nodiscard]] coro::task_t<uint8_vector> request(buffer payload);
        [[nodiscard]] std::string summary() const;
    private:
        struct impl_t;
        std::unique_ptr<impl_t> _impl;
    };

    class server_bootstrap_t {
    public:
        explicit server_bootstrap_t(transport_config_t cfg);
        ~server_bootstrap_t();
        server_bootstrap_t(server_bootstrap_t &&) noexcept;
        server_bootstrap_t &operator=(server_bootstrap_t &&) noexcept;

        server_bootstrap_t(const server_bootstrap_t &) = delete;
        server_bootstrap_t &operator=(const server_bootstrap_t &) = delete;

        [[nodiscard]] bool available() const noexcept;
        [[nodiscard]] std::string summary() const;
    private:
        struct impl_t;
        std::unique_ptr<impl_t> _impl;
    };

    [[nodiscard]] bool compiled() noexcept;
    [[nodiscard]] std::string compile_summary();
}
