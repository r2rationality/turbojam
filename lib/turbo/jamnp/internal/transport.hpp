#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025-2026 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <string>

#include <turbo/common/error.hpp>

namespace turbo::jamnp {
    struct address_t;
}

namespace turbo::jamnp::transport {
    enum class backend_kind_t {
        ngtcp2
    };

    struct transport_error: turbo::error {
        using turbo::error::error;
    };

    backend_kind_t active_backend() noexcept;
    backend_kind_t requested_backend();
    bool ngtcp2_enabled() noexcept;
    bool backend_compiled(backend_kind_t backend) noexcept;
    bool backend_selectable(backend_kind_t backend) noexcept;
    std::string backend_name(backend_kind_t backend);
    std::string active_backend_name();
    std::string requested_backend_name();
    std::string normalized_ipv6_host(const address_t &addr);
    std::string bind_host(const address_t &addr);
}
