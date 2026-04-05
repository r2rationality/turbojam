/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025-2026 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#ifdef _MSC_VER
#   include <SDKDDKVer.h>
#endif
#include <boost/asio/ip/address_v6.hpp>
#include <boost/asio/ip/udp.hpp>
#include <cstdlib>
#include <string_view>

#include <turbo/jamnp/client.hpp>
#include "transport.hpp"

namespace turbo::jamnp::transport {
    backend_kind_t active_backend() noexcept
    {
        return backend_kind_t::ngtcp2;
    }

    backend_kind_t requested_backend()
    {
        if (const auto *raw = std::getenv("TURBO_JAMNP_BACKEND"); raw) {
            const std::string_view name { raw };
            if (name == "ngtcp2")
                return backend_kind_t::ngtcp2;
        }
        return active_backend();
    }

    bool ngtcp2_enabled() noexcept
    {
        return true;
    }

    bool backend_compiled(const backend_kind_t backend) noexcept
    {
        switch (backend) {
            case backend_kind_t::ngtcp2:
                return ngtcp2_enabled();
        }
        return false;
    }

    bool backend_selectable(const backend_kind_t backend) noexcept
    {
        return backend_compiled(backend);
    }

    std::string backend_name(const backend_kind_t backend)
    {
        switch (backend) {
            case backend_kind_t::ngtcp2:
                return "ngtcp2";
        }
        return "unknown";
    }

    std::string active_backend_name()
    {
        return backend_name(active_backend());
    }

    std::string requested_backend_name()
    {
        return backend_name(requested_backend());
    }

    std::string normalized_ipv6_host(const address_t &addr)
    {
        const auto ip = boost::asio::ip::make_address_v6(addr.host);
        const boost::asio::ip::udp::endpoint endpoint { ip, addr.port };
        return endpoint.address().to_string();
    }

    std::string bind_host(const address_t &addr)
    {
        return normalized_ipv6_host(addr);
    }
}
