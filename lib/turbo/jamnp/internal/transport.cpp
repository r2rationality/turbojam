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
