/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <unordered_map>
#include <turbo/common/format.hpp>

// Must be included only once for the entire project!
#ifdef _WIN32
#   include <openssl/applink.c>
#endif

#include "msquic.hpp"

extern "C" {
    const MsQuicApi *MsQuic = nullptr;
}

namespace turbo::jamnp::quic {
    std::string status_name(const long status)
    {
        static_assert(std::is_same_v<long, QUIC_STATUS>);
        static std::unordered_map<QUIC_STATUS, std::string> names {
            { QUIC_STATUS_SUCCESS, "QUIC_STATUS_SUCCESS" },
            { QUIC_STATUS_PENDING, "QUIC_STATUS_PENDING" },
            { QUIC_STATUS_CONTINUE, "QUIC_STATUS_CONTINUE" },
            { QUIC_STATUS_OUT_OF_MEMORY, "QUIC_STATUS_OUT_OF_MEMORY" },
            { QUIC_STATUS_INVALID_PARAMETER, "QUIC_STATUS_INVALID_PARAMETER" },
            { QUIC_STATUS_INVALID_STATE, "QUIC_STATUS_INVALID_STATE" },
            { QUIC_STATUS_NOT_SUPPORTED, "QUIC_STATUS_NOT_SUPPORTED" },
            { QUIC_STATUS_NOT_FOUND, "QUIC_STATUS_NOT_FOUND" },
            { QUIC_STATUS_BUFFER_TOO_SMALL, "QUIC_STATUS_BUFFER_TOO_SMALL" },
            { QUIC_STATUS_HANDSHAKE_FAILURE, "QUIC_STATUS_HANDSHAKE_FAILURE" },
            { QUIC_STATUS_ABORTED, "QUIC_STATUS_ABORTED" },
            { QUIC_STATUS_ADDRESS_IN_USE, "QUIC_STATUS_ADDRESS_IN_USE" },
            { QUIC_STATUS_INVALID_ADDRESS, "QUIC_STATUS_INVALID_ADDRESS" },
            { QUIC_STATUS_CONNECTION_TIMEOUT, "QUIC_STATUS_CONNECTION_TIMEOUT" },
            { QUIC_STATUS_CONNECTION_IDLE, "QUIC_STATUS_CONNECTION_IDLE" },
            { QUIC_STATUS_INTERNAL_ERROR, "QUIC_STATUS_INTERNAL_ERROR" },
            { QUIC_STATUS_UNREACHABLE, "QUIC_STATUS_UNREACHABLE" },
            { QUIC_STATUS_CONNECTION_REFUSED, "QUIC_STATUS_CONNECTION_REFUSED" },
            { QUIC_STATUS_PROTOCOL_ERROR, "QUIC_STATUS_PROTOCOL_ERROR" },
            { QUIC_STATUS_VER_NEG_ERROR, "QUIC_STATUS_VER_NEG_ERROR" },
            { QUIC_STATUS_USER_CANCELED, "QUIC_STATUS_USER_CANCELED" },
            { QUIC_STATUS_ALPN_NEG_FAILURE, "QUIC_STATUS_ALPN_NEG_FAILURE" },
            { QUIC_STATUS_STREAM_LIMIT_REACHED, "QUIC_STATUS_STREAM_LIMIT_REACHED" }
        };
        if (const auto it = names.find(status); it != names.end())
            return fmt::format("{} ({:08X})", it->second, status);
        return fmt::format("QUIC_STATUS_UNKNOWN {:08X}", status);
    }
}