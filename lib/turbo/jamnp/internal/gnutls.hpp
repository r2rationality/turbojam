#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025-2026 R2 Rationality OU (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <gnutls/gnutls.h>
#include <turbo/common/error.hpp>

namespace turbo::jamnp::internal {
    [[nodiscard]] inline std::string gnutls_error_text(const int code) {
        if (const char *msg = gnutls_strerror(code); msg)
            return msg;
        return fmt::format("GnuTLS error {}", code);
    }

    struct gnutls_global_state_t {
        gnutls_global_state_t() {
            if (const auto err = gnutls_global_init(); err != GNUTLS_E_SUCCESS) [[unlikely]]
                throw error{fmt::format("gnutls_global_init failed: {}", gnutls_error_text(err))};
        }

        ~gnutls_global_state_t() {
            gnutls_global_deinit();
        }
    };

    [[nodiscard]] inline gnutls_global_state_t &gnutls_global_state()
    {
        static gnutls_global_state_t state{};
        return state;
    }
}
