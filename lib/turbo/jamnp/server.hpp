#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/crypto/ed25519.hpp>
#include "client.hpp"

namespace turbo::jamnp {
    struct server_t {
        server_t(address_t addr, std::string app_name, std::string alpn_id, const std::string &cert_prefix);
        ~server_t();
        void run();
    private:
        struct impl_t;
        std::unique_ptr<impl_t> _impl;
    };

    [[nodiscard]] extern byte_array<32> dev_trivial_seed(uint32_t i);
    [[nodiscard]] extern secure_byte_array<32> dev_secret_seed(buffer prefix, buffer input_seed);
    [[nodiscard]] extern crypto::ed25519::key_pair_t dev_ed25519(buffer input_seed);
}
