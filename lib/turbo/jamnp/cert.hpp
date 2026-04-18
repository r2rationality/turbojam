#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025-2026 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/crypto/ed25519.hpp>

namespace turbo::jamnp {
    extern std::string alternative_name_varlen(buffer bytes);
    extern std::string alternative_name(const crypto::ed25519::vkey_t &vk);
    extern void write_cert(const std::string &cert_path, const std::string &key_path, const crypto::ed25519::key_pair_t &kp);
}
