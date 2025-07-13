#pragma once

#include <turbo/crypto/ed25519.hpp>

namespace turbo::jamnp {
    extern std::string cert_name_base32(buffer bytes);
    extern std::string cert_name_from_vk(const crypto::ed25519::vkey_t &vk);
    extern void write_cert(const std::string &cert_path, const std::string &key_path, const crypto::ed25519::key_pair_t &kp);
}
