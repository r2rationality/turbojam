#pragma once

#include <turbo/crypto/ed25519.hpp>

namespace turbo::jamsnp {
    extern std::string cert_name_base32(buffer bytes);
    extern std::string cert_name_from_vk(const crypto::ed25519::vkey_t &vk);
}
