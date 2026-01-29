#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace ed25519_consensus {
    namespace internal {
        extern "C" {
            int zip215_ed25519_verify(
                const void* vk,
                const void* sig,
                const void* msg,
                size_t msg_len);
        }
    }

    inline bool zip215_verify(const std::span<const uint8_t, 64> &sig, const std::span<const uint8_t> &msg, const std::span<const uint8_t, 32> &vk) {
        return internal::zip215_ed25519_verify(vk.data(), sig.data(), msg.data(), msg.size()) == 1;
    }
}
