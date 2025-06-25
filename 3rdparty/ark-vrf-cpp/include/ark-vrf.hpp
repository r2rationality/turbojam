#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace ark_vrf {
    namespace internal {
        extern "C" {
            int init(const void *path_ptr, size_t path_len);
            int ring_commitment(void* out_ptr, size_t out_len, const void* vkeys_ptr, size_t vkeys_len);
            int ring_vrf_output(void *out_ptr, size_t out_len, const void *sig_ptr, size_t sig_len);
            int ring_vrf_verify(size_t ring_size, const void *comm_ptr, size_t comm_len,
                const void* sig_ptr, size_t sig_len,
                const void *input_ptr, size_t input_len, const void *aux_ptr, size_t aux_len);
            int ietf_vrf_output(void *out_ptr, size_t out_len, const void *sig_ptr, size_t sig_len);
            int ietf_vrf_verify(const void* vkey_ptr, size_t vkey_len,
                const void* sig_ptr, size_t sig_len,
                const void *input_ptr, size_t input_len, const void *aux_ptr, size_t aux_len);
        }
    }

    inline int init(const std::string_view path)
    {
        return internal::init(path.data(), path.size());
    }

    inline int ring_commitment(const std::span<uint8_t> &out, const std::span<const uint8_t> &vkeys)
    {
        return internal::ring_commitment(out.data(), out.size(), vkeys.data(), vkeys.size());
    }

    inline int ring_vrf_output(const std::span<uint8_t, 32> &out, const std::span<const uint8_t> &sig)
    {
        return internal::ring_vrf_output(out.data(), out.size(), sig.data(), sig.size());
    }

    inline int ring_vrf_verify(size_t ring_size, const std::span<const uint8_t> &comm,
        const std::span<const uint8_t> &sig,
        const std::span<const uint8_t> &input, const std::span<const uint8_t> &aux)
    {
        return internal::ring_vrf_verify(ring_size, comm.data(), comm.size(),
            sig.data(), sig.size(),
            input.data(), input.size(), aux.data(), aux.size());
    }

    inline int ietf_vrf_output(const std::span<uint8_t, 32> &out, const std::span<const uint8_t> &sig)
    {
        return internal::ietf_vrf_output(out.data(), out.size(), sig.data(), sig.size());
    }

    inline int ietf_vrf_verify(const std::span<const uint8_t> &vkey, const std::span<const uint8_t> &sig,
        const std::span<const uint8_t> &input, const std::span<const uint8_t> &aux)
    {
        return internal::ietf_vrf_verify(vkey.data(), vkey.size(), sig.data(), sig.size(),
            input.data(), input.size(), aux.data(), aux.size());
    }
}
