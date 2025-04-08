#pragma once

#include <cstddef>

namespace ark_vrf_cpp {
    extern "C" {
        int init(const void *path_ptr, size_t path_len);
        int ring_commitment(void* out_ptr, size_t path_len, const void* vkeys_ptr, size_t vkeys_len);
        int vrf_output(void *out_ptr, size_t path_len, const void *sig_ptr, size_t sig_len);
        int vrf_verify(size_t ring_size, const void *comm_ptr, size_t comm_len, const void* sig_ptr, size_t sig_len,
            const void *input_ptr, size_t input_len, const void *aux_ptr, size_t aux_len);
    }
}
