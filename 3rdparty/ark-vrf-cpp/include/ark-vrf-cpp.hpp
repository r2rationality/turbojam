#pragma once

namespace ark_vrf_cpp {
    extern "C" {
        int init(const void *path_ptr, size_t path_len);
        int ring_commitment(void* out_ptr, const void* vkeys_ptr, size_t vkeys_len);
        int vrf_verify(void* out_ptr, size_t ring_size, const void *comm_ptr, const void* sig_ptr,
            const void *input_ptr, size_t input_len, const void *aux_ptr, size_t aux_len);
    }
}
