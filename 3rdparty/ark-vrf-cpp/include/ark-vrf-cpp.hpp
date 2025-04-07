#pragma once

namespace ark_vrf_cpp {
    extern "C" {
        int ring_commitment(void* out_ptr, const void* vkeys_ptr, size_t vkeys_len, const void *path_ptr, size_t path_len);
    }
}
