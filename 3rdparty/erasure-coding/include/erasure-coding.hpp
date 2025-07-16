#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace erasure_coding {
    namespace internal {
        extern "C" {
            int construct_chunks_c(void *shards_ptr, size_t shards_len, uint16_t n_chunks, const void *data_ptr, size_t data_len);
        }
    }

    inline int construct_chunks(const std::span<uint8_t> &shards, const uint16_t n_chunks, const std::span<const uint8_t> &data)
    {
        return internal::construct_chunks_c(shards.data(), shards.size(), n_chunks, data.data(), data.size());
    }
}
