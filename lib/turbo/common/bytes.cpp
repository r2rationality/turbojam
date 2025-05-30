#include "bytes.hpp"

namespace turbo {
    void secure_clear(std::span<uint8_t> store)
    {
        std::fill_n<volatile uint8_t *>(store.data(), store.size(), 0);
    }
}