#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <cstdint>
#include <turbo/common/bytes.hpp>

namespace turbo::jam::codec {
    struct encoder {
        void uint_trivial(const size_t num_bytes, const uint64_t val)
        {
            auto x = val;
            for (size_t i = 0; i < num_bytes; ++i) {
                _bytes.emplace_back(static_cast<uint8_t>(x & 0xFF));
                x >>= 8;
            }
            if (x) [[unlikely]]
                throw error(fmt::format("{} cannot be encoded as a sequence of {} bytes", val, num_bytes));
        }

        template<typename T>
        void uint_general(T x)
        {
            size_t l = 0;
            while (x >= 1 << (7 * l)) {
                ++l;
            }
            const auto base = 8 * l;
            _bytes.emplace_back(0x100 - (1 << 8 - l) + (x >> base));
            uint_trivial(l, x & ((1 << base) - 1));
        }

        template<typename T>
        void encode(const T &val)
        {
            using T = std::decay_t<T>;
            if constexpr (std::is_same_v<uint64_t, T>) {
                uint_trivial(8, val);
            } else if constexpr (std::is_same_v<uint32_t, T>) {
                uint_trivial(4, val);
            } else if constexpr (std::is_same_v<uint16_t, T>) {
                uint_trivial(2, val);
            } else if constexpr (std::is_same_v<uint8_t, T>) {
                uint_trivial(1, val);
            } else {
                val.to_bytes(*this);
            }
        }
    private:
        uint8_vector _bytes {};
    };

    struct decoder {
        explicit decoder(const buffer bytes) noexcept:
            _ptr { bytes.data() },
            _end { bytes.data() + bytes.size() }
        {
        }

        template<typename T>
        T uint_trivial(const size_t num_bytes)
        {
            T x = 0;
            for (size_t i = 0; i < num_bytes; ++i) {
                x <<= 8;
                x |= _next();
            }
            return x;
        }

        template<typename T>
        T decode()
        {
            using T = std::decay_t<T>;
            if constexpr (std::is_same_v<uint64_t, T>) {
                return uint_trivial<T>(8);
            } else if constexpr (std::is_same_v<uint32_t, T>) {
                return uint_trivial<T>(4);
            } else if constexpr (std::is_same_v<uint16_t, T>) {
                return uint_trivial<T>(2);
            } else if constexpr (std::is_same_v<uint8_t, T>) {
                return uint_trivial<T>(1);
            } else {
                return T::from_bytes(*this);
            }
        }
    private:
        const uint8_t *_ptr, *_end;

        uint8_t _next()
        {
            if (_ptr >= _end) [[unlikely]]
                throw error("codec: an attempt to read past the end of the byte stream");
            return *_ptr++;
        }
    };

    template<typename T>
    encoder &operator<<(encoder &enc, const T &val)
    {
        enc.encode(val);
        return enc;
    }
}
