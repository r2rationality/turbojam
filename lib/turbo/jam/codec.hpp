#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <cstdint>
#include <turbo/common/bytes.hpp>
#include <turbo/common/file.hpp>
#include <turbo/common/numeric-cast.hpp>

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

        void uint_general(const uint64_t x)
        {
            static constexpr size_t max_uint_val = uint64_t { 1 } << 63;
            if (x >= max_uint_val) [[unlikely]] {
                _bytes.emplace_back(0xFF);
                uint_trivial(8, x);
                return;
            }
            if (x == 0) {
                _bytes.emplace_back(0);
                return;
            }
            size_t l = 0;
            while (x >= uint64_t { 1 } << (7 * (l + 1))) {
                ++l;
            }
            const auto base = l << 3;
            const auto bit_mask = static_cast<uint8_t>(0x100 - (uint8_t { 1 } << (8 - l)));
            const auto high_bits = static_cast<uint8_t>(x >> base);
            _bytes.emplace_back(bit_mask | high_bits);
            uint_trivial(l, x & ((uint64_t { 1 } << base) - 1));
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

        uint8_vector &bytes()
        {
            return _bytes;
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
                x |= next() << (i * 8);
            }
            return x;
        }

        template<typename T=uint64_t>
        T uint_general()
        {
            auto prefix = uint_trivial<uint8_t>(1);
            size_t l = 0;
            while (prefix & (1 << (7 - l))) {
                prefix &= ~(1 << (7 - l));
                ++l;
            }
            uint64_t res = prefix << (l << 3);
            res |= uint_trivial<uint64_t>(l);
            return numeric_cast<T>(res);
        }

        template<typename T>
        T decode()
        {
            if constexpr (std::is_same_v<uint64_t, T>) {
                return uint_trivial<T>(8);
            } else if constexpr (std::is_same_v<uint32_t, T>) {
                return uint_trivial<T>(4);
            } else if constexpr (std::is_same_v<uint16_t, T>) {
                return uint_trivial<T>(2);
            } else if constexpr (std::is_same_v<uint8_t, T>) {
                return uint_trivial<T>(1);
            } else if constexpr (std::is_same_v<bool, T>) {
                return static_cast<T>(uint_trivial<uint8_t>(1));
            } else {
                return T::from_bytes(*this);
            }
        }

        uint8_t next()
        {
            if (_ptr >= _end) [[unlikely]]
                throw error("codec: an attempt to read past the end of the byte stream");
            return *_ptr++;
        }

        buffer next_bytes(const size_t sz)
        {
            if (_ptr + sz > _end) [[unlikely]]
                throw error("codec: an attempt to read past the end of the byte stream");
            const auto *begin = _ptr;
            _ptr += sz;
            return { begin, sz };
        }

        bool empty() const noexcept
        {
            return _ptr >= _end;
        }
    private:
        const uint8_t *_ptr, *_end;
    };

    template<typename T>
    encoder &operator<<(encoder &enc, const T &val)
    {
        enc.encode(val);
        return enc;
    }

    template<typename T>
    T load(const std::string &path)
    {
        const auto bytes = file::read(path);
        decoder dec { bytes };
        return T::from_bytes(dec);
    }
}
