#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <cstdint>
#include <turbo/common/bytes.hpp>
#include <turbo/common/file.hpp>
#include <turbo/common/logger.hpp>
#include <turbo/common/numeric-cast.hpp>
#include <turbo/common/serializable.hpp>

namespace turbo::jam {
    struct decoder;

    template<typename T>
    concept from_bytes_c = requires(T t, decoder &dec)
    {
        { T::from_bytes(dec) };
    };

    struct encoder;

    template<typename T>
    concept to_bytes_c = requires(T t, encoder &enc)
    {
        { t.to_bytes(enc) };
    };

    struct encoder: codec::archive_t {
        static void uint_fixed(const std::span<uint8_t> &bytes, const size_t num_bytes, const uint64_t val)
        {
            if (!num_bytes) [[unlikely]]
                throw error("jam::codec::encoder: uint_fixed: num_bytes must be greater than 0!");
            if (bytes.size() != num_bytes) [[unlikely]]
                throw error(fmt::format("uint_fixed: expected an output buffer of {} bytes, got {}", num_bytes, bytes.size()));
            auto x = val;
            for (size_t i = 0; i < num_bytes; ++i) {
                bytes[i] = static_cast<uint8_t>(x & 0xFF);
                x >>= 8;
            }
            if (x) [[unlikely]]
                throw error(fmt::format("{} cannot be encoded as a sequence of {} bytes", val, num_bytes));
        }

        template<typename ...Args>
        explicit encoder(const Args &... args)
        {
            (process(args), ...);
        }

        void push(const std::string_view)
        {
            // do nothing
        }

        void pop()
        {
            // do nothing
        }

        void uint_fixed(const size_t num_bytes, const uint64_t val)
        {
            _bytes.insert(_bytes.end(), num_bytes, 0U);
            // insert can reallocate, so take the pointer only after that
            uint_fixed(std::span{_bytes.data() + _bytes.size() - num_bytes, num_bytes}, num_bytes, val);
        }

        void uint_varlen(const uint64_t x)
        {
            static_assert(sizeof(x) == 8U, "uint_varlen: sizeof(x) != 8U");
            if (x == 0U) {
                _bytes.emplace_back(0U);
                return;
            }
            for (uint64_t l = 0U, boundary = uint64_t{1} << 7U; l < 8U; ++l, boundary <<= 7U) {
                if (x < boundary) {
                    const auto base = l << 3U;
                    const auto bit_mask = static_cast<uint8_t>(0x100U - (1U << (8U - l)));
                    const auto high_bits = static_cast<uint8_t>(x >> base);
                    _bytes.reserve(_bytes.size() + size_t{1} + static_cast<size_t>(l));
                    _bytes.emplace_back(bit_mask | high_bits);
                    if (l > 0U)
                        uint_fixed(l, x & ((uint64_t{1} << base) - 1U));
                    return;
                }
            }
            // x >= 2^56
            _bytes.reserve(_bytes.size() + size_t{9});
            _bytes.emplace_back(0xFF);
            uint_fixed(8, x);
        }

        template<typename T>
        void process(codec::as_variant_t<T> av)
        {
            auto ci = av.val.index();
            if (av.overrides) {
                const auto it = av.overrides->encode_overrides.find(ci);
                if (it != av.overrides->encode_overrides.end())
                    ci = it->second;
            }
            uint_fixed(1, numeric_cast<uint8_t>(ci));
            std::visit([&](const auto &vv) {
                process(vv);
            }, av.val);
        }

        template<typename T>
        void process(const T &val)
        {
            if constexpr (to_bytes_c<T>) {
                val.to_bytes(*this);
            } else if constexpr (codec::serializable_c<T>) {
                // since the encoder methods do not update the value, it's safe to const_cast the value
                // this is needed to not implement a custom cost serialize method in each of the serialized classes
                const_cast<T &>(val).serialize(*this);
            } else if constexpr (codec::varlen_uint_c<T>) {
                uint_varlen(val.value());
            } else if constexpr (codec::optional_like_c<T>) {
                if (val.has_value()) {
                    uint_fixed(1, 1);
                    process(*val);
                } else {
                    uint_fixed(1, 0);
                }
            } else if constexpr (codec::bounded_range_c<T>) {
                codec::check_bounds(val);
                uint_varlen(val.size());
                for (const auto &v: val)
                    process(v);
            } else if constexpr (codec::map_like_c<T>) {
                uint_varlen(val.size());
                for (const auto &[k, v]: val) {
                    process(k);
                    process(v);
                }
            } else if constexpr (codec::byte_array_like_c<T>) {
                _bytes << buffer{val.data(), val.size()};
            } else if constexpr (codec::byte_sequence_like_c<T>) {
                uint_varlen(val.size());
                _bytes << buffer{val.data(), val.size()};
            } else if constexpr (codec::fixed_array_like_c<T>) {
                for (const auto &v: val)
                    process(v);
            } else if constexpr (std::is_same_v<T, std::string>) {
                uint_varlen(val.size());
                _bytes << buffer{val};
            } else if constexpr (std::is_same_v<T, uint64_t>) {
                uint_fixed(8, val);
            } else if constexpr (std::is_same_v<T, uint32_t>) {
                uint_fixed(4, val);
            } else if constexpr (std::is_same_v<T, uint16_t>) {
                uint_fixed(2, val);
            } else if constexpr (std::is_same_v<T, uint8_t>) {
                uint_fixed(1, val);
            } else if constexpr (std::is_same_v<T, bool>) {
                uint_fixed(1, static_cast<uint8_t>(val));
            } else if constexpr (std::convertible_to<T, std::span<const uint8_t>>) {
                _bytes << static_cast<std::span<const uint8_t>>(val);
            } else {
                throw error(fmt::format("serialization is not enabled for type {}", typeid(T).name()));
            }
        }

        template<typename T>
        void process(const std::string_view, const T &val)
        {
            process(val);
        }

        void next_bytes(const buffer data)
        {
            _bytes << data;
        }

        uint8_vector &bytes()
        {
            return _bytes;
        }

        const uint8_vector &bytes() const
        {
            return _bytes;
        }
    private:
        uint8_vector _bytes {};
    };

    struct decoder: codec::archive_t {
        explicit decoder(const buffer bytes) noexcept:
            _ptr{bytes.data()},
            _end{bytes.data() + bytes.size()}
        {
        }

        void push(const std::string_view)
        {
            // do nothing
        }

        void pop()
        {
            // do nothing
        }

        template<std::unsigned_integral T>
        T uint_fixed(const size_t num_bytes)
        {
            if (num_bytes > 8) [[unlikely]]
                throw error("uint_trivial supports 8-bytes values at most!");
            T x = 0;
            for (size_t i = 0; i < num_bytes; ++i) {
                x |= static_cast<T>(next()) << (i * 8);
            }
            return x;
        }

        template<std::unsigned_integral T=uint64_t>
        T uint_varlen()
        {
            static_assert(sizeof(T) <= 8U, "uint_varlen: only supports types with the size of 8 bytes or less!");
            auto prefix = uint_fixed<uint8_t>(1);
            size_t l = 0;
            while (prefix & (1U << (7U - l))) {
                prefix &= ~(1U << (7U - l));
                ++l;
            }
            uint64_t res = static_cast<uint64_t>(prefix) << (l * 8U);
            res |= uint_fixed<uint64_t>(l);
            return numeric_cast<T>(res);
        }

        template<typename T>
        void process(codec::as_variant_t<T> av)
        {
            auto vi = uint_fixed<uint8_t>(1);
            if (av.overrides) {
                const auto it = av.overrides->decode_overrides.find(vi);
                if (it != av.overrides->decode_overrides.end())
                    vi = it->second;
            }
            variant_set_type<T, 0>(av.val, vi, *this);
        }

        template<typename T>
        void process(T &val)
        {
            if constexpr (from_bytes_c<T>) {
                val = T::from_bytes(*this);
            } else if constexpr (codec::serializable_c<T>) {
                val.serialize(*this);
            } else if constexpr (codec::varlen_uint_c<T>) {
                val = uint_varlen<typename T::base_type>();
            } else if constexpr (codec::optional_like_c<T>) {
                val.reset();
                switch (const auto typ = uint_fixed<uint8_t>(1)) {
                    case 0: break;
                    case 1: val.emplace(); process(*val); break;
                    [[unlikely]] default: throw error(fmt::format("unsupported optional type: {}", typ));
                }
            } else if constexpr (codec::bounded_range_c<T>) {
                const auto sz = uint_varlen<size_t>();
                if (!(static_cast<int>(sz >= T::min_size) & static_cast<int>(sz <= T::max_size))) [[unlikely]]
                    throw error(fmt::format("array size {} is out of allowed bounds: [{}, {}]", sz, T::min_size, T::max_size));
                val.clear();
                if constexpr (requires { val.reserve(sz); })
                    val.reserve(sz);
                for (size_t i = 0; i < sz; ++i) {
                    typename T::value_type v;
                    process(v);
                    if constexpr (codec::has_emplace_c<T>) {
                        val.emplace_hint_unique(val.end(), std::move(v));
                    } else {
                        val.emplace_back(std::move(v));
                    }
                }
            } else if constexpr (codec::map_like_c<T>) {
                const auto sz = uint_varlen<size_t>();
                val.clear();
                for (size_t i = 0; i < sz; ++i) {
                    typename T::key_type k;
                    process(k);
                    typename T::mapped_type v;
                    process(v);
                    if (const auto [it, created] = val.try_emplace(std::move(k), std::move(v)); !created) [[unlikely]]
                        logger::warn("a {} map contains non-unique items: {}", typeid(val).name(), it->first);
                }
            } else if constexpr (codec::byte_array_like_c<T>) {
                const auto data = next_bytes(val.size());
                memcpy(val.data(), data.data(), val.size());
            } else if constexpr (codec::byte_sequence_like_c<T>) {
                const auto sz = uint_varlen<size_t>();
                const auto data = next_bytes(sz);
                val.assign(data.begin(), data.end());
            } else if constexpr (codec::fixed_array_like_c<T>) {
                for (size_t i = 0; i < val.size(); ++i)
                    process(val[i]);
            } else if constexpr (std::is_same_v<T, std::string>) {
                const auto sz = uint_varlen<size_t>();
                const auto data = next_bytes(sz);
                val.assign(data.begin(), data.end());
            } else if constexpr (std::is_same_v<uint64_t, T>) {
                val = uint_fixed<T>(8);
            } else if constexpr (std::is_same_v<uint32_t, T>) {
                val = uint_fixed<T>(4);
            } else if constexpr (std::is_same_v<uint16_t, T>) {
                val = uint_fixed<T>(2);
            } else if constexpr (std::is_same_v<uint8_t, T>) {
                val = uint_fixed<T>(1);
            } else if constexpr (std::is_same_v<bool, T>) {
                val = static_cast<T>(uint_fixed<uint8_t>(1));
            } else {
                throw error(fmt::format("serialization is not enabled for type {}", typeid(T).name()));
            }
        }

        template<typename T>
        void process(const std::string_view, T &val)
        {
            process(val);
        }

        [[nodiscard]] uint8_t next()
        {
            if (_ptr >= _end) [[unlikely]]
                throw error("codec: an attempt to read past the end of the byte stream");
            ++_consumed;
            return *_ptr++;
        }

        [[nodiscard]] buffer next_bytes(const size_t sz)
        {
            if (_ptr + sz > _end) [[unlikely]]
                throw error("codec: an attempt to read past the end of the byte stream");
            const auto *begin = _ptr;
            _consumed += sz;
            _ptr += sz;
            return {begin, sz};
        }

        [[nodiscard]] size_t consumed() const noexcept {
            return _consumed;
        }

        [[nodiscard]] bool empty() const noexcept
        {
            return _ptr >= _end;
        }
    private:
        const uint8_t *_ptr, *_end;
        size_t _consumed = 0;
    };

    template<typename T>
    encoder &operator<<(encoder &enc, const T &val)
    {
        enc.process(val);
        return enc;
    }

    template<typename T>
    T from(decoder &dec)
    {
        if constexpr (from_bytes_c<T>) {
            return T::from_bytes(dec);
        } else {
            return codec::from<T>(dec);
        }
    }

    template<typename T>
    T from_bytes(const buffer bytes)
    {
        decoder dec{bytes};
        return from<T>(dec);
    }

    template<typename T>
    T load_obj(const std::string &path)
    {
        const auto bytes = file::read(path);
        return from_bytes<T>(bytes);
    }
}
