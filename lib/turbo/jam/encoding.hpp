#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <cstdint>
#include <turbo/common/bytes.hpp>
#include <turbo/common/file.hpp>
#include <turbo/common/numeric-cast.hpp>
#include <turbo/codec/serializable.hpp>

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
            auto x = val;
            for (size_t i = 0; i < num_bytes; ++i) {
                _bytes.emplace_back(static_cast<uint8_t>(x & 0xFF));
                x >>= 8;
            }
            if (x) [[unlikely]]
                throw error(fmt::format("{} cannot be encoded as a sequence of {} bytes", val, num_bytes));
        }

        void uint_varlen(const uint64_t x)
        {
            static constexpr size_t max_uint_val = uint64_t { 1 } << 63;
            if (x >= max_uint_val) [[unlikely]] {
                _bytes.emplace_back(0xFF);
                uint_fixed(8, x);
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
            uint_fixed(l, x & ((uint64_t { 1 } << base) - 1));
        }

        template<typename T>
        void process_uint(const T &val)
        {
            uint_fixed(sizeof(val), val);
        }

        template<typename T>
        void process_varlen_uint(const T &val)
        {
            uint_varlen(val);
        }

        void process_array(auto &self, const size_t min_sz=0, const size_t max_sz=std::numeric_limits<size_t>::max())
        {
            if (!(static_cast<int>(self.size() >= min_sz) & static_cast<int>(self.size() <= max_sz))) [[unlikely]]
                throw error(fmt::format("array size {} is out of allowed bounds: [{}, {}]", self.size(), min_sz, max_sz));
            process_varlen_uint(self.size());
            for (const auto &v: self)
                encode(v);
        }

        void process_map(auto &m)
        {
            process_varlen_uint(m.size());
            for (const auto &[k, v]: m) {
                process(k);
                process(v);
            }
        }

        void process_array_fixed(auto &self)
        {
            for (const auto &v: self)
                encode(v);
        }

        void process_bytes(const buffer bytes)
        {
            process_varlen_uint(bytes.size());
            _bytes << bytes;
        }

        void process_bytes_fixed(const buffer bytes)
        {
            _bytes << bytes;
        }

        void process_optional(auto &val)
        {
            if (val.has_value()) {
                uint_fixed(1, 1);
                process(*val);
            } else {
                uint_fixed(1, 0);
            }
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
            } else {
                throw error(fmt::format("serialization is not enabled for type {}", typeid(T).name()));
            }
        }

        template<typename T>
        void process(const std::string_view, const T &val)
        {
            process(val);
        }

        template<typename T>
        void encode(const T &val)
        {
            process(val);;
        }

        uint8_vector &bytes()
        {
            return _bytes;
        }
    private:
        uint8_vector _bytes {};
    };

    struct decoder: codec::archive_t {
        explicit decoder(const buffer bytes) noexcept:
            _ptr { bytes.data() },
            _end { bytes.data() + bytes.size() }
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

        template<typename T>
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

        template<typename T=uint64_t>
        T uint_varlen()
        {
            auto prefix = uint_fixed<uint8_t>(1);
            size_t l = 0;
            while (prefix & (1 << (7 - l))) {
                prefix &= ~(1 << (7 - l));
                ++l;
            }
            uint64_t res = prefix << (l << 3);
            res |= uint_fixed<uint64_t>(l);
            return numeric_cast<T>(res);
        }

        template<typename T>
        T decode()
        {
            if constexpr (from_bytes_c<T>) {
                return T::from_bytes(*this);
            } else if constexpr (codec::serializable_c<T>) {
                return T::template from<T>(*this);
            } else if constexpr (std::is_same_v<uint64_t, T>) {
                return uint_fixed<T>(8);
            } else if constexpr (std::is_same_v<uint32_t, T>) {
                return uint_fixed<T>(4);
            } else if constexpr (std::is_same_v<uint16_t, T>) {
                return uint_fixed<T>(2);
            } else if constexpr (std::is_same_v<uint8_t, T>) {
                return uint_fixed<T>(1);
            } else if constexpr (std::is_same_v<bool, T>) {
                return static_cast<T>(uint_fixed<uint8_t>(1));
            } else {
                throw error(fmt::format("serialization is not enabled for type {}", typeid(T).name()));
            }
        }

        template<typename T>
        void process_varlen_uint(T &val)
        {
            val = uint_varlen<T>();
        }

        template<typename T>
        void process_uint(T &val)
        {
            val = uint_fixed<T>(sizeof(val));
        }

        template<typename T>
        void process(T &val)
        {
            val = decode<T>();
        }

        template<typename T>
        void process(const std::string_view, T &val)
        {
            process(val);
        }

        template<typename T>
        void process_variant(T &val, const codec::variant_names_t<T> &)
        {
            const auto typ = uint_fixed<uint8_t>(1);
            variant_set_type<T, 0>(val, typ, *this);
        }

        void process_optional(auto &val)
        {
            val.reset();
            switch (const auto typ = uint_fixed<uint8_t>(1)) {
                case 0: break;
                case 1:
                    val.emplace();
                    process(*val);
                    break;
                [[unlikely]] default: throw error(fmt::format("unsupported optional type: {}", typ));
            }
        }

        void process_map(auto &m, const std::string_view /*key_name*/, const std::string_view /*val_name*/)
        {
            using T = std::decay_t<decltype(m)>;
            const auto sz = uint_varlen<size_t>();
            m.clear();
            for (size_t i = 0; i < sz; ++i) {
                auto k = decode<typename T::key_type>();
                auto v = decode<typename T::mapped_type>();
                const auto [it, created] = m.try_emplace(std::move(k), std::move(v));
                if (!created) [[unlikely]]
                    throw error(fmt::format("a map contains non-unique items: {}", typeid(m).name()));
            }
        }

        void process_array(auto &self, const size_t min_sz=0, const size_t max_sz=std::numeric_limits<size_t>::max())
        {
            using T = std::decay_t<decltype(self)>;
            const auto sz = uint_varlen<size_t>();
            if (!(static_cast<int>(sz >= min_sz) & static_cast<int>(sz <= max_sz))) [[unlikely]]
                throw error(fmt::format("array size {} is out of allowed bounds: [{}, {}]", self.size(), min_sz, max_sz));
            self.clear();
            self.reserve(sz);
            for (size_t i = 0; i < sz; ++i) {
                typename T::value_type v;
                process(v);
                if constexpr (codec::has_emplace_c<T>) {
                    self.emplace_hint_unique(self.end(), std::move(v));
                } else {
                    self.emplace_back(std::move(v));
                }
            }
        }

        void process_array_fixed(auto &self)
        {
            for (size_t i = 0; i < self.size(); ++i) {
                process(self[i]);
            }
        }

        void process_bytes(std::vector<uint8_t> &bytes)
        {
            const auto sz = uint_varlen<size_t>();
            bytes.reserve(sz);
            for (size_t i = 0; i < sz; ++i)
                bytes.emplace_back(next());
        }

        void process_bytes_fixed(const std::span<uint8_t> bytes)
        {
            for (size_t i = 0; i < bytes.size(); ++i)
                bytes[i] = next();
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
    T load_obj(const std::string &path)
    {
        const auto bytes = file::read(path);
        decoder dec { bytes };
        if constexpr (from_bytes_c<T>) {
            return T::from_bytes(dec);
        } else if constexpr (codec::serializable_c<T>) {
            return T::from(dec);
        } else {
            throw error(fmt::format("binary deserialization not support for type {}", typeid(T).name()));
        }
    }
}
