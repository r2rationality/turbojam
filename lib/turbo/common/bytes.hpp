#pragma once
/* Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com) */

#include <algorithm>
#include <array>
#include <span>
#include "error.hpp"
#include "format.hpp"

namespace turbo {
    typedef std::span<uint8_t> write_buffer;

    template <typename T>
    constexpr T host_to_net(T value) noexcept
    {
        const int x = 1;
        if (*reinterpret_cast<const char *>(&x) == 1) {
            char* ptr = reinterpret_cast<char*>(&value);
            std::reverse(ptr, ptr + sizeof(T));
        }
        return value;
    }

    template <typename T>
    constexpr T net_to_host(T value) noexcept
    {
        const int x = 1;
        if (*reinterpret_cast<const char *>(&x) == 1) {
            char* ptr = reinterpret_cast<char*>(&value);
            std::reverse(ptr, ptr + sizeof(T));
        }
        return value;
    }

    struct buffer: std::span<const uint8_t> {
        buffer() =default;
        buffer(const buffer &) =default;

        template <typename T, size_t SZ>
        buffer(const std::span<T, SZ> bytes):
            buffer { reinterpret_cast<const uint8_t *>(bytes.data()), SZ * sizeof(T) }
        {
        }

        template <typename T>
        buffer(const std::span<T> bytes):
            buffer { reinterpret_cast<const uint8_t *>(bytes.data()), bytes.size() * sizeof(T) }
        {
        }

        buffer(const uint8_t *data, const size_t sz):
            std::span<const uint8_t> { data, sz }
        {
        }

        buffer(const std::string_view s):
            buffer { reinterpret_cast<const uint8_t *>(s.data()), s.size() }
        {
        }

        buffer(const std::string &s):
            buffer { reinterpret_cast<const uint8_t *>(s.data()), s.size() }
        {
        }

        buffer &operator=(const buffer &o) =default;

        template<typename M>
        static constexpr buffer from(const M &val)
        {
            return buffer { reinterpret_cast<const uint8_t *>(&val), sizeof(val) };
        }

        template<typename M>
        constexpr M to() const
        {
            if (size() != sizeof(M)) [[unlikely]]
                throw error(fmt::format("buffer size: {} does not match the type's size: {}!", size(), sizeof(M)));
            return *reinterpret_cast<const M*>(data());
        }

        template<typename M>
        constexpr M to_host() const
        {
            if (size() != sizeof(M)) [[unlikely]]
                throw error(fmt::format("buffer size: {} does not match the type's size: {}!", size(), sizeof(M)));
            return net_to_host(*reinterpret_cast<const M*>(data()));
        }

        operator std::string_view() const noexcept
        {
            return { reinterpret_cast<const char *>(data()), size() };
        }

        std::strong_ordering operator<=>(const buffer &o) const noexcept
        {
            const auto min_sz = std::min(size(), o.size());
            const auto cmp = memcmp(data(), o.data(), min_sz);
            if (cmp < 0)
                return std::strong_ordering::less;
            if (cmp > 0)
                return std::strong_ordering::greater;
            return size() <=> o.size();
        }

        bool operator==(const buffer &o) const noexcept
        {
            return std::strong_ordering::equal == (*this <=> o);
        }

        uint8_t at(const size_t off) const
        {
            if (off < size()) [[likely]]
                return (*this)[off];
            throw error(fmt::format("requested offset: {} that behind the end of buffer: {}!", off, size()));
        }

        buffer subbuf(const size_t offset, const size_t sz) const
        {
            if (offset + sz <= size()) [[likely]]
                return buffer { data() + offset, sz };
            throw error(fmt::format("requested offset: {} and size: {} end over the end of buffer's size: {}!", offset, sz, size()));
        }

        buffer subbuf(const size_t offset) const
        {
            if (offset <= size()) [[likely]]
                return subbuf(offset, size() - offset);
            throw error(fmt::format("a buffer's offset {} is greater than its size {}", offset, size()));
        }
    };

    template<size_t SZ>
    struct
    byte_array: std::array<uint8_t, SZ> {
        using base_type = std::array<uint8_t, SZ>;
        using base_type::base_type;

        template<typename C=byte_array<SZ>>
        static C from_hex(const std::string_view hex)
        {
            C data;
            init_from_hex(data, hex);
            return data;
        }

        byte_array() =default;

        byte_array(const std::initializer_list<uint8_t> s) {
            if (s.size() != SZ) [[unlikely]]
                throw error(fmt::format("span must be of size {} but got {}", SZ, s.size()));
            size_t i = 0;
            for (const auto b: s)
                *(base_type::data() + i++) = b;
        }

        byte_array(const buffer s)
        {
            if (s.size() != SZ) [[unlikely]]
                throw error(fmt::format("string_view must be of size {} but got {}", SZ, s.size()));
            memcpy(this, std::data(s), SZ);
        }

        byte_array(const std::string_view s)
        {
            if (s.size() != SZ) [[unlikely]]
                throw error(fmt::format("string_view must be of size {} but got {}", SZ, s.size()));
            memcpy(this, std::data(s), SZ);
        }

        byte_array &operator=(const buffer s)
        {
            if (s.size() != SZ) [[unlikely]]
                throw error(fmt::format("string_view must be of size {} but got {}", SZ, s.size()));
            memcpy(this, std::data(s), SZ);
            return *this;
        }

        byte_array &operator=(const std::string_view s)
        {
            if (s.size() != SZ) [[unlikely]]
                throw error(fmt::format("string_view must be of size {} but got {}", SZ, s.size()));
            memcpy(this, std::data(s), SZ);
            return *this;
        }

        static consteval [[nodiscard]] size_t num_bits()
        {
            return SZ * 8;
        }

        bool bit(const size_t bit_no) const
        {
            const auto byte_no = bit_no >> 3;
            const auto byte_bit_no = bit_no & 0x7;
            if (byte_no >= SZ) [[unlikely]]
                throw error(fmt::format("a bit number {} is out of range for byte strings of {} bytes", bit_no, SZ));
            return base_type::operator[](byte_no) & (1U << byte_bit_no);
        }

        operator buffer() const noexcept
        {
            return { base_type::data(), SZ };
            static_assert(std::is_convertible_v<byte_array, buffer>);
        }

        explicit operator std::string_view() const noexcept
        {
            return { reinterpret_cast<const char *>(base_type::data()), base_type::size() };
        }
    };

    extern void secure_clear(std::span<uint8_t> store);

    template<size_t SZ>
    struct secure_byte_array: byte_array<SZ>
    {
        using byte_array<SZ>::byte_array;

        static secure_byte_array<SZ> from_hex(const std::string_view hex)
        {
            secure_byte_array<SZ> data;
            init_from_hex(data, hex);
            return data;
        }

        ~secure_byte_array()
        {
            secure_clear(*this);
        }
    };

    inline uint8_t uint_from_oct(char k)
    {
        switch (std::tolower(k)) {
            case '0': return 0;
            case '1': return 1;
            case '2': return 2;
            case '3': return 3;
            case '4': return 4;
            case '5': return 5;
            case '6': return 6;
            case '7': return 7;
            default: throw error(fmt::format("unexpected character in an octal number: {}!", k));
        }
    }

    inline uint8_t uint_from_hex(char k)
    {
        switch (std::tolower(k)) {
            case '0': return 0;
            case '1': return 1;
            case '2': return 2;
            case '3': return 3;
            case '4': return 4;
            case '5': return 5;
            case '6': return 6;
            case '7': return 7;
            case '8': return 8;
            case '9': return 9;
            case 'a': return 10;
            case 'b': return 11;
            case 'c': return 12;
            case 'd': return 13;
            case 'e': return 14;
            case 'f': return 15;
            default: throw error(fmt::format("unexpected character in a hex number: {}!", k));
        }
    }

    inline void init_from_hex(std::span<uint8_t> out, const std::string_view hex)
    {
        if (hex.size() != out.size() * 2)
            throw error(fmt::format("hex string must have {} characters but got {}: {}!", out.size() * 2, hex.size(), hex));
        for (size_t i = 0; i < out.size(); ++i)
            out[i] = uint_from_hex(hex[i * 2]) << 4 | uint_from_hex(hex[i * 2 + 1]);
    }

    struct uint8_vector: std::vector<uint8_t> {
        using base_type = std::vector<uint8_t>;
        using base_type::base_type;

        template<typename C=uint8_vector>
        static C from_hex(const std::string_view hex)
        {
            if (hex.size() % 2 != 0)
                throw error(fmt::format("hex string must have an even number of characters but got {}!", hex.size()));
            C data(hex.size() / 2);
            init_from_hex(data, hex);
            return data;
        }

        uint8_vector() noexcept =default;

        uint8_vector(base_type &&o) noexcept:
            base_type { std::move(o) }
        {
        }

        uint8_vector(const size_t sz):
            std::vector<uint8_t>(sz)
        {
        }

        uint8_vector(const buffer bytes):
            std::vector<uint8_t> { bytes.begin(), bytes.end() }
        {
        }

        operator buffer() const noexcept
        {
            return { data(), size() };
        }

        std::string_view str() const noexcept
        {
            return { reinterpret_cast<const char *>(data()), size() };
        }

        uint8_vector &operator=(const buffer bytes)
        {
            resize(bytes.size());
            memcpy(data(), bytes.data(), bytes.size());
            return *this;
        }

        std::strong_ordering operator<=>(const buffer &o) const noexcept
        {
            return static_cast<buffer>(*this) <=> o;
        }

        std::strong_ordering operator<=>(const uint8_vector &o) const noexcept
        {
            return static_cast<buffer>(*this) <=> static_cast<buffer>(o);
        }

        bool operator==(const uint8_vector &o) const noexcept
        {
            return std::strong_ordering::equal == (*this <=> static_cast<buffer>(o));
        }

        bool operator==(const buffer &o) const noexcept
        {
            return std::strong_ordering::equal == (*this <=> o);
        }
    };

    static_assert(std::is_constructible_v<uint8_vector, buffer>);
    static_assert(std::is_constructible_v<buffer, uint8_vector>);
    static_assert(std::is_convertible_v<uint8_vector, buffer>);

    // Intended to be used as the target for IO operations. Does not initialize newly allocated memory.
    struct write_vector {
        write_vector(const write_vector &) =delete;
        write_vector() =default;

        write_vector(const size_t sz)
        {
            resize(sz);
        }

        write_vector(const buffer bytes)
        {
            resize(bytes.size());
            memcpy(data(), bytes.data(), _size);
        }

        write_vector(write_vector &&o):
            _capacity { o._capacity },
            _size { o._size },
            _ptr { std::move(o._ptr) }
        {
        }

        write_vector &operator=(write_vector &&o)
        {
            _capacity = o._capacity;
            _size = o._size;
            _ptr = std::move(o._ptr);
            return *this;
        }

        write_vector &operator=(const buffer bytes)
        {
            resize(bytes.size());
            memcpy(data(), bytes.data(), _size);
            return *this;
        }

        void clear()
        {
            resize(0);
        }

        void reserve(const size_t new_cap)
        {
            if (new_cap > _capacity) {
                ptr_type new_ptr { reinterpret_cast<uint8_t *>(::operator new (new_cap)) };
                // memcpy correctly handles the case when 0 bytes are copied
                memcpy(new_ptr.get(), _ptr.get(), _size);
                _ptr = std::move(new_ptr);
                _capacity = new_cap;
            }
        }

        void resize(const size_t new_sz)
        {
            reserve(new_sz);
            _size = new_sz;
        }

        size_t size() const noexcept
        {
            return _size;
        }

        size_t capacity() const noexcept
        {
            return _capacity;
        }

        // can return a nullptr when _size is 0!
        uint8_t *data() const noexcept
        {
            return _ptr.get();
        }

        uint8_t operator[](const size_t idx) const noexcept
        {
            return *(_ptr.get() + idx);
        }

        operator std::span<uint8_t>() const noexcept
        {
            return { data(), size() };
        }

        operator buffer() const noexcept
        {
            return { data(), size() };
        }

        std::string_view str() const noexcept
        {
            return { reinterpret_cast<const char *>(data()), size() };
        }

        std::strong_ordering operator<=>(const buffer &o) const noexcept
        {
            return static_cast<buffer>(*this) <=> o;
        }

        bool operator==(const buffer &o) const noexcept
        {
            return std::strong_ordering::equal == (*this <=> o);
        }

        bool operator==(const uint8_vector &o) const noexcept
        {
            return std::strong_ordering::equal == (*this <=> static_cast<buffer>(o));
        }

        bool operator==(const write_vector &o) const noexcept
        {
            return std::strong_ordering::equal == (*this <=> static_cast<buffer>(o));
        }
    private:
        struct deleter_t {
            void operator()(uint8_t *ptr)
            {
                ::operator delete(ptr);
            }
        };

        using value_type = uint8_t;
        using ptr_type = std::unique_ptr<value_type, deleter_t>;

        size_t _capacity = 0;
        size_t _size = 0;
        ptr_type _ptr {};
    };

    inline write_vector &operator<<(write_vector &v, const buffer buf)
    {
        const size_t end_off = v.size();
        v.resize(end_off + buf.size());
        memcpy(v.data() + end_off, buf.data(), buf.size());
        return v;
    }

    inline std::pmr::vector<uint8_t> &operator<<(std::pmr::vector<uint8_t> &v, const buffer buf)
    {
        const size_t end_off = v.size();
        v.resize(end_off + buf.size());
        memcpy(v.data() + end_off, buf.data(), buf.size());
        return v;
    }

    struct buffer_lowercase: buffer {
        using buffer::buffer;
    };

    inline uint8_vector &operator<<(uint8_vector &v, const uint8_t b)
    {
        const size_t end_off = v.size();
        v.resize(end_off + 1);
        v[end_off] = b;
        return v;
    }

    inline uint8_vector &operator<<(uint8_vector &v, const buffer buf)
    {
        const size_t end_off = v.size();
        v.resize(end_off + buf.size());
        memcpy(v.data() + end_off, buf.data(), buf.size());
        return v;
    }
}

namespace fmt {
    template<size_t SZ>
    struct formatter<std::array<const uint8_t, SZ>>: formatter<std::span<const uint8_t>> {
    };

    template<size_t SZ>
    struct formatter<std::array<uint8_t, SZ>>: formatter<std::span<const uint8_t>> {
    };

    template<>
    struct formatter<turbo::buffer>: formatter<std::span<const uint8_t>> {
    };

    template<>
    struct formatter<turbo::write_vector>: formatter<turbo::buffer> {
    };

    template<>
    struct formatter<turbo::uint8_vector>: formatter<turbo::buffer> {
    };

    template<>
    struct formatter<turbo::buffer_lowercase>: formatter<int> {
        template<typename FormatContext>
        auto format(const std::span<const uint8_t> &data, FormatContext &ctx) const -> decltype(ctx.out()) {
            auto out_it = ctx.out();
            for (uint8_t v: data) {
                out_it = fmt::format_to(out_it, "{:02x}", v);
            }
            return out_it;
        }
    };
}