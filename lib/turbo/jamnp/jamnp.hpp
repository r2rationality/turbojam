#pragma once
/* This file is part of TurboJam project:
 * https://github.com/r2rationality/turbojam/ Copyright (c) 2025-2026 R2
 * Rationality OÜ (info at r2rationality dot com) This code is distributed under
 * the license specified in: https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/bytes.hpp>

namespace turbo::jamnp {
    struct protocol_id_t {
        static constexpr std::string_view prefix = "jamnp-s";
        static constexpr std::string_view builder_suffix = "builder";
        using hash4_t = byte_array<4>;
        using hash4_span_t = const std::span<const uint8_t, sizeof(hash4_t)>;

        const uint16_t version = 0;
        const bool builder = false;
        const hash4_t genesis_hash4;

        static protocol_id_t from_text(const std::string_view text) {
            const auto parts = _split(text, '/');
            if (parts.size() < 3U || parts.size() > 4U) [[unlikely]]
                throw error(fmt::format("invalid protocol id: {}", text));
            if (parts[0] != prefix) [[unlikely]]
                throw error(fmt::format("invalid protocol id: {}", text));
            const auto ver = _to_uint16(parts[1]);
            if (ver != 0U) [[unlikely]]
                throw error(fmt::format("unsupported protocol version: {}", ver));
            const auto hash = hash4_t::from_hex(parts[2]);
            _validate_hex_case(parts[2]);
            if (parts.size() == 3U)
                return {ver, hash};
            if (parts[3] != builder_suffix) [[unlikely]]
                throw error(fmt::format("invalid protocol id: {}", text));
            return {ver, hash, true};
        }

        protocol_id_t(const uint16_t ver, const hash4_span_t &hash, const bool bld=false):
            version{ver},
            builder{bld},
            genesis_hash4{hash}
        {
        }

        [[nodiscard]] bool compatible(const protocol_id_t &o) const {
            if (version != o.version)
                return false;
            return genesis_hash4 == o.genesis_hash4;
        }

        operator std::string() const {
            return fmt::format("{}/{}/{}{}", prefix, version, buffer_lowercase{genesis_hash4.data(), genesis_hash4.size()}, builder ? "/builder" : "");
        }

    private:
        static std::vector<std::string_view> _split(const std::string_view s, const char sep) {
            std::vector<std::string_view> parts{};
            for (size_t start = 0;;) {
                const auto pos = s.find(sep, start);
                if (pos == std::string_view::npos) {
                    parts.emplace_back(s.substr(start));
                    break;
                }
                parts.emplace_back(s.substr(start, pos - start));
                start = pos + 1;
            }
            return parts;
        }

        static uint16_t _to_uint16(const std::string_view s) {
            unsigned int value{};
            const auto result = std::from_chars(s.data(), s.data() + s.size(), value);
            if (result.ec != std::errc{} || result.ptr != s.data() + s.size()) [[unlikely]]
                throw error(fmt::format("invalid uint16_t value: {}", s));
            if (value > std::numeric_limits<uint16_t>::max()) [[unlikely]]
                throw error(fmt::format("invalid uint16_t value: {}", value));
            return static_cast<uint16_t>(value);
        }

        static void _validate_hex_case(const uint8_t k) {
            if ((k < '0' || k > '9') && (k < 'a' || k > 'f')) [[unlikely]]
                throw error(fmt::format("unexpected hex character case: {}!", static_cast<char>(k)));
        }

        static void _validate_hex_case(const buffer hex) {
            for (const auto k: hex)
                _validate_hex_case(k);
        }
    };
}