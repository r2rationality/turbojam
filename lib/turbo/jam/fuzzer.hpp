#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#ifdef _MSC_VER
#   include <SDKDDKVer.h>
#endif
#include <boost/asio/awaitable.hpp>

#include "types/header.hpp"
#include "types/state-dict.hpp"

namespace turbo::jam {
    template<typename CFG>
    struct genesis_t;
}

namespace turbo::jam::fuzzer {
    struct version_t {
        uint8_t major;
        uint8_t minor;
        uint8_t patch;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("major"sv, major);
            archive.process("minor"sv, minor);
            archive.process("patch"sv, patch);
        }

        bool operator==(const version_t &) const = default;
    };

    struct features_t {
        using value_type = uint32_t;

        static constexpr value_type f_ancestry = 0x01;
        static constexpr value_type f_fork    = 0x02;

        void serialize(auto &archive)
        {
            archive.process(_bits);
        }

        explicit features_t(): features_t{f_ancestry | f_fork}
        {}

        explicit features_t(value_type bits)
        {
            for (const auto feat: {f_ancestry, f_fork}) {
                if (bits & feat) {
                    _bits |= feat;
                    bits ^= feat;
                }
            }
            if (bits) [[unlikely]]
                throw error{"unexpected feature bits: {:08X}", bits};
        }

        [[nodiscard]] bool ancestry() const noexcept {
            return _bits & f_ancestry;
        }

        [[nodiscard]] bool fork() const noexcept {
            return _bits & f_fork;
        }

        [[nodiscard]] features_t common(const features_t &o) const noexcept {
            return features_t{_bits & o._bits};
        }

        [[nodiscard]] bool operator==(const features_t &) const =default;
    private:
        value_type _bits = 0;
    };

    struct peer_info_t {
        // app name is first to simplify initialization
        std::string app_name{"turbojam"};
        features_t fuzz_features{};
        uint8_t fuzz_version=0x01; // indicate support for v1
        version_t jam_version{0, 8, 0};
        version_t app_version{0, 3, 2};

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("fuzz_version"sv, fuzz_version);
            archive.process("fuzz_features"sv, fuzz_features);
            archive.process("jam_version"sv, jam_version);
            archive.process("app_version"sv, app_version);
            archive.process("app_name"sv, app_name);
        }

        void compatible_with(const peer_info_t &o) const
        {
            if (fuzz_version != o.fuzz_version) [[unlikely]]
                throw error{"fuzzer version mismatch: {} != {}", fuzz_version, o.fuzz_version};
            if (jam_version != o.jam_version) [[unlikely]]
                throw error{"jam version mismatch: {} != {}", jam_version, o.jam_version};
        }

        [[nodiscard]] features_t compatible_features(const peer_info_t &o) const
        {
            return fuzz_features.common(o.fuzz_features);
        }

        bool operator==(const peer_info_t &) const =default;
    };

    template<typename CFG>
    using import_block_t = block_t<CFG>;

    template<typename CFG>
    struct initialize_t {
        header_t<CFG> header;
        state_snapshot_t state;
        partial_ancestry_t<CFG> ancestry{};

        static initialize_t from_snapshot(const state_snapshot_t &state);

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("header"sv, header);
            archive.process("state"sv, state);
            archive.process("ancestry"sv, ancestry);
        }

        bool operator==(const initialize_t &) const =default;
    };

    struct get_state_t: header_hash_t {
        using header_hash_t::header_hash_t;
    };

    struct error_t: std::string {
        void serialize(auto &archive)
        {
            archive.process(static_cast<std::string &>(*this));
        }
    };

    template<typename CFG>
    using message_base_t = std::variant<
        peer_info_t,
        initialize_t<CFG>,
        state_root_t,
        import_block_t<CFG>,
        get_state_t,
        state_snapshot_t,
        error_t
    >;
    template<typename CFG>
    struct message_t: message_base_t<CFG> {
        using base_type = message_base_t<CFG>;
        using base_type::base_type;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            static_assert(std::variant_size_v<base_type> > 0);
            static constexpr codec::variant_names_t<base_type> names {
                "peer_info"sv,
                "initialize"sv,
                "state_root"sv,
                "import_block"sv,
                "get_state"sv,
                "state"sv,
                "error"sv
            };
            static const codec::variant_index_overrides_t overrides{{{255U, 6U}}};
            archive.process(codec::as_variant<base_type>(*this, names, &overrides));
        }

        bool operator==(const message_t &) const =default;
    };

    template<typename CFG>
    struct local_processor_t {
        local_processor_t(std::string chain_id, std::string_view chain_dir, features_t feats=features_t{});
        ~local_processor_t();
        boost::asio::awaitable<message_t<CFG>> process(message_t<CFG> msg);
    private:
        struct impl_t;
        std::unique_ptr<impl_t> _impl;
    };
}
