#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include "types/header.hpp"
#include "types/state-dict.hpp"

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

    using features_t = uint32_t;

    struct peer_info_t {
        // app name is first to simplify initialization
        std::string app_name{"turbojam"};
        uint8_t fuzz_version=0x01; // indicate support for v1
        features_t fuzz_features=0x00000000; // indicate no supported features
        version_t jam_version{0, 7, 0};
        version_t app_version{0, 1, 4};

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
            if (jam_version != o.jam_version) [[unlikely]]
                throw error(fmt::format("jam version mismatch: {} != {}", jam_version, o.jam_version));
        }

        bool operator==(const peer_info_t &) const =default;
    };

    template<typename CFG>
    using import_block_t = block_t<CFG>;

    template<typename CFG>
    struct initialize_t {
        header_t<CFG> header;
        state_snapshot_t state;
        ancestry_t<CFG> ancestry;

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
            archive.process_string(*this);
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
            static const codec::variant_names_t<base_type> names {
                "peer_info"sv,
                "initialize"sv,
                "state_root"sv,
                "import_block"sv,
                "get_state"sv,
                "state"sv,
                "error"sv
            };
            static const codec::variant_index_overrides_t overrides{{{255U, 6U}}};
            archive.template process_variant<base_type>(*this, names, &overrides);
        }

        bool operator==(const message_t &) const =default;
    };

    template<typename CFG>
    struct processor_t {
        processor_t(std::string chain_id, file::tmp_directory tmp_dir);
        ~processor_t();
        message_t<CFG> process(message_t<CFG> msg);
    private:
        struct impl_t;
        std::unique_ptr<impl_t> _impl;
    };
}
