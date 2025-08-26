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

    struct peer_info_t {
        std::string name;
        version_t app_version{0, 1, 1};
        version_t jam_version{0, 7, 0};

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("name"sv, name);
            archive.process("app_version"sv, app_version);
            archive.process("jam_version"sv, jam_version);
        }

        void compatible_with(const peer_info_t &o) const
        {
            if (jam_version != o.jam_version) [[unlikely]]
                throw error(fmt::format("jam version mismatch: {} != {}", jam_version, o.jam_version));
        }
    };

    template<typename CFG>
    using import_block_t = block_t<CFG>;

    template<typename CFG>
    struct set_state_t {
        header_t<CFG> header;
        state_snapshot_t state;

        static set_state_t from_snapshot(const state_snapshot_t &state);

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("header"sv, header);
            archive.process("state"sv, state);
        }
    };

    struct get_state_t {
        header_hash_t header_hash;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("header_hash"sv, header_hash);
        }
    };

    template<typename CFG>
    using message_base_t = std::variant<
        peer_info_t,
        import_block_t<CFG>,
        set_state_t<CFG>,
        get_state_t,
        state_snapshot_t,
        state_root_t
    >;
    template<typename CFG>
    struct message_t: message_base_t<CFG> {
        using base_type = message_base_t<CFG>;
        using base_type::base_type;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            static_assert(std::variant_size_v<base_type> > 0);
            static codec::variant_names_t<base_type> names {
                "peer_info"sv,
                "import_block"sv,
                "set_state"sv,
                "get_state"sv,
                "state"sv,
                "state_root"sv
            };
            archive.template process_variant<base_type>(*this, names);
        }
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
