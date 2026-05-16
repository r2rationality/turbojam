#pragma once
/* This file is part of TurboJam project:
 * https://github.com/r2rationality/turbojam/ Copyright (c) 2025-2026 R2
 * Rationality OÜ (info at r2rationality dot com) This code is distributed under
 * the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/bytes.hpp>
#include <turbo/crypto/ed25519.hpp>
#include <turbo/jam/types/header.hpp>
#include <turbo/jam/types/state-dict.hpp>
#include <turbo/jam/merkle.hpp>
#include <gnutls/x509.h>

namespace turbo::jamnp {
    extern std::string alternative_name_varlen(buffer bytes);
    extern std::string alternative_name(const crypto::ed25519::vkey_t &vk);

    struct error: turbo::error {
        using turbo::error::error;
    };

    struct address_t {
        std::string host;
        uint16_t port;

        void serialize(auto &archive) {
            using namespace std::string_view_literals;
            archive.process("host"sv, host);
            archive.process("port"sv, port);
        }
    };

    struct cert_pair_t {
        cert_pair_t() = default;
        ~cert_pair_t();
        cert_pair_t(cert_pair_t &&o) noexcept;
        cert_pair_t &operator=(cert_pair_t &&o) noexcept;

        cert_pair_t(const cert_pair_t &) = delete;
        cert_pair_t &operator=(const cert_pair_t &) = delete;

        [[nodiscard]] bool empty() const noexcept;

        gnutls_x509_crt_t certificate = nullptr;
        gnutls_x509_privkey_t private_key = nullptr;
    };

    [[nodiscard]] extern cert_pair_t make_cert(const crypto::ed25519::key_pair_t &kp);
    [[nodiscard]] extern jam::state_snapshot_t local_genesis_state();

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
                return {hash, ver};
            if (parts[3] != builder_suffix) [[unlikely]]
                throw error(fmt::format("invalid protocol id: {}", text));
            return {hash, ver, true};
        }

        static protocol_id_t from_local_dev_spec();

        protocol_id_t(const hash4_span_t &hash, const uint16_t ver=0, const bool bld=false):
            version{ver},
            builder{bld},
            genesis_hash4{hash}
        {
        }

        protocol_id_t(const jam::header_hash_span_t &hash, const uint16_t ver=0, const bool bld=false):
            version{ver},
            builder{bld},
            genesis_hash4{hash.subspan(0, 4)}
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

    struct leaf_t {
        jam::header_hash_t hash;
        uint32_t slot;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("hash"sv, hash);
            archive.process("slot"sv, slot);
        }
    };

    using final_t = leaf_t;

    struct handshake_t {
        final_t final;
        jam::sequence_t<leaf_t> leaves{};

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("final"sv, final);
            archive.process("leaves"sv, leaves);
        }
    };

    // UP 0
    template<typename CFG>
    struct block_announcement_t {
        jam::header_t<CFG> header;
        final_t final;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("header"sv, header);
            archive.process("final"sv, final);
        }
    };

    enum class direction_t: uint8_t {
        ascending = 0,
        descending = 1
    };

    // CE 128
    struct block_request_t {
        jam::header_hash_t hash;
        direction_t direction;
        uint32_t max_blocks;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("hash"sv, hash);
            archive.process("direction"sv, direction);
            archive.process("max_blocks"sv, max_blocks);
        }
    };

    // CE 129
    struct state_request_t {
        jam::header_hash_t hash;
        jam::merkle::trie::key_t key_start;
        jam::merkle::trie::key_t key_end;
        uint32_t max_size;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("hash"sv, hash);
            archive.process("key_start"sv, key_start);
            archive.process("key_end"sv, key_end);
            archive.process("max_size"sv, max_size);
        }
    };

    struct state_resp_t {
        jam::sequence_t<jam::merkle::trie::key_t> boundaries{};
        jam::state_snapshot_t state{};

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("boundaries"sv, boundaries);
            archive.process("state"sv, state);
        }
    };

    // CE 131/132
    struct ticket_announcement_t {
        jam::epoch_index_t epoch;
        jam::ticket_envelope_t ticket;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("epoch"sv, epoch);
            archive.process("ticket"sv, ticket);
        }
    };

    // CE 133
    template<typename CFG>
    struct work_package_submission_t {
        jam::core_index_t core;
        jam::work_package_t<CFG> work_package;
    };

    using extrinsic_t = jam::byte_sequence_t;
    using import_proof_t = jam::sequence_t<jam::opaque_hash_t>;

    struct segments_root_map_config_t {
        std::string key_name = "hash";
        std::string val_name = "root";
    };
    using segments_root_map_t = jam::flat_map_t<jam::work_package_hash_t, jam::opaque_hash_t, segments_root_map_config_t>;

    // CE 146, 134
    struct work_package_bundle_submission_t {
        jam::core_index_t core;
        segments_root_map_t segments_root_map;
    };

    struct work_package_processed_t {
        jam::work_package_hash_t hash;
        jam::ed25519_signature_t signature;
    };

    // CE 135
    template<typename CFG>
    using guaranteed_work_report_t = jam::report_guarantee_t<CFG>;

    // CE 136 - no special structures are necessary
    struct shard_justification0_t {
        jam::opaque_hash_t hash;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("hash"sv, hash);
        }
    };

    struct shard_justification1_t {
        jam::opaque_hash_t hash1;
        jam::opaque_hash_t hash2;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("hash1"sv, hash1);
            archive.process("hash2"sv, hash2);
        }
    };

    using shard_justification_base_t = std::variant<
        shard_justification0_t,
        shard_justification1_t
    >;
    struct shard_justification_t: shard_justification_base_t {
        using base_type = shard_justification_base_t;
        using base_type::base_type;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            static_assert(std::variant_size_v<base_type> > 0);
            static constexpr codec::variant_names_t<base_type> names{
                "0"sv,
                "1"sv
            };
            archive.process(codec::as_variant<base_type>(*this, names));
        }
    };

    template<typename CFG>
    using segment_shard_t = jam::byte_array_t<CFG::WG_segment_size / CFG::R_shard_recovery_threshold>;

    // TODO: define work_package_bundle_t

    // CE 137,138 - work-package-bundle shard request
    struct shard_request_t {
        jam::erasure_root_t erasure_root;
        jam::shard_index_t shard;
    };

    // CE 139/140 - import-segment shard request
    struct segment_shard_request_t {
        jam::erasure_root_t erasure_root;
        jam::shard_index_t shard;
        jam::segment_indices_t segment_indices;
    };

    template<typename CFG>
    struct shard_justification2_t {
        segment_shard_t<CFG> shard;
    };

    template<typename CFG>
    using segment_shard_justification_base_t = std::variant<
        shard_justification0_t,
        shard_justification1_t,
        shard_justification2_t<CFG>
    >;
    template<typename CFG>
    struct segment_shard_justification_t: segment_shard_justification_base_t<CFG> {
        using base_type = segment_shard_justification_base_t<CFG>;
        using base_type::base_type;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            static_assert(std::variant_size_v<base_type> > 0);
            static constexpr codec::variant_names_t<base_type> names{
                "0"sv,
                "1"sv,
                "2"sv
            };
            archive.process(codec::as_variant<base_type>(*this, names));
        }
    };

    // CE 148
    struct segment_request_t {
        jam::opaque_hash_t segment_tree_root;
        jam::segment_indices_t segment_indices;
    };

    // CE 141
    template<typename CFG>
    struct assurance_t {
        jam::opaque_hash_t anchor;
        jam::bitset_t<CFG::avail_bitfield_bytes * 8> bitfield;
        jam::ed25519_signature_t signature;
    };

    // CE 142
    struct preimage_announcement_t {
        jam::service_id_t service;
        jam::opaque_hash_t hash;
        jam::preimage_length_t length;
    };

    // CE 143
    struct preimage_request_t {
        jam::opaque_hash_t hash;
    };

    // CE 144
    using tranche_t = uint8_t;
    struct core_audit_announcement_t {
        jam::core_index_t core;
        jam::work_report_hash_t work_report;
    };
    using core_audit_announcements_t = jam::sequence_t<core_audit_announcement_t>;

    struct audit_announcement_base_t {
        core_audit_announcements_t core_announcements{};
        jam::ed25519_signature_t signature;
    };

    struct first_tranche_evidence_t {
        jam::bandersnatch_vrf_signature_t signature;
    };

    struct no_show_t {
        jam::validator_index_t validator;
        audit_announcement_base_t announcement;
    };
    using no_shows_t = jam::sequence_t<no_show_t>;

    struct next_tranche_evidence_t {
        jam::bandersnatch_vrf_signature_t signature;
        no_shows_t no_shows;
    };

    struct audit_announcement_t {
        jam::header_hash_t anchor;
        tranche_t tranche;
        audit_announcement_base_t announcement;
    };

    // CE 145
    enum class validity_t: uint8_t {
        invalid = 0,
        valid = 1
    };

    struct guarantee_t {
        uint32_t slot;
        jam::guarantor_signatures_t signatures;
    };

    struct judgement_publication_t {
        jam::epoch_index_t epoch;
        jam::validator_index_t validator;
        validity_t validity;
        jam::work_report_hash_t work_report_hash;
        jam::ed25519_signature_t signature;
    };
}
