#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <array>
#include <bitset>
#include <optional>
#include <variant>
#include <vector>
#include <boost/container/flat_map.hpp>
#include <boost/container/flat_set.hpp>
#include <turbo/codec/json.hpp>
#include <turbo/common/bytes.hpp>
#include <turbo/crypto/blake2b.hpp>
#include <turbo/jam/encoding.hpp>
#include "errors.hpp"
#include "constants.hpp"

namespace turbo::jam {
    // jam-types.asn

    struct byte_sequence_t: uint8_vector {
        using base_type = uint8_vector;
        using base_type::base_type;

        void serialize(auto &archive)
        {
            archive.process_bytes(*this);
        }
    };

    template<typename T, size_t MIN=0, size_t MAX=std::numeric_limits<size_t>::max()>
    struct sequence_t: std::vector<T> {
        static constexpr size_t min_size = MIN;
        static constexpr size_t max_size = MAX;
        static_assert(MIN <= MAX);
        using base_type = std::vector<T>;
        using base_type::base_type;

        void serialize(auto &archive)
        {
            archive.process_array(*this, MIN, MAX);
        }
    };

    template<typename T, size_t MIN=0, size_t MAX=std::numeric_limits<size_t>::max()>
    struct set_t: boost::container::flat_set<T> {
        static constexpr size_t min_size = MIN;
        static constexpr size_t max_size = MAX;
        static_assert(MIN <= MAX);
        using base_type = boost::container::flat_set<T>;
        using base_type::base_type;

        void serialize(auto &archive)
        {
            archive.process_array(*this, MIN, MAX);
        }
    };

    template<typename T, size_t SZ>
    struct fixed_sequence_t: std::array<T, SZ> {
        static_assert(SZ > 0);
        using base_type = std::array<T, SZ>;
        using base_type::base_type;

        void serialize(auto &archive)
        {
            archive.process_array_fixed(*this);
        }
    };

    struct map_config_t {
        std::string key_name = "unknown";
        std::string val_name = "unknown";
    };

    template<typename K, typename V, typename CFG>
    struct map_t: std::map<K, V> {
        using base_type = std::map<K, V>;
        using base_type::base_type;

        static CFG config()
        {
            static CFG cfg;
            return cfg;
        }

        void serialize(auto &archive)
        {
            archive.process_map(*this, config().key_name, config().val_name);
        }
    };

    template<typename K, typename V, typename CFG>
    struct flat_map_t: boost::container::flat_map<K, V> {
        using base_type = boost::container::flat_map<K, V>;
        using base_type::base_type;

        static CFG config()
        {
            static CFG cfg;
            return cfg;
        }

        void serialize(auto &archive)
        {
            archive.process_map(*this, config().key_name, config().val_name);
        }
    };

    template<typename K, typename V, typename CFG>
    struct filedb_map_t: std::map<K, V> {
        using base_type = std::map<K, V>;
        using base_type::base_type;

        static CFG config()
        {
            static CFG cfg;
            return cfg;
        }

        void serialize(auto &archive)
        {
            archive.process_map(*this, config().key_name, config().val_name);
        }
    };

    template<typename T>
    struct optional_t: std::optional<T> {
        using base_type = std::optional<T>;
        using base_type::base_type;

        void serialize(auto &archive)
        {
            archive.process_optional(*this);
        }

        bool operator==(const optional_t &o) const noexcept
        {
            return *reinterpret_cast<const base_type*>(this) == *reinterpret_cast<const base_type*>(&o);
        }
    };

    template<size_t SZ>
    struct byte_array_t: byte_array<SZ> {
        using base_type = byte_array<SZ>;
        using base_type::base_type;

        void serialize(auto &archive)
        {
            archive.process_bytes_fixed(*this);
        }
    };

    template<size_t SZ>
    struct bitset_t: byte_array_t<SZ / 8> {
        using base_type = byte_array_t<SZ / 8>;
        using base_type::base_type;

        bool test(const size_t pos) const
        {
            if (pos >= SZ) [[unlikely]]
                throw error(fmt::format("the requested bit index: {} is out of range: [0;{})", pos, SZ));
            const auto byte_pos = pos >> 3;
            const auto bit_pos = pos & 7;
            return (*this)[byte_pos] & (1 << bit_pos);
        }
    };

    using byte_array_32_t = byte_array_t<32>;

    using bandersnatch_public_t = byte_array_t<32>;
    using ed25519_public_t = byte_array_t<32>;
    using bls_public_t = byte_array_t<144>;

    using bandersnatch_vrf_signature_t = byte_array_t<96>;
    using bandersnatch_ring_vrf_signature_t = byte_array_t<784>;
    using ed25519_signature_t = byte_array_t<64>;

    using bandersnatch_ring_commitment_t = byte_array_t<144>;

    using opaque_hash_t = byte_array_t<32>;

    // JAM (4.28)
    template<typename CFG>
    struct time_slot_t {
        static std::chrono::sys_time<std::chrono::seconds> jam_era_start()
        {
            static std::tm t {};
            t.tm_sec = 0;
            t.tm_min = 0;
            t.tm_hour = 12;
            t.tm_mday = 1;
            t.tm_mon = 0;
            t.tm_year = 2025 - 1900;
            t.tm_isdst = 0;
#           if defined(_WIN32)
                time_t time_since_epoch = _mkgmtime(&t);
#           else
                time_t time_since_epoch = timegm(&t);
#           endif
            return std::chrono::sys_time<std::chrono::seconds>{std::chrono::seconds{time_since_epoch}};
        }

        static time_slot_t current()
        {
            static auto era_start = jam_era_start();
            // JAM time does not account for leap seconds!
            const auto diff = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now() - era_start).count();
            if (diff < 0) [[unlikely]]
                throw error("the current time is before the JAM start era!");
            return { numeric_cast<uint32_t>(diff) };
        }

        time_slot_t(const uint32_t slot):
            _val { slot }
        {
        }

        time_slot_t() noexcept =default;
        time_slot_t(const time_slot_t &) noexcept =default;
        time_slot_t &operator=(const time_slot_t &) noexcept =default;

        void serialize(auto &archive)
        {
            archive.process_uint(_val);
        }

        [[nodiscard]] uint32_t slot() const
        {
            return _val;
        }

        [[nodiscard]] uint32_t epoch() const
        {
            return _val / CFG::E_epoch_length;
        }

        [[nodiscard]] uint32_t epoch_slot() const
        {
            return _val % CFG::E_epoch_length;
        }

        std::strong_ordering operator<=>(const time_slot_t &o) const noexcept
        {
            return _val <=> o._val;
        }

        bool operator==(const time_slot_t &o) const noexcept
        {
            return (*this <=> o) == std::strong_ordering::equal;
        }
    private:
        uint32_t _val = 0;
    };

    using validator_index_t = uint16_t;
    using core_index_t = uint16_t;

    using header_hash_t = opaque_hash_t;
    using state_root_t = opaque_hash_t;
    using beefy_root_t = opaque_hash_t;
    using work_package_hash_t = opaque_hash_t;
    using work_report_hash_t = opaque_hash_t;
    using exports_root_t = opaque_hash_t;
    using erasure_root_t = opaque_hash_t;

    template<typename T>
    struct varlen_uint_t {
        using base_type = T;

        varlen_uint_t() =default;

        varlen_uint_t(const T val):
            _val { val }
        {
        }

        void serialize(auto &archive)
        {
            archive.process_varlen_uint(_val);
        }

        operator T() const
        {
            return _val;
        }

        template<typename T2>
        varlen_uint_t &operator+=(const varlen_uint_t<T2> &o)
        {
            _val += numeric_cast<T>(static_cast<T2>(o));
            return *this;
        }

        varlen_uint_t &operator+=(const varlen_uint_t &o)
        {
            _val += o._val;
            return *this;
        }

        varlen_uint_t &operator-=(const varlen_uint_t &o)
        {
            _val -= o._val;
            return *this;
        }

        varlen_uint_t &operator++()
        {
            ++_val;
            return *this;
        }
    private:
        T _val = 0;
    };

    using gas_t = varlen_uint_t<uint64_t>;

    using entropy_t = opaque_hash_t;
    using entropy_buffer_t = fixed_sequence_t<entropy_t, 4>;

    using validator_metadata_t = byte_array_t<128>;

    struct validator_data_t {
        bandersnatch_public_t bandersnatch; // JAM (6.9)
        static_assert(sizeof(bandersnatch) == 32);
        ed25519_public_t ed25519; // JAM (6.10)
        static_assert(sizeof(ed25519) == 32);
        bls_public_t bls; // JAM (6.11)
        static_assert(sizeof(bls) == 144);
        validator_metadata_t metadata; // JAM (6.12)
        static_assert(sizeof(metadata) == 128);

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("bandersnatch"sv, bandersnatch);
            archive.process("ed25519"sv, ed25519);
            archive.process("bls"sv, bls);
            archive.process("metadata"sv, metadata);
        }

        bool operator==(const validator_data_t &o) const = default;
    };
    static_assert(sizeof(validator_data_t) == 336); // JAM paper (6.8)

    using service_id_t = uint32_t;
    using balance_t = uint64_t;

    using prerequisites_t = sequence_t<opaque_hash_t>;

    // GP 11.1.2: X
    template<typename CFG>
    struct refine_context_t {
	    header_hash_t anchor; // a
	    state_root_t state_root; // S
	    beefy_root_t beefy_root; // b
	    header_hash_t lookup_anchor; // l
	    time_slot_t<CFG> lookup_anchor_slot; // t
	    prerequisites_t prerequisites; // p_bold

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("anchor"sv, anchor);
            archive.process("state_root"sv, state_root);
            archive.process("beefy_root"sv, beefy_root);
            archive.process("lookup_anchor"sv, lookup_anchor);
            archive.process("lookup_anchor_slot"sv, lookup_anchor_slot);
            archive.process("prerequisites"sv, prerequisites);
        }

        bool operator==(const refine_context_t &o) const = default;
    };

    using authorizer_hash_t = opaque_hash_t;

    template<typename CONSTANT_SET=config_prod>
    using auth_queue_t = fixed_sequence_t<authorizer_hash_t, CONSTANT_SET::Q_auth_queue_size>;

    template<typename CONSTANT_SET=config_prod>
    using auth_queues_t = fixed_sequence_t<auth_queue_t<CONSTANT_SET>, CONSTANT_SET::C_core_count>;

    // max size: auth_pool_max_size
    template<typename CFG=config_prod>
    using auth_pool_t = sequence_t<authorizer_hash_t, 0, CFG::O_auth_pool_max_size>;

    struct core_authorizer_t {
        core_index_t core;
        opaque_hash_t auth_hash;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("core"sv, core);
            archive.process("auth_hash"sv, auth_hash);
        }

        bool operator==(const core_authorizer_t &o) const = default;
    };
    using core_authorizers_t = sequence_t<core_authorizer_t>;

    template<typename CFG=config_prod>
    using auth_pools_t = fixed_sequence_t<auth_pool_t<CFG>, CFG::C_core_count>;

    struct import_spec_t {
        opaque_hash_t tree_root;
        uint16_t index;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("tree_root"sv, tree_root);
            archive.process("index"sv, index);
        }

        bool operator==(const import_spec_t &o) const = default;
    };

    struct extrinsic_spec_t {
        opaque_hash_t hash;
        uint32_t len;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("hash"sv, hash);
            archive.process("len"sv, len);
        }

        bool operator==(const extrinsic_spec_t &o) const = default;
    };

    struct work_item_t {
        service_id_t service;
        opaque_hash_t code_hash;
        gas_t::base_type refine_gas_limit;
        gas_t::base_type accumulate_gas_limit;
        uint16_t export_count;
        byte_sequence_t payload;
        sequence_t<import_spec_t> import_segments;
        sequence_t<extrinsic_spec_t> extrinsic;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("service"sv, service);
            archive.process("code_hash"sv, code_hash);
            archive.process("refine_gas_limit"sv, refine_gas_limit);
            archive.process("accumulate_gas_limit"sv, accumulate_gas_limit);
            archive.process("export_count"sv, export_count);
            archive.process("payload"sv, payload);
            archive.process("import_segments"sv, import_segments);
            archive.process("extrinsic"sv, extrinsic);
        }

        bool operator==(const work_item_t &o) const = default;
    };

    template<typename CFG>
    struct work_package_t {
        service_id_t auth_code_host;
        opaque_hash_t auth_code_hash;
        refine_context_t<CFG> context;
        byte_sequence_t authorization;
        byte_sequence_t authorizer_config;
        sequence_t<work_item_t, 1, CFG::I_max_work_items> items;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("auth_code_host"sv, auth_code_host);
            archive.process("auth_code_hash"sv, auth_code_hash);
            archive.process("context"sv, context);
            archive.process("authorization"sv, authorization);
            archive.process("authorizer_config"sv, authorizer_config);
            archive.process("items"sv, items);
        }

        bool operator==(const work_package_t &o) const = default;
    };

    struct work_result_ok_t {
        byte_sequence_t data;

        void serialize(auto &archive)
        {
            archive.process_bytes(data);
        }

        bool operator==(const work_result_ok_t &o) const = default;
    };

    struct work_result_out_of_gas_t {
        void serialize(auto &)
        {
            // do nothing
        }

        bool operator==(const work_result_out_of_gas_t &) const
        {
            return true;
        }
    };

    struct work_result_panic_t {
        void serialize(auto &)
        {
            // do nothing
        }

        bool operator==(const work_result_panic_t &) const
        {
            return true;
        }
    };

    struct work_result_bad_exports_t {
        void serialize(auto &)
        {
            // do nothing
        }

        bool operator==(const work_result_bad_exports_t &) const
        {
            return true;
        }
    };

    struct work_result_bad_code_t {
        void serialize(auto &)
        {
            // do nothing
        }

        bool operator==(const work_result_bad_code_t &) const
        {
            return true;
        }
    };

    struct work_result_code_oversize_t {
        void serialize(auto &)
        {
            // do nothing
        }

        bool operator==(const work_result_code_oversize_t &) const
        {
            return true;
        }
    };

    struct work_result_bad_digest_t {
        void serialize(auto &)
        {
            // do nothing
        }

        bool operator==(const work_result_bad_digest_t &) const
        {
            return true;
        }
    };

    using work_exec_result_base_t = std::variant<
        work_result_ok_t,
        work_result_out_of_gas_t,
        work_result_panic_t,
        work_result_bad_exports_t,
        work_result_bad_digest_t,
        work_result_bad_code_t,
        work_result_code_oversize_t
    >;
    struct work_exec_result_t: work_exec_result_base_t {
        using base_type = work_exec_result_base_t;
        using base_type::base_type;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            static_assert(std::variant_size_v<base_type> > 0);
            static codec::variant_names_t<base_type> names {
                "ok"sv,
                "out_of_gas"sv,
                "panic"sv,
                "bad_exports"sv,
                "bad_digest"sv,
                "bad_code"sv,
                "code_oversize"sv
            };
            archive.template process_variant<base_type>(*this, names);
        }
    };

    struct refine_load_t {
        gas_t gas_used; // u
        varlen_uint_t<uint16_t> imports; // i
        varlen_uint_t<uint16_t> extrinsic_count; // x
        varlen_uint_t<uint32_t> extrinsic_size; // z
        varlen_uint_t<uint16_t> exports; // e

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("gas_used"sv, gas_used);
            archive.process("imports"sv, imports);
            archive.process("extrinsic_count"sv, extrinsic_count);
            archive.process("extrinsic_size"sv, extrinsic_size);
            archive.process("exports"sv, exports);
        }

        bool operator==(const refine_load_t &o) const = default;
    };

    // JAM (11.6)
    struct work_result_t {
        service_id_t service_id; // s
        opaque_hash_t code_hash; // c
        opaque_hash_t payload_hash; // y
        // gas_t accumulate_gas; gas_t is variable_length but currently the value is fixed length
        gas_t::base_type accumulate_gas; // g
        work_exec_result_t result; // l
        refine_load_t refine_load;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("service_id"sv, service_id);
            archive.process("code_hash"sv, code_hash);
            archive.process("payload_hash"sv, payload_hash);
            archive.process("accumulate_gas"sv, accumulate_gas);
            archive.process("result"sv, result);
            archive.process("refine_load"sv, refine_load);
        }

        bool operator==(const work_result_t &o) const = default;
    };
    using work_results_t = sequence_t<work_result_t, 1, 16>;

    // (11.5)
    struct work_package_spec_t {
        work_package_hash_t hash; // p
        uint32_t length; // l
        erasure_root_t erasure_root; // u
        erasure_root_t exports_root; // e
        uint16_t exports_count; // n

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("hash"sv, hash);
            archive.process("length"sv, length);
            archive.process("erasure_root"sv, erasure_root);
            archive.process("exports_root"sv, exports_root);
            archive.process("exports_count"sv, exports_count);
        }

        bool operator==(const work_package_spec_t &o) const = default;
    };

    struct segment_root_lookup_item {
        work_package_hash_t work_package_hash;
        opaque_hash_t segment_tree_root;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("work_package_hash"sv, work_package_hash);
            archive.process("segment_tree_root"sv, segment_tree_root);
        }

        bool operator==(const segment_root_lookup_item &o) const = default;
    };

    using segment_root_lookup_t = sequence_t<segment_root_lookup_item>;

    // JAM (11.2)
    template<typename CFG>
    struct work_report_t {
        work_package_spec_t package_spec{}; // s_bold
        refine_context_t<CFG> context{}; // c_bold
        varlen_uint_t<core_index_t> core_index{}; // c
        opaque_hash_t authorizer_hash{}; // a
        gas_t auth_gas_used{}; // g
        byte_sequence_t auth_output{}; // t
        segment_root_lookup_t segment_root_lookup{}; // l
        work_results_t results{}; // d

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("package_spec"sv, package_spec);
            archive.process("context"sv, context);
            archive.process("core_index"sv, core_index);
            archive.process("authorizer_hash"sv, authorizer_hash);
            archive.process("auth_gas_used"sv, auth_gas_used);
            archive.process("auth_output"sv, auth_output);
            archive.process("segment_root_lookup"sv, segment_root_lookup);
            archive.process("results"sv, results);
        }

        bool operator==(const work_report_t &o) const = default;
    };
    static_assert(codec::serializable_c<work_report_t<config_prod>>);
    static_assert(codec::serializable_c<work_report_t<config_tiny>>);

    template<typename CFG>
    using work_reports_t = sequence_t<work_report_t<CFG>>;

    template<typename CFG>
    struct avail_assurance_t {
        opaque_hash_t anchor;
        bitset_t<CFG::avail_bitfield_bytes * 8> bitfield;
        validator_index_t validator_index;
        ed25519_signature_t signature;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("anchor"sv, anchor);
            archive.process("bitfield"sv, bitfield);
            archive.process("validator_index"sv, validator_index);
            archive.process("signature"sv, signature);
        }

        bool operator==(const avail_assurance_t &o) const = default;
    };

    template<typename CFG=config_prod>
    using assurances_extrinsic_t = sequence_t<avail_assurance_t<CFG>, 0, CFG::V_validator_count>;

    template<typename CFG>
    struct availability_assignment_t {
        work_report_t<CFG> report;
        uint32_t timeout;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("report"sv, report);
            archive.process("timeout"sv, timeout);
        }

        bool operator==(const availability_assignment_t &o) const = default;
    };

    template<typename CFG>
    using availability_assignments_item_t = optional_t<availability_assignment_t<CFG>>;

    template<typename CFG>
    using validators_data_t = fixed_sequence_t<validator_data_t, CFG::V_validator_count>;

    template<typename CFG>
    using availability_assignments_t = fixed_sequence_t<availability_assignments_item_t<CFG>, CFG::C_core_count>;

    using mmr_peak_t = optional_t<opaque_hash_t>;

    using mmr_peaks_t = sequence_t<mmr_peak_t>;
    struct mmr_t: mmr_peaks_t {
        using base_type = mmr_peaks_t;
        using base_type::base_type;

        void place(size_t idx, const opaque_hash_t &h);
        void append(const opaque_hash_t &h);
        [[nodiscard]] opaque_hash_t root() const;
    };

    struct reported_work_package_t {
        work_report_hash_t hash;
        exports_root_t exports_root;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("hash"sv, hash);
            archive.process("exports_root"sv, exports_root);
        }

        std::strong_ordering operator<=>(const reported_work_package_t &o) const
        {
            return hash <=> o.hash;
        }

        bool operator==(const reported_work_package_t &o) const noexcept = default;
    };

    template<typename CFG>
    using reported_work_seq_t = set_t<reported_work_package_t, 0, CFG::C_core_count>;

    template<typename CFG>
    struct block_info_t {
        header_hash_t header_hash {}; // h
        opaque_hash_t beefy_root {}; // b - MMR root
        state_root_t state_root {}; // s
        reported_work_seq_t<CFG> reported {}; // p

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("header_hash"sv, header_hash);
            archive.process("beefy_root"sv, beefy_root);
            archive.process("state_root"sv, state_root);
            archive.process("reported"sv, reported);
        }

        bool operator==(const block_info_t &o) const noexcept = default;
    };

    template<typename CFG>
    using blocks_history_t = sequence_t<block_info_t<CFG>, 0, CFG::H_max_blocks_history>;

    template<typename CFG>
    struct recent_blocks_t {
        blocks_history_t<CFG> history;
        mmr_t mmr{};

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("history"sv, history);
            archive.push("mmr");
            archive.process("peaks", mmr);
            archive.pop();
        }

        bool operator==(const recent_blocks_t &o) const noexcept = default;
    };

    struct validator_statistics_t {
        uint32_t blocks;
        uint32_t tickets;
        uint32_t pre_images;
        uint32_t pre_images_size;
        uint32_t guarantees;
        uint32_t assurances;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("blocks"sv, blocks);
            archive.process("tickets"sv, tickets);
            archive.process("pre_images"sv, pre_images);
            archive.process("pre_images_size"sv, pre_images_size);
            archive.process("guarantees"sv, guarantees);
            archive.process("assurances"sv, assurances);
        }

        bool operator==(const validator_statistics_t &o) const = default;
    };

    using ticket_id_t = opaque_hash_t;
    using ticket_attempt_t = uint8_t;

    struct ticket_envelope_t {
        ticket_attempt_t attempt;
        bandersnatch_ring_vrf_signature_t signature;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("attempt"sv, attempt);
            archive.process("signature"sv, signature);
        }

        bool operator==(const ticket_envelope_t &o) const = default;
    };

    // JAM (6.6)
    struct ticket_body_t {
        ticket_id_t id;
        ticket_attempt_t attempt;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("id"sv, id);
            archive.process("attempt"sv, attempt);
        }

        std::strong_ordering operator<=>(const ticket_body_t &o) const
        {
            if (const auto cmp = id <=> o.id; cmp != std::strong_ordering::equal)
                return cmp;
            return attempt <=> o.attempt;
        }

        bool operator==(const ticket_body_t &o) const
        {
            return (*this <=> o) == std::strong_ordering::equal;
        }
    };

    // JAM (6.5)
    template<typename CFG=config_prod>
    using tickets_accumulator_t = set_t<ticket_body_t, 0, CFG::E_epoch_length>;

    template<typename CFG=config_prod>
    using tickets_t = fixed_sequence_t<ticket_body_t, CFG::E_epoch_length>;

    template<typename CFG=config_prod>
    using keys_t = fixed_sequence_t<bandersnatch_public_t, CFG::E_epoch_length>;

    // JAM (6.5)
    template<typename CFG>
    struct tickets_or_keys_t: std::variant<tickets_t<CFG>, keys_t<CFG>> {
        using base_type = std::variant<tickets_t<CFG>, keys_t<CFG>>;
        using base_type::base_type;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            static_assert(std::variant_size_v<base_type> > 0);
            static codec::variant_names_t<base_type> names {
                "tickets"sv,
                "keys"sv
            };
            archive.template process_variant<base_type>(*this, names);
        }
    };

    template<typename CFG=config_prod>
    using tickets_extrinsic_t = sequence_t<ticket_envelope_t, 0, CFG::K_max_tickets_per_block>;

    struct judgement_t {
        bool vote; // v
        validator_index_t index; // i
        ed25519_signature_t signature; // s

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("vote"sv, vote);
            archive.process("index"sv, index);
            archive.process("signature"sv, signature);
        }

        std::strong_ordering operator<=>(const judgement_t &o) const
        {
            // JAM (10.10) judgements are ordered by validator_index first!
            if (const auto cmp = index <=> o.index; cmp != std::strong_ordering::equal)
                return cmp;
            if (const auto cmp = vote <=> o.vote; cmp != std::strong_ordering::equal)
                return cmp;
            if (const auto cmp = signature <=> o.signature; cmp != std::strong_ordering::equal)
                return cmp;
            return std::strong_ordering::equal;
        }

        bool operator==(const judgement_t &o) const
        {
            return (*this <=> o) == std::strong_ordering::equal;
        }
    };

    template<typename CFG>
    struct verdict_t {
        work_report_hash_t report; // r
        uint32_t age; // a
        fixed_sequence_t<judgement_t, CFG::validator_super_majority> judgements; // j

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("target"sv, report);
            archive.process("age"sv, age);
            archive.process("votes"sv, judgements);
        }

        bool operator==(const verdict_t &o) const = default;
    };

    struct culprit_t {
        work_report_hash_t report; // r
        ed25519_public_t key; // k
        ed25519_signature_t signature; // s

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("target"sv, report);
            archive.process("key"sv, key);
            archive.process("signature"sv, signature);
        }

        bool operator==(const culprit_t &o) const = default;
    };

    struct fault_t {
        work_report_hash_t report;
        bool vote;
        ed25519_public_t key;
        ed25519_signature_t signature;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("target"sv, report);
            archive.process("vote"sv, vote);
            archive.process("key"sv, key);
            archive.process("signature"sv, signature);
        }

        bool operator==(const fault_t &o) const = default;
    };

    using ed25519_keys_set_t = set_t<ed25519_public_t>;

    // JAM (10.1)
    struct disputes_records_t {
        set_t<work_report_hash_t> good{};
        set_t<work_report_hash_t> bad{};
        set_t<work_report_hash_t> wonky{};
        ed25519_keys_set_t offenders{};

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("good"sv, good);
            archive.process("bad"sv, bad);
            archive.process("wonky"sv, wonky);
            archive.process("offenders"sv, offenders);
        }

        [[nodiscard]] bool known_report(const work_report_hash_t &r) const noexcept {
            if (good.contains(r))
                return true;
            if (bad.contains(r))
                return true;
            if (wonky.contains(r))
                return true;
            return false;
        };

        bool operator==(const disputes_records_t &o) const = default;
    };

    template<typename CFG>
    struct disputes_extrinsic_t {
        sequence_t<verdict_t<CFG>> verdicts{};
        sequence_t<culprit_t> culprits{};
        sequence_t<fault_t> faults{};

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("verdicts"sv, verdicts);
            archive.process("culprits"sv, culprits);
            archive.process("faults"sv, faults);
        }

        bool empty() const
        {
            if (!verdicts.empty())
                return false;
            if (!culprits.empty())
                return false;
            if (!faults.empty())
                return false;
            return true;
        }

        bool operator==(const disputes_extrinsic_t &o) const = default;
    };

    struct preimage_t {
        service_id_t requester;
        byte_sequence_t blob;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("requester"sv, requester);
            archive.process("blob"sv, blob);
        }

        std::strong_ordering operator<=>(const preimage_t &o) const noexcept
        {
            if (const auto cmp = requester <=> o.requester; cmp != std::strong_ordering::equal)
                return cmp;
            return blob <=> o.blob;
        }

        bool operator==(const preimage_t &o) const noexcept = default;
    };

    using preimages_extrinsic_t = sequence_t<preimage_t>;

    struct validator_signature_t {
        validator_index_t validator_index;
        ed25519_signature_t signature;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("validator_index"sv, validator_index);
            archive.process("signature"sv, signature);
        }

        bool operator==(const validator_signature_t &o) const = default;
    };

    template<typename CFG>
    struct report_guarantee_t {
        work_report_t<CFG> report;
        time_slot_t<CFG> slot;
        sequence_t<validator_signature_t> signatures;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("report"sv, report);
            archive.process("slot"sv, slot);
            archive.process("signatures"sv, signatures);
        }

        bool operator==(const report_guarantee_t &o) const = default;
    };

    template<typename CFG=config_prod>
    using guarantees_extrinsic_t = sequence_t<report_guarantee_t<CFG>, 0, CFG::C_core_count>;

    using report_deps_t = set_t<work_package_hash_t>;

    template<typename CFG>
    struct ready_record_t {
        work_report_t<CFG> report;
        report_deps_t dependencies;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("report"sv, report);
            archive.process("dependencies"sv, dependencies);
        }

        bool operator==(const ready_record_t &o) const = default;
    };

    template<typename CFG>
    using ready_queue_item_t = sequence_t<ready_record_t<CFG>>;

    template<typename CFG>
    using ready_queue_t = fixed_sequence_t<ready_queue_item_t<CFG>, CFG::E_epoch_length>;

    using accumulated_queue_item_t = set_t<work_package_hash_t>;

    template<typename CFG>
    using accumulated_queue_t = fixed_sequence_t<accumulated_queue_item_t, CFG::E_epoch_length>;

    struct always_accumulate_map_config_t {
        std::string key_name = "id";
        std::string val_name = "gas";
    };

    /*struct always_accumulate_map_item_t {
        service_id_t id;
        gas_t gas;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("id"sv, id);
            archive.process("gas"sv, gas);
        }

        bool operator==(const always_accumulate_map_item_t &o) const = default;
    };*/
    using free_services_t = flat_map_t<service_id_t, gas_t, always_accumulate_map_config_t>;

    template<typename CFG>
    using assigners_t = fixed_sequence_t<service_id_t, CFG::C_core_count>;

    template<typename CFG>
    struct privileges_t {
        service_id_t bless; // m
        assigners_t<CFG> assign; // a
        service_id_t designate; // v
        free_services_t always_acc; // z

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("bless"sv, bless);
            archive.process("assign"sv, assign);
            archive.process("designate"sv, designate);
            archive.process("always_acc"sv, always_acc);
        }

        bool operator==(const privileges_t &o) const = default;
    };

    using accumulate_root_t = opaque_hash_t;

    struct epoch_mark_validator_keys_t {
        bandersnatch_public_t bandersnatch;
        ed25519_public_t ed25519;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("bandersnatch"sv, bandersnatch);
            archive.process("ed25519"sv, ed25519);
        }

        bool operator==(const epoch_mark_validator_keys_t &o) const = default;
    };

    template<typename CFG>
    struct epoch_mark_validators_t: fixed_sequence_t<epoch_mark_validator_keys_t, CFG::V_validator_count> {
        using base_type = fixed_sequence_t<epoch_mark_validator_keys_t, CFG::V_validator_count>;
        using base_type::base_type;

        epoch_mark_validators_t(const validators_data_t<CFG> &o)
        {
            if (o.size() != this->size()) [[unlikely]]
                throw error("internal error: validators_t size != epoch_mark_validators_t!");
            for (size_t i = 0; i < this->size(); ++i) {
                auto &v_dst = (*this)[i];
                const auto &v_src = o[i];
                v_dst.bandersnatch = v_src.bandersnatch;
                v_dst.ed25519 = v_src.ed25519;
            }
        }

        bool operator==(const validators_data_t<CFG> &o) const
        {
            if (o.size() != this->size())
                return false;
            for (size_t vi = 0; vi < this->size(); ++vi) {
                if (o[vi].bandersnatch != this->operator[](vi).bandersnatch)
                    return false;
                if (o[vi].ed25519 != this->operator[](vi).ed25519)
                    return false;
            }
            return true;
        }
    };

    template<typename CFG>
    struct epoch_mark_t {
        entropy_t entropy {};
        entropy_t tickets_entropy {};
        epoch_mark_validators_t<CFG> validators {};

        void serialize(auto &archive)
        {
            using namespace std::placeholders;
            archive.process("entropy", entropy);
            archive.process("tickets_entropy", tickets_entropy);
            archive.process("validators", validators);
        }

        bool operator==(const epoch_mark_t &o) const = default;
    };

    template<typename CFG=config_prod>
    using tickets_mark_t = fixed_sequence_t<ticket_body_t, CFG::E_epoch_length>;

    using offenders_mark_t = ed25519_keys_set_t;

    template<typename CFG=config_prod>
    using validators_statistics_t = fixed_sequence_t<validator_statistics_t, CFG::V_validator_count>;

    struct core_activity_record_t {
        varlen_uint_t<uint32_t> da_load = 0;
        varlen_uint_t<uint16_t> popularity = 0;
        varlen_uint_t<uint16_t> imports = 0;
        varlen_uint_t<uint16_t> extrinsic_count = 0;
        varlen_uint_t<uint32_t> extrinsic_size = 0;
        varlen_uint_t<uint16_t> exports = 0;
        varlen_uint_t<uint32_t> bundle_size = 0;
        gas_t gas_used = 0;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("da_load"sv, da_load);
            archive.process("popularity"sv, popularity);
            archive.process("imports"sv, imports);
            archive.process("extrinsic_count"sv, extrinsic_count);
            archive.process("extrinsic_size"sv, extrinsic_size);
            archive.process("exports"sv, exports);
            archive.process("bundle_size"sv, bundle_size);
            archive.process("gas_used"sv, gas_used);
        }

        bool operator==(const core_activity_record_t &o) const = default;
    };

    template<typename CFG>
    using cores_statistics_t = fixed_sequence_t<core_activity_record_t, CFG::C_core_count>;

    struct service_activity_record_t {
        varlen_uint_t<uint16_t> provided_count {};
        varlen_uint_t<uint32_t> provided_size {};
        varlen_uint_t<uint32_t> refinement_count {};
        gas_t refinement_gas_used {};
        varlen_uint_t<uint32_t> imports {};
        varlen_uint_t<uint32_t> extrinsic_count {};
        varlen_uint_t<uint32_t> extrinsic_size {};
        varlen_uint_t<uint32_t> exports {};
        varlen_uint_t<uint32_t> accumulate_count {};
        gas_t accumulate_gas_used {};

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("provided_count"sv, provided_count);
            archive.process("provided_size"sv, provided_size);
            archive.process("refinement_count"sv, refinement_count);
            archive.process("refinement_gas_used"sv, refinement_gas_used);
            archive.process("imports"sv, imports);
            archive.process("extrinsic_count"sv, extrinsic_count);
            archive.process("extrinsic_size"sv, extrinsic_size);
            archive.process("exports"sv, exports);
            archive.process("accumulate_count"sv, accumulate_count);
            archive.process("accumulate_gas_used"sv, accumulate_gas_used);
        }

        bool operator==(const service_activity_record_t &o) const = default;
    };

    struct services_statistics_config_t {
        std::string key_name = "id";
        std::string val_name = "record";
    };
    using services_statistics_t = map_t<service_id_t, service_activity_record_t, services_statistics_config_t>;

    template<typename CFG>
    struct statistics_t {
        validators_statistics_t<CFG> current {};
        validators_statistics_t<CFG> last {};
        cores_statistics_t<CFG> cores {};
        services_statistics_t services {};

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("vals_current"sv, current);
            archive.process("vals_last"sv, last);
            archive.process("cores"sv, cores);
            archive.process("services"sv, services);
        }

        bool operator==(const statistics_t &o) const = default;
    };
}
