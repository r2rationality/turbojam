#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <array>
#include <bitset>
#include <cmath>
#include <cstdint>
#include <optional>
#include <variant>
#include <vector>
#include <boost/container/flat_set.hpp>
#include <turbo/codec/json.hpp>
#include <turbo/common/bytes.hpp>
#include "constants.hpp"
#include "encoding.hpp"

namespace turbo::jam {
    // jam-types.asn

    template<typename T>
    concept from_json_c = requires(T t, const boost::json::value &j)
    {
        { T::from_json(j) };
    };

    struct byte_sequence_t: uint8_vector, codec::serializable_t<byte_sequence_t> {
        using base_type = uint8_vector;
        using base_type::base_type;

        void serialize(auto &archive)
        {
            archive.process_bytes(*this);
        }

        void serialize(auto &archive) const
        {
            static_assert(std::remove_reference_t<decltype(archive)>::read_only);
            const_cast<byte_sequence_t &>(*this).serialize(archive);
        }
    };

    template<typename T, size_t MIN=0, size_t MAX=std::numeric_limits<size_t>::max()>
    struct sequence_t: std::vector<T>, codec::serializable_t<sequence_t<T, MIN, MAX>> {
        static constexpr size_t min_size = MIN;
        static constexpr size_t max_size = MAX;
        static_assert(MIN < MAX);
        using base_type = std::vector<T>;
        using base_type::base_type;

        void serialize(auto &archive)
        {
            archive.process_array(*this, MIN, MAX);
        }

        void serialize(auto &archive) const
        {
            static_assert(std::remove_reference_t<decltype(archive)>::read_only);
            const_cast<sequence_t &>(*this).serialize(archive);
        }
    };

    template<typename T, size_t SZ>
    struct fixed_sequence_t: std::array<T, SZ>, codec::serializable_t<fixed_sequence_t<T, SZ>> {
        static_assert(SZ > 0);
        using base_type = std::array<T, SZ>;
        using base_type::base_type;

        void serialize(auto &archive)
        {
            archive.process_array_fixed(*this);
        }

        void serialize(auto &archive) const
        {
            static_assert(std::remove_reference_t<decltype(archive)>::read_only);
            const_cast<fixed_sequence_t &>(*this).serialize(archive);
        }
    };

    struct map_config_t {
        std::string key_name = "unknown";
        std::string val_name = "unknown";
    };

    template<typename K, typename V, typename CFG>
    struct map_t: std::map<K, V>, codec::serializable_t<map_t<K, V, CFG>> {
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

        void serialize(auto &archive) const
        {
            static_assert(std::remove_reference_t<decltype(archive)>::read_only);
            const_cast<map_t &>(*this).serialize(archive);
        }
    };

    template<typename T>
    struct optional_t: std::optional<T>, codec::serializable_t<optional_t<T>> {
        using base_type = std::optional<T>;
        using base_type::base_type;

        void serialize(auto &archive)
        {
            archive.process_optional(*this);
        }

        void serialize(auto &archive) const
        {
            static_assert(std::remove_reference_t<decltype(archive)>::read_only);
            const_cast<optional_t &>(*this).serialize(archive);
        }

        bool operator==(const optional_t &o) const noexcept
        {
            return *reinterpret_cast<const base_type*>(this) == *reinterpret_cast<const base_type*>(&o);
        }
    };

    template<size_t SZ>
    struct byte_array_t: byte_array<SZ>, codec::serializable_t<byte_array_t<SZ>> {
        using base_type = byte_array<SZ>;
        using base_type::base_type;

        void serialize(auto &archive)
        {
            archive.process_bytes_fixed(*this);
        }

        void serialize(auto &archive) const
        {
            static_assert(std::remove_reference_t<decltype(archive)>::read_only);
            const_cast<byte_array_t &>(*this).serialize(archive);
        }

        template<typename C=byte_array_t>
        static C from_bytes(decoder &dec)
        {
            return C::template from<C>(dec);
        }

        template<typename C=byte_array_t>
        static C from_json(const boost::json::value &j)
        {
            codec::json::decoder dec { j };
            return C::template from<C>(dec);
        }

        void to_bytes(encoder &enc) const
        {
            enc.bytes() << *this;
        }
    };

    template<size_t SZ>
    struct bitset_t: byte_array_t<SZ / 8> {
        using base_type = byte_array_t<SZ / 8>;
        using base_type::base_type;

        static bitset_t from_bytes(decoder &dec)
        {
            return base_type::template from_bytes<bitset_t>(dec);
        }

        static bitset_t from_json(const boost::json::value &j)
        {
            return base_type::template from_json<bitset_t>(j);
        }

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

    template<typename CONSTANTS>
    struct time_slot_t: codec::serializable_t<time_slot_t<CONSTANTS>> {
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

        void serialize(auto &archive) const
        {
            static_assert(std::remove_reference_t<decltype(archive)>::read_only);
            const_cast<time_slot_t &>(*this).serialize(archive);
        }

        uint32_t slot() const
        {
            return _val;
        }

        uint32_t epoch() const
        {
            return _val / CONSTANTS::epoch_length;
        }

        uint32_t epoch_slot() const
        {
            return _val % CONSTANTS::epoch_length;
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
    struct varlen_uint_t: codec::serializable_t<varlen_uint_t<T>> {
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

        void serialize(auto &archive) const
        {
            static_assert(std::remove_reference_t<decltype(archive)>::read_only);
            archive.process_varlen_uint(const_cast<varlen_uint_t &>(*this)._val);
        }

        operator T() const
        {
            return _val;
        }

        varlen_uint_t &operator+=(const varlen_uint_t &o)
        {
            _val += o._val;
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
        bandersnatch_public_t bandersnatch;
        ed25519_public_t ed25519;
        bls_public_t bls;
        validator_metadata_t metadata;

        static validator_data_t from_bytes(decoder &dec);
        static validator_data_t from_json(const boost::json::value &json);

        bool operator==(const validator_data_t &o) const
        {
            return bandersnatch == o.bandersnatch && ed25519 == o.ed25519 && bls == o.bls && metadata == o.metadata;
        }
    };
    static_assert(sizeof(validator_data_t) == 336); // JAM paper (6.8)

    using service_id_t = uint32_t;

    struct service_info_t {
        opaque_hash_t code_hash {};
        uint64_t balance = 0;
        // gas saved in the fixed format form
        gas_t::base_type min_item_gas = 0;
        gas_t::base_type min_memo_gas = 0;
        uint64_t bytes = 0;
        uint32_t items = 0;

        static service_info_t from_bytes(decoder &dec);
        bool operator==(const service_info_t &o) const noexcept;
    };

    using prerequisites_t = sequence_t<opaque_hash_t, 0, 8>;

    // GP 11.1.2: X
    template<typename CONSTANTS>
    struct refine_context_t: codec::serializable_t<refine_context_t<CONSTANTS>> {
	    header_hash_t anchor;
	    state_root_t state_root;
	    beefy_root_t beefy_root;
	    header_hash_t lookup_anchor;
	    time_slot_t<CONSTANTS> lookup_anchor_slot;
	    prerequisites_t prerequisites;

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

        void serialize(auto &archive) const
        {
            static_assert(std::remove_reference_t<decltype(archive)>::read_only);
            const_cast<refine_context_t &>(*this).serialize(archive);
        }

        bool operator==(const refine_context_t &o) const
        {
            if (anchor != o.anchor)
                return false;
            if (state_root != o.state_root)
                return false;
            if (beefy_root != o.beefy_root)
                return false;
            if (lookup_anchor != o.lookup_anchor)
                return false;
            if (lookup_anchor_slot != o.lookup_anchor_slot)
                return false;
            if (prerequisites != o.prerequisites)
                return false;
            return true;
        }
    };

    struct authorizer_t: codec::serializable_t<authorizer_t> {
        opaque_hash_t code_hash;
        byte_sequence_t params;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("code_hash"sv, code_hash);
            archive.process("params"sv, params);
        }

        void serialize(auto &archive) const
        {
            static_assert(std::remove_reference_t<decltype(archive)>::read_only);
            const_cast<authorizer_t &>(*this).serialize(archive);
        }

        bool operator==(const authorizer_t &o) const
        {
            return code_hash == o.code_hash && params == o.params;
        }
    };

    using authorizer_hash_t = opaque_hash_t;

    template<typename CONSTANT_SET=config_prod>
    using auth_queue_t = fixed_sequence_t<authorizer_hash_t, CONSTANT_SET::auth_queue_size>;

    template<typename CONSTANT_SET=config_prod>
    using auth_queues_t = fixed_sequence_t<auth_queue_t<CONSTANT_SET>, CONSTANT_SET::core_count>;

    // max size: auth_pool_max_size
    template<typename CONSTANTS=config_prod>
    using auth_pool_t = sequence_t<authorizer_hash_t, 0, CONSTANTS::auth_pool_max_size>;

    struct core_authorizer_t {
        core_index_t core;
        opaque_hash_t auth_hash;

        static core_authorizer_t from_bytes(decoder &dec);
        static core_authorizer_t from_json(const boost::json::value &json);

        bool operator==(const core_authorizer_t &o) const
        {
            return core == o.core && auth_hash == o.auth_hash;
        }
    };
    using core_authorizers_t = sequence_t<core_authorizer_t>;

    template<typename CONSTANTS=config_prod>
    struct auth_pools_t: fixed_sequence_t<auth_pool_t<CONSTANTS>, CONSTANTS::core_count>
    {
        using base_type = fixed_sequence_t<auth_pool_t<CONSTANTS>, CONSTANTS::core_count>;
        using base_type::base_type;

        auth_pools_t apply(const time_slot_t<CONSTANTS> &slot, const core_authorizers_t &cas, const auth_queues_t<CONSTANTS> &phi) const;
    };

    struct import_spec_t: codec::serializable_t<import_spec_t> {
        opaque_hash_t tree_root;
        uint16_t index;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("tree_root"sv, tree_root);
            archive.process("index"sv, index);
        }

        void serialize(auto &archive) const
        {
            static_assert(std::remove_reference_t<decltype(archive)>::read_only);
            const_cast<import_spec_t &>(*this).serialize(archive);
        }

        bool operator==(const import_spec_t &o) const
        {
            return tree_root == o.tree_root && index == o.index;
        }
    };

    struct extrinsic_spec_t: codec::serializable_t<extrinsic_spec_t> {
        opaque_hash_t hash;
        uint32_t len;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("hash"sv, hash);
            archive.process("len"sv, len);
        }

        void serialize(auto &archive) const
        {
            static_assert(std::remove_reference_t<decltype(archive)>::read_only);
            const_cast<extrinsic_spec_t &>(*this).serialize(archive);
        }

        bool operator==(const extrinsic_spec_t &o) const
        {
            return hash == o.hash && len == o.len;
        }
    };

    struct work_item_t: codec::serializable_t<work_item_t> {
        service_id_t service;
        opaque_hash_t code_hash;
        byte_sequence_t payload;
        // gas is stored as a fixed uint!
        gas_t::base_type refine_gas_limit;
        gas_t::base_type accumulate_gas_limit;
        sequence_t<import_spec_t> import_segments;
        sequence_t<extrinsic_spec_t> extrinsic;
        uint16_t export_count;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("service"sv, service);
            archive.process("code_hash"sv, code_hash);
            archive.process("payload"sv, payload);
            archive.process("refine_gas_limit"sv, refine_gas_limit);
            archive.process("accumulate_gas_limit"sv, accumulate_gas_limit);
            archive.process("import_segments"sv, import_segments);
            archive.process("extrinsic"sv, extrinsic);
            archive.process("export_count"sv, export_count);
        }

        void serialize(auto &archive) const
        {
            static_assert(std::remove_reference_t<decltype(archive)>::read_only);
            const_cast<work_item_t &>(*this).serialize(archive);
        }

        static work_item_t from_bytes(decoder &dec)
        {
            return from(dec);
        }

        static work_item_t from_json(const boost::json::value &j)
        {
            codec::json::decoder dec { j };
            return from(dec);
        }

        bool operator==(const work_item_t &o) const
        {
            return service == o.service && code_hash == o.code_hash && payload == o.payload
                && refine_gas_limit == o.refine_gas_limit && accumulate_gas_limit == o.accumulate_gas_limit
                && import_segments == o.import_segments && extrinsic == o.extrinsic
                && export_count == o.export_count;
        }
    };

    template<typename CONSTANTS>
    struct work_package_t: codec::serializable_t<work_package_t<CONSTANTS>> {
        byte_sequence_t authorization;
        service_id_t auth_code_host;
        authorizer_t authorizer;
        refine_context_t<CONSTANTS> context;
        sequence_t<work_item_t, 1, 16> items;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("authorization"sv, authorization);
            archive.process("auth_code_host"sv, auth_code_host);
            archive.process("authorizer"sv, authorizer);
            archive.process("context"sv, context);
            archive.process("items"sv, items);
        }

        void serialize(auto &archive) const
        {
            static_assert(std::remove_reference_t<decltype(archive)>::read_only);
            const_cast<work_package_t &>(*this).serialize(archive);
        }

        bool operator==(const work_package_t &o) const
        {
            return authorization == o.authorization && auth_code_host == o.auth_code_host
                && authorizer == o.authorizer && context == o.context
                && items == o.items;
        }
    };

    struct work_result_ok_t: codec::serializable_t<work_result_ok_t> {
        byte_sequence_t data;

        void serialize(auto &archive)
        {
            archive.process_bytes(data);
        }

        void serialize(auto &archive) const
        {
            static_assert(std::remove_reference_t<decltype(archive)>::read_only);
            const_cast<work_result_ok_t &>(*this).serialize(archive);
        }

        bool operator==(const work_result_ok_t &o) const
        {
            return data == o.data;
        }
    };

    struct work_result_out_of_gas_t {
        bool operator==(const work_result_out_of_gas_t &) const
        {
            return true;
        }
    };

    struct work_result_panic_t {
        bool operator==(const work_result_panic_t &) const
        {
            return true;
        }
    };

    struct work_result_bad_exports_t {
        bool operator==(const work_result_bad_exports_t &) const
        {
            return true;
        }
    };

    struct work_result_bad_code_t {
        bool operator==(const work_result_bad_code_t &) const
        {
            return true;
        }
    };

    struct work_result_code_oversize_t {
        bool operator==(const work_result_code_oversize_t &) const
        {
            return true;
        }
    };

    using work_exec_result_base_t = std::variant<work_result_ok_t, work_result_out_of_gas_t, work_result_panic_t, work_result_bad_exports_t,
                                            work_result_bad_code_t, work_result_code_oversize_t>;
    struct work_exec_result_t: work_exec_result_base_t {
        static work_exec_result_t from_bytes(decoder &dec);
        static work_exec_result_t from_json(const boost::json::value &json);
        void to_bytes(encoder &enc) const;
    };

    struct refine_load_t: codec::serializable_t<refine_load_t> {
        gas_t gas_used;
        varlen_uint_t<uint16_t> imports;
        varlen_uint_t<uint16_t> extrinsic_count;
        varlen_uint_t<uint32_t> extrinsic_size;
        varlen_uint_t<uint16_t> exports;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("gas_used"sv, gas_used);
            archive.process("imports"sv, imports);
            archive.process("extrinsic_count"sv, extrinsic_count);
            archive.process("extrinsic_size"sv, extrinsic_size);
            archive.process("exports"sv, exports);
        }

        void serialize(auto &archive) const
        {
            static_assert(std::remove_reference_t<decltype(archive)>::read_only);
            const_cast<refine_load_t &>(*this).serialize(archive);
        }

        bool operator==(const refine_load_t &o) const
        {
            if (gas_used != o.gas_used)
                return false;
            if (imports != o.imports)
                return false;
            if (extrinsic_count != o.extrinsic_count)
                return false;
            if (extrinsic_size != o.extrinsic_size)
                return false;
            if (exports != o.exports)
                return false;
            return true;
        }
    };

    struct work_result_t: codec::serializable_t<work_result_t> {
        service_id_t service_id;
        opaque_hash_t code_hash;
        opaque_hash_t payload_hash;
        // gas_t accumulate_gas; gas_t is variable_length but currently the value is fixed length
        gas_t::base_type accumulate_gas;
        work_exec_result_t result;
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

        void serialize(auto &archive) const
        {
            static_assert(std::remove_reference_t<decltype(archive)>::read_only);
            const_cast<work_result_t &>(*this).serialize(archive);
        }

        bool operator==(const work_result_t &o) const
        {
            if (service_id != o.service_id)
                return false;
            if (code_hash != o.code_hash)
                return false;
            if (payload_hash != o.payload_hash)
                return false;
            if (accumulate_gas != o.accumulate_gas)
                return false;
            if (result != o.result)
                return false;
            if (refine_load != o.refine_load)
                return false;
            return true;
        }
    };
    using work_results_t = sequence_t<work_result_t, 1, 16>;

    struct work_package_spec_t {
        work_package_hash_t hash;
        uint32_t length;
        erasure_root_t erasure_root;
        erasure_root_t exports_root;
        uint16_t exports_count;

        static work_package_spec_t from_bytes(decoder &dec);
        static work_package_spec_t from_json(const boost::json::value &json);
        void to_bytes(encoder &enc) const;

        bool operator==(const work_package_spec_t &o) const
        {
            return hash == o.hash && length == o.length && erasure_root == o.erasure_root
                && erasure_root == o.erasure_root && exports_root == o.exports_root
                && exports_count == o.exports_count;
        }
    };

    struct segment_root_lookup_item {
        work_package_hash_t work_package_hash;
        opaque_hash_t segment_tree_root;

        static segment_root_lookup_item from_bytes(decoder &dec);
        static segment_root_lookup_item from_json(const boost::json::value &json);
        void to_bytes(encoder &enc) const;

        bool operator==(const segment_root_lookup_item &o) const
        {
            return work_package_hash == o.work_package_hash && segment_tree_root == o.segment_tree_root;
        }
    };

    using segment_root_lookup_t = sequence_t<segment_root_lookup_item, 0, 8>;

    template<typename CONSTANTS>
    struct work_report_t: codec::serializable_t<work_report_t<CONSTANTS>> {
        work_package_spec_t package_spec {};
        refine_context_t<CONSTANTS> context {};
        core_index_t core_index {};
        opaque_hash_t authorizer_hash {};
        byte_sequence_t auth_output {};
        segment_root_lookup_t segment_root_lookup {};
        work_results_t results {};
        gas_t auth_gas_used {};

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("package_spec"sv, package_spec);
            archive.process("context"sv, context);
            archive.process("core_index"sv, core_index);
            archive.process("authorizer_hash"sv, authorizer_hash);
            archive.process("auth_output"sv, auth_output);
            archive.process("segment_root_lookup"sv, segment_root_lookup);
            archive.process("results"sv, results);
            archive.process("auth_gas_used"sv, auth_gas_used);
        }

        void serialize(auto &archive) const
        {
            static_assert(std::remove_reference_t<decltype(archive)>::read_only);
            const_cast<work_report_t &>(*this).serialize(archive);
        }

        bool operator==(const work_report_t &o) const
        {
            return package_spec == o.package_spec && context == o.context && core_index == o.core_index
                && authorizer_hash == o.authorizer_hash && auth_output == o.auth_output
                && segment_root_lookup == o.segment_root_lookup && results == o.results
                && auth_gas_used == o.auth_gas_used;
        }
    };
    static_assert(codec::serializable_c<work_report_t<config_prod>>);
    static_assert(codec::serializable_c<work_report_t<config_tiny>>);
    template<typename CONSTANTS>
    using work_reports_t = sequence_t<work_report_t<CONSTANTS>>;

    template<typename CONSTANTS>
    struct avail_assurance_t: codec::serializable_t<avail_assurance_t<CONSTANTS>> {
        opaque_hash_t anchor;
        bitset_t<CONSTANTS::avail_bitfield_bytes * 8> bitfield;
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

        void serialize(auto &archive) const
        {
            static_assert(std::remove_reference_t<decltype(archive)>::read_only);
            const_cast<avail_assurance_t &>(*this).serialize(archive);
        }

        bool operator==(const avail_assurance_t &o) const
        {
            if (anchor != o.anchor)
                return false;
            if (bitfield != o.bitfield)
                return false;
            if (validator_index != o.validator_index)
                return false;
            if (signature != o.signature)
                return false;
            return true;
        }
    };

    template<typename CONSTANTS=config_prod>
    using assurances_extrinsic_t = sequence_t<avail_assurance_t<CONSTANTS>, 0, CONSTANTS::validator_count>;

    template<typename CONSTANTS>
    struct availability_assignment_t  {
        work_report_t<CONSTANTS> report;
        uint32_t timeout;

        static availability_assignment_t from_bytes(decoder &dec);
        static availability_assignment_t from_json(const boost::json::value &json);

        bool operator==(const availability_assignment_t &o) const
        {
            return report == o.report && timeout == o.timeout;
        }
    };

    template<typename CONSTANTS>
    using availability_assignments_item_t = optional_t<availability_assignment_t<CONSTANTS>>;

    template<typename CONSTANTS>
    using validators_data_t = fixed_sequence_t<validator_data_t, CONSTANTS::validator_count>;

    template<typename CONSTANTS=config_prod>
    struct availability_assignments_t: fixed_sequence_t<availability_assignments_item_t<CONSTANTS>, CONSTANTS::core_count> {
        using base_type = fixed_sequence_t<availability_assignments_item_t<CONSTANTS>, CONSTANTS::core_count>;
        using base_type::base_type;

        availability_assignments_t apply(work_reports_t<CONSTANTS> &out, const validators_data_t<CONSTANTS> &kappa,
            const time_slot_t<CONSTANTS> &tau, const header_hash_t parent, const assurances_extrinsic_t<CONSTANTS> &assurances) const;
    };

    using mmr_peak_t = optional_t<opaque_hash_t>;

    using mmr_base_t = sequence_t<mmr_peak_t>;
    struct mmr_t: mmr_base_t {
        using base_type = mmr_base_t;
        using base_type::base_type;

        mmr_t append(const opaque_hash_t &l) const;
        opaque_hash_t root() const;
    };

    struct reported_work_package_t {
        work_report_hash_t hash;
        exports_root_t exports_root;

        static reported_work_package_t from_bytes(decoder &dec);
        static reported_work_package_t from_json(const boost::json::value &json);

        std::strong_ordering operator<=>(const reported_work_package_t &o) const
        {
            return hash <=> o.hash;
        }

        bool operator==(const reported_work_package_t &o) const noexcept
        {
            return hash == o.hash && exports_root == o.exports_root;
        }
    };
    using reported_work_seq_t = sequence_t<reported_work_package_t>;

    struct block_info_t: codec::serializable_t<block_info_t> {
        header_hash_t header_hash;
        mmr_t mmr;
        state_root_t state_root;
        reported_work_seq_t reported;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("header_hash"sv, header_hash);
            archive.process("mmr"sv, mmr);
            archive.process("state_root"sv, state_root);
            archive.process("reported"sv, reported);
        }

        void serialize(auto &archive) const
        {
            static_assert(std::remove_reference_t<decltype(archive)>::read_only);
            const_cast<block_info_t &>(*this).serialize(archive);
        }

        bool operator==(const block_info_t &o) const noexcept
        {
            return header_hash == o.header_hash && mmr == o.mmr && state_root == o.state_root && reported == o.reported;
        }
    };

    template<typename CONSTANTS=config_prod>
    struct blocks_history_t: sequence_t<block_info_t, 0, CONSTANTS::max_blocks_history>
    {
        using base_type = sequence_t<block_info_t, 0, CONSTANTS::max_blocks_history>;
        using base_type::base_type;

        blocks_history_t apply(const header_hash_t &, const state_root_t &, const opaque_hash_t &, const reported_work_seq_t &) const;
    };

    struct activity_record_t {
        uint32_t blocks;
        uint32_t tickets;
        uint32_t pre_images;
        uint32_t pre_images_size;
        uint32_t guarantees;
        uint32_t assurances;

        static activity_record_t from_bytes(decoder &dec);
        bool operator==(const activity_record_t &) const;
    };

    using ticket_id_t = opaque_hash_t;
    using ticket_attempt_t = uint8_t;

    struct ticket_envelope_t: codec::serializable_t<ticket_envelope_t> {
        ticket_attempt_t attempt;
        bandersnatch_ring_vrf_signature_t signature;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("attempt"sv, attempt);
            archive.process("signature"sv, signature);
        }

        void serialize(auto &archive) const
        {
            static_assert(std::remove_reference_t<decltype(archive)>::read_only);
            const_cast<ticket_envelope_t &>(*this).serialize(archive);
        }

        bool operator==(const ticket_envelope_t &o) const
        {
            if (attempt != o.attempt)
                return false;
            if (signature != o.signature)
                return false;
            return true;
        }
    };

    struct ticket_body_t: codec::serializable_t<ticket_envelope_t> {
        ticket_id_t id;
        ticket_attempt_t attempt;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("id"sv, id);
            archive.process("attempt"sv, attempt);
        }

        void serialize(auto &archive) const
        {
            static_assert(std::remove_reference_t<decltype(archive)>::read_only);
            const_cast<ticket_body_t &>(*this).serialize(archive);
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

    template<typename CONSTANTS=config_prod>
    using tickets_accumulator_t = sequence_t<ticket_body_t, 0, CONSTANTS::epoch_length>;

    template<typename CONSTANTS=config_prod>
    using tickets_t = fixed_sequence_t<ticket_body_t, CONSTANTS::epoch_length>;

    template<typename CONSTANTS=config_prod>
    using keys_t = fixed_sequence_t<bandersnatch_public_t, CONSTANTS::epoch_length>;

    template<typename CONSTANTS>
    struct tickets_or_keys_t: std::variant<tickets_t<CONSTANTS>, keys_t<CONSTANTS>> {
        using base_type = std::variant<tickets_t<CONSTANTS>, keys_t<CONSTANTS>>;
        using base_type::base_type;

        static tickets_or_keys_t from_bytes(decoder &dec);
    };

    template<typename CONSTANTS=config_prod>
    using tickets_extrinsic_t = sequence_t<ticket_envelope_t, 0, CONSTANTS::max_tickets_per_block>;

    struct judgement_t: codec::serializable_t<judgement_t> {
        bool vote;
        validator_index_t index;
        ed25519_signature_t signature;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("vote"sv, vote);
            archive.process("index"sv, index);
            archive.process("signature"sv, signature);
        }

        void serialize(auto &archive) const
        {
            static_assert(std::remove_reference_t<decltype(archive)>::read_only);
            const_cast<judgement_t &>(*this).serialize(archive);
        }

        bool operator==(const judgement_t &o) const
        {
            return vote == o.vote && index == o.index && signature == o.signature;
        }
    };

    template<typename CONSTANTS>
    struct verdict_t: codec::serializable_t<verdict_t<CONSTANTS>> {
        opaque_hash_t target;
        uint32_t age;
        fixed_sequence_t<judgement_t, CONSTANTS::validator_super_majority> votes;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("target"sv, target);
            archive.process("age"sv, age);
            archive.process("votes"sv, votes);
        }

        void serialize(auto &archive) const
        {
            static_assert(std::remove_reference_t<decltype(archive)>::read_only);
            const_cast<verdict_t &>(*this).serialize(archive);
        }

        bool operator==(const verdict_t &o) const
        {
            if (target != o.target)
                return false;
            if (age != o.age)
                return false;
            if (votes != o.votes)
                return false;
            return true;
        }
    };

    struct culprit_t: codec::serializable_t<culprit_t> {
        work_report_hash_t target;
        ed25519_public_t key;
        ed25519_signature_t signature;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("target"sv, target);
            archive.process("key"sv, key);
            archive.process("signature"sv, signature);
        }

        void serialize(auto &archive) const
        {
            static_assert(std::remove_reference_t<decltype(archive)>::read_only);
            const_cast<culprit_t &>(*this).serialize(archive);
        }

        bool operator==(const culprit_t &o) const
        {
            if (target != o.target)
                return false;
            if (key != o.key)
                return false;
            if (signature != o.signature)
                return false;
            return true;
        }
    };

    struct fault_t: codec::serializable_t<fault_t> {
        work_report_hash_t target;
        bool vote;
        ed25519_public_t key;
        ed25519_signature_t signature;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("target"sv, target);
            archive.process("vote"sv, vote);
            archive.process("key"sv, key);
            archive.process("signature"sv, signature);
        }

        void serialize(auto &archive) const
        {
            static_assert(std::remove_reference_t<decltype(archive)>::read_only);
            const_cast<fault_t &>(*this).serialize(archive);
        }

        bool operator==(const fault_t &o) const
        {
            return target == o.target && vote == o.vote && key == o.key && signature == o.signature;
        }
    };

    using ed25519_keys_t = sequence_t<ed25519_public_t>;

    struct disputes_records_t {
        sequence_t<work_report_hash_t> good;
        sequence_t<work_report_hash_t> bad;
        sequence_t<work_report_hash_t> wonky;
        ed25519_keys_t offenders;
    };

    template<typename CONSTANTS>
    struct disputes_extrinsic_t: codec::serializable_t<disputes_extrinsic_t<CONSTANTS>> {
        sequence_t<verdict_t<CONSTANTS>> verdicts {};
        sequence_t<culprit_t> culprits {};
        sequence_t<fault_t> faults {};

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("verdicts"sv, verdicts);
            archive.process("culprits"sv, culprits);
            archive.process("faults"sv, faults);
        }

        void serialize(auto &archive) const
        {
            static_assert(std::remove_reference_t<decltype(archive)>::read_only);
            const_cast<disputes_extrinsic_t &>(*this).serialize(archive);
        }

        bool operator==(const disputes_extrinsic_t &o) const
        {
            if (verdicts != o.verdicts)
                return false;
            if (culprits != o.culprits)
                return false;
            if (faults != o.faults)
                return false;
            return true;
        }
    };

    struct preimage_t: codec::serializable_t<preimage_t> {
        service_id_t requester;
        byte_sequence_t blob;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("requester"sv, requester);
            archive.process("blob"sv, blob);
        }

        void serialize(auto &archive) const
        {
            static_assert(std::remove_reference_t<decltype(archive)>::read_only);
            const_cast<preimage_t &>(*this).serialize(archive);
        }

        std::strong_ordering operator<=>(const preimage_t &o) const noexcept
        {
            if (const auto cmp = requester <=> o.requester; cmp != std::strong_ordering::equal)
                return cmp;
            return blob <=> o.blob;
        }

        bool operator==(const preimage_t &o) const noexcept
        {
            return (*this <=> o) == std::strong_ordering::equal;
        }
    };

    using preimages_extrinsic_t = sequence_t<preimage_t>;

    struct validator_signature_t: codec::serializable_t<validator_signature_t> {
        validator_index_t validator_index;
        ed25519_signature_t signature;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("validator_index"sv, validator_index);
            archive.process("signature"sv, signature);
        }

        void serialize(auto &archive) const
        {
            static_assert(std::remove_reference_t<decltype(archive)>::read_only);
            const_cast<validator_signature_t &>(*this).serialize(archive);
        }

        bool operator==(const validator_signature_t &o) const
        {
            return validator_index == o.validator_index && signature == o.signature;
        }
    };

    template<typename CONSTANTS>
    struct report_guarantee_t: codec::serializable_t<report_guarantee_t<CONSTANTS>> {
        work_report_t<CONSTANTS> report;
        time_slot_t<CONSTANTS> slot;
        sequence_t<validator_signature_t> signatures;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("report"sv, report);
            archive.process("slot"sv, slot);
            archive.process("signatures"sv, signatures);
        }

        void serialize(auto &archive) const
        {
            static_assert(std::remove_reference_t<decltype(archive)>::read_only);
            const_cast<report_guarantee_t &>(*this).serialize(archive);
        }

        bool operator==(const report_guarantee_t &o) const
        {
            if (report != o.report)
                return false;
            if (slot != o.slot)
                return false;
            if (signatures != o.signatures)
                return false;
            return true;
        }
    };

    template<typename CONSTANTS=config_prod>
    using guarantees_extrinsic_t = sequence_t<report_guarantee_t<CONSTANTS>, 0, CONSTANTS::core_count>;

    template<typename CONSTANTS>
    struct ready_record_t: codec::serializable_t<ready_record_t<CONSTANTS>> {
        work_report_t<CONSTANTS> report;
        sequence_t<work_package_hash_t> dependencies;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("report"sv, report);
            archive.process("dependencies"sv, dependencies);
        }

        void serialize(auto &archive) const
        {
            static_assert(std::remove_reference_t<decltype(archive)>::read_only);
            const_cast<ready_record_t &>(*this).serialize(archive);
        }

        bool operator==(const ready_record_t &o) const
        {
            return report == o.report && dependencies == o.dependencies;
        }
    };

    template<typename CONSTANTS>
    using ready_queue_item_t = sequence_t<ready_record_t<CONSTANTS>>;

    template<typename CONSTANTS>
    using ready_queue_t = fixed_sequence_t<ready_queue_item_t<CONSTANTS>, CONSTANTS::epoch_length>;

    using accumulated_queue_item_t = sequence_t<work_package_hash_t>;

    template<typename CONSTANTS>
    using accumulated_queue_t = fixed_sequence_t<accumulated_queue_item_t, CONSTANTS::epoch_length>;

    struct always_accumulate_map_item_t {
        service_id_t id;
        gas_t gas;

        static always_accumulate_map_item_t from_bytes(decoder &dec);
        static always_accumulate_map_item_t from_json(const boost::json::value &json);

        bool operator==(const always_accumulate_map_item_t &o) const
        {
            return id == o.id && gas == o.gas;
        }
    };

    struct privileges_t {
        service_id_t bless;
        service_id_t assign;
        service_id_t designate;
        sequence_t<always_accumulate_map_item_t> always_acc;

        static privileges_t from_bytes(decoder &dec);
        bool operator==(const privileges_t &o) const;
    };

    using accumulate_root_t = opaque_hash_t;

    struct epoch_mark_validator_keys_t: codec::serializable_t<epoch_mark_validator_keys_t> {
        bandersnatch_public_t bandersnatch;
        ed25519_public_t ed25519;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("bandersnatch"sv, bandersnatch);
            archive.process("ed25519"sv, ed25519);
        }

        void serialize(auto &archive) const
        {
            static_assert(std::remove_reference_t<decltype(archive)>::read_only);
            const_cast<epoch_mark_validator_keys_t &>(*this).serialize(archive);
        }

        bool operator==(const epoch_mark_validator_keys_t &o) const
        {
            return bandersnatch == o.bandersnatch && ed25519 == o.ed25519;
        }
    };

    template<typename CONSTANTS>
    struct epoch_mark_t: codec::serializable_t<epoch_mark_t<CONSTANTS>> {
        entropy_t entropy {};
        entropy_t tickets_entropy {};
        fixed_sequence_t<epoch_mark_validator_keys_t, CONSTANTS::validator_count> validators {};

        void serialize(auto &archive)
        {
            using namespace std::placeholders;
            archive.process("entropy", entropy);
            archive.process("tickets_entropy", tickets_entropy);
            archive.process("validators", validators);
        }

        void serialize(auto &archive) const
        {
            static_assert(std::remove_reference_t<decltype(archive)>::read_only);
            const_cast<epoch_mark_t &>(*this).serialize(archive);
        }

        bool operator==(const epoch_mark_t &o) const
        {
            return entropy == o.entropy && tickets_entropy == o.tickets_entropy && validators == o.validators;
        }
    };

    template<typename CONSTANTS=config_prod>
    using tickets_mark_t = fixed_sequence_t<ticket_body_t, CONSTANTS::epoch_length>;

    using offenders_mark_t = ed25519_keys_t;

    struct preimages_config_t {
        std::string key_name = "hash";
        std::string val_name = "blob";
    };
    using preimages_t = map_t<opaque_hash_t, byte_sequence_t, preimages_config_t>;

    struct lookup_met_map_key_t {
        opaque_hash_t hash;
        uint32_t length;

        static lookup_met_map_key_t from_bytes(decoder &dec);
        static lookup_met_map_key_t from_json(const boost::json::value &j);

        std::strong_ordering operator<=>(const lookup_met_map_key_t &o) const noexcept
        {
            const auto cmp = hash <=> o.hash;
            if (cmp != std::strong_ordering::equal)
                return cmp;
            return length <=> o.length;
        }

        bool operator==(const lookup_met_map_key_t &o) const
        {
            return (*this <=> o) == std::strong_ordering::equal;
        }
    };

    struct lookup_metas_config_t {
        std::string key_name = "key";
        std::string val_name = "value";
    };
    template<typename CONSTANTS>
    using lookup_met_map_val_t = sequence_t<time_slot_t<CONSTANTS>, 0, 3>;
    template<typename CONSTANTS>
    using lookup_metas_t = map_t<lookup_met_map_key_t, lookup_met_map_val_t<CONSTANTS>, lookup_metas_config_t>;

    template<typename CONSTANTS>
    struct account_t: codec::serializable_t<account_t<CONSTANTS>> {
        preimages_t preimages {};
        lookup_metas_t<CONSTANTS> lookup_metas {};
        service_info_t info {};

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("preimages", preimages);
            archive.process("lookup_metas", lookup_metas);
            archive.process("info", info);
        }

        void serialize(auto &archive) const
        {
            static_assert(std::remove_reference_t<decltype(archive)>::read_only);
            const_cast<account_t &>(*this).serialize(archive);
        }

        bool operator==(const account_t &o) const
        {
            if (preimages != o.preimages)
                return false;
            if (lookup_metas != o.lookup_metas)
                return false;
            if (info != o.info)
                return false;
            return true;
        }
    };

    struct accounts_config_t {
        std::string key_name = "id";
        std::string val_name = "data";
    };

    template<typename CONSTANTS>
    struct accounts_t: map_t<service_id_t, account_t<CONSTANTS>, accounts_config_t> {
        using base_type = map_t<service_id_t, account_t<CONSTANTS>, accounts_config_t>;
        using base_type::base_type;

        accounts_t apply(const time_slot_t<CONSTANTS> &, const preimages_extrinsic_t &) const;
    };

    template<typename CONSTANTS>
    struct header_t: codec::serializable_t<header_t<CONSTANTS>> {
        header_hash_t parent;
        state_root_t parent_state_root;
        opaque_hash_t extrinsic_hash;
        time_slot_t<CONSTANTS> slot;
        optional_t<epoch_mark_t<CONSTANTS>> epoch_mark;
        optional_t<tickets_mark_t<CONSTANTS>> tickets_mark;
        offenders_mark_t offenders_mark;
        validator_index_t author_index;
        bandersnatch_vrf_signature_t entropy_source;
        bandersnatch_vrf_signature_t seal;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("parent"sv, parent);
            archive.process("parent_state_root"sv, parent_state_root);
            archive.process("extrinsic_hash"sv, extrinsic_hash);
            archive.process("slot"sv, slot);
            archive.process("epoch_mark"sv, epoch_mark);
            archive.process("tickets_mark"sv, tickets_mark);
            archive.process("offenders_mark"sv, offenders_mark);
            archive.process("author_index"sv, author_index);
            archive.process("entropy_source"sv, entropy_source);
            archive.process("seal"sv, seal);
        }

        void serialize(auto &archive) const
        {
            static_assert(std::remove_reference_t<decltype(archive)>::read_only);
            const_cast<header_t &>(*this).serialize(archive);
        }

        bool operator==(const header_t &o) const
        {
            if (parent != o.parent)
                return false;
            if (parent_state_root != o.parent_state_root)
                return false;
            if (extrinsic_hash != o.extrinsic_hash)
                return false;
            if (slot != o.slot)
                return false;
            if (epoch_mark != o.epoch_mark)
                return false;
            if (tickets_mark != o.tickets_mark)
                return false;
            if (offenders_mark != o.offenders_mark)
                return false;
            if (author_index != o.author_index)
                return false;
            if (entropy_source != o.entropy_source)
                return false;
            if (seal != o.seal)
                return false;
            return true;
        }
    };

    template<typename CONSTANTS>
    struct extrinsic_t: codec::serializable_t<extrinsic_t<CONSTANTS>> {
        // JAM paper: ET - capital epsilon with a lower index T
        tickets_extrinsic_t<CONSTANTS> tickets;
        // JAM paper: EP - capital epsilon with a lower index P
        preimages_extrinsic_t preimages;
        // JAM paper: EP - capital epsilon with a lower index G
        guarantees_extrinsic_t<CONSTANTS> guarantees;
        // JAM paper: EP - capital epsilon with a lower index A
        assurances_extrinsic_t<CONSTANTS> assurances;
        // JAM paper: EP - capital epsilon with a lower index D
        disputes_extrinsic_t<CONSTANTS> disputes;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("tickets"sv, tickets);
            archive.process("preimages"sv, preimages);
            archive.process("guarantees"sv, guarantees);
            archive.process("assurances"sv, assurances);
            archive.process("disputes"sv, disputes);
        }

        void serialize(auto &archive) const
        {
            static_assert(std::remove_reference_t<decltype(archive)>::read_only);
            const_cast<extrinsic_t &>(*this).serialize(archive);
        }

        bool operator==(const extrinsic_t &o) const
        {
            if (tickets != o.tickets)
                return false;
            if (preimages != o.preimages)
                return false;
            if (guarantees != o.guarantees)
                return false;
            if (assurances != o.assurances)
                return false;
            if (disputes != o.disputes)
                return false;
            return true;
        }
    };

    template<typename CONSTANTS=config_prod>
    using activity_records_t = fixed_sequence_t<activity_record_t, CONSTANTS::validator_count>;

    struct core_activity_record_t: codec::serializable_t<core_activity_record_t> {
        gas_t gas_used = 0;
        varlen_uint_t<uint16_t> imports = 0;
        varlen_uint_t<uint16_t> extrinsic_count = 0;
        varlen_uint_t<uint32_t> extrinsic_size = 0;
        varlen_uint_t<uint16_t> exports = 0;
        varlen_uint_t<uint32_t> bundle_size = 0;
        varlen_uint_t<uint32_t> da_load = 0;
        varlen_uint_t<uint16_t> popularity = 0;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("gas_used"sv, gas_used);
            archive.process("imports"sv, imports);
            archive.process("extrinsic_count"sv, extrinsic_count);
            archive.process("extrinsic_size"sv, extrinsic_size);
            archive.process("exports"sv, exports);
            archive.process("bundle_size"sv, bundle_size);
            archive.process("da_load"sv, da_load);
            archive.process("popularity"sv, popularity);
        }

        bool operator==(const core_activity_record_t &o) const
        {
            if (gas_used != o.gas_used)
                return false;
            if (imports != o.imports)
                return false;
            if (extrinsic_count != o.extrinsic_count)
                return false;
            if (extrinsic_size != o.extrinsic_size)
                return false;
            if (exports != o.exports)
                return false;
            if (bundle_size != o.bundle_size)
                return false;
            if (da_load != o.da_load)
                return false;
            if (popularity != o.popularity)
                return false;
            return true;
        }
    };

    template<typename CONSTANTS>
    using core_statistics_t = fixed_sequence_t<core_activity_record_t, CONSTANTS::core_count>;

    struct service_activity_record_t: codec::serializable_t<service_activity_record_t> {
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
        varlen_uint_t<uint32_t> on_transfers_count {};
        gas_t on_transfers_gas_used {};

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
            archive.process("on_transfers_count"sv, on_transfers_count);
            archive.process("on_transfers_gas_used"sv, on_transfers_gas_used);
        }

        bool operator==(const service_activity_record_t &o) const
        {
            if (provided_count != o.provided_count)
                return false;
            if (provided_size != o.provided_size)
                return false;
            if (refinement_count != o.refinement_count)
                return false;
            if (refinement_gas_used != o.refinement_gas_used)
                return false;
            if (imports != o.imports)
                return false;
            if (extrinsic_count != o.extrinsic_count)
                return false;
            if (extrinsic_size != o.extrinsic_size)
                return false;
            if (exports != o.exports)
                return false;
            if (accumulate_count != o.accumulate_count)
                return false;
            if (accumulate_gas_used != o.accumulate_gas_used)
                return false;
            if (on_transfers_count != o.on_transfers_count)
                return false;
            if (on_transfers_gas_used != o.on_transfers_gas_used)
                return false;
            return true;
        }
    };

    struct services_statistics_config_t {
        std::string key_name = "id";
        std::string val_name = "service";
    };
    using services_statistics_t = map_t<service_id_t, service_activity_record_t, services_statistics_config_t>;

    template<typename CONSTANTS>
    struct statistics_t: codec::serializable_t<statistics_t<CONSTANTS>> {
        activity_records_t<CONSTANTS> current {};
        activity_records_t<CONSTANTS> last {};
        core_statistics_t<CONSTANTS> cores {};
        services_statistics_t services {};

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("current"sv, current);
            archive.process("last"sv, last);
            archive.process("cores"sv, cores);
            archive.process("services"sv, services);
        }

        void serialize(auto &archive) const
        {
            static_assert(std::remove_reference_t<decltype(archive)>::read_only);
            const_cast<statistics_t &>(*this).serialize(archive);
        }

        bool operator==(const statistics_t &o) const
        {
            if (current != o.current)
                return false;
            if (last != o.last)
                return false;
            if (cores != o.cores)
                return false;
            if (services != o.services)
                return false;
            return true;
        }
    };

    template<typename CONSTANTS>
    struct block_t: codec::serializable_t<block_t<CONSTANTS>> {
        // JAM paper: H - capital eta
        header_t<CONSTANTS> header;
        // JAM paper: E - capital epsilon
        extrinsic_t<CONSTANTS> extrinsic;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("header"sv, header);
            archive.process("extrinsic"sv, extrinsic);
        }

        void serialize(auto &archive) const
        {
            static_assert(std::remove_reference_t<decltype(archive)>::read_only);
            const_cast<block_t &>(*this).serialize(archive);
        }

        bool operator==(const block_t &o) const
        {
            if (header != o.header)
                return false;
            if (extrinsic != o.extrinsic)
                return false;
            return true;
        }
    };
}
