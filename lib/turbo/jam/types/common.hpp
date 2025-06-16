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
#include <turbo/jam/encoding.hpp>
#include "errors.hpp"
#include "constants.hpp"
#include "turbo/crypto/blake2b.hpp"

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
        static_assert(MIN < MAX);
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
        static_assert(MIN < MAX);
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
    template<typename CONSTANTS>
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
            return _val / CONSTANTS::epoch_length;
        }

        [[nodiscard]] uint32_t epoch_slot() const
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

        bool operator==(const validator_data_t &o) const
        {
            return bandersnatch == o.bandersnatch && ed25519 == o.ed25519 && bls == o.bls && metadata == o.metadata;
        }
    };
    static_assert(sizeof(validator_data_t) == 336); // JAM paper (6.8)

    using service_id_t = uint32_t;
    using balance_t = uint64_t;

    struct service_info_t;

    // This structure captures updates rather than absolute values.
    // For this reason int64_t types are used to track potential decreases of the aboslute values.
    struct service_info_update_t {
        service_info_t &base;
        std::optional<opaque_hash_t> code_hash {};
        int64_t balance = 0;
        // gas saved in the fixed format form
        std::optional<gas_t::base_type> min_item_gas {};
        std::optional<gas_t::base_type> min_memo_gas {};
        int64_t bytes = 0;
        int32_t items = 0;

        bool empty() const
        {
            if (code_hash)
                return false;
            if (balance)
                return false;
            if (min_item_gas)
                return false;
            if (min_memo_gas)
                return false;
            if (bytes)
                return false;
            if (items)
                return false;
            return true;
        }

        void consume_from(service_info_update_t &&o)
        {
            if (o.code_hash)
                code_hash = o.code_hash;
            balance += o.balance;
            if (o.min_item_gas)
                min_item_gas = o.min_item_gas;
            if (o.min_memo_gas)
                min_memo_gas = o.min_memo_gas;
            bytes += o.bytes;
            items += o.items;
        }

        inline void commit();
    };

    struct service_info_t {
        opaque_hash_t code_hash {};
        balance_t balance = 0;
        // gas saved in the fixed format form
        gas_t::base_type min_item_gas = 0;
        gas_t::base_type min_memo_gas = 0;
        uint64_t bytes = 0;
        uint32_t items = 0;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("code_hash"sv, code_hash);
            archive.process("balance"sv, balance);
            archive.process("min_item_gas"sv, min_item_gas);
            archive.process("min_memo_gas"sv, min_memo_gas);
            archive.process("bytes"sv, bytes);
            archive.process("items"sv, items);
        }

        void consume_from(service_info_update_t &&o)
        {
            if (o.code_hash)
                code_hash = *o.code_hash;
            balance += o.balance;
            if (o.min_item_gas)
                min_item_gas = *o.min_item_gas;
            if (o.min_memo_gas)
                min_memo_gas = *o.min_memo_gas;
            bytes += o.bytes;
            items += o.items;
        }

        bool operator==(const service_info_t &o) const noexcept
        {
            if (code_hash != o.code_hash)
                return false;
            if (balance != o.balance)
                return false;
            if (min_item_gas != o.min_item_gas)
                return false;
            if (min_memo_gas != o.min_memo_gas)
                return false;
            if (bytes != o.bytes)
                return false;
            if (items != o.items)
                return false;
            return true;
        }
    };

    inline void service_info_update_t::commit()
    {
        base.consume_from(std::move(*this));
    }

    using prerequisites_t = sequence_t<opaque_hash_t>;

    // GP 11.1.2: X
    template<typename CONSTANTS>
    struct refine_context_t {
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

    struct authorizer_t {
        opaque_hash_t code_hash;
        byte_sequence_t params;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("code_hash"sv, code_hash);
            archive.process("params"sv, params);
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

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("core"sv, core);
            archive.process("auth_hash"sv, auth_hash);
        }

        bool operator==(const core_authorizer_t &o) const
        {
            return core == o.core && auth_hash == o.auth_hash;
        }
    };
    using core_authorizers_t = sequence_t<core_authorizer_t>;

    template<typename CONSTANTS=config_prod>
    using auth_pools_t = fixed_sequence_t<auth_pool_t<CONSTANTS>, CONSTANTS::core_count>;

    struct import_spec_t {
        opaque_hash_t tree_root;
        uint16_t index;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("tree_root"sv, tree_root);
            archive.process("index"sv, index);
        }

        bool operator==(const import_spec_t &o) const
        {
            return tree_root == o.tree_root && index == o.index;
        }
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

        bool operator==(const extrinsic_spec_t &o) const
        {
            return hash == o.hash && len == o.len;
        }
    };

    struct work_item_t {
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

        bool operator==(const work_item_t &o) const
        {
            return service == o.service && code_hash == o.code_hash && payload == o.payload
                && refine_gas_limit == o.refine_gas_limit && accumulate_gas_limit == o.accumulate_gas_limit
                && import_segments == o.import_segments && extrinsic == o.extrinsic
                && export_count == o.export_count;
        }
    };

    template<typename CONSTANTS>
    struct work_package_t {
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

        bool operator==(const work_package_t &o) const
        {
            return authorization == o.authorization && auth_code_host == o.auth_code_host
                && authorizer == o.authorizer && context == o.context
                && items == o.items;
        }
    };

    struct work_result_ok_t {
        byte_sequence_t data;

        void serialize(auto &archive)
        {
            archive.process_bytes(data);
        }

        bool operator==(const work_result_ok_t &o) const
        {
            return data == o.data;
        }
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

    using work_exec_result_base_t = std::variant<
        work_result_ok_t,
        work_result_out_of_gas_t,
        work_result_panic_t,
        work_result_bad_exports_t,
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
                "bad_code"sv,
                "code_oversize"sv
            };
            archive.template process_variant<base_type>(*this, names);
        }
    };

    struct refine_load_t {
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

    // JAM (11.6)
    struct work_result_t {
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

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("hash"sv, hash);
            archive.process("length"sv, length);
            archive.process("erasure_root"sv, erasure_root);
            archive.process("exports_root"sv, exports_root);
            archive.process("exports_count"sv, exports_count);
        }

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

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("work_package_hash"sv, work_package_hash);
            archive.process("segment_tree_root"sv, segment_tree_root);
        }

        bool operator==(const segment_root_lookup_item &o) const
        {
            return work_package_hash == o.work_package_hash && segment_tree_root == o.segment_tree_root;
        }
    };

    using segment_root_lookup_t = sequence_t<segment_root_lookup_item>;

    // JAM (11.2)
    template<typename CONSTANTS>
    struct work_report_t {
        work_package_spec_t package_spec {};
        refine_context_t<CONSTANTS> context {};
        varlen_uint_t<core_index_t> core_index {};
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
    struct avail_assurance_t {
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
    struct availability_assignment_t {
        work_report_t<CONSTANTS> report;
        uint32_t timeout;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("report"sv, report);
            archive.process("timeout"sv, timeout);
        }

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

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("hash"sv, hash);
            archive.process("exports_root"sv, exports_root);
            //archive.process("work_package_hash"sv, hash);
            //archive.process("segment_tree_root"sv, exports_root);
        }

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

    struct block_info_t {
        header_hash_t header_hash {};
        mmr_t mmr {};
        state_root_t state_root {};
        reported_work_seq_t reported {};

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("header_hash"sv, header_hash);
            archive.push("mmr");
            archive.process("peaks"sv, mmr);
            archive.pop();
            archive.process("state_root"sv, state_root);
            archive.process("reported"sv, reported);
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
    };

    struct activity_record_t {
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

        bool operator==(const activity_record_t &o) const
        {
            if (blocks != o.blocks)
                return false;
            if (tickets != o.tickets)
                return false;
            if (pre_images != o.pre_images)
                return false;
            if (pre_images_size != o.pre_images_size)
                return false;
            if (guarantees != o.guarantees)
                return false;
            if (assurances != o.assurances)
                return false;
            return true;
        }
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

        bool operator==(const ticket_envelope_t &o) const
        {
            if (attempt != o.attempt)
                return false;
            if (signature != o.signature)
                return false;
            return true;
        }
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
    template<typename CONSTANTS=config_prod>
    using tickets_accumulator_t = sequence_t<ticket_body_t, 0, CONSTANTS::epoch_length>;

    template<typename CONSTANTS=config_prod>
    using tickets_t = fixed_sequence_t<ticket_body_t, CONSTANTS::epoch_length>;

    template<typename CONSTANTS=config_prod>
    using keys_t = fixed_sequence_t<bandersnatch_public_t, CONSTANTS::epoch_length>;

    // JAM (6.5)
    template<typename CONSTANTS>
    struct tickets_or_keys_t: std::variant<tickets_t<CONSTANTS>, keys_t<CONSTANTS>> {
        using base_type = std::variant<tickets_t<CONSTANTS>, keys_t<CONSTANTS>>;
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

    template<typename CONSTANTS=config_prod>
    using tickets_extrinsic_t = sequence_t<ticket_envelope_t, 0, CONSTANTS::max_tickets_per_block>;

    struct judgement_t {
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

    template<typename CONSTANTS>
    struct verdict_t {
        work_report_hash_t target;
        uint32_t age;
        fixed_sequence_t<judgement_t, CONSTANTS::validator_super_majority> votes;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("target"sv, target);
            archive.process("age"sv, age);
            archive.process("votes"sv, votes);
        }

        std::strong_ordering operator<=>(const verdict_t &o) const
        {
            // (10.7) ordered by report hash
            if (const auto cmp = target <=> o.target; cmp != std::strong_ordering::equal)
                return cmp;
            if (const auto cmp = age <=> o.age; cmp != std::strong_ordering::equal)
                return cmp;
            if (const auto cmp = votes <=> o.votes; cmp != std::strong_ordering::equal)
                return cmp;
            return std::strong_ordering::equal;
        }

        bool operator==(const verdict_t &o) const
        {
            return (*this <=> o) == std::strong_ordering::equal;
        }
    };

    struct culprit_t {
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

        std::strong_ordering operator<=>(const culprit_t &o) const
        {
            // (10.8) ordered by key
            if (const auto cmp = key <=> o.key; cmp != std::strong_ordering::equal)
                return cmp;
            if (const auto cmp = target <=> o.target; cmp != std::strong_ordering::equal)
                return cmp;
            if (const auto cmp = signature <=> o.signature; cmp != std::strong_ordering::equal)
                return cmp;
            return std::strong_ordering::equal;
        }

        bool operator==(const culprit_t &o) const
        {
            return (*this <=> o) == std::strong_ordering::equal;
        }
    };

    struct fault_t {
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

        std::strong_ordering operator<=>(const fault_t &o) const
        {
            // (10.8) ordered by key
            if (const auto cmp = key <=> o.key; cmp != std::strong_ordering::equal)
                return cmp;
            if (const auto cmp = target <=> o.target; cmp != std::strong_ordering::equal)
                return cmp;
            if (const auto cmp = vote <=> o.vote; cmp != std::strong_ordering::equal)
                return cmp;
            if (const auto cmp = signature <=> o.signature; cmp != std::strong_ordering::equal)
                return cmp;
            return std::strong_ordering::equal;
        }

        bool operator==(const fault_t &o) const
        {
            return (*this <=> o) == std::strong_ordering::equal;
        }
    };

    using ed25519_keys_set_t = set_t<ed25519_public_t>;

    // JAM (10.1)
    struct disputes_records_t {
        set_t<work_report_hash_t> good {};
        set_t<work_report_hash_t> bad {};
        set_t<work_report_hash_t> wonky {};
        ed25519_keys_set_t offenders {};

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("good"sv, good);
            archive.process("bad"sv, bad);
            archive.process("wonky"sv, wonky);
            archive.process("offenders"sv, offenders);
        }

        bool operator==(const disputes_records_t &o) const
        {
            if (good != o.good)
                return false;
            if (bad != o.bad)
                return false;
            if (wonky != o.wonky)
                return false;
            if (offenders != o.offenders)
                return false;
            return true;
        }
    };

    template<typename CONSTANTS>
    struct disputes_extrinsic_t {
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

        bool operator==(const preimage_t &o) const noexcept
        {
            return (*this <=> o) == std::strong_ordering::equal;
        }
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

        bool operator==(const validator_signature_t &o) const
        {
            return validator_index == o.validator_index && signature == o.signature;
        }
    };

    template<typename CONSTANTS>
    struct report_guarantee_t {
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

    using report_deps_t = set_t<work_package_hash_t>;

    template<typename CONSTANTS>
    struct ready_record_t {
        work_report_t<CONSTANTS> report;
        report_deps_t dependencies;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("report"sv, report);
            archive.process("dependencies"sv, dependencies);
        }

        bool operator==(const ready_record_t &o) const
        {
            if (report != o.report)
                return false;
            if (dependencies != o.dependencies)
                return false;
            return true;
        }
    };

    template<typename CONSTANTS>
    using ready_queue_item_t = sequence_t<ready_record_t<CONSTANTS>>;

    template<typename CONSTANTS>
    using ready_queue_t = fixed_sequence_t<ready_queue_item_t<CONSTANTS>, CONSTANTS::epoch_length>;

    using accumulated_queue_item_t = set_t<work_package_hash_t>;

    template<typename CONSTANTS>
    using accumulated_queue_t = fixed_sequence_t<accumulated_queue_item_t, CONSTANTS::epoch_length>;

    struct always_accumulate_map_item_t {
        service_id_t id;
        gas_t gas;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("id"sv, id);
            archive.process("gas"sv, gas);
        }

        bool operator==(const always_accumulate_map_item_t &o) const
        {
            return id == o.id && gas == o.gas;
        }
    };

    using free_services_t = sequence_t<always_accumulate_map_item_t>;

    struct privileges_t {
        service_id_t bless;
        service_id_t assign;
        service_id_t designate;
        free_services_t always_acc;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("bless"sv, bless);
            archive.process("assign"sv, assign);
            archive.process("designate"sv, designate);
            archive.process("always_acc"sv, always_acc);
        }

        bool operator==(const privileges_t &o) const
        {
            if (bless != o.bless)
                return false;
            if (assign != o.assign)
                return false;
            if (designate != o.designate)
                return false;
            if (always_acc != o.always_acc)
                return false;
            return true;
        }
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

        bool operator==(const epoch_mark_validator_keys_t &o) const
        {
            return bandersnatch == o.bandersnatch && ed25519 == o.ed25519;
        }
    };

    template<typename CONSTANTS>
    struct epoch_mark_validators_t: fixed_sequence_t<epoch_mark_validator_keys_t, CONSTANTS::validator_count> {
        using base_type = fixed_sequence_t<epoch_mark_validator_keys_t, CONSTANTS::validator_count>;
        using base_type::base_type;

        epoch_mark_validators_t(const validators_data_t<CONSTANTS> &o)
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

        bool operator==(const validators_data_t<CONSTANTS> &o) const
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

    template<typename CONSTANTS>
    struct epoch_mark_t {
        entropy_t entropy {};
        entropy_t tickets_entropy {};
        epoch_mark_validators_t<CONSTANTS> validators {};

        void serialize(auto &archive)
        {
            using namespace std::placeholders;
            archive.process("entropy", entropy);
            archive.process("tickets_entropy", tickets_entropy);
            archive.process("validators", validators);
        }

        bool operator==(const epoch_mark_t &o) const
        {
            return entropy == o.entropy && tickets_entropy == o.tickets_entropy && validators == o.validators;
        }
    };

    template<typename CONSTANTS=config_prod>
    using tickets_mark_t = fixed_sequence_t<ticket_body_t, CONSTANTS::epoch_length>;

    using offenders_mark_t = ed25519_keys_set_t;

    // JAM (5.1)

    template<typename CONSTANTS>
    struct header_t {
        // H_p
        header_hash_t parent {};
        // H_r - ancestors need to be stored only for previous 24-hours of any block to be validated
        state_root_t parent_state_root {};
        // H_x - merkle commitment (H^#) to the block's external data
        opaque_hash_t extrinsic_hash {};
        // H_t
        time_slot_t<CONSTANTS> slot {};
        // H_e
        optional_t<epoch_mark_t<CONSTANTS>> epoch_mark {};
        // H_w
        optional_t<tickets_mark_t<CONSTANTS>> tickets_mark {};
        // H_o
        offenders_mark_t offenders_mark {};
        // H_i
        validator_index_t author_index {};
        // H_v
        bandersnatch_vrf_signature_t entropy_source {};
        // H_s
        bandersnatch_vrf_signature_t seal {};

        [[nodiscard]] uint8_vector unsigned_bytes() const
        {
            encoder enc {};
            const_cast<header_t &>(*this).serialize_unsigned(enc);
            return std::move(enc.bytes());
        }

        [[nodiscard]] header_hash_t hash() const
        {
            header_hash_t res;
            encoder enc {};
            enc.process(*this);
            crypto::blake2b::digest(res, enc.bytes());
            return res;
        }

        void verify_signatures(const bandersnatch_public_t &vkey, const tickets_or_keys_t<CONSTANTS> &gamma_s, const entropy_t &eta3) const;

        void serialize_unsigned(auto &archive)
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
        }

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            serialize_unsigned(archive);
            archive.process("seal"sv, seal);
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

    template<typename CONSTANTS=config_prod>
    using activity_records_t = fixed_sequence_t<activity_record_t, CONSTANTS::validator_count>;

    struct core_activity_record_t {
        varlen_uint_t<uint32_t> da_load = 0;
        varlen_uint_t<uint16_t> popularity = 0;
        varlen_uint_t<uint16_t> imports = 0;
        varlen_uint_t<uint16_t> exports = 0;
        varlen_uint_t<uint32_t> extrinsic_size = 0;
        varlen_uint_t<uint16_t> extrinsic_count = 0;
        varlen_uint_t<uint32_t> bundle_size = 0;
        gas_t gas_used = 0;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("da_load"sv, da_load);
            archive.process("popularity"sv, popularity);
            archive.process("imports"sv, imports);
            archive.process("exports"sv, exports);
            archive.process("extrinsic_size"sv, extrinsic_size);
            archive.process("extrinsic_count"sv, extrinsic_count);
            archive.process("bundle_size"sv, bundle_size);
            archive.process("gas_used"sv, gas_used);
        }

        bool operator==(const core_activity_record_t &o) const
        {
            if (da_load != o.da_load)
                return false;
            if (popularity != o.popularity)
                return false;
            if (imports != o.imports)
                return false;
            if (exports != o.exports)
                return false;
            if (extrinsic_size != o.extrinsic_size)
                return false;
            if (extrinsic_count != o.extrinsic_count)
                return false;
            if (bundle_size != o.bundle_size)
                return false;
            if (gas_used != o.gas_used)
                return false;
            return true;
        }
    };

    template<typename CONSTANTS>
    using core_statistics_t = fixed_sequence_t<core_activity_record_t, CONSTANTS::core_count>;

    struct service_activity_record_t {
        varlen_uint_t<uint16_t> provided_count {};
        varlen_uint_t<uint32_t> provided_size {};
        varlen_uint_t<uint32_t> refinement_count {};
        gas_t refinement_gas_used {};
        varlen_uint_t<uint32_t> imports {};
        varlen_uint_t<uint32_t> exports {};
        varlen_uint_t<uint32_t> extrinsic_size {};
        varlen_uint_t<uint32_t> extrinsic_count {};
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
            archive.process("exports"sv, exports);
            archive.process("extrinsic_size"sv, extrinsic_size);
            archive.process("extrinsic_count"sv, extrinsic_count);
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
            if (exports != o.exports)
                return false;
            if (extrinsic_size != o.extrinsic_size)
                return false;
            if (extrinsic_count != o.extrinsic_count)
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
        std::string val_name = "record";
    };
    using services_statistics_t = map_t<service_id_t, service_activity_record_t, services_statistics_config_t>;

    template<typename CONSTANTS>
    struct statistics_t {
        activity_records_t<CONSTANTS> current {};
        activity_records_t<CONSTANTS> last {};
        core_statistics_t<CONSTANTS> cores {};
        services_statistics_t services {};

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("vals_current"sv, current);
            archive.process("vals_last"sv, last);
            archive.process("cores"sv, cores);
            archive.process("services"sv, services);
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
}
