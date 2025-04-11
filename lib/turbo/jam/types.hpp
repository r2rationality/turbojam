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
#include <boost/json.hpp>
#include <turbo/common/bytes.hpp>
#include "constants.hpp"
#include "codec.hpp"

namespace turbo::jam {
    // jam-types.asn

    template<typename T>
    concept from_json_c = requires(T t, const boost::json::value &j)
    {
        { T::from_json(j) };
    };

    struct byte_sequence_t: uint8_vector {
        using base_type = uint8_vector;
        using base_type::base_type;

        static byte_sequence_t from_bytes(codec::decoder &dec);
        static byte_sequence_t from_json(const boost::json::value &);
        void to_bytes(codec::encoder &) const;
    };

    template<typename T, size_t MIN=0, size_t MAX=std::numeric_limits<size_t>::max()>
    struct sequence_t: std::vector<T> {
        static constexpr size_t min_size = MIN;
        static constexpr size_t max_size = MAX;
        static_assert(MIN < MAX);
        using base_type = std::vector<T>;
        using base_type::base_type;

        template<typename C=sequence_t>
        static C from_bytes(codec::decoder &dec)
        {
            const auto sz = dec.uint_general();
            if (static_cast<int>(sz < MIN) | static_cast<int>(sz > MAX)) [[unlikely]]
                throw error(fmt::format("the recorded number of elements is {} and outside of the allowed range [{}:{}] for {}",
                            sz, MIN, MAX, typeid(sequence_t).name()));
            C res {};
            res.reserve(sz);
            for (size_t i = 0; i < sz; i++)
                res.emplace_back(dec.decode<T>());
            return res;
        }

        template<typename C=sequence_t>
        static C from_json(const boost::json::value &j)
        {
            const auto &j_arr = j.as_array();
            const auto sz = j_arr.size();
            if (static_cast<int>(sz < MIN) | static_cast<int>(sz > MAX)) [[unlikely]]
                throw error(fmt::format("the recorded number of elements is {} and outside of the allowed range [{}:{}] for {}",
                            sz, MIN, MAX, typeid(sequence_t).name()));
            C res {};
            res.reserve(sz);
            for (const auto &jv: j_arr) {
                if constexpr (from_json_c<T>) {
                    res.emplace_back(T::from_json(jv));
                } else if constexpr (std::is_convertible_v<uint64_t, T>) {
                    res.emplace_back(boost::json::value_to<T>(jv));
                } else {
                    throw error(fmt::format("{} type must have from_json static method!", typeid(T).name()));
                }
            }
            return res;
        }

        void to_bytes(codec::encoder &enc) const
        {
            enc.uint_general(base_type::size());
            for (const auto &item: *this)
                item.to_bytes(enc);
        }
    };

    template<typename T, size_t SZ>
    struct fixed_sequence_t: std::array<T, SZ> {
        static_assert(SZ > 0);
        using base_type = std::array<T, SZ>;
        using base_type::base_type;

        template<typename C=fixed_sequence_t>
        static C from_bytes(codec::decoder &dec)
        {
            C res {};
            for (size_t i = 0; i < SZ; i++)
                res[i] = dec.decode<T>();
            return res;
        }

        template<typename C=fixed_sequence_t>
        static C from_json(const boost::json::value &j)
        {
            const auto &j_arr = j.as_array();
            if (j_arr.size() != SZ) [[unlikely]]
                throw error(fmt::format("{} expects an array of {} items but got {}", typeid(C).name(), SZ, j_arr.size()));
            C res {};
            size_t i = 0;
            for (const auto &jv: j_arr)
                res[i++] = T::from_json(jv);
            return res;
        }
    };

    template<typename K, typename V>
    struct map_t: std::map<K, V> {
        using base_type = std::map<K, V>;
        using base_type::base_type;

        template<typename C=map_t>
        static C from_bytes(codec::decoder &dec)
        {
            const auto sz = dec.uint_general();
            C res {};
            for (size_t i = 0; i < sz; i++) {
                auto k = dec.decode<K>(); // ensures that k is read before v!
                const auto [it, created] = res.try_emplace(std::move(k), dec.decode<V>());
                if (!created) [[unlikely]]
                    throw error(fmt::format("a duplicate key in the map of type {}", typeid(map_t).name()));
            }
            return res;
        }

        template<typename C=map_t>
        static C from_json(const boost::json::value &j, const std::string_view key_name, const std::string_view val_name)
        {
            const auto &j_arr = j.as_array();
            C res {};
            for (const auto &jv: j_arr) {
                if constexpr (from_json_c<K>) {
                    auto k = K::from_json(jv.at(key_name)); // ensures that k is read before v!
                    const auto [it, created] = res.try_emplace(std::move(k), V::from_json(jv.at(val_name)));
                    if (!created) [[unlikely]]
                                throw error(fmt::format("a duplicate key in the map of type {}", typeid(map_t).name()));
                } else if constexpr (std::is_constructible_v<uint64_t, K>) {
                    auto k = boost::json::value_to<K>(jv.at(key_name));
                    const auto [it, created] = res.try_emplace(std::move(k), V::from_json(jv.at(val_name)));
                    if (!created) [[unlikely]]
                        throw error(fmt::format("a duplicate key in the map of type {}", typeid(map_t).name()));
                } else {
                    throw error(fmt::format("{} type must have from_json static method!", typeid(K).name()));
                }
            }
            return res;
        }
    };

    template<typename T>
    struct optional_t: std::optional<T> {
        using base_type = std::optional<T>;
        using base_type::base_type;

        static optional_t from_bytes(codec::decoder &dec)
        {
            const auto typ = dec.decode<uint8_t>();
            switch (typ) {
                case 0: return {};
                case 1: return { dec.decode<T>() };
                [[unlikely]] default: throw error(fmt::format("invalid optional type: {}", typ));
            }
        }

        static optional_t from_json(const boost::json::value &j)
        {
            if (!j.is_null()) {
                return T::from_json(j);
            }
            return {};
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

        template<typename C=byte_array_t>
        static C from_bytes(codec::decoder &dec)
        {
            return C { dec.next_bytes(SZ) };
        }

        template<typename C=byte_array_t>
        static C from_json(const boost::json::value &j)
        {
            const auto hex = boost::json::value_to<std::string_view>(j);
            if (!hex.starts_with("0x")) [[unlikely]]
                throw error(fmt::format("expected a hex string but got: {}", hex));
            C res;
            turbo::init_from_hex(res, hex.substr(2));
            return res;
        }

        void to_bytes(codec::encoder &enc) const
        {
            enc.bytes() << *this;
        }
    };

    template<size_t SZ>
    struct bitset_t: byte_array_t<SZ / 8> {
        using base_type = byte_array_t<SZ / 8>;
        using base_type::base_type;

        static bitset_t from_bytes(codec::decoder &dec)
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
    struct time_slot_t {
        static time_slot_t from_bytes(codec::decoder &dec);
        static time_slot_t from_json(const boost::json::value &j);

        time_slot_t(const uint32_t slot):
            _val { slot }
        {
        }

        time_slot_t() noexcept =default;
        time_slot_t(const time_slot_t &) noexcept =default;
        time_slot_t &operator=(const time_slot_t &) noexcept =default;

        void to_bytes(codec::encoder &enc) const;

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

    using gas_t = uint64_t;

    using entropy_t = opaque_hash_t;
    using entropy_buffer_t = fixed_sequence_t<entropy_t, 4>;

    using validator_metadata_t = byte_array_t<128>;

    struct validator_data_t {
        bandersnatch_public_t bandersnatch;
        ed25519_public_t ed25519;
        bls_public_t bls;
        validator_metadata_t metadata;

        static validator_data_t from_bytes(codec::decoder &dec);
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
        gas_t min_item_gas = 0;
        gas_t min_memo_gas = 0;
        uint64_t bytes = 0;
        uint32_t items = 0;

        static service_info_t from_bytes(codec::decoder &dec);
        bool operator==(const service_info_t &o) const noexcept;
    };

    using prerequisites_t = sequence_t<opaque_hash_t, 0, 8>;

    // GP 11.1.2: X
    template<typename CONSTANTS>
    struct refine_context_t {
	    header_hash_t anchor;
	    state_root_t state_root;
	    beefy_root_t beefy_root;
	    header_hash_t lookup_anchor;
	    time_slot_t<CONSTANTS> lookup_anchor_slot;
	    prerequisites_t prerequisites;

        static refine_context_t from_bytes(codec::decoder &dec);
        static refine_context_t from_json(const boost::json::value &);
        void to_bytes(codec::encoder &enc) const;
        bool operator==(const refine_context_t &o) const;
    };

    struct authorizer_t  {
        opaque_hash_t code_hash;
        byte_sequence_t params;

        static authorizer_t from_bytes(codec::decoder &dec);
        static authorizer_t from_json(const boost::json::value &);

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

        static core_authorizer_t from_bytes(codec::decoder &dec);
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

        static auth_pools_t from_bytes(codec::decoder &dec);
        static auth_pools_t from_json(const boost::json::value &json);
        auth_pools_t apply(const time_slot_t<CONSTANTS> &slot, const core_authorizers_t &cas, const auth_queues_t<CONSTANTS> &phi) const;
    };

    struct import_spec_t {
        opaque_hash_t tree_root;
        uint16_t index;

        static import_spec_t from_bytes(codec::decoder &dec);
        static import_spec_t from_json(const boost::json::value &json);

        bool operator==(const import_spec_t &o) const
        {
            return tree_root == o.tree_root && index == o.index;
        }
    };

    struct extrinsic_spec_t {
        opaque_hash_t hash;
        uint32_t len;

        static extrinsic_spec_t from_bytes(codec::decoder &dec);
        static extrinsic_spec_t from_json(const boost::json::value &json);

        bool operator==(const extrinsic_spec_t &o) const
        {
            return hash == o.hash && len == o.len;
        }
    };

    struct work_item_t {
        service_id_t service;
        opaque_hash_t code_hash;
        byte_sequence_t payload;
        gas_t refine_gas_limit;
        gas_t accumulate_gas_limit;
        sequence_t<import_spec_t> import_segments;
        sequence_t<extrinsic_spec_t> extrinsic;
        uint16_t export_count;

        static work_item_t from_bytes(codec::decoder &dec);
        static work_item_t from_json(const boost::json::value &json);

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

        static work_package_t from_bytes(codec::decoder &dec);
        static work_package_t from_json(const boost::json::value &json);

        bool operator==(const work_package_t &o) const
        {
            return authorization == o.authorization && auth_code_host == o.auth_code_host
                && authorizer == o.authorizer && context == o.context
                && items == o.items;
        }
    };

    struct work_result_ok_t {
        byte_sequence_t data;

        static work_result_ok_t from_bytes(codec::decoder &dec);
        static work_result_ok_t from_json(const boost::json::value &json);
        void to_bytes(codec::encoder &enc) const;

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

    struct work_exec_result_t: std::variant<work_result_ok_t, work_result_out_of_gas_t, work_result_panic_t, work_result_bad_exports_t,
                                            work_result_bad_code_t, work_result_code_oversize_t> {
        static work_exec_result_t from_bytes(codec::decoder &dec);
        static work_exec_result_t from_json(const boost::json::value &json);
        void to_bytes(codec::encoder &enc) const;
    };

    struct refine_load_t {
        gas_t gas_used;
        uint16_t imports;
        uint16_t extrinsic_count;
        uint32_t extrinsic_size;
        uint16_t exports;

        static refine_load_t from_bytes(codec::decoder &dec);
        static refine_load_t from_json(const boost::json::value &json);
        void to_bytes(codec::encoder &enc) const;

        bool operator==(const refine_load_t &o) const
        {
            return gas_used == o.gas_used && imports == o.imports && extrinsic_count == o.extrinsic_count
                && extrinsic_size == o.extrinsic_size && exports == o.exports;
        }
    };

    struct work_result_t {
        service_id_t service_id;
        opaque_hash_t code_hash;
        opaque_hash_t payload_hash;
        gas_t accumulate_gas;
        work_exec_result_t result;
        refine_load_t refine_load;

        static work_result_t from_bytes(codec::decoder &dec);
        static work_result_t from_json(const boost::json::value &json);
        void to_bytes(codec::encoder &enc) const;

        bool operator==(const work_result_t &o) const
        {
            return service_id == o.service_id && code_hash == o.code_hash && payload_hash == o.payload_hash
                && accumulate_gas == o.accumulate_gas && refine_load == o.refine_load
                && refine_load == o.refine_load;
        }
    };
    using work_results_t = sequence_t<work_result_t, 1, 16>;

    struct work_package_spec_t {
        work_package_hash_t hash;
        uint32_t length;
        erasure_root_t erasure_root;
        erasure_root_t exports_root;
        uint16_t exports_count;

        static work_package_spec_t from_bytes(codec::decoder &dec);
        static work_package_spec_t from_json(const boost::json::value &json);
        void to_bytes(codec::encoder &enc) const;

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

        static segment_root_lookup_item from_bytes(codec::decoder &dec);
        static segment_root_lookup_item from_json(const boost::json::value &json);
        void to_bytes(codec::encoder &enc) const;

        bool operator==(const segment_root_lookup_item &o) const
        {
            return work_package_hash == o.work_package_hash && segment_tree_root == o.segment_tree_root;
        }
    };

    using segment_root_lookup_t = sequence_t<segment_root_lookup_item, 0, 8>;

    template<typename CONSTANTS>
    struct work_report_t {
        work_package_spec_t package_spec;
        refine_context_t<CONSTANTS> context;
        core_index_t core_index;
        opaque_hash_t authorizer_hash;
        byte_sequence_t auth_output;
        segment_root_lookup_t segment_root_lookup;
        work_results_t results;
        gas_t auth_gas_used;

        static work_report_t from_bytes(codec::decoder &dec);
        static work_report_t from_json(const boost::json::value &json);
        void to_bytes(codec::encoder &enc) const;

        bool operator==(const work_report_t &o) const
        {
            return package_spec == o.package_spec && context == o.context && core_index == o.core_index
                && authorizer_hash == o.authorizer_hash && auth_output == o.auth_output
                && segment_root_lookup == o.segment_root_lookup && results == o.results
                && auth_gas_used == o.auth_gas_used;
        }
    };
    template<typename CONSTANTS>
    using work_reports_t = sequence_t<work_report_t<CONSTANTS>>;

    template<typename CONSTANTS=config_prod>
    struct avail_assurance_t {
        opaque_hash_t anchor;
        bitset_t<CONSTANTS::avail_bitfield_bytes * 8> bitfield;
        validator_index_t validator_index;
        ed25519_signature_t signature;

        static avail_assurance_t from_bytes(codec::decoder &dec)
        {
            return {
                dec.decode<decltype(anchor)>(),
                dec.decode<decltype(bitfield)>(),
                dec.decode<decltype(validator_index)>(),
                dec.decode<decltype(signature)>()
            };
        }

        static avail_assurance_t from_json(const boost::json::value &j)
        {
            return {
                decltype(anchor)::from_json(j.at("anchor")),
                decltype(bitfield)::from_json(j.at("bitfield")),
                boost::json::value_to<decltype(validator_index)>(j.at("validator_index")),
                decltype(signature)::from_json(j.at("signature"))
            };
        }

        bool operator==(const avail_assurance_t &o) const
        {
            return anchor == o.anchor && bitfield == o.bitfield && validator_index == o.validator_index && signature == o.signature;
        }
    };

    template<typename CONSTANTS=config_prod>
    using assurances_extrinsic_t = sequence_t<avail_assurance_t<CONSTANTS>, 0, CONSTANTS::validator_count>;

    template<typename CONSTANTS>
    struct availability_assignment_t  {
        work_report_t<CONSTANTS> report;
        uint32_t timeout;

        static availability_assignment_t from_bytes(codec::decoder &dec);
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

        static availability_assignments_t from_bytes(codec::decoder &dec)
        {
            return base_type::template from_bytes<availability_assignments_t>(dec);
        }

        static availability_assignments_t from_json(const boost::json::value &j)
        {
            return base_type::template from_json<availability_assignments_t>(j);
        }

        availability_assignments_t apply(work_reports_t<CONSTANTS> &out, const validators_data_t<CONSTANTS> &kappa,
            const time_slot_t<CONSTANTS> &tau, const header_hash_t parent, const assurances_extrinsic_t<CONSTANTS> &assurances) const;
    };

    using mmr_peak_t = optional_t<opaque_hash_t>;

    struct mmr_t: sequence_t<mmr_peak_t> {
        using base_type = sequence_t<mmr_peak_t>;
        using base_type::base_type;

        static mmr_t from_bytes(codec::decoder &dec);
        static mmr_t from_json(const boost::json::value &json);
        mmr_t append(const opaque_hash_t &l) const;
        opaque_hash_t root() const;
    };

    struct reported_work_package_t {
        work_report_hash_t hash;
        exports_root_t exports_root;

        static reported_work_package_t from_bytes(codec::decoder &dec);
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

    struct block_info_t {
        header_hash_t header_hash;
        mmr_t mmr;
        state_root_t state_root;
        reported_work_seq_t reported;

        static block_info_t from_bytes(codec::decoder &dec);
        static block_info_t from_json(const boost::json::value &json);

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

        static blocks_history_t from_bytes(codec::decoder &dec);
        static blocks_history_t from_json(const boost::json::value &json);
        blocks_history_t apply(const header_hash_t &, const state_root_t &, const opaque_hash_t &, const reported_work_seq_t &) const;
    };

    struct activity_record_t {
        uint32_t blocks;
        uint32_t tickets;
        uint32_t pre_images;
        uint32_t pre_images_size;
        uint32_t guarantees;
        uint32_t assurances;

        static activity_record_t from_bytes(codec::decoder &dec);
        bool operator==(const activity_record_t &) const;
    };

    using ticket_id_t = opaque_hash_t;
    using ticket_attempt_t = uint8_t;

    struct ticket_envelope_t {
        ticket_attempt_t attempt;
        bandersnatch_ring_vrf_signature_t signature;

        static ticket_envelope_t from_bytes(codec::decoder &dec);
        static ticket_envelope_t from_json(const boost::json::value &json);

        bool operator==(const ticket_envelope_t &o) const
        {
            return attempt == o.attempt && signature == o.signature;
        }
    };

    struct ticket_body_t {
        ticket_id_t id;
        ticket_attempt_t attempt;

        static ticket_body_t from_bytes(codec::decoder &dec);
        static ticket_body_t from_json(const boost::json::value &json);

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

        static tickets_or_keys_t from_bytes(codec::decoder &dec);
    };

    template<typename CONSTANTS=config_prod>
    using tickets_extrinsic_t = sequence_t<ticket_envelope_t, 0, CONSTANTS::max_tickets_per_block>;

    struct judgement_t {
        bool vote;
        validator_index_t index;
        ed25519_signature_t signature;

        static judgement_t from_bytes(codec::decoder &dec);
        static judgement_t from_json(const boost::json::value &json);

        bool operator==(const judgement_t &o) const
        {
            return vote == o.vote && index == o.index && signature == o.signature;
        }
    };

    template<typename CONSTANTS=config_prod>
    struct verdict_t {
        opaque_hash_t target;
        uint32_t age;
        fixed_sequence_t<judgement_t, CONSTANTS::validator_super_majority> votes;

        static verdict_t from_bytes(codec::decoder &dec)
        {
            return {
                dec.decode<decltype(target)>(),
                dec.decode<decltype(age)>(),
                dec.decode<decltype(votes)>()
            };
        }

        static verdict_t from_json(const boost::json::value &j)
        {
            return {
                decltype(target)::from_json(j.at("target")),
                boost::json::value_to<decltype(age)>(j.at("age")),
                decltype(votes)::from_json(j.at("votes"))
            };
        }

        bool operator==(const verdict_t &o) const
        {
            return target == o.target && age == o.age && votes == o.votes;
        }
    };

    struct culprit_t {
        work_report_hash_t target;
        ed25519_public_t key;
        ed25519_signature_t signature;

        static culprit_t from_bytes(codec::decoder &dec);
        static culprit_t from_json(const boost::json::value &json);

        bool operator==(const culprit_t &o) const
        {
            return target == o.target && key == o.key && signature == o.signature;
        }
    };

    struct fault_t {
        work_report_hash_t target;
        bool vote;
        ed25519_public_t key;
        ed25519_signature_t signature;

        static fault_t from_bytes(codec::decoder &dec);
        static fault_t from_json(const boost::json::value &json);

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

    template<typename CONSTANTS=config_prod>
    struct disputes_extrinsic_t {
        sequence_t<verdict_t<CONSTANTS>> verdicts;
        sequence_t<culprit_t> culprits;
        sequence_t<fault_t> faults;

        static disputes_extrinsic_t from_bytes(codec::decoder &dec)
        {
            return {
                dec.decode<decltype(verdicts)>(),
                dec.decode<decltype(culprits)>(),
                dec.decode<decltype(faults)>()
            };
        }

        static disputes_extrinsic_t from_json(const boost::json::value &j)
        {
            return {
                decltype(verdicts)::from_json(j.at("verdicts")),
                decltype(culprits)::from_json(j.at("culprits")),
                decltype(faults)::from_json(j.at("faults"))
            };
        }

        bool operator==(const disputes_extrinsic_t &o) const
        {
            return verdicts == o.verdicts && culprits == o.culprits && faults == o.faults;
        }
    };

    struct preimage_t  {
        service_id_t requester;
        byte_sequence_t blob;

        static preimage_t from_bytes(codec::decoder &dec);
        static preimage_t from_json(const boost::json::value &json);

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

        static validator_signature_t from_bytes(codec::decoder &dec);
        static validator_signature_t from_json(const boost::json::value &json);

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

        static report_guarantee_t from_bytes(codec::decoder &dec);
        static report_guarantee_t from_json(const boost::json::value &json);

        bool operator==(const report_guarantee_t &o) const
        {
            return report == o.report && slot == o.slot && signatures == o.signatures;
        }
    };

    template<typename CONSTANTS=config_prod>
    using guarantees_extrinsic_t = sequence_t<report_guarantee_t<CONSTANTS>, 0, CONSTANTS::core_count>;

    template<typename CONSTANTS>
    struct ready_record_t {
        work_report_t<CONSTANTS> report;
        sequence_t<work_package_hash_t> dependencies;

        static ready_record_t from_bytes(codec::decoder &dec);
        static ready_record_t from_json(const boost::json::value &json);

        bool operator==(const ready_record_t &o) const
        {
            return report == o.report && dependencies == o.dependencies;
        }
    };

    template<typename CONSTANTS>
    using ready_queue_item_t = sequence_t<ready_record_t<CONSTANTS>>;

    template<typename CONSTANTS=config_prod>
    using ready_queue_t = fixed_sequence_t<ready_queue_item_t<CONSTANTS>, CONSTANTS::ready_queue_count>;

    using accumulated_queue_item_t = sequence_t<work_package_hash_t>;

    template<typename CONSTANTS=config_prod>
    using accumulated_queue_t = fixed_sequence_t<accumulated_queue_item_t, CONSTANTS::epoch_length>;

    struct always_accumulate_map_item_t {
        service_id_t id;
        gas_t gas;

        static always_accumulate_map_item_t from_bytes(codec::decoder &dec);
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
    };

    using accumulate_root_t = opaque_hash_t;

    struct epoch_mark_validator_keys_t {
        bandersnatch_public_t bandersnatch;
        ed25519_public_t ed25519;

        static epoch_mark_validator_keys_t from_bytes(codec::decoder &dec);
        static epoch_mark_validator_keys_t from_json(const boost::json::value &j);

        bool operator==(const epoch_mark_validator_keys_t &o) const
        {
            return bandersnatch == o.bandersnatch && ed25519 == o.ed25519;
        }
    };

    template<typename CONSTANTS=config_prod>
    struct epoch_mark_t {
        entropy_t entropy;
        entropy_t tickets_entropy;
        fixed_sequence_t<epoch_mark_validator_keys_t, CONSTANTS::validator_count> validators;

        static epoch_mark_t from_bytes(codec::decoder &dec)
        {
            return {
                dec.decode<decltype(entropy)>(),
                dec.decode<decltype(tickets_entropy)>(),
                dec.decode<decltype(validators)>()
            };
        }

        static epoch_mark_t from_json(const boost::json::value &json)
        {
            return {
                decltype(entropy)::from_json(json.at("entropy")),
                decltype(tickets_entropy)::from_json(json.at("tickets_entropy")),
                decltype(validators)::from_json(json.at("validators"))
            };
        }

        bool operator==(const epoch_mark_t &o) const
        {
            return entropy == o.entropy && tickets_entropy == o.tickets_entropy && validators == o.validators;
        }
    };

    template<typename CONSTANTS=config_prod>
    using tickets_mark_t = fixed_sequence_t<ticket_body_t, CONSTANTS::epoch_length>;

    using offenders_mark_t = ed25519_keys_t;

    using preimages_t = map_t<opaque_hash_t, byte_sequence_t>;

    struct lookup_met_map_key_t {
        opaque_hash_t hash;
        uint32_t length;

        static lookup_met_map_key_t from_bytes(codec::decoder &dec);
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

    template<typename CONSTANTS>
    using lookup_met_map_val_t = sequence_t<time_slot_t<CONSTANTS>, 0, 3>;
    template<typename CONSTANTS>
    using lookup_metas_t = map_t<lookup_met_map_key_t, lookup_met_map_val_t<CONSTANTS>>;

    template<typename CONSTANTS>
    struct account_t {
        preimages_t preimages {};
        lookup_metas_t<CONSTANTS> lookup_metas {};
        service_info_t info {};

        static account_t from_bytes(codec::decoder &dec);
        static account_t from_json(const boost::json::value &j);
        bool operator==(const account_t &) const;
    };

    template<typename CONSTANTS>
    struct accounts_t: map_t<service_id_t, account_t<CONSTANTS>> {
        using base_type = map_t<service_id_t, account_t<CONSTANTS>>;
        using base_type::base_type;

        static accounts_t from_bytes(codec::decoder &);
        static accounts_t from_json(const boost::json::value &j);
        accounts_t apply(const time_slot_t<CONSTANTS> &, const preimages_extrinsic_t &) const;
    };

    template<typename CONSTANTS=config_prod>
    struct header_t {
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

        static header_t from_bytes(codec::decoder &dec)
        {
            return {
                dec.decode<decltype(parent)>(),
                dec.decode<decltype(parent_state_root)>(),
                dec.decode<decltype(extrinsic_hash)>(),
                dec.decode<decltype(slot)>(),
                dec.decode<decltype(epoch_mark)>(),
                dec.decode<decltype(tickets_mark)>(),
                dec.decode<decltype(offenders_mark)>(),
                dec.decode<decltype(author_index)>(),
                dec.decode<decltype(entropy_source)>(),
                dec.decode<decltype(seal)>()
            };
        }

        static header_t from_json(const boost::json::value &j)
        {
            return {
                decltype(parent)::from_json(j.at("parent")),
                decltype(parent_state_root)::from_json(j.at("parent_state_root")),
                decltype(extrinsic_hash)::from_json(j.at("extrinsic_hash")),
                decltype(slot)::from_json(j.at("slot")),
                decltype(epoch_mark)::from_json(j.at("epoch_mark")),
                decltype(tickets_mark)::from_json(j.at("tickets_mark")),
                decltype(offenders_mark)::from_json(j.at("offenders_mark")),
                boost::json::value_to<decltype(author_index)>(j.at("author_index")),
                decltype(entropy_source)::from_json(j.at("entropy_source")),
                decltype(seal)::from_json(j.at("seal"))
            };
        }

        void to_bytes(codec::encoder &enc) const
        {
            enc << parent;
            enc << parent_state_root;
            enc << extrinsic_hash;
            enc << slot;
            enc << epoch_mark;
            enc << tickets_mark;
            enc << offenders_mark;
            enc << author_index;
            enc << entropy_source;
            enc << seal;
        }

        bool operator==(const header_t &o) const
        {
            return parent == o.parent && parent_state_root == o.parent_state_root && extrinsic_hash == o.extrinsic_hash
                && slot == o.slot && epoch_mark == o.epoch_mark && tickets_mark == o.tickets_mark
                && offenders_mark == o.offenders_mark && author_index == o.author_index && entropy_source == o.entropy_source
                && seal == o.seal;
        }
    };

    template<typename CONSTANTS=config_prod>
    struct extrinsic_t {
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

        static extrinsic_t from_bytes(codec::decoder &dec)
        {
            return {
                dec.decode<decltype(tickets)>(),
                dec.decode<decltype(preimages)>(),
                dec.decode<decltype(guarantees)>(),
                dec.decode<decltype(assurances)>(),
                dec.decode<decltype(disputes)>()
            };
        }

        static extrinsic_t from_json(const boost::json::value &j)
        {
            return {
                decltype(tickets)::from_json(j.at("tickets")),
                decltype(preimages)::from_json(j.at("preimages")),
                decltype(guarantees)::from_json(j.at("guarantees")),
                decltype(assurances)::from_json(j.at("assurances")),
                decltype(disputes)::from_json(j.at("disputes"))
            };
        }

        void to_bytes(codec::encoder &enc) const
        {
            enc << tickets;
            enc << preimages;
            enc << guarantees;
            enc << assurances;
            enc << disputes;
        }

        bool operator==(const extrinsic_t &o) const
        {
            return tickets == o.tickets && preimages == o.preimages && guarantees == o.guarantees
                && assurances == o.assurances && disputes == o.disputes;
        }
    };

    template<typename CONSTANTS=config_prod>
    using activity_records_t = fixed_sequence_t<activity_record_t, CONSTANTS::validator_count>;

    struct core_activity_record_t {
        gas_t gas_used = 0;
        uint16_t imports = 0;
        uint16_t extrinsic_count = 0;
        uint32_t extrinsic_size = 0;
        uint16_t exports = 0;
        uint32_t bundle_size = 0;
        uint32_t da_load = 0;
        uint16_t popularity = 0;

        static core_activity_record_t from_bytes(codec::decoder &dec);
        bool operator==(const core_activity_record_t &o) const;
    };

    template<typename CONSTANTS>
    using core_statistics_t = fixed_sequence_t<core_activity_record_t, CONSTANTS::core_count>;

    struct service_activity_record_t {
        uint16_t provided_count = 0;
        uint32_t provided_size = 0;
        uint32_t refinement_count = 0;
        uint64_t refinement_gas_used = 0;
        uint32_t imports = 0;
        uint32_t extrinsic_count = 0;
        uint32_t extrinsic_size = 0;
        uint32_t exports = 0;
        uint32_t accumulate_count = 0;
        uint64_t accumulate_gas_used = 0;
        uint32_t on_transfers_count = 0;
        uint64_t on_transfers_gas_used = 0;

        static service_activity_record_t from_bytes(codec::decoder &dec);
        bool operator==(const service_activity_record_t &o) const;
    };
    using services_statistics_t = map_t<service_id_t, service_activity_record_t>;

    template<typename CONSTANTS=config_prod>
    struct statistics_t {
        activity_records_t<CONSTANTS> current {};
        activity_records_t<CONSTANTS> last {};
        core_statistics_t<CONSTANTS> cores {};
        services_statistics_t services {};

        static statistics_t from_bytes(codec::decoder &dec);
        bool operator==(const statistics_t &o) const;
    };

    template<typename CONSTANTS=config_prod>
    struct block_t {
        // JAM paper: H - capital eta
        header_t<CONSTANTS> header;
        // JAM paper: E - capital epsilon
        extrinsic_t<CONSTANTS> extrinsic;

        static block_t from_bytes(codec::decoder &dec)
        {
            return {
                dec.decode<decltype(header)>(),
                dec.decode<decltype(extrinsic)>()
            };
        }

        static block_t from_json(const boost::json::value &j)
        {
            return {
                decltype(header)::from_json(j.at("header")),
                decltype(extrinsic)::from_json(j.at("extrinsic"))
            };
        }

        void to_bytes(codec::encoder &enc) const
        {
            enc << header;
            enc << extrinsic;
        }

        bool operator==(const block_t &o) const
        {
            return header == o.header && extrinsic == o.extrinsic;
        }
    };
}
