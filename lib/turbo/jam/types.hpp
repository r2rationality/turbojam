#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <array>
#include <cmath>
#include <cstdint>
#include <optional>
#include <variant>
#include <vector>
#include <turbo/common/bytes.hpp>
#include "codec.hpp"

namespace turbo::jam {

    struct config_prod {
        static constexpr size_t epoch_length = 600;
        static constexpr size_t core_count = 341;
        static constexpr size_t validator_count = core_count * 3;
        static constexpr size_t validator_super_majority = validator_count * 2 / 3 + 1;
        static constexpr size_t avail_bitfield_bytes = (core_count + 7) / 8;
        static constexpr size_t max_tickets_per_block = 16;
        static constexpr size_t tickets_per_validator = 2;
        static constexpr size_t max_blocks_history = 8;
        static constexpr size_t auth_pool_max_size = 8;
        static constexpr size_t auth_queue_size = 80;
        static constexpr size_t core_assignment_rotation_period = 10;
        static constexpr size_t ticket_attempts = 2;
    };

    struct config_tiny: config_prod {
        static constexpr size_t core_count = 2;
        static constexpr size_t validator_count = core_count * 3;
        static constexpr size_t epoch_length = 12;
        static constexpr size_t validator_super_majority = validator_count * 2 / 3 + 1;
        static constexpr size_t avail_bitfield_bytes = (core_count + 7) / 8;
        static constexpr size_t core_assignment_rotation_period = 4;
        static constexpr size_t ticket_attempts = 3;
    };

    // jam-types.asn

    struct byte_sequence_t: uint8_vector {
        using base_type = uint8_vector;
        using base_type::base_type;

        static byte_sequence_t from_bytes(codec::decoder &dec)
        {
            const auto sz = dec.uint_general();
            return { dec.next_bytes(sz) };
        }
    };

    template<typename T, size_t MIN=0, size_t MAX=std::numeric_limits<size_t>::max()>
    struct sequence_t: std::vector<T> {
        static constexpr size_t min_size = MIN;
        static constexpr size_t max_size = MAX;
        static_assert(MIN < MAX);
        using base_type = std::vector<T>;
        using base_type::base_type;

        static sequence_t from_bytes(codec::decoder &dec)
        {
            const auto sz = dec.uint_general();
            if (static_cast<int>(sz < MIN) | static_cast<int>(sz > MAX)) [[unlikely]]
                throw error(fmt::format("the recorded number of elements is {} and outside of the allowed range [{}:{}] for {}",
                            sz, MIN, MAX, typeid(sequence_t).name()));
            sequence_t res {};
            res.reserve(sz);
            for (size_t i = 0; i < sz; i++)
                res.emplace_back(dec.decode<T>());
            return res;
        }
    };

    template<typename T, size_t SZ>
    struct fixed_sequence_t: std::array<T, SZ> {
        static_assert(SZ > 0);
        using base_type = std::array<T, SZ>;
        using base_type::base_type;

        static fixed_sequence_t from_bytes(codec::decoder &dec)
        {
            fixed_sequence_t res {};
            for (size_t i = 0; i < SZ; i++)
                res[i] = dec.decode<T>();
            return res;
        }

        template<typename C>
        static C from_bytes_as(codec::decoder &dec)
        {
            C res {};
            for (size_t i = 0; i < SZ; i++)
                res[i] = dec.decode<T>();
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

        bool operator==(const optional_t &o) const noexcept
        {
            return *reinterpret_cast<const base_type*>(this) == *reinterpret_cast<const base_type*>(&o);
        }
    };

    template<size_t SZ>
    struct byte_array_t: byte_array<SZ> {
        using base_type = byte_array<SZ>;
        using base_type::base_type;

        static byte_array_t from_bytes(codec::decoder &dec)
        {
            return { dec.next_bytes(SZ) };
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

    using time_slot_t = uint32_t;
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
    using entropy_buffer = fixed_sequence_t<entropy_t, 4>;

    using validator_metadata_t = byte_array_t<128>;

    struct validator_data_t {
        bandersnatch_public_t bandersnatch;
        ed25519_public_t ed25519;
        bls_public_t bls;
        validator_metadata_t metadata;

        static validator_data_t from_bytes(codec::decoder &dec);
    };

    using service_id_t = uint32_t;

    struct service_info_t {
        opaque_hash_t code_hash;
        uint64_t balance;
        gas_t min_item_gas;
        gas_t min_memo_gas;
        uint64_t bytes;
        uint32_t items;
    };

    struct refine_context_t {
	    header_hash_t anchor;
	    state_root_t state_root;
	    beefy_root_t beefy_root;
	    header_hash_t lookup_anchor;
	    time_slot_t lookup_anchor_slot;
	    sequence_t<opaque_hash_t> prerequisites;

        static refine_context_t from_bytes(codec::decoder &dec);
    };

    struct authorizer_t  {
        opaque_hash_t code_hash;
        byte_sequence_t params;

        static authorizer_t from_bytes(codec::decoder &dec);
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

        static core_authorizer_t from_bytes(codec::decoder &dec)
        {
            return {
                dec.decode<decltype(core)>(),
                dec.decode<decltype(auth_hash)>()
            };
        }
    };
    using core_authorizers_t = sequence_t<core_authorizer_t>;

    template<typename CONSTANTS=config_prod>
    struct auth_pools_t: fixed_sequence_t<auth_pool_t<CONSTANTS>, CONSTANTS::core_count>
    {
        using base_type = fixed_sequence_t<auth_pool_t<CONSTANTS>, CONSTANTS::core_count>;
        using base_type::base_type;

        static auth_pools_t from_bytes(codec::decoder &dec);
        auth_pools_t apply(time_slot_t slot, const core_authorizers_t &cas, const auth_queues_t<CONSTANTS> &phi) const;
    };

    struct import_spec_t {
        opaque_hash_t tree_root;
        uint16_t index;

        static import_spec_t from_bytes(codec::decoder &dec);
    };

    struct extrinsic_spec_t {
        opaque_hash_t hash;
        uint32_t len;

        static extrinsic_spec_t from_bytes(codec::decoder &dec);
    };

    struct work_item_t {
        service_id_t service;
        opaque_hash_t code_hash;
        byte_sequence_t payload;
        gas_t refine_gas_limit;
        gas_t accumulate_gas_limit;
        sequence_t<import_spec_t> import_specs;
        sequence_t<extrinsic_spec_t> extrinsic_specs;
        uint16_t export_count;

        static work_item_t from_bytes(codec::decoder &dec);
    };

    struct work_package_t {
        byte_sequence_t authorization;
        service_id_t auth_code_host;
        authorizer_t authorizer;
        refine_context_t context;
        sequence_t<work_item_t, 1, 16> items;

        static work_package_t from_bytes(codec::decoder &dec);
    };

    struct work_result_ok_t {
        byte_sequence_t data;

        static work_result_ok_t from_bytes(codec::decoder &dec);
    };
    struct work_result_out_of_gas_t {};
    struct work_result_panic_t {};
    struct work_result_bad_exports_t {};
    struct work_result_bad_code_t {};
    struct work_result_code_oversize_t {};

    struct work_exec_result_t: std::variant<work_result_ok_t, work_result_out_of_gas_t, work_result_panic_t, work_result_bad_exports_t,
                                            work_result_bad_code_t, work_result_code_oversize_t> {
        static work_exec_result_t from_bytes(codec::decoder &dec);
    };

    struct work_result_t {
        service_id_t service_id;
        opaque_hash_t code_hash;
        opaque_hash_t payload_hash;
        gas_t accumulate_gas;
        work_exec_result_t result;

        static work_result_t from_bytes(codec::decoder &dec);
    };

    struct work_package_spec_t {
        work_package_hash_t hash;
        uint32_t length;
        erasure_root_t erasure_root;
        erasure_root_t exports_root;
        uint16_t exports_count;

        static work_package_spec_t from_bytes(codec::decoder &dec);
    };

    struct segment_root_lookup_item {
        work_package_hash_t work_package_hash;
        opaque_hash_t segment_tree_root;

        static segment_root_lookup_item from_bytes(codec::decoder &dec);
    };

    using segment_root_lookup_t = sequence_t<segment_root_lookup_item>;

    struct work_report_t {
        work_package_spec_t package_spec;
        refine_context_t context;
        core_index_t core_index;
        opaque_hash_t authorizer_hash;
        byte_sequence_t auth_output;
        segment_root_lookup_t segment_root_lookup;
        sequence_t<work_result_t, 1, 16> results;

        static work_report_t from_bytes(codec::decoder &dec);
    };
    using work_reports_t = sequence_t<work_report_t>;

    struct availability_assignment_t  {
        work_report_t report;
        uint32_t timeout;

        static availability_assignment_t from_bytes(codec::decoder &dec);
    };

    using availability_assignments_item_t = optional_t<availability_assignment_t>;

    template<typename CONSTANT_SET=config_prod>
    using validators_data_t = fixed_sequence_t<validator_data_t, CONSTANT_SET::validator_count>;

    template<typename CONSTANT_SET=config_prod>
    using availability_assignments_t = fixed_sequence_t<availability_assignments_item_t, CONSTANT_SET::core_count>;

    using mmr_peak_t = optional_t<opaque_hash_t>;

    struct mmr_t: sequence_t<mmr_peak_t> {
        using base_type = sequence_t<mmr_peak_t>;
        using base_type::base_type;

        static mmr_t from_bytes(codec::decoder &dec);
        mmr_t append(const opaque_hash_t &l) const;
    };

    struct reported_work_package_t {
        work_report_hash_t hash;
        exports_root_t exports_root;

        static reported_work_package_t from_bytes(codec::decoder &dec);

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
        blocks_history_t apply(const header_hash_t &, const state_root_t &, const opaque_hash_t &, const reported_work_seq_t &) const;
    };

    struct activity_record_t {
        uint32_t blocks;
        uint32_t tickets;
        uint32_t pre_images;
        uint32_t pre_images_size;
        uint32_t guarantees;
        uint32_t assurances;
    };

    template<typename CONSTANTS=config_prod>
    using activity_records_t = fixed_sequence_t<activity_record_t, CONSTANTS::validator_count>;

    template<typename CONSTANTS=config_prod>
    struct statistics_t {
        activity_records_t<CONSTANTS> current;
        activity_records_t<CONSTANTS> last;
    };

    using ticket_id_t = opaque_hash_t;
    using ticket_attempt_t = uint8_t;

    struct ticket_envelope_t {
        ticket_attempt_t attempt;
        bandersnatch_ring_vrf_signature_t signature;

        static ticket_envelope_t from_bytes(codec::decoder &dec);
    };

    struct ticket_body_t {
        ticket_id_t id;
        ticket_attempt_t attempt;

        static ticket_body_t from_bytes(codec::decoder &dec);
    };

    template<typename CONSTANTS=config_prod>
    using tickets_accumulator_t = sequence_t<ticket_body_t, 0, CONSTANTS::epoch_length>;

    template<typename CONSTANTS=config_prod>
    using tickets_t = fixed_sequence_t<ticket_body_t, CONSTANTS::epoch_length>;

    template<typename CONSTANTS=config_prod>
    using keys_t = fixed_sequence_t<bandersnatch_public_t, CONSTANTS::epoch_length>;

    template<typename CONSTANTS=config_prod>
    using tickets_or_keys_t = std::variant<tickets_t<CONSTANTS>, keys_t<CONSTANTS>>;

    template<typename CONSTANTS=config_prod>
    using tickets_extrinsic_t = sequence_t<ticket_envelope_t, 0, CONSTANTS::max_tickets_per_block>;

    struct judgement_t {
        bool vote;
        validator_index_t index;
        ed25519_signature_t signature;

        static judgement_t from_bytes(codec::decoder &dec);
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
    };

    struct culprit_t {
        work_report_hash_t target;
        ed25519_public_t key;
        ed25519_signature_t signature;

        static culprit_t from_bytes(codec::decoder &dec);
    };

    struct fault_t {
        work_report_hash_t target;
        bool vote;
        ed25519_public_t key;
        ed25519_signature_t signature;

        static fault_t from_bytes(codec::decoder &dec);
    };

    struct disputes_records_t {
        sequence_t<work_report_hash_t> good;
        sequence_t<work_report_hash_t> bad;
        sequence_t<work_report_hash_t> wonky;
        sequence_t<ed25519_public_t> offenders;
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
    };

    struct preimage_t  {
        service_id_t requester;
        byte_sequence_t blob;

        static preimage_t from_bytes(codec::decoder &dec);
    };

    using preimages_extrinsic_t = sequence_t<preimage_t>;

    template<typename CONSTANTS=config_prod>
    struct avail_assurance_t {
        opaque_hash_t anchor;
        byte_array_t<CONSTANTS::avail_bitfield_bytes> bitfield;
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
    };

    template<typename CONSTANTS=config_prod>
    using assurances_extrinsic_t = sequence_t<avail_assurance_t<CONSTANTS>, 0, CONSTANTS::validator_count>;

    struct validator_signature_t {
        validator_index_t validator_index;
        ed25519_signature_t signature;

        static validator_signature_t from_bytes(codec::decoder &dec);
    };

    struct report_guarantee_t {
        work_report_t report;
        time_slot_t slot;
        sequence_t<validator_signature_t> signatures;

        static report_guarantee_t from_bytes(codec::decoder &dec);
    };

    template<typename CONSTANTS=config_prod>
    using guarantees_extrinsic_t = sequence_t<report_guarantee_t, 0, CONSTANTS::core_count>;

    struct ready_record_t {
        work_report_t report;
        sequence_t<work_package_hash_t> dependencies;
    };

    using ready_queue_item_t = sequence_t<ready_record_t>;

    template<typename CONSTANTS=config_prod>
    using ready_queue_t = fixed_sequence_t<ready_queue_item_t, CONSTANTS::ready_queue_count>;

    using accumulated_queue_item_t = sequence_t<work_package_hash_t>;

    template<typename CONSTANTS=config_prod>
    using accumulated_queue_t = fixed_sequence_t<accumulated_queue_item_t, CONSTANTS::epoch_length>;

    struct always_accumulate_map_item_t {
        service_id_t id;
        gas_t gas;
    };

    struct privileges_t {
        service_id_t bless;
        service_id_t assign;
        service_id_t designate;
        sequence_t<always_accumulate_map_item_t> always_acc;
    };

    using accumulate_root_t = opaque_hash_t;

    template<typename CONSTANTS=config_prod>
    struct epoch_mark_t {
        entropy_t entropy;
        entropy_t tickets_entropy;
        fixed_sequence_t<bandersnatch_public_t, CONSTANTS::validator_count> validators;

        static epoch_mark_t from_bytes(codec::decoder &dec)
        {
            return {
                dec.decode<decltype(entropy)>(),
                dec.decode<decltype(tickets_entropy)>(),
                dec.decode<decltype(validators)>()
            };
        }
    };

    template<typename CONSTANTS=config_prod>
    using tickets_mark_t = fixed_sequence_t<ticket_body_t, CONSTANTS::epoch_length>;

    using offenders_mark_t = sequence_t<ed25519_public_t>;

    template<typename CONSTANTS=config_prod>
    struct header_t {
        header_hash_t parent;
        state_root_t parent_state_root;
        opaque_hash_t extrinsic_hash;
        time_slot_t slot;
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

        void to_bytes(codec::encoder &enc) const
        {
            enc << tickets;
            enc << preimages;
            enc << guarantees;
            enc << assurances;
            enc << disputes;
        }
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

        void to_bytes(codec::encoder &enc) const
        {
            enc << header;
            enc << extrinsic;
        }
    };
}
