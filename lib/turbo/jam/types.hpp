#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <array>
#include <cstdint>
#include <optional>
#include <variant>
#include <vector>

namespace turbo::jam {

    struct constants {
        static constexpr size_t validator_count = 1023;
        static constexpr size_t epoch_length = 600;
        static constexpr size_t core_count = 341;
        static constexpr size_t validator_super_majority = validator_count * 2 / 3 + 1;
        static constexpr size_t avail_bitfield_bytes = 0;
        static constexpr size_t max_blocks_history = 0;
        static constexpr size_t max_tickets_per_block = 0;
        static constexpr size_t auth_pool_max_size = 0;
        static constexpr size_t auth_queue_size = 0;
    };

    // jam-types.asn

    using byte_sequence_t = std::vector<uint8_t>;

    template<size_t SZ>
    struct byte_array_t: std::array<uint8_t, SZ> {
        using base_type = std::array<uint8_t, SZ>;
        using base_type::base_type;
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
    using entropy_buffer = std::array<entropy_t, 4>;

    using validator_metadata_t = byte_array_t<128>;

    struct validator_data_t {
        bandersnatch_public_t bandersnatch;
        ed25519_public_t ed25519;
        bls_public_t bls;
        validator_metadata_t metadata;
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
	    std::vector<opaque_hash_t> prerequisites;
    };

    struct authorizer_t  {
        opaque_hash_t code_hash;
        byte_sequence_t params;
    };

    using authorizer_hash_t = opaque_hash_t;

    // max size: auth_pool_max_size
    using auth_pool_t = std::vector<authorizer_hash_t>;

    template<typename CONSTANT_SET=constants>
    using auth_pools_t = std::array<auth_pool_t, CONSTANT_SET::core_count>;

    template<typename CONSTANT_SET=constants>
    using auth_queue_t = std::array<authorizer_hash_t, CONSTANT_SET::auth_queue_size>;

    template<typename CONSTANT_SET=constants>
    using auth_queues_t = std::array<auth_queue_t<CONSTANT_SET>, CONSTANT_SET::core_count>;

    struct import_spec_t {
        opaque_hash_t tree_root;
        uint16_t index;
    };

    struct extrinsic_spec_t {
        opaque_hash_t hash;
        uint32_t len;
    };

    struct work_item_t {
        service_id_t service;
        opaque_hash_t code_hash;
        byte_sequence_t payload;
        gas_t refine_gas_limit;
        gas_t accumulate_gas_limit;
        std::vector<import_spec_t> import_specs;
        std::vector<extrinsic_spec_t> extrinsic_specs;
        uint16_t export_count;
    };

    struct work_package_t {
        byte_sequence_t authorization;
        service_id_t auth_code_host;
        authorizer_t authorizer;
        refine_context_t context;
        std::vector<work_item_t> items; // size: 1..16;
    };

    enum class work_exec_result_t: uint8_t {
        ok = 0,
        out_of_gas = 1,
        panic = 2,
        bad_exports = 3,
        bad_code = 4,
        code_oversize = 5
    };

    struct work_result_t {
        service_id_t service_id;
        opaque_hash_t code_hash;
        opaque_hash_t payload_hash;
        gas_t accumulate_gas;
        work_exec_result_t result;
    };

    struct work_package_spec_t {
        work_package_hash_t hash;
        uint32_t length;
        erasure_root_t erasure_root;
        erasure_root_t exports_root;
        uint16_t exports_count;
    };

    struct segment_root_lookup_item {
        work_package_hash_t work_package_hash;
        opaque_hash_t segment_tree_root;
    };

    using segment_root_lookup_t = std::vector<segment_root_lookup_item>;

    struct work_report_t {
        work_package_spec_t package_spec;
        refine_context_t context;
        core_index_t core_index;
        opaque_hash_t authorizer_hash;
        byte_sequence_t auth_output;
        segment_root_lookup_t segment_root_lookup;
        std::vector<work_result_t> results; // 1..16
    };

    struct availability_assignment_t  {
        work_report_t report;
        uint32_t timeout;
    };

    using availability_assignments_item_t = std::optional<availability_assignment_t>;

    template<typename CONSTANT_SET=constants>
    using validators_data_t = std::array<validator_data_t, CONSTANT_SET::validator_count>;

    template<typename CONSTANT_SET=constants>
    using availability_assignments = std::array<availability_assignments_item_t, CONSTANT_SET::core_count>;

    using mmr_peak_t = std::optional<opaque_hash_t>;
    using mmr_t = std::vector<mmr_peak_t>;

    struct reported_work_package_t {
        work_report_hash_t hash;
        exports_root_t exports_root;
    };

    struct block_info_t {
        header_hash_t header_hash;
        mmr_t mmr;
        state_root_t state_root;
        std::vector<reported_work_package_t> reported;
    };

    using blocks_history_t = std::vector<block_info_t>; //0..max-blocks-history

    struct activity_record_t {
        uint32_t blocks;
        uint32_t tickets;
        uint32_t pre_images;
        uint32_t pre_images_size;
        uint32_t guarantees;
        uint32_t assurances;
    };

    template<typename CONSTANTS=constants>
    using activity_records_t = std::array<activity_record_t, CONSTANTS::validator_count>;

    template<typename CONSTANTS=constants>
    struct statistics_t {
        activity_records_t<CONSTANTS> current;
        activity_records_t<CONSTANTS> last;
    };

    using ticket_id_t = opaque_hash_t;
    using ticket_attempt_t = uint8_t;

    struct ticket_envelope_t {
        ticket_attempt_t attempt;
        bandersnatch_ring_vrf_signature_t signature;
    };

    struct ticket_body_t {
        ticket_id_t id;
        ticket_attempt_t attempt;
    };

    using tickets_accumulator_t = std::vector<ticket_body_t>; // 0..epoch-length

    template<typename CONSTANTS=constants>
    using tickets_t = std::array<ticket_body_t, CONSTANTS::epoch_length>;

    template<typename CONSTANTS=constants>
    using keys_t = std::array<bandersnatch_public_t, CONSTANTS::epoch_length>;

    template<typename CONSTANTS=constants>
    using tickets_or_keys_t = std::variant<tickets_t<CONSTANTS>, keys_t<CONSTANTS>>;

    using tickets_extrinsic_t = std::vector<ticket_envelope_t>; // 0..max-tickets-per-block

    struct judgement_t {
        bool vote;
        validator_index_t index;
        ed25519_signature_t signature;
    };

    template<typename CONSTANTS=constants>
    struct verdict_t {
        opaque_hash_t target;
        uint32_t age;
        std::array<judgement_t, CONSTANTS::validator_super_majority> votes;
    };

    struct culprit_t {
        work_report_hash_t target;
        ed25519_public_t key;
        ed25519_signature_t signature;
    };

    struct fault_t {
        work_report_hash_t target;
        bool vote;
        ed25519_public_t key;
        ed25519_signature_t signature;
    };

    struct disputes_records_t {
        std::vector<work_report_hash_t> good;
        std::vector<work_report_hash_t> bad;
        std::vector<work_report_hash_t> wonky;
        std::vector<ed25519_public_t> offenders;
    };

    template<typename CONSTANTS=constants>
    struct disputes_extrinsic_t {
        verdict_t<CONSTANTS> verdicts;
        culprit_t culprits;
        fault_t faults;
    };

    struct preimage_t  {
        service_id_t requester;
        byte_sequence_t blob;
    };

    using preimages_extrinsic_t = std::vector<preimage_t>;

    template<typename CONSTANTS=constants>
    struct avail_assurance_t {
        opaque_hash_t anchor;
        byte_array_t<CONSTANTS::max_bitfield_bytes> bitfield;
        validator_index_t validator_index;
        ed25519_signature_t signature;
    };

    template<typename CONSTANTS=constants>
    using assurances_extrinsic_t = std::vector<avail_assurance_t<CONSTANTS>>; // 0..validators-count

    struct validator_signature_t {
        validator_index_t validator_index;
        ed25519_signature_t signature;
    };

    struct report_guarantee_t {
        work_report_t report;
        time_slot_t slot;
        std::vector<validator_signature_t> signatures;
    };

    using guarantees_extrinsic_t = std::vector<report_guarantee_t>; // 0..cores-count

    struct ready_record_t {
        work_report_t report;
        std::vector<work_package_hash_t> dependencies;
    };

    using ready_queue_item_t = std::vector<ready_record_t>;

    template<typename CONSTANTS=constants>
    using ready_queue_t = std::array<ready_queue_item_t, CONSTANTS::ready_queue_count>;

    using accumulated_queue_item_t = std::vector<work_package_hash_t>;

    template<typename CONSTANTS=constants>
    using accumulated_queue_t = std::array<accumulated_queue_item_t, CONSTANTS::epoch_length>;

    struct always_accumulate_map_item_t {
        service_id_t id;
        gas_t gas;
    };

    struct privileges_t {
        service_id_t bless;
        service_id_t assign;
        service_id_t designate;
        std::vector<always_accumulate_map_item_t> always_acc;
    };

    using accumulate_root_t = opaque_hash_t;

    template<typename CONSTANTS=constants>
    struct epoch_mark_t {
        entropy_t entropy;
        entropy_t tickets_entropy;
        std::array<bandersnatch_public_t, CONSTANTS::validator_count> validators;
    };

    template<typename CONSTANTS=constants>
    using tickets_mark_t = std::array<ticket_body_t, CONSTANTS::epoch_length>;

    using offenders_mark_t = std::vector<ed25519_public_t>;

    template<typename CONSTANTS=constants>
    struct header_t {
        header_hash_t parent;
        state_root_t parent_state_root;
        opaque_hash_t extrinsic_hash;
        time_slot_t slot;
        std::optional<epoch_mark_t<CONSTANTS>> epoch_mark;
        std::optional<tickets_mark_t<CONSTANTS>> tickets_mark;
        offenders_mark_t offenders_mark;
        validator_index_t author_index;
        bandersnatch_vrf_signature_t entropy_source;
        bandersnatch_vrf_signature_t seal;
    };

    template<typename CONSTANTS=constants>
    struct extrinsic_t {
        tickets_extrinsic_t tickets;
        preimages_extrinsic_t preimages;
        guarantees_extrinsic_t guarantees;
        assurances_extrinsic_t<CONSTANTS> assurances;
        disputes_extrinsic_t<CONSTANTS> disputes;
    };

    template<typename CONSTANTS=constants>
    struct block_t {
        header_t<CONSTANTS> header;
        extrinsic_t<CONSTANTS> extrinsic;
    };
}
