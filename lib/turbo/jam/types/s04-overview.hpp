#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include "common.hpp"

namespace turbo::jam {
    // JAM (4.3)
    template<typename CONSTANTS>
    struct extrinsic_t {
        tickets_extrinsic_t<CONSTANTS> tickets;
        preimages_extrinsic_t preimages;
        guarantees_extrinsic_t<CONSTANTS> guarantees;
        assurances_extrinsic_t<CONSTANTS> assurances;
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

    // JAM (4.2)
    template<typename CONSTANTS>
        struct block_t {
        header_t<CONSTANTS> header;
        extrinsic_t<CONSTANTS> extrinsic;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("header"sv, header);
            archive.process("extrinsic"sv, extrinsic);
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

    template<typename CONSTANTS=config_prod>
    struct safrole_state_t {
        tickets_accumulator_t<CONSTANTS> a {}; // prior sealing key ticket accumulator
        validators_data_t<CONSTANTS> k {}; // prior next epoch validator keys and metadata
        tickets_or_keys_t<CONSTANTS> s; // prior sealing key series
        bandersnatch_ring_commitment_t z {}; // prior bandersnatch ring commitment

        bool operator==(const safrole_state_t &o) const noexcept;
    };

    template<typename CONSTANTS>
    struct safrole_output_data_t {
        optional_t<epoch_mark_t<CONSTANTS>> epoch_mark;
        optional_t<tickets_mark_t<CONSTANTS>> tickets_mark;

        static safrole_output_data_t from_bytes(decoder &dec)
        {
            return {
                dec.decode<decltype(epoch_mark)>(),
                dec.decode<decltype(tickets_mark)>()
            };
        }

        bool operator==(const safrole_output_data_t &o) const
        {
            if (epoch_mark != o.epoch_mark)
                return false;
            if (tickets_mark != o.tickets_mark)
                return false;
            return true;
        }
    };

    // This data structure is need only because the json names in reports_output_items_t
    // differ from what's encoded in the conformance tests
    struct reports_output_item_t {
        work_report_hash_t work_package_hash;
        exports_root_t segment_tree_root;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("work_package_hash"sv, work_package_hash);
            archive.process("segment_tree_root"sv, segment_tree_root);
        }

        std::strong_ordering operator<=>(const reports_output_item_t &o) const
        {
            if (const auto cmp = work_package_hash <=> o.work_package_hash; cmp == std::weak_ordering::less || cmp == std::weak_ordering::greater)
                return cmp;
            if (const auto cmp = segment_tree_root <=> o.segment_tree_root; cmp == std::weak_ordering::less || cmp == std::weak_ordering::greater)
                return cmp;
            return std::strong_ordering::equal;
        }

        bool operator==(const reports_output_item_t &o) const noexcept
        {
            return work_package_hash <=> o.work_package_hash == std::strong_ordering::equal;
        }
    };
    using reports_output_items_t = sequence_t<reports_output_item_t>;

    struct reports_output_data_t {
        reports_output_items_t reported;
        sequence_t<ed25519_public_t> reporters;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("reported"sv, reported);
            archive.process("reporters"sv, reporters);
        }

        bool operator==(const reports_output_data_t &o) const
        {
            if (reported != o.reported)
                return false;
            if (reporters != o.reporters)
                return false;
            return true;
        }
    };

    // JAM (4.4) - lowercase sigma
    template<typename CONSTANTS=config_prod>
    struct state_t {
        auth_pools_t<CONSTANTS> alpha {}; // authorizations
        blocks_history_t<CONSTANTS> beta {}; // most recent blocks
        safrole_state_t<CONSTANTS> gamma {};
        accounts_t<CONSTANTS> delta {}; // services
        entropy_buffer_t eta {};
        validators_data_t<CONSTANTS> iota {}; // next validators
        validators_data_t<CONSTANTS> kappa {}; // active validators
        validators_data_t<CONSTANTS> lambda {}; // prev validators
        availability_assignments_t<CONSTANTS> rho {}; // assigned work reports
        time_slot_t<CONSTANTS> tau {};
        auth_queues_t<CONSTANTS> phi {}; // work authorizer queue
        privileges_t chi {};
        disputes_records_t psi {}; // judgements
        statistics_t<CONSTANTS> pi {};
        ready_queue_t<CONSTANTS> nu {}; // work reports ready to be accumulated
        accumulated_queue_t<CONSTANTS> ksi {}; // recently accumulated reports

        // JAM (4.1): Kapital upsilon
        void apply(const block_t<CONSTANTS> &);

        // Methods internally used by the apply and in unit tests
        // Todo: make them protected and the respective unit test class friends

        // JAM (4.5)
        void update_time(const time_slot_t<CONSTANTS> &slot);
        // JAM (4.7)
        // JAM (4.8)
        // JAM (4.9)
        // JAM (4.10)
        safrole_output_data_t<CONSTANTS> update_safrole(const time_slot_t<CONSTANTS> &slot, const entropy_t &entropy, const tickets_extrinsic_t<CONSTANTS> &extrinsic);
        // JAM (4.12)
        // JAM (4.13)
        // JAM (4.14)
        // JAM (4.15)
        reports_output_data_t update_reports(const time_slot_t<CONSTANTS> &slot, const guarantees_extrinsic_t<CONSTANTS> &guarantees);
        // JAM (4.11)
        offenders_mark_t update_disputes(const disputes_extrinsic_t<CONSTANTS> &disputes);
        // JAM (4.18)
        void provide_preimages(const time_slot_t<CONSTANTS> &slot, const preimages_extrinsic_t &preimages);
        // JAM (4.20)
        void update_statistics(const time_slot_t<CONSTANTS> &slot, validator_index_t val_idx, const extrinsic_t<CONSTANTS> &extrinsic);
        // JAM (4.16)
        accumulate_root_t accumulate(const time_slot_t<CONSTANTS> &slot, const work_reports_t<CONSTANTS> &reports);
        bool operator==(const state_t &o) const noexcept;
    private:
        using guarantor_assignments_t = fixed_sequence_t<core_index_t, CONSTANTS::validator_count>;

        static bandersnatch_ring_commitment_t _ring_commitment(const validators_data_t<CONSTANTS> &);
        static validators_data_t<CONSTANTS> _capital_phi(const validators_data_t<CONSTANTS> &iota, const offenders_mark_t &psi_o);
        static keys_t<CONSTANTS> _fallback_key_sequence(const entropy_t &entropy, const validators_data_t<CONSTANTS> &kappa);
        static tickets_t<CONSTANTS> _permute_tickets(const tickets_accumulator_t<CONSTANTS> &gamma_a);
        static guarantor_assignments_t _guarantor_assignments(const entropy_t &e, const time_slot_t<CONSTANTS> &slot);
    };
}
