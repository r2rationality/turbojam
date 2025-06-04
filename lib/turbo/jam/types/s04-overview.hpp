#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include "common.hpp"
#include "state-dict.hpp"

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

        bool empty() const
        {
            if (!tickets.empty())
                return false;
            if (!preimages.empty())
                return false;
            if (!guarantees.empty())
                return false;
            if (!assurances.empty())
                return false;
            if (!disputes.empty())
                return false;
            return true;
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

    // JAM (6.3) - Changed: new order k, y_z, y_s, y_a but not reflected in the tests yet
    template<typename CONSTANTS=config_prod>
    struct safrole_state_t {
        validators_data_t<CONSTANTS> k {}; // prior next epoch validator keys and metadata
        bandersnatch_ring_commitment_t z {}; // prior bandersnatch ring commitment
        tickets_or_keys_t<CONSTANTS> s; // prior sealing key series
        tickets_accumulator_t<CONSTANTS> a {}; // prior sealing key ticket accumulator

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("k"sv, k);
            archive.process("z"sv, z);
            archive.process("s"sv, s);
            archive.process("a"sv, a);
        }

        bool operator==(const safrole_state_t &o) const noexcept;
    };

    template<typename CONSTANTS>
    struct safrole_output_data_t {
        optional_t<epoch_mark_t<CONSTANTS>> epoch_mark;
        optional_t<tickets_mark_t<CONSTANTS>> tickets_mark;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("epoch_mark"sv, epoch_mark);
            archive.process("tickets_mark"sv, tickets_mark);
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
        entropy_buffer_t eta {}; // JAM (6.21)
        validators_data_t<CONSTANTS> iota {}; // next validators JAM (6.7)
        validators_data_t<CONSTANTS> kappa {}; // active validators JAM (6.7)
        validators_data_t<CONSTANTS> lambda {}; // prev validators JAM (6.7)
        availability_assignments_t<CONSTANTS> rho {}; // assigned work reports
        time_slot_t<CONSTANTS> tau {};
        auth_queues_t<CONSTANTS> phi {}; // work authorizer queue
        privileges_t chi {};
        disputes_records_t psi {}; // judgements
        statistics_t<CONSTANTS> pi {};
        ready_queue_t<CONSTANTS> nu {}; // JAM (12.3): work reports ready to be accumulated
        accumulated_queue_t<CONSTANTS> ksi {}; // JAM (12.1): recently accumulated reports

        state_t() =default;

        state_t(const state_dict_t &state_dict)
        {
            *this = state_dict;
        }

        [[nodiscard]] std::optional<std::string> diff(const state_t &o) const;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("alpha"sv, alpha);
            archive.process("beta"sv, beta);
            archive.process("gamma"sv, gamma);
            archive.process("delta"sv, delta);
            archive.process("eta"sv, eta);
            archive.process("kappa"sv, kappa);
            archive.process("lambda"sv, lambda);
            archive.process("rho"sv, rho);
            archive.process("tau"sv, tau);
            archive.process("chi"sv, chi);
            archive.process("psi"sv, psi);
            archive.process("pi"sv, pi);
            archive.process("nu"sv, nu);
            archive.process("ksi"sv, ksi);
        }

        // export & import
        state_dict_t state_dict() const;
        state_t &operator=(const state_dict_t &);

        // JAM (4.1): Kapital upsilon
        void apply(const block_t<CONSTANTS> &);
        std::exception_ptr try_apply(const block_t<CONSTANTS> &) noexcept;

        // Methods internally used by the apply and in unit tests
        // Todo: make them protected and the respective unit test classes friends?

        // JAM (4.5)
        void update_time(const time_slot_t<CONSTANTS> &slot);
        // JAM (4.6)
        void update_history_1(const state_root_t &sr);
        void update_history_2(const header_hash_t &hh, const std::optional<opaque_hash_t> &ar, const reported_work_seq_t &wp);
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
        // JAM (4.19)
        void update_auth_pools(const time_slot_t<CONSTANTS> &slot, const core_authorizers_t &cas);
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
