#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include "types.hpp"

namespace turbo::jam {
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

    struct reports_output_data_t {
        reported_work_seq_t reported;
        sequence_t<ed25519_public_t> reporters;

        static reports_output_data_t from_bytes(decoder &dec)
        {
            return {
                dec.decode<decltype(reported)>(),
                dec.decode<decltype(reporters)>()
            };
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

    // lower-case sigma in terms of the JAM paper
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
        ready_queue_t<CONSTANTS> nu {}; // work reports ready to be accumulated
        accumulated_queue_t<CONSTANTS> ksi {}; // recently accumulated reports
        statistics_t<CONSTANTS> pi {};
        availability_assignments_t<CONSTANTS> ro {}; // assigned work reports
        time_slot_t<CONSTANTS> tau {};
        auth_queues_t<CONSTANTS> phi {}; // work authorizer queue
        privileges_t chi {};
        sequence_t<ed25519_public_t> psi_o_post {}; // offenders posterior

        // Not implemented
        struct psi_t {}; // judgements

        safrole_output_data_t<CONSTANTS> update_safrole(const time_slot_t<CONSTANTS> &slot, const entropy_t &entropy, const tickets_extrinsic_t<CONSTANTS> &extrinsic);
        reports_output_data_t update_reports(const time_slot_t<CONSTANTS> &slot, const guarantees_extrinsic_t<CONSTANTS> &guarantees);
        void update_statistics(const time_slot_t<CONSTANTS> &slot, validator_index_t val_idx, const extrinsic_t<CONSTANTS> &extrinsic);
        accumulate_root_t accumulate(const time_slot_t<CONSTANTS> &slot, const work_reports_t<CONSTANTS> &reports);

        // JAM paper: Kapital upsilon
        void apply(const block_t<CONSTANTS> &)
        {
            // for performance this function operates on the same set
            // this means that extra care must be taken when handling errors
            // to ensure that the state after a failed apply never changes
        }

        state_t apply(const block_info_t &) const;
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