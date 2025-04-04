#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include "types.hpp"

namespace turbo::jam {

    // lower-case sigma in terms of the JAM paper
    template<typename CONSTANTS=config_prod>
    struct state_t {
        auth_pools_t<CONSTANTS> alpha {}; // authorizations
        blocks_history_t<CONSTANTS> beta {}; // most recent blocks
        tickets_accumulator_t<CONSTANTS> gamma_a {}; // prior sealing key ticket accumulator
        validators_data_t<CONSTANTS> gamma_k {}; // prior next epoch validator keys and metadata
        tickets_or_keys_t<CONSTANTS> gamma_s {}; // prior sealing key series
        bandersnatch_ring_commitment_t gamma_z {}; // prior bandersnatch ring commitment
        accounts_t<CONSTANTS> delta {}; // services
        entropy_buffer_t eta {};
        validators_data_t<CONSTANTS> iota {}; // next validators
        validators_data_t<CONSTANTS> kappa {}; // active validators
        validators_data_t<CONSTANTS> lambda {}; // prev validators
        statistics_t<CONSTANTS> pi;
        availability_assignments_t<CONSTANTS> ro {}; // assigned work reports
        time_slot_t<CONSTANTS> tau;
        auth_queues_t<CONSTANTS> phi {}; // work authorizer queue
        sequence_t<ed25519_public_t> psi_o_post {}; // offenders posterio

        // Not implemented

        struct gamma_t {}; // validator-selection state
        struct chi_t {}; // privileged services
        struct psi_t {}; // judgements
        struct nu_t {}; // work reports ready to be accumulated
        struct ksi_t {}; // recently accumulated work reports

        void update_statistics(const time_slot_t<CONSTANTS> &slot, validator_index_t val_idx, const extrinsic_t<CONSTANTS> &extrinsic);

        // JAM paper: Kapital upsilon
        void apply(const block_t<CONSTANTS> &)
        {
            // for performance this function operates on the same set
            // this means that extra care must be taken when handling errors
            // to ensure that the state after a failed apply never changes
        }

        state_t apply(const block_info_t &) const;
        bool operator==(const state_t &o) const noexcept;
    };
}