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
        auth_queues_t<CONSTANTS> phi {}; // work authorizer queue

        // Not implemented

        // validator-selection state
        struct gamma_t {};
        // services
        struct delta_t {};
        // entropy
        struct eta_t {};
        // scheduled validators
        struct iota_t {};
        // active validators
        struct kappa_t {};
        // archive validators
        struct lambda_t {};
        // assigned work reports
        struct ro_t {};
        // most recent timeslot
        time_slot_t tau_t {};
        // validator statistics
        struct pi_t {};
        // privileged services
        struct chi_t {};
        // judgements
        struct psi_t {};
        // work reports ready to be accumulated
        struct nu_t {};
        // recently accumulated work reports
        struct ksi_t {};

        // JAM paper: Kapital upsilon
        void apply(const block_t<CONSTANTS> &blk)
        {
            // for performance this function operates on the same set
            // this means that extra care must be taken when handling errors
            // to ensure that the state after a failed apply never changes
        }

        state_t apply(const block_info_t &) const;
        bool operator==(const state_t &o) const noexcept;
    };
}