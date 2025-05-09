#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include "types/common.hpp"

namespace turbo::jam::accumulate {
    // JAM (12.13)
    template<typename CONSTANTS>
    struct mutable_state_t {
        // JAM: bold d
        accounts_t<CONSTANTS> &services;
        // JAM: bold i
        validators_data_t<CONSTANTS> &iota;
        // JAM: bold q
        auth_pools_t<CONSTANTS> &queue;
        // JAM: bold x
        privileges_t &privileges;
    };

    using deferred_transfer_metadata_t = byte_array_t<128>;

    // JAM (12.14)
    struct deferred_transfer_t {
        // JAM: s
        service_id_t source;
        // JAM: d
        service_id_t destination;
        // JAM: a
        balance_t amount;
        // JAM: m
        deferred_transfer_metadata_t metadata;
        // JAM: g
        gas_t gas_limit;
    };
    using deferred_transfers_t = sequence_t<deferred_transfer_t>;

    template<typename CONSTANTS>
    using service_code_preimages_t = map_t<service_id_t, byte_sequence_t, CONSTANTS>;

    // JAM (B.7)
    template<typename CONSTANTS>
    struct host_call_state_t {
        // JAM: s
        service_id_t service_id = 0;
        // JAM: bold u
        mutable_state_t<CONSTANTS> state;
        // JAM: i
        service_id_t i = 0;
        // JAM: bold t
        deferred_transfer_metadata_t transfers {};
        // JAM: y
        optional_t<opaque_hash_t> result {};
        // JAM: p
        service_code_preimages_t<CONSTANTS> code {};
    };
}
