#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include "common.hpp"

namespace turbo::jam {
    // JAM D.1
    using state_key_t = byte_array_t<31>;
    using state_key_subhash_t = byte_array_t<27>;
    using state_dict_base_t = std::map<state_key_t, byte_sequence_t>;
    struct state_dict_t: state_dict_base_t {
        using base_type = state_dict_base_t;
        using base_type::base_type;

        static state_key_t make_key(uint8_t id);
        static state_key_t make_key(uint8_t id, service_id_t service_id);
        static state_key_t make_key(service_id_t service_id, const state_key_subhash_t &subhash);
    };
}