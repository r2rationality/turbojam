#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include "machine.hpp"
#include "types/s04-overview.hpp"

namespace turbo::jam {
    template<typename CONFIG>
    struct host_service_t {
        using res_t = machine::host_call_res_t;

        host_service_t(machine::machine_t &m, state_t<CONFIG> &st, service_id_t service_id, time_slot_t<CONFIG> slot);

        // General functions
        res_t gas();
        res_t lookup();
        res_t read();
        res_t write();
        res_t info();

        // Accumulate functions
        res_t bless();
        res_t assign();
        res_t designate();
        res_t checkpoint();
        res_t new_();
        res_t upgrade();
        res_t transfer();
        res_t eject();
        res_t query();
        res_t solicit();
        res_t forget();
        res_t yield();
        res_t provide();

        // Refine functions
        res_t historical_lookup();
        res_t fetch();
        res_t export_();
        res_t machine();
        res_t peek();
        res_t poke();
        res_t zero();
        res_t void_();
        res_t invoke();
        res_t expunge();
    private:
        machine::machine_t &_m;
        state_t<CONFIG> &_st;
        service_id_t _service_id;
        account_t<CONFIG> &_service;
        time_slot_t<CONFIG> _slot;
    };
}
