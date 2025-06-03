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
        host_service_t(machine::machine_t &m, state_t<CONFIG> &st, service_id_t service_id, time_slot_t<CONFIG> slot);
        [[nodiscard]] machine::host_call_res_t call(machine::register_val_t id) noexcept;
    private:
        machine::machine_t &_m;
        state_t<CONFIG> &_st;
        service_id_t _service_id;
        account_t<CONFIG> &_service;
        time_slot_t<CONFIG> _slot;

        // helper methods
        typename accounts_t<CONFIG>::value_type &_get_service(machine::register_val_t id);

        template<typename M>
        static typename M::mapped_type &_get_value(M &m, const typename M::key_type &key);

        template<typename M>
        static const typename M::mapped_type &_get_value(const M &m, const typename M::key_type &key);

        // General functions
        void gas();
        void lookup();
        void read();
        void write();
        void info();

        // Accumulate functions
        void bless();
        void assign();
        void designate();
        void checkpoint();
        void new_();
        void upgrade();
        void transfer();
        void eject();
        void query();
        void solicit();
        void forget();
        void yield();
        void provide();

        // Refine functions
        void historical_lookup();
        void fetch();
        void export_();
        void machine();
        void peek();
        void poke();
        void zero();
        void void_();
        void invoke();
        void expunge();
    };
}
