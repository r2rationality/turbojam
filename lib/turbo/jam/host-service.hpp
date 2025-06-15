#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include "machine.hpp"
#include "state.hpp"

namespace turbo::jam {
    template<typename CONFIG>
    struct host_service_base_t {
        host_service_base_t(machine::machine_t &m, mutable_services_state_t<CONFIG> &services, service_id_t service_id, time_slot_t<CONFIG> slot);
    protected:
        using call_func = std::function<void()>;
        struct service_lookup_res_t {
            service_id_t id;
            mutable_service_state_t<CONFIG> &account;
        };

        machine::machine_t &_m;
        mutable_services_state_t<CONFIG> &_services;
        service_id_t _service_id;
        mutable_service_state_t<CONFIG> &_service;
        time_slot_t<CONFIG> _slot;

        // helper methods
        service_lookup_res_t _get_service(machine::register_val_t id);

        template<typename M>
        static typename M::mapped_type &_get_value(M &m, const typename M::key_type &key);

        template<typename M>
        static const typename M::mapped_type &_get_value(const M &m, const typename M::key_type &key);

        [[nodiscard]] machine::host_call_res_t _safe_call(const call_func &f) noexcept;

        // General functions
        void gas();
        void lookup();
        void read();
        void write();
        void info();
        void log();
    };

    template<typename CONFIG>
    struct host_service_accumulate_t: protected host_service_base_t<CONFIG> {
        using base_type = host_service_base_t<CONFIG>;

        host_service_accumulate_t(machine::machine_t &m, service_id_t service_id, time_slot_t<CONFIG> slot,
            accumulate_context_t<CONFIG> &ctx_ok, accumulate_context_t<CONFIG> &ctx_err);
        [[nodiscard]] machine::host_call_res_t call(machine::register_val_t id) noexcept;
    private:
        accumulate_context_t<CONFIG> &_ok;
        accumulate_context_t<CONFIG> &_err;

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
    };

    template<typename CONFIG>
    struct host_service_on_transfer_t: protected host_service_base_t<CONFIG> {
        using base_type = host_service_base_t<CONFIG>;
        using base_type::base_type;

        [[nodiscard]] machine::host_call_res_t call(machine::register_val_t id) noexcept;
    };
}
