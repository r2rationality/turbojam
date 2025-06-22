#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include "machine.hpp"
#include "state.hpp"

namespace turbo::jam {
    template<typename CFG>
    struct fetch_params_t {
        const work_package_t<CFG> *package = nullptr; // GP p
        const opaque_hash_t *nonce = nullptr; // GP n
        // r - ?
        // i - ?
        // i-bold-dash - ?
        // x-bold-dash - ?
        const accumulate_operands_t *operands = nullptr; // GP o
        const deferred_transfers_t *transfers = nullptr; // GP t
    };

    template<typename CFG>
    struct host_service_params_t {
        machine::machine_t &m;
        mutable_services_state_t<CFG> &services;
        service_id_t service_id;
        time_slot_t<CFG> slot;
        fetch_params_t<CFG> fetch;
    };

    template<typename CFG>
    struct host_service_base_t {
        host_service_base_t(const host_service_params_t<CFG> &params);
    protected:
        using call_func = std::function<void()>;
        struct service_lookup_res_t {
            service_id_t id;
            mutable_service_state_t<CFG> *account;
        };

        const host_service_params_t<CFG> &_p;
        mutable_service_state_t<CFG> &_service;

        // helper methods
        service_lookup_res_t _get_service(machine::register_val_t id);
        [[nodiscard]] machine::host_call_res_t _safe_call(const call_func &f) noexcept;

        // General functions
        void gas();
        void fetch();
        void lookup();
        void read();
        void write();
        void info();
        void log();
    };

    template<typename CFG>
    struct host_service_accumulate_t: protected host_service_base_t<CFG> {
        using base_type = host_service_base_t<CFG>;

        host_service_accumulate_t(const host_service_params_t<CFG> &params,
            accumulate_context_t<CFG> &ctx_ok, accumulate_context_t<CFG> &ctx_err);
        [[nodiscard]] machine::host_call_res_t call(machine::register_val_t id) noexcept;
    private:
        accumulate_context_t<CFG> &_ok;
        accumulate_context_t<CFG> &_err;

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

    template<typename CFG>
    struct host_service_on_transfer_t: host_service_base_t<CFG> {
        using base_type = host_service_base_t<CFG>;
        using base_type::base_type;

        [[nodiscard]] machine::host_call_res_t call(machine::register_val_t id) noexcept;
    };
}
