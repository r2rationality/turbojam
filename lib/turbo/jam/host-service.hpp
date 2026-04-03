#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <utility>
#include <turbo/common/logger.hpp>
#include "machine.hpp"
#include "state.hpp"

namespace turbo::jam {
    enum class host_call_t: uint8_t {
        gas = 0,
        fetch = 1,
        lookup = 2,
        read = 3,
        write = 4,
        info = 5,

        historical_lookup = 6,
        export_ = 7,
        machine = 8,
        peek = 9,
        poke = 10,
        pages = 11,
        invoke = 12,
        expunge = 13,

        bless = 14,
        assign = 15,
        designate = 16,
        checkpoint = 17,
        new_ = 18,
        upgrade = 19,
        transfer = 20,
        eject = 21,
        query = 22,
        solicit = 23,
        forget = 24,
        yield = 25,
        provide = 26,
        log = 100
    };

    template<typename CFG>
    struct fetch_params_t {
        const work_package_t<CFG> *package = nullptr; // GP p
        const opaque_hash_t *nonce = nullptr; // GP n
        const byte_sequence_t *auth_output = nullptr; // GP r-bold
        const uint16_t *refined_item_index = nullptr;
        const sequence_t<byte_sequence_t> *imports = nullptr; // GP i-bold-dash
        const sequence_t<byte_sequence_t> *exports = nullptr; // GP x-bold-dash
        const accumulate_inputs_t<CFG> *inputs = nullptr; // GP o
        const deferred_transfers_t<CFG> *transfers = nullptr; // GP t
    };

    template<typename CFG>
    struct host_service_params_t {
        machine::machine_t &m;
        account_updates_t<CFG> &services;
        service_id_t service_id;
        time_slot_t<CFG> slot;
        fetch_params_t<CFG> fetch;
    };

    template<typename CFG>
    struct host_service_base_t {
        host_service_base_t(host_service_params_t<CFG> params);
    protected:
        struct service_lookup_res_t {
            service_id_t id;
            std::optional<service_info_t<CFG>> account;
        };

        const host_service_params_t<CFG> _p;

        // helper methods
        service_info_t<CFG> _service_info() const;
        service_lookup_res_t _get_service(machine::register_val_t id);
        template<typename F>
        [[nodiscard]] machine::host_call_res_t _safe_call(F &&f) noexcept
        {
            try {
                f();
            } catch (const err_bad_service_id_t &) {
                _p.m.set_reg(7, machine::host_call_res_t::none);
                return std::monostate {};
            } catch (machine::exit_out_of_gas_t &ex) {
                return machine::exit_out_of_gas_t { std::move(ex) };
            } catch (const machine::exit_page_fault_t &) {
                return machine::exit_panic_t {};
            } catch (const std::exception &ex) {
                logger::error("host call failed with error: {}", ex.what());
                return machine::exit_panic_t {};
            } catch (...) {
                logger::error("host call failed with unknown error");
                return machine::exit_panic_t {};
            }
            return std::monostate {};
        }

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
    struct host_service_is_authorized_t: host_service_base_t<CFG> {
        using base_type = host_service_base_t<CFG>;
        using base_type::base_type;

        host_service_is_authorized_t(host_service_params_t<CFG> params);
        [[nodiscard]] machine::host_call_res_t call(machine::register_val_t id) noexcept;
    };

    template<typename CFG>
    struct host_service_refine_t: host_service_base_t<CFG> {
        using base_type = host_service_base_t<CFG>;
        using base_type::base_type;

        host_service_refine_t(host_service_params_t<CFG> params);
        [[nodiscard]] machine::host_call_res_t call(machine::register_val_t id) noexcept;
    };

    template<typename CFG>
    struct host_service_accumulate_t: protected host_service_base_t<CFG> {
        using base_type = host_service_base_t<CFG>;

        host_service_accumulate_t(host_service_params_t<CFG> params,
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
}
