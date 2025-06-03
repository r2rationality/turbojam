/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <iostream>
#include "host-service.hpp"

namespace turbo::jam {
    template<typename CONFIG>
    host_service_t<CONFIG>::host_service_t(machine::machine_t &m, state_t<CONFIG> &st, const service_id_t service_id, time_slot_t<CONFIG> slot):
        _m { m },
        _st { st },
        _service_id { service_id },
        _service { _st.delta.at(service_id) },
        _slot { std::move(slot) }
    {
    }

    template<typename CONFIG>
    machine::host_call_res_t host_service_t<CONFIG>::gas()
    {
        _m.consume_gas(10);
        _m.set_reg(7, _m.gas());
        return std::monostate {};
    }

    template<typename CONFIG>
    typename host_service_t<CONFIG>::res_t host_service_t<CONFIG>::lookup()
    {
        return machine::exit_panic_t {};
    }

    template<typename CONFIG>
    typename host_service_t<CONFIG>::res_t host_service_t<CONFIG>::read()
    {
        return machine::exit_panic_t {};
    }

    template<typename CONFIG>
    machine::host_call_res_t host_service_t<CONFIG>::write()
    {
        if (_service.info.balance >= _service.balance_threshold()) {
            const auto k_o = _m.regs()[7];
            const auto k_z = _m.regs()[8];
            const auto key_data = _m.mem(k_o, k_z);
            if (!key_data) [[unlikely]]
                return machine::exit_panic_t {};
            encoder enc {};
            enc.uint_fixed(4, _service_id);
            enc.bytes() << *key_data;
            opaque_hash_t key_hash;
            crypto::blake2b::digest(key_hash, enc.bytes());
            std::cout << fmt::format("write key: {} size: {} hash: {}\n", key_data, key_data->size(),  key_hash) << std::flush;
            const auto v_o = _m.regs()[9];
            const auto v_z = _m.regs()[10];
            if (v_z == 0) {
                _service.erase(_slot, key_hash, k_z);
                _m.set_reg(7, machine::host_call_res_t::none);
            } else {
                const auto val_data = _m.mem(v_o, v_z);
                if (!val_data) [[unlikely]]
                    return machine::exit_panic_t {};
                std::cout << fmt::format("write data: {} size: {}\n", val_data, val_data->size()) << std::flush;
                _service.insert(_slot, key_hash, k_z, *val_data);
                _m.set_reg(7, v_z);
            }
            _service.info.balance -= _service.info.min_memo_gas;
        } else {
            _m.set_reg(7, machine::host_call_res_t::full);
        }
        _m.consume_gas(10);
        return std::monostate {};
    }

    template<typename CONFIG>
    typename host_service_t<CONFIG>::res_t host_service_t<CONFIG>::info()
    {
        return machine::exit_panic_t {};
    }

    template<typename CONFIG>
    typename host_service_t<CONFIG>::res_t host_service_t<CONFIG>::bless()
    {
        return machine::exit_panic_t {};
    }

    template<typename CONFIG>
    typename host_service_t<CONFIG>::res_t host_service_t<CONFIG>::assign()
    {
        return machine::exit_panic_t {};
    }

    template<typename CONFIG>
    typename host_service_t<CONFIG>::res_t host_service_t<CONFIG>::designate()
    {
        return machine::exit_panic_t {};
    }

    template<typename CONFIG>
    typename host_service_t<CONFIG>::res_t host_service_t<CONFIG>::checkpoint()
    {
        return machine::exit_panic_t {};
    }

    template<typename CONFIG>
    typename host_service_t<CONFIG>::res_t host_service_t<CONFIG>::new_()
    {
        return machine::exit_panic_t {};
    }

    template<typename CONFIG>
    typename host_service_t<CONFIG>::res_t host_service_t<CONFIG>::upgrade()
    {
        return machine::exit_panic_t {};
    }

    template<typename CONFIG>
    typename host_service_t<CONFIG>::res_t host_service_t<CONFIG>::transfer()
    {
        return machine::exit_panic_t {};
    }

    template<typename CONFIG>
    typename host_service_t<CONFIG>::res_t host_service_t<CONFIG>::eject()
    {
        return machine::exit_panic_t {};
    }

    template<typename CONFIG>
    typename host_service_t<CONFIG>::res_t host_service_t<CONFIG>::query()
    {
        return machine::exit_panic_t {};
    }

    template<typename CONFIG>
    typename host_service_t<CONFIG>::res_t host_service_t<CONFIG>::solicit()
    {
        return machine::exit_panic_t {};
    }

    template<typename CONFIG>
    typename host_service_t<CONFIG>::res_t host_service_t<CONFIG>::forget()
    {
        return machine::exit_panic_t {};
    }

    template<typename CONFIG>
    typename host_service_t<CONFIG>::res_t host_service_t<CONFIG>::yield()
    {
        return machine::exit_panic_t {};
    }

    template<typename CONFIG>
    typename host_service_t<CONFIG>::res_t host_service_t<CONFIG>::provide()
    {
        return machine::exit_panic_t {};
    }

    template<typename CONFIG>
    typename host_service_t<CONFIG>::res_t host_service_t<CONFIG>::historical_lookup()
    {
        return machine::exit_panic_t {};
    }

    template<typename CONFIG>
    typename host_service_t<CONFIG>::res_t host_service_t<CONFIG>::fetch()
    {
        return machine::exit_panic_t {};
    }

    template<typename CONFIG>
    typename host_service_t<CONFIG>::res_t host_service_t<CONFIG>::export_()
    {
        return machine::exit_panic_t {};
    }

    template<typename CONFIG>
    typename host_service_t<CONFIG>::res_t host_service_t<CONFIG>::machine()
    {
        return machine::exit_panic_t {};
    }

    template<typename CONFIG>
    typename host_service_t<CONFIG>::res_t host_service_t<CONFIG>::peek()
    {
        return machine::exit_panic_t {};
    }

    template<typename CONFIG>
    typename host_service_t<CONFIG>::res_t host_service_t<CONFIG>::poke()
    {
        return machine::exit_panic_t {};
    }

    template<typename CONFIG>
    typename host_service_t<CONFIG>::res_t host_service_t<CONFIG>::zero()
    {
        return machine::exit_panic_t {};
    }

    template<typename CONFIG>
    typename host_service_t<CONFIG>::res_t host_service_t<CONFIG>::void_()
    {
        return machine::exit_panic_t {};
    }

    template<typename CONFIG>
    typename host_service_t<CONFIG>::res_t host_service_t<CONFIG>::invoke()
    {
        return machine::exit_panic_t {};
    }

    template<typename CONFIG>
    typename host_service_t<CONFIG>::res_t host_service_t<CONFIG>::expunge()
    {
        return machine::exit_panic_t {};
    }

    template host_service_t<config_prod>;
    template host_service_t<config_tiny>;
}