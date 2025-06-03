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
        std::cout << fmt::format("host::gas\n") << std::flush;
        _m.consume_gas(10);
        _m.set_reg(7, _m.gas());
        return std::monostate {};
    }

    template<typename CONFIG>
    typename host_service_t<CONFIG>::res_t host_service_t<CONFIG>::lookup()
    {
        std::cout << fmt::format("host::lookup\n") << std::flush;
        _m.consume_gas(10);
        const auto &omega = _m.regs();
        const account_t<CONFIG> *a = nullptr;
        if (omega[7] == numeric_cast<machine::register_val_t>(_service_id)
                || omega[7] == std::numeric_limits<machine::register_val_t>::max()) {
            a = &_service;
        } else {
            const auto a_it = _st.delta.find(numeric_cast<service_id_t>(omega[7]));
            if (a_it == _st.delta.end()) [[unlikely]] {
                _m.set_reg(7, machine::host_call_res_t::none);
                return std::monostate {};
            }
            a = &a_it->second;
        }
        const auto h = omega[8];
        const auto o = omega[9];
        const auto key_mem = _m.mem(h, 32);
        if (!key_mem) [[unlikely]]
            return machine::exit_panic_t {};
        const opaque_hash_t key { *key_mem };
        const auto p_it = _service.preimages.find(key);
        if (p_it == _service.preimages.end()) [[unlikely]] {
            _m.set_reg(7, machine::host_call_res_t::none);
            return std::monostate {};
        }
        const auto &val = p_it->second;
        const auto f = std::min(omega[10], val.size());
        const auto l = std::min(omega[11], val.size() - f);
        if (!_m.mem_write(o, static_cast<buffer>(val).subbuf(0, l))) [[unlikely]]
            return machine::exit_panic_t {};
        _m.set_reg(7, val.size());
        return std::monostate {};
    }

    template<typename CONFIG>
    typename host_service_t<CONFIG>::res_t host_service_t<CONFIG>::read()
    {
        std::cout << fmt::format("host::read\n") << std::flush;
        _m.consume_gas(10);
        const auto &omega = _m.regs();
        const auto s_id = omega[7] == std::numeric_limits<machine::register_val_t>::max() ? _service_id : omega[7];
        const auto a_it = _st.delta.find(s_id);
        if (a_it == _st.delta.end()) [[unlikely]] {
            _m.set_reg(7, machine::host_call_res_t::none);
            return std::monostate {};
        }
        auto &a = a_it->second;
        const auto ko = omega[8];
        const auto kz = omega[9];
        const auto o = omega[10];
        const auto key_mem = _m.mem(ko, kz);
        if (!key_mem) [[unlikely]]
            return machine::exit_panic_t {};
        encoder enc {};
        enc.uint_fixed(4, s_id);
        enc.next_bytes(*key_mem);
        const auto key = crypto::blake2b::digest<opaque_hash_t>(enc.bytes());
        const auto s_it = a.storage.find(key);
        if (s_it == a.storage.end()) [[unlikely]] {
            _m.set_reg(7, machine::host_call_res_t::none);
            return std::monostate {};
        }
        const auto &val = s_it->second;
        const auto f = std::min(omega[11], val.size());
        const auto l = std::min(omega[12], val.size() - f);
        if (!_m.mem_write(o, static_cast<buffer>(val).subbuf(0, l))) [[unlikely]]
            return machine::exit_panic_t {};
        _m.set_reg(7, val.size());
        return std::monostate {};
    }

    template<typename CONFIG>
    machine::host_call_res_t host_service_t<CONFIG>::write()
    {
        std::cout << fmt::format("host::write\n") << std::flush;
        _m.consume_gas(10);
        if (_service.info.balance >= _service.balance_threshold()) {
            const auto k_o = _m.regs()[7];
            const auto k_z = _m.regs()[8];
            const auto key_data = _m.mem(k_o, k_z);
            if (!key_data) [[unlikely]]
                return machine::exit_panic_t {};
            encoder enc {};
            enc.uint_fixed(4, _service_id);
            enc.next_bytes(*key_data);
            opaque_hash_t key_hash;
            crypto::blake2b::digest(key_hash, enc.bytes());
            std::cout << fmt::format("write key: {} size: {} hash: {}\n", key_data, key_data->size(),  key_hash) << std::flush;
            const auto v_o = _m.regs()[9];
            const auto v_z = _m.regs()[10];
            if (v_z == 0) {
                if (const auto p_it = _service.storage.find(key_hash); p_it != _service. storage.end()) {
                    _service.info.bytes -= p_it->second.size();
                    --_service.info.items;
                }
                _m.set_reg(7, machine::host_call_res_t::none);
            } else {
                const auto val_data = _m.mem(v_o, v_z);
                if (!val_data) [[unlikely]]
                    return machine::exit_panic_t {};
                std::cout << fmt::format("write data: {} size: {}\n", val_data, val_data->size()) << std::flush;
                auto [p_it, p_created] = _service.storage.try_emplace(key_hash, *val_data);
                if (!p_created) {
                    _service.info.bytes -= p_it->second.size();
                    p_it->second = byte_sequence_t { *val_data };
                } else {
                    ++_service.info.items;
                }
                _service.info.bytes += val_data->size();
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
        std::cout << fmt::format("host::info\n") << std::flush;
        _m.consume_gas(10);
        const auto &omega = _m.regs();
        const account_t<CONFIG> *t = nullptr;
        if (omega[7] == std::numeric_limits<machine::register_val_t>::max()) {
            t = &_service;
        } else {
            const auto a_it = _st.delta.find(omega[7]);
            if (a_it == _st.delta.end()) [[unlikely]] {
                _m.set_reg(7, machine::host_call_res_t::none);
                return std::monostate {};
            }
        }
        encoder enc {};
        enc.process(t->info.code_hash);
        enc.process(t->info.balance);
        // JAM 0.6.5 mentions an element t_t which is not part of the service's info - not clear what it means
        enc.process(_slot);
        enc.process(t->info.min_item_gas);
        enc.process(t->info.min_memo_gas);
        enc.process(t->info.bytes);
        enc.process(t->info.items);
        const auto o = omega[8];
        if (!_m.mem_write(o, enc.bytes())) [[unlikely]]
            return machine::exit_panic_t {};
        _m.set_reg(7, machine::host_call_res_t::ok);
        return std::monostate {};
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