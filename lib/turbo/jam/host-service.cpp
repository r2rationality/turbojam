/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <iostream>
#include "host-service.hpp"

namespace turbo::jam {
    using namespace std::string_view_literals;

    struct err_unknown_key_t: error {
        using error::error;
    };

    template<typename CONFIG>
    host_service_base_t<CONFIG>::host_service_base_t(machine::machine_t &m, state_t<CONFIG> &st, const service_id_t service_id, time_slot_t<CONFIG> slot):
        _m { m },
        _st { st },
        _service_id { service_id },
        _service { _st.delta.at(service_id) },
        _slot { std::move(slot) }
    {
    }

    template<typename CONFIG>
    typename accounts_t<CONFIG>::value_type &host_service_base_t<CONFIG>::_get_service(machine::register_val_t id)
    {
        if (id == std::numeric_limits<machine::register_val_t>::max())
            id = _service_id;
        const auto a_it = _st.delta.find(numeric_cast<service_id_t>(id));
        if (a_it == _st.delta.end()) [[unlikely]]
            throw err_bad_service_id_t {};
        return *a_it;
    }

    template<typename CONFIG>
    template<typename M>
    const typename M::mapped_type &host_service_base_t<CONFIG>::_get_value(const M &m, const typename M::key_type &key)
    {
        if (const auto p_it = m.find(key); p_it != m.end()) [[likely]]
            return p_it->second;
        throw err_unknown_key_t { fmt::format("cannot find a service with id {}", key) };
    }

    template<typename CONFIG>
    template<typename M>
    typename M::mapped_type &host_service_base_t<CONFIG>::_get_value(M &m, const typename M::key_type &key)
    {
        return const_cast<typename M::mapped_type &>(_get_value(static_cast<const M &>(m), key));
    }

    template<typename CONFIG>
    machine::host_call_res_t host_service_base_t<CONFIG>::_safe_call(const call_func &f) noexcept
    {
        try {
            f();
        } catch (const err_unknown_key_t &) {
            _m.set_reg(7, machine::host_call_res_t::none);
            return std::monostate {};
        } catch (const err_bad_service_id_t &) {
            _m.set_reg(7, machine::host_call_res_t::none);
            return std::monostate {};
        } catch (machine::exit_out_of_gas_t &ex) {
            return machine::exit_out_of_gas_t { std::move(ex) };
        } catch (machine::exit_page_fault_t &ex) {
            return machine::exit_panic_t {};
        } catch (const std::exception &ex) {
            std::cerr << fmt::format("host call failed with error: {}", ex.what());
            return machine::exit_panic_t {};
        } catch (...) {
            std::cerr << fmt::format("host call failed with unknown error");
            return machine::exit_panic_t {};
        }
        return std::monostate {};
    }

    template<typename CONFIG>
    void host_service_base_t<CONFIG>::gas()
    {
        _m.set_reg(7, _m.gas());
    }

    template<typename CONFIG>
    void host_service_base_t<CONFIG>::lookup()
    {
        const auto &omega = _m.regs();
        const auto &[s_id, a] = _get_service(omega[7]);
        const auto h = omega[8];
        const auto o = omega[9];
        const opaque_hash_t key { _m.mem_read(h, 32) };
        const auto &val = _get_value(_service.preimages, key);
        const auto f = std::min(omega[10], val.size());
        const auto l = std::min(omega[11], val.size() - f);
        _m.mem_write(o, static_cast<buffer>(val).subbuf(0, l));
        _m.set_reg(7, val.size());
    }

    template<typename CONFIG>
    void host_service_base_t<CONFIG>::read()
    {
        const auto &omega = _m.regs();
        const auto &[s_id, a] = _get_service(omega[7]);
        const auto ko = omega[8];
        const auto kz = omega[9];
        const auto o = omega[10];
        encoder enc {};
        enc.uint_fixed(4, s_id);
        enc.next_bytes(_m.mem_read(ko, kz));
        const auto key = crypto::blake2b::digest<opaque_hash_t>(enc.bytes());
        const auto &val = _get_value(a.storage, key);
        const auto f = std::min(omega[11], val.size());
        const auto l = std::min(omega[12], val.size() - f);
        _m.mem_write(o, static_cast<buffer>(val).subbuf(0, l));
        _m.set_reg(7, val.size());
    }

    template<typename CONFIG>
    void host_service_base_t<CONFIG>::write()
    {
        if (_service.info.balance >= _service.balance_threshold()) {
            const auto k_o = _m.regs()[7];
            const auto k_z = _m.regs()[8];
            const auto key_data = _m.mem_read(k_o, k_z);
            encoder enc {};
            enc.uint_fixed(4, _service_id);
            enc.next_bytes(key_data);
            opaque_hash_t key_hash;
            crypto::blake2b::digest(key_hash, enc.bytes());
            const auto v_o = _m.regs()[9];
            const auto v_z = _m.regs()[10];
            if (v_z == 0) {
                //std::cout << fmt::format("service {} write: delete key: {}\n", _service_id, key_hash) << std::flush;
                if (const auto p_it = _service.storage.find(key_hash); p_it != _service.storage.end()) {
                    _service.info.bytes -= sizeof(p_it->first);
                    _service.info.bytes -= p_it->second.size();
                    --_service.info.items;
                }
                _m.set_reg(7, machine::host_call_res_t::none);
            } else {
                auto val_data = _m.mem_read(v_o, v_z);
                //std::cout << fmt::format("service {} write: set key: {} val: {}\n", _service_id, key_hash, val_data) << std::flush;
                auto [p_it, p_created] = _service.storage.try_emplace(key_hash, val_data);
                if (!p_created) {
                    _service.info.bytes -= p_it->second.size();
                    p_it->second = byte_sequence_t { std::move(val_data) };
                } else {
                    _service.info.bytes += sizeof(p_it->first);
                    ++_service.info.items;
                }
                _service.info.bytes += v_z;
                _m.set_reg(7, v_z);
            }
            //_service.info.balance -= _service.info.min_memo_gas;
        } else {
            _m.set_reg(7, machine::host_call_res_t::full);
        }
    }

    template<typename CONFIG>
    void host_service_base_t<CONFIG>::info()
    {
        const auto &omega = _m.regs();
        const auto &[t_id, t] = _get_service(omega[7]);
        // JAM 0.6.5 mentions an element t_t which is not part of the service's info - not clear what it means
        encoder enc {
            t.info.code_hash, t.info.balance, _slot,
            t.info.min_item_gas, t.info.min_memo_gas,
            t.info.bytes, t.info.items
        };
        const auto o = omega[8];
        _m.mem_write(o, enc.bytes());
        _m.set_reg(7, machine::host_call_res_t::ok);
    }

    static std::string_view log_level_name(const machine::register_val_t level)
    {
        switch (level) {
            case 0: return "error"sv;
            case 1: return "warning"sv;
            case 2: return "info"sv;
            case 3: return "debug"sv;
            case 4: return "trace"sv;
            default: return "unknown"sv;
        }
    }

    template<typename CONFIG>
    void host_service_base_t<CONFIG>::log()
    {
        const auto &omega = _m.regs();
        const auto level = omega[7];
        std::optional<std::string> target {};
        if (omega[8] != 0 || omega[9] != 0)
            target.emplace(_m.mem_read(omega[8], omega[9]).str());
        const auto msg = _m.mem_read(omega[10], omega[11]);
        std::cout << fmt::format("[PVM/{}] [{}]: {}\n", target, log_level_name(level), msg.str()) << std::flush;
    }

    template<typename CONFIG>
    host_service_accumulate_t<CONFIG>::host_service_accumulate_t(machine::machine_t &m, state_t<CONFIG> &st, service_id_t service_id, time_slot_t<CONFIG> slot,
            accumulate::context_t<CONFIG> &ctx_ok, accumulate::context_t<CONFIG> &ctx_err):
        base_type { m, st, service_id, slot },
        _ok { ctx_ok },
        _err { ctx_err }
    {
    }

    template<typename CONFIG>
    [[nodiscard]] machine::host_call_res_t host_service_accumulate_t<CONFIG>::call(const machine::register_val_t id) noexcept
    {
        return base_type::_safe_call([&] {
            //std::cout << fmt::format("PVM: host call #{}\n", id) << std::flush;
            gas_t::base_type gas_used = 10;
            switch (id) {
                case 0: base_type::gas(); break;
                case 1: base_type::lookup(); break;
                case 2: base_type::read(); break;
                case 3: base_type::write(); break;
                case 4: base_type::info(); break;
                case 5: bless(); break;
                case 6: assign(); break;
                case 7: designate(); break;
                case 8: checkpoint(); break;
                case 9: new_(); break;
                case 10: upgrade(); break;
                case 11: transfer(); break;
                case 12: eject(); break;
                case 13: query(); break;
                case 14: solicit(); break;
                case 15: forget(); break;
                case 16: yield(); break;
                    //case ??: return provide(); break;
                case 100:
                    base_type::log();
                    gas_used = 0;
                    break;
                default:
                    base_type::_m.set_reg(7, machine::host_call_res_t::what);
                    break;
            }
            base_type::_m.consume_gas(gas_used);
        });
    }

    template<typename CONFIG>
    void host_service_accumulate_t<CONFIG>::bless()
    {
        throw machine::exit_panic_t {};
    }

    template<typename CONFIG>
    void host_service_accumulate_t<CONFIG>::assign()
    {
        throw machine::exit_panic_t {};
    }

    template<typename CONFIG>
    void host_service_accumulate_t<CONFIG>::designate()
    {
        throw machine::exit_panic_t {};
    }

    template<typename CONFIG>
    void host_service_accumulate_t<CONFIG>::checkpoint()
    {
        throw machine::exit_panic_t {};
    }

    template<typename CONFIG>
    void host_service_accumulate_t<CONFIG>::new_()
    {
        throw machine::exit_panic_t {};
    }

    template<typename CONFIG>
    void host_service_accumulate_t<CONFIG>::upgrade()
    {
        throw machine::exit_panic_t {};
    }

    template<typename CONFIG>
    void host_service_accumulate_t<CONFIG>::transfer()
    {
        throw machine::exit_panic_t {};
    }

    template<typename CONFIG>
    void host_service_accumulate_t<CONFIG>::eject()
    {
        throw machine::exit_panic_t {};
    }

    template<typename CONFIG>
    void host_service_accumulate_t<CONFIG>::query()
    {
        throw machine::exit_panic_t {};
    }

    template<typename CONFIG>
    void host_service_accumulate_t<CONFIG>::solicit()
    {
        throw machine::exit_panic_t {};
    }

    template<typename CONFIG>
    void host_service_accumulate_t<CONFIG>::forget()
    {
        throw machine::exit_panic_t {};
    }

    template<typename CONFIG>
    void host_service_accumulate_t<CONFIG>::yield()
    {
        throw machine::exit_panic_t {};
    }

    template<typename CONFIG>
    void host_service_accumulate_t<CONFIG>::provide()
    {
        throw machine::exit_panic_t {};
    }

    template<typename CONFIG>
    machine::host_call_res_t host_service_on_transfer_t<CONFIG>::call(const machine::register_val_t id) noexcept
    {
        return base_type::_safe_call([&] {
            gas_t::base_type gas_used = 10;
            switch (id) {
                case 0: base_type::gas(); break;
                case 1: base_type::lookup(); break;
                case 2: base_type::read(); break;
                case 3: base_type::write(); break;
                case 4: base_type::info(); break;
                case 100:
                    base_type::log();
                    gas_used = 0;
                    break;
                default:
                    base_type::_m.set_reg(7, machine::host_call_res_t::what);
                    break;
            }
            base_type::_m.consume_gas(gas_used);
        });
    }

    template host_service_accumulate_t<config_prod>;
    template host_service_accumulate_t<config_tiny>;

    template host_service_on_transfer_t<config_prod>;
    template host_service_on_transfer_t<config_tiny>;
}