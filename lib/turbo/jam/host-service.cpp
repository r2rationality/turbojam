/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/logger.hpp>
#include "host-service.hpp"

namespace turbo::jam {
    using namespace std::string_view_literals;

    struct err_unknown_key_t: error {
        using error::error;
    };

    template<typename CFG>
    static mutable_service_state_t<CFG> make_mutable_service(account_t<CFG> &service)
    {
        return {
            container::std_map_update_api_t { service.storage },
            container::std_map_update_api_t { service.preimages },
            container::std_map_update_api_t { service.lookup_metas },
            service_info_update_t { service.info }
        };
    }

    template<typename CFG>
    host_service_base_t<CFG>::host_service_base_t(machine::machine_t &m, mutable_services_state_t<CFG> &services, const service_id_t service_id, const time_slot_t<CFG> slot):
        _m { m },
        _services { services },
        _service_id { service_id },
        _service { _services.get_mutable(service_id) },
        _slot { std::move(slot) }
    {
    }

    template<typename CFG>
    machine::host_call_res_t host_service_base_t<CFG>::call(const machine::register_val_t id) noexcept
    {
        return _safe_call([&] {
            _call(id);
        });
    }

    template<typename CFG>
    void host_service_base_t<CFG>::_call(const machine::register_val_t id)
    {
        gas_t::base_type gas_used = 10;
        switch (id) {
            case 0: gas(); break;
            case 1: lookup(); break;
            case 2: read(); break;
            case 3: write(); break;
            case 4: info(); break;
            case 18: fetch(); break;
            case 100:
                log();
                gas_used = 0;
                break;
            default:
                _m.set_reg(7, machine::host_call_res_t::what);
                break;
        }
        _m.consume_gas(gas_used);
    }

    template<typename CFG>
    typename host_service_base_t<CFG>::service_lookup_res_t host_service_base_t<CFG>::_get_service(machine::register_val_t id)
    {
        if (id == std::numeric_limits<machine::register_val_t>::max())
            id = _service_id;
        return { numeric_cast<service_id_t>(id), _services.get_mutable_ptr(id) };
    }

    template<typename CFG>
    machine::host_call_res_t host_service_base_t<CFG>::_safe_call(const call_func &f) noexcept
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
            logger::error("host call failed with error: {}", ex.what());
            return machine::exit_panic_t {};
        } catch (...) {
            logger::error("host call failed with unknown error");
            return machine::exit_panic_t {};
        }
        return std::monostate {};
    }

    template<typename CFG>
    void host_service_base_t<CFG>::gas()
    {
        _m.set_reg(7, _m.gas());
    }

    template<typename CFG>
    void host_service_base_t<CFG>::fetch()
    {
        const auto &omega = _m.regs();
        std::optional<uint8_vector> v {};
        switch (omega[10]) {
            case 0: {
                encoder enc {};
                enc.uint_fixed(8, CFG::min_balance_per_item);
                enc.uint_fixed(8, CFG::min_balance_per_octet);
                enc.uint_fixed(8, CFG::min_balance_per_service);
                enc.uint_fixed(2, CFG::core_count);
                enc.uint_fixed(4, CFG::preimage_expunge_delay);
                enc.uint_fixed(4, CFG::epoch_length);
                enc.uint_fixed(8, CFG::max_accumulate_gas);
                enc.uint_fixed(8, CFG::max_is_authorized_gas);
                enc.uint_fixed(8, CFG::max_refine_gas);
                enc.uint_fixed(8, CFG::max_total_accumulation_gas);
                enc.uint_fixed(2, CFG::max_blocks_history);
                enc.uint_fixed(2, CFG::max_work_items);
                enc.uint_fixed(2, CFG::max_report_dependencies);
                enc.uint_fixed(4, CFG::max_lookup_anchor_age);
                enc.uint_fixed(2, CFG::auth_pool_max_size);
                enc.uint_fixed(2, CFG::slot_period);
                enc.uint_fixed(2, CFG::auth_queue_size);
                enc.uint_fixed(2, CFG::core_assignment_rotation_period);
                enc.uint_fixed(2, CFG::accumulation_queue_size);
                enc.uint_fixed(2, CFG::max_package_extrinsics);
                enc.uint_fixed(2, CFG::reported_work_timeout);
                enc.uint_fixed(2, CFG::validator_count);
                enc.uint_fixed(4, CFG::max_is_authorized_code_size);
                enc.uint_fixed(4, CFG::max_work_package_size);
                enc.uint_fixed(4, CFG::max_service_code_size);
                enc.uint_fixed(4, CFG::segment_piece_size);
                enc.uint_fixed(4, CFG::segment_size);
                enc.uint_fixed(4, CFG::max_work_package_imports);
                enc.uint_fixed(4, CFG::segment_num_pieces);
                enc.uint_fixed(4, CFG::max_blobs_size);
                enc.uint_fixed(4, CFG::transfer_memo_size);
                enc.uint_fixed(4, CFG::max_package_exports);
                enc.uint_fixed(4, CFG::ticket_submission_end);
                v.emplace(std::move(enc.bytes()));
                break;
            }
            case 13: {
                break;
            }
            default:
                break;
        }
        if (v) {
            const auto o = omega[7];
            const auto f = std::min(omega[8], v->size());
            const auto l = std::min(omega[9], v->size() - f);
            _m.mem_write(o, static_cast<buffer>(*v).subbuf(0, l));
            _m.set_reg(7, v->size());
        } else {
            _m.set_reg(7, machine::host_call_res_t::none);
        }
    }

    template<typename CFG>
    void host_service_base_t<CFG>::lookup()
    {
        const auto &omega = _m.regs();
        const auto [s_id, a] = _get_service(omega[7]);
        const auto h = omega[8];
        const auto o = omega[9];
        const opaque_hash_t key { _m.mem_read(h, 32) };
        std::optional<write_vector> val {};
        if (a)
            val = a->preimages.get(key);
        if (val) {
            const auto f = std::min(omega[10], val->size());
            const auto l = std::min(omega[11], val->size() - f);
            _m.mem_write(o, static_cast<buffer>(*val).subbuf(0, l));
            _m.set_reg(7, val->size());
        } else {
            _m.set_reg(7, machine::host_call_res_t::none);
        }
    }

    template<typename CFG>
    void host_service_base_t<CFG>::read() {
        const auto &omega = _m.regs();
        const auto [s_id, a] = _get_service(omega[7]);
        const auto ko = omega[8];
        const auto kz = omega[9];
        const auto o = omega[10];
        encoder enc {};
        enc.uint_fixed(4, s_id);
        enc.next_bytes(_m.mem_read(ko, kz));
        std::optional<write_vector> val {};
        if (a) {
            const auto key = crypto::blake2b::digest<opaque_hash_t>(enc.bytes());
            val = a->storage.get(key);
        }
        if (val) {
            const auto f = std::min(omega[11], val->size());
            const auto l = std::min(omega[12], val->size() - f);
            _m.mem_write(o, static_cast<buffer>(*val).subbuf(0, l));
            _m.set_reg(7, val->size());
        } else {
            _m.set_reg(7, machine::host_call_res_t::none);
        }
    }

    template<typename CFG>
    void host_service_base_t<CFG>::write()
    {
        const auto k_o = _m.regs()[7];
        const auto k_z = _m.regs()[8];
        const auto key_data = _m.mem_read(k_o, k_z);
        encoder enc {};
        enc.uint_fixed(4, _service_id);
        enc.next_bytes(key_data);
        const auto key_hash = crypto::blake2b::digest<opaque_hash_t>(enc.bytes());
        const auto v_o = _m.regs()[9];
        const auto v_z = _m.regs()[10];
        const auto prev_val = _service.storage.get(key_hash);
        const auto balance_threshold = account_balance_threshold(_service.lookup_metas, _service.storage);
        if (_service.info.base.get().balance >= balance_threshold) {
            if (v_z == 0) {
                logger::trace("service {} write: delete key: {}", _service_id, key_data);
                if (prev_val) {
                    // move the stats update into the erase method?
                    _service.info.bytes -= sizeof(key_hash);
                    _service.info.bytes -= prev_val->size();
                    --_service.info.items;
                    _service.storage.erase(key_hash);
                }
            } else {
                auto val_data = _m.mem_read(v_o, v_z);
                logger::trace("service {} write: set key: {} hash: {} val: {}", _service_id, key_data, key_hash, val_data);
                if (prev_val) {
                    _service.info.bytes -= prev_val->size();
                } else {
                    _service.info.bytes += sizeof(key_hash);
                    ++_service.info.items;
                }
                _service.storage.set(key_hash, static_cast<buffer>(val_data));
                _service.info.bytes += v_z;
            }
            const machine::register_val_t l = prev_val ? prev_val->size() : machine::host_call_res_t::none;
            _m.set_reg(7, l);
        } else {
            _m.set_reg(7, machine::host_call_res_t::full);
        }
    }

    template<typename CFG>
    void host_service_base_t<CFG>::info()
    {
        const auto &omega = _m.regs();
        const auto [t_id, t] = _get_service(omega[7]);
        std::optional<uint8_vector> m {};
        if (t) {
            auto info = t->info.combine();
            // JAM 0.6.5 mentions an element t_t which is not part of the service's info - not clear what it means
            encoder enc {
                info.code_hash, info.balance, _slot,
                info.min_item_gas, info.min_memo_gas,
                info.bytes, info.items
            };
            m.emplace(std::move(enc.bytes()));
        }
        if (m) {
            const auto o = omega[8];
            _m.mem_write(o, *m);
            _m.set_reg(7, machine::host_call_res_t::ok);
        } else {
            _m.set_reg(7, machine::host_call_res_t::none);
        }
    }

    static logger::level log_level(const machine::register_val_t level)
    {
        switch (level) {
            case 0: return logger::level::err;
            case 1: return logger::level::warn;
            case 2: return logger::level::info;
            case 3: return logger::level::debug;
            case 4: return logger::level::trace;
            default: return logger::level::warn;
        }
    }

    template<typename CFG>
    void host_service_base_t<CFG>::log()
    {
        const auto &omega = _m.regs();
        const auto level = omega[7];
        std::optional<std::string> target {};
        if (omega[8] != 0 || omega[9] != 0)
            target.emplace(_m.mem_read(omega[8], omega[9]).str());
        const auto msg = _m.mem_read(omega[10], omega[11]);
        logger::log(log_level(level), "[PVM/{}]: {}", target, msg.str());
    }

    template<typename CFG>
    host_service_accumulate_t<CFG>::host_service_accumulate_t(machine::machine_t &m, service_id_t service_id, time_slot_t<CFG> slot,
            accumulate_context_t<CFG> &ctx_ok, accumulate_context_t<CFG> &ctx_err):
        base_type { m, ctx_ok.state.services, service_id, slot },
        _ok { ctx_ok },
        _err { ctx_err }
    {
    }

    template<typename CFG>
    [[nodiscard]] machine::host_call_res_t host_service_accumulate_t<CFG>::call(const machine::register_val_t id) noexcept
    {
        return base_type::_safe_call([&] {
            logger::trace("PVM: host call #{}", id);
            gas_t::base_type gas_used = 10;
            switch (id) {
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
                    base_type::_call(id);
                    // the gas has been adjusted in the base_type::call
                    gas_used = 0;
                    break;
            }
            base_type::_m.consume_gas(gas_used);
        });
    }

    template<typename CFG>
    void host_service_accumulate_t<CFG>::bless()
    {
        if (base_type::_service_id != _ok.state.chi.bless)
            throw machine::exit_panic_t {};
        const auto &omega = base_type::_m.regs();
        const auto m = omega[7];
        const auto a = omega[8];
        const auto v = omega[9];
        const auto o = omega[10];
        const auto n = omega[11];

        free_services_t fs {};
        for (size_t i = 0; i < n; ++i) {
            const auto bytes = base_type::_m.mem_read(o + i * 12, 12);
            decoder dec { bytes };
            const auto s = dec.uint_fixed<service_id_t>(4);
            const gas_t g { dec.uint_fixed<gas_t::base_type>(8) };
            fs.emplace_back(s, g);
        }

        if (std::max(std::max(m, a), v) <= std::numeric_limits<service_id_t>::max()) {
            _ok.state.chi = {
                static_cast<service_id_t>(m),
                static_cast<service_id_t>(a),
                static_cast<service_id_t>(v),
                std::move(fs)
            };
            base_type::_m.set_reg(7, machine::host_call_res_t::ok);
        } else {
            base_type::_m.set_reg(7, machine::host_call_res_t::who);
        }
    }

    template<typename CFG>
    void host_service_accumulate_t<CFG>::assign()
    {
        if (base_type::_service_id != _ok.state.chi.assign)
            throw machine::exit_panic_t {};
        const auto &omega = base_type::_m.regs();
        const auto o = omega[8];
        auth_queue_t<CFG> v;
        for (size_t i = 0; i < CFG::auth_queue_size; ++i) {
            v[i] = static_cast<buffer>(base_type::_m.mem_read(o + i * 32, 32));
        }
        if (const auto c = omega[7]; c < CFG::core_count) {
            _ok.state.phi[c] = std::move(v);
            base_type::_m.set_reg(7, machine::host_call_res_t::ok);
        } else {
            base_type::_m.set_reg(7, machine::host_call_res_t::core);
        }
    }

    template<typename CFG>
    void host_service_accumulate_t<CFG>::designate()
    {
        if (base_type::_service_id != _ok.state.chi.designate)
            throw machine::exit_panic_t {};
        const auto &omega = base_type::_m.regs();
        const auto o = omega[7];
        validators_data_t<CFG> v;
        for (size_t i = 0; i < v.size(); ++i) {
            decoder dec { base_type::_m.mem_read(o + i * 336, 336) };
            dec.process(v[i]);
        }
        _ok.state.iota.emplace(std::move(v));
        base_type::_m.set_reg(7, machine::host_call_res_t::ok);
    }

    template<typename CFG>
    void host_service_accumulate_t<CFG>::checkpoint()
    {
        _err = _ok;
        base_type::_m.set_reg(7, base_type::_m.gas());
    }

    template<typename CFG>
    void host_service_accumulate_t<CFG>::new_()
    {
        throw machine::exit_panic_t {};
    }

    template<typename CFG>
    void host_service_accumulate_t<CFG>::upgrade()
    {
        throw machine::exit_panic_t {};
    }

    template<typename CFG>
    void host_service_accumulate_t<CFG>::transfer()
    {
        throw machine::exit_panic_t {};
    }

    template<typename CFG>
    void host_service_accumulate_t<CFG>::eject()
    {
        throw machine::exit_panic_t {};
    }

    template<typename CFG>
    void host_service_accumulate_t<CFG>::query()
    {
        throw machine::exit_panic_t {};
    }

    template<typename CFG>
    void host_service_accumulate_t<CFG>::solicit()
    {
        throw machine::exit_panic_t {};
    }

    template<typename CFG>
    void host_service_accumulate_t<CFG>::forget()
    {
        throw machine::exit_panic_t {};
    }

    template<typename CFG>
    void host_service_accumulate_t<CFG>::yield()
    {
        throw machine::exit_panic_t {};
    }

    template<typename CFG>
    void host_service_accumulate_t<CFG>::provide()
    {
        throw machine::exit_panic_t {};
    }

    template struct host_service_base_t<config_prod>;
    template struct host_service_base_t<config_tiny>;

    template struct host_service_accumulate_t<config_prod>;
    template struct host_service_accumulate_t<config_tiny>;
}