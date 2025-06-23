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
    host_service_base_t<CFG>::host_service_base_t(const host_service_params_t<CFG> &params):
        _p { params },
        _service { _p.services.get_mutable(_p.service_id) }
    {
    }

    template<typename CFG>
    machine::host_call_res_t host_service_on_transfer_t<CFG>::call(const machine::register_val_t id) noexcept
    {
        return this->_safe_call([&] {
            logger::trace("PVM: host call #{}", id);
            gas_t::base_type gas_used = 10;
            switch (id) {
                case 0: base_type::gas(); break;
                case 1: base_type::lookup(); break;
                case 2: base_type::read(); break;
                case 3: base_type::write(); break;
                case 4: base_type::info(); break;
                case 18: base_type::fetch(); break;
                default:
                    this->_p.m.set_reg(7, machine::host_call_res_t::what);
                    break;
            }
            this->_p.m.consume_gas(gas_used);
        });
    }

    template<typename CFG>
    machine::host_call_res_t host_service_is_authorized_t<CFG>::call(const machine::register_val_t id) noexcept
    {
        return this->_safe_call([&] {
            logger::trace("PVM: host call #{}", id);
            gas_t::base_type gas_used = 10;
            switch (id) {
                case 0: base_type::gas(); break;
                case 18: base_type::fetch(); break;
                default:
                    this->_p.m.set_reg(7, machine::host_call_res_t::what);
                    break;
            }
            this->_p.m.consume_gas(gas_used);
        });
    }

    template<typename CFG>
    [[nodiscard]] machine::host_call_res_t host_service_refine_t<CFG>::call(const machine::register_val_t id) noexcept
    {
        return this->_safe_call([&] {
            logger::trace("PVM: host call #{}", id);
            gas_t::base_type gas_used = 10;
            switch (id) {
                // generic
                case 0: base_type::gas(); break;
                case 1: base_type::lookup(); break;
                case 2: base_type::read(); break;
                case 3: base_type::write(); break;
                case 4: base_type::info(); break;
                case 18: base_type::fetch(); break;
                // refine-specific
                /*case 5: bless(); break;
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
                case 16: yield(); break;*/
                //case ??: return provide(); break;
                case 100:
                    base_type::log();
                    gas_used = 0;
                    break;
                default:
                    this->_p.m.set_reg(7, machine::host_call_res_t::what);
                    break;
            }
            this->_p.m.consume_gas(gas_used);
        });
    }

    template<typename CFG>
    typename host_service_base_t<CFG>::service_lookup_res_t host_service_base_t<CFG>::_get_service(machine::register_val_t id)
    {
        if (id == std::numeric_limits<machine::register_val_t>::max())
            id = _p.service_id;
        return { numeric_cast<service_id_t>(id), _p.services.get_mutable_ptr(id) };
    }

    template<typename CFG>
    machine::host_call_res_t host_service_base_t<CFG>::_safe_call(const call_func &f) noexcept
    {
        try {
            f();
        } catch (const err_unknown_key_t &) {
            _p.m.set_reg(7, machine::host_call_res_t::none);
            return std::monostate {};
        } catch (const err_bad_service_id_t &) {
            _p.m.set_reg(7, machine::host_call_res_t::none);
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
        _p.m.set_reg(7, _p.m.gas());
    }

    template<typename CFG>
    void host_service_base_t<CFG>::fetch()
    {
        const auto &omega = _p.m.regs();
        logger::trace("host_service::fetch {}", omega[10]);
        std::optional<uint8_vector> v {};
        switch (omega[10]) {
            case 0: {
                encoder enc {};
                enc.uint_fixed(8, CFG::BI_min_balance_per_item);
                enc.uint_fixed(8, CFG::BL_min_balance_per_octet);
                enc.uint_fixed(8, CFG::BS_min_balance_per_service);
                enc.uint_fixed(2, CFG::C_core_count);
                enc.uint_fixed(4, CFG::D_preimage_expunge_delay);
                enc.uint_fixed(4, CFG::E_epoch_length);
                enc.uint_fixed(8, CFG::GA_max_accumulate_gas);
                enc.uint_fixed(8, CFG::GI_max_is_authorized_gas);
                enc.uint_fixed(8, CFG::GR_max_refine_gas);
                enc.uint_fixed(8, CFG::GT_max_total_accumulation_gas);
                enc.uint_fixed(2, CFG::H_max_blocks_history);
                enc.uint_fixed(2, CFG::I_max_work_items);
                enc.uint_fixed(2, CFG::J_max_report_dependencies);
                enc.uint_fixed(2, CFG::K_max_tickets_per_block);
                enc.uint_fixed(4, CFG::L_max_lookup_anchor_age);
                enc.uint_fixed(2, CFG::N_ticket_attempts);
                enc.uint_fixed(2, CFG::O_auth_pool_max_size);
                enc.uint_fixed(2, CFG::P_slot_period);
                enc.uint_fixed(2, CFG::Q_auth_queue_size);
                enc.uint_fixed(2, CFG::R_core_assignment_rotation_period);
                enc.uint_fixed(2, CFG::T_max_package_extrinsics);
                enc.uint_fixed(2, CFG::U_reported_work_timeout);
                enc.uint_fixed(2, CFG::V_validator_count);
                enc.uint_fixed(4, CFG::WA_max_is_authorized_code_size);
                enc.uint_fixed(4, CFG::WB_max_work_package_size);
                enc.uint_fixed(4, CFG::WC_max_service_code_size);
                enc.uint_fixed(4, CFG::WE_segment_piece_size);
                enc.uint_fixed(4, CFG::WM_max_work_package_imports);
                enc.uint_fixed(4, CFG::WP_segment_num_pieces);
                enc.uint_fixed(4, CFG::WR_max_blobs_size);
                enc.uint_fixed(4, CFG::WT_transfer_memo_size);
                enc.uint_fixed(4, CFG::WX_max_package_exports);
                enc.uint_fixed(4, CFG::Y_ticket_submission_end);
                v.emplace(std::move(enc.bytes()));
                break;
            }
            case 1:
                if (_p.fetch.nonce)
                    v.emplace(*_p.fetch.nonce);
                break;
            case 7:
                if (_p.fetch.package) {
                    encoder enc { *_p.fetch.package };
                    v.emplace(std::move(enc.bytes()));
                }
                break;
            case 8:
                if (_p.fetch.package) {
                    encoder enc { _p.fetch.package->authorizer, _p.fetch.package->params };
                    v.emplace(std::move(enc.bytes()));
                }
                break;
            case 9:
                if (_p.fetch.package) {
                    encoder enc { _p.fetch.package->authorization };
                    v.emplace(std::move(enc.bytes()));
                }
                break;
            case 10:
                if (_p.fetch.package) {
                    encoder enc { _p.fetch.package->context };
                    v.emplace(std::move(enc.bytes()));
                }
                break;
            case 13:
                if (_p.fetch.package && _p.fetch.package->items.size() > omega[11]) {
                    encoder enc { _p.fetch.package->items[omega[11]].payload };
                    v.emplace(std::move(enc.bytes()));
                }
                break;
            case 14:
                if (_p.fetch.operands) {
                    encoder enc { *_p.fetch.operands };
                    v.emplace(std::move(enc.bytes()));
                }
                break;
            case 15:
                if (_p.fetch.operands && omega[11] < _p.fetch.operands->size()) {
                    encoder enc { _p.fetch.operands[omega[11]] };
                    v.emplace(std::move(enc.bytes()));
                }
                break;
            case 16:
                if (_p.fetch.transfers) {
                    encoder enc { *_p.fetch.transfers };
                    v.emplace(std::move(enc.bytes()));
                }
                break;
            case 17:
                if (_p.fetch.transfers && omega[11] < _p.fetch.transfers->size()) {
                    encoder enc { _p.fetch.transfers[omega[11]] };
                    v.emplace(std::move(enc.bytes()));
                }
                break;
            default:
                break;
        }
        if (v) {
            const auto o = omega[7];
            const auto f = std::min(omega[8], v->size());
            const auto l = std::min(omega[9], v->size() - f);
            _p.m.mem_write(o, static_cast<buffer>(*v).subbuf(0, l));
            _p.m.set_reg(7, v->size());
        } else {
            _p.m.set_reg(7, machine::host_call_res_t::none);
        }
    }

    template<typename CFG>
    void host_service_base_t<CFG>::lookup()
    {
        const auto &omega = _p.m.regs();
        const auto [s_id, a] = _get_service(omega[7]);
        const auto h = omega[8];
        const auto o = omega[9];
        const opaque_hash_t key { _p.m.mem_read(h, 32) };
        std::optional<write_vector> val {};
        if (a)
            val = a->preimages.get(key);
        if (val) {
            const auto f = std::min(omega[10], val->size());
            const auto l = std::min(omega[11], val->size() - f);
            _p.m.mem_write(o, static_cast<buffer>(*val).subbuf(0, l));
            _p.m.set_reg(7, val->size());
        } else {
            _p.m.set_reg(7, machine::host_call_res_t::none);
        }
    }

    template<typename CFG>
    void host_service_base_t<CFG>::read() {
        const auto &omega = _p.m.regs();
        const auto [s_id, a] = _get_service(omega[7]);
        const auto ko = omega[8];
        const auto kz = omega[9];
        const auto o = omega[10];
        encoder enc {};
        enc.uint_fixed(4, s_id);
        enc.next_bytes(_p.m.mem_read(ko, kz));
        std::optional<write_vector> val {};
        if (a) {
            const auto key = crypto::blake2b::digest<opaque_hash_t>(enc.bytes());
            val = a->storage.get(key);
        }
        if (val) {
            const auto f = std::min(omega[11], val->size());
            const auto l = std::min(omega[12], val->size() - f);
            _p.m.mem_write(o, static_cast<buffer>(*val).subbuf(0, l));
            _p.m.set_reg(7, val->size());
        } else {
            _p.m.set_reg(7, machine::host_call_res_t::none);
        }
    }

    template<typename CFG>
    void host_service_base_t<CFG>::write()
    {
        const auto k_o = _p.m.regs()[7];
        const auto k_z = _p.m.regs()[8];
        const auto key_data = _p.m.mem_read(k_o, k_z);
        encoder enc {};
        enc.uint_fixed(4, _p.service_id);
        enc.next_bytes(key_data);
        const auto key_hash = crypto::blake2b::digest<opaque_hash_t>(enc.bytes());
        const auto v_o = _p.m.regs()[9];
        const auto v_z = _p.m.regs()[10];
        const auto prev_val = _service.storage.get(key_hash);
        const auto balance_threshold = account_balance_threshold(_service.lookup_metas, _service.storage);
        if (_service.info.base.balance >= balance_threshold) {
            if (v_z == 0) {
                logger::trace("service {} write: delete key: {}", _p.service_id, key_data);
                if (prev_val) {
                    // move the stats update into the erase method?
                    _service.info.bytes -= sizeof(key_hash);
                    _service.info.bytes -= prev_val->size();
                    --_service.info.items;
                    _service.storage.erase(key_hash);
                }
            } else {
                auto val_data = _p.m.mem_read(v_o, v_z);
                logger::trace("service {} write: set key: {} hash: {} val: {}", _p.service_id, key_data, key_hash, val_data);
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
            _p.m.set_reg(7, l);
        } else {
            _p.m.set_reg(7, machine::host_call_res_t::full);
        }
    }

    template<typename CFG>
    void host_service_base_t<CFG>::info()
    {
        const auto &omega = _p.m.regs();
        const auto [t_id, t] = _get_service(omega[7]);
        std::optional<uint8_vector> m {};
        if (t) {
            auto info = t->info.combine();
            // JAM 0.6.5 mentions an element t_t which is not part of the service's info - not clear what it means
            encoder enc {
                info.code_hash, info.balance, _p.slot,
                info.min_item_gas, info.min_memo_gas,
                info.bytes, info.items
            };
            m.emplace(std::move(enc.bytes()));
        }
        if (m) {
            const auto o = omega[8];
            _p.m.mem_write(o, *m);
            _p.m.set_reg(7, machine::host_call_res_t::ok);
        } else {
            _p.m.set_reg(7, machine::host_call_res_t::none);
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
        const auto &omega = _p.m.regs();
        const auto level = omega[7];
        std::optional<std::string> target {};
        if (omega[8] != 0 || omega[9] != 0)
            target.emplace(_p.m.mem_read(omega[8], omega[9]).str());
        const auto msg = _p.m.mem_read(omega[10], omega[11]);
        logger::log(log_level(level), "[PVM/{}]: {}", target, msg.str());
    }

    template<typename CFG>
    host_service_accumulate_t<CFG>::host_service_accumulate_t(const host_service_params_t<CFG> &params,
            accumulate_context_t<CFG> &ctx_ok, accumulate_context_t<CFG> &ctx_err):
        base_type { params },
        _ok { ctx_ok },
        _err { ctx_err }
    {
    }

    template<typename CFG>
    [[nodiscard]] machine::host_call_res_t host_service_accumulate_t<CFG>::call(const machine::register_val_t id) noexcept
    {
        return this->_safe_call([&] {
            logger::trace("PVM: host call #{}", id);
            gas_t::base_type gas_used = 10;
            switch (id) {
                // generic
                case 0: base_type::gas(); break;
                case 1: base_type::lookup(); break;
                case 2: base_type::read(); break;
                case 3: base_type::write(); break;
                case 4: base_type::info(); break;
                case 18: base_type::fetch(); break;
                // accumulate-specific
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
                    this->_p.m.set_reg(7, machine::host_call_res_t::what);
                    break;
            }
            this->_p.m.consume_gas(gas_used);
        });
    }

    template<typename CFG>
    void host_service_accumulate_t<CFG>::bless()
    {
        if (this->_p.service_id != _ok.state.chi.bless)
            throw machine::exit_panic_t {};
        const auto &omega = this->_p.m.regs();
        const auto m = omega[7];
        const auto a = omega[8];
        const auto v = omega[9];
        const auto o = omega[10];
        const auto n = omega[11];

        free_services_t fs {};
        for (size_t i = 0; i < n; ++i) {
            const auto bytes = this->_p.m.mem_read(o + i * 12, 12);
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
            this->_p.m.set_reg(7, machine::host_call_res_t::ok);
        } else {
            this->_p.m.set_reg(7, machine::host_call_res_t::who);
        }
    }

    template<typename CFG>
    void host_service_accumulate_t<CFG>::assign()
    {
        if (this->_p.service_id != _ok.state.chi.assign)
            throw machine::exit_panic_t {};
        const auto &omega = this->_p.m.regs();
        const auto o = omega[8];
        auth_queue_t<CFG> v;
        for (size_t i = 0; i < v.size(); ++i) {
            v[i] = static_cast<buffer>(this->_p.m.mem_read(o + i * 32, 32));
        }
        if (const auto c = omega[7]; c < CFG::C_core_count) {
            _ok.state.phi[c] = std::move(v);
            this->_p.m.set_reg(7, machine::host_call_res_t::ok);
        } else {
            this->_p.m.set_reg(7, machine::host_call_res_t::core);
        }
    }

    template<typename CFG>
    void host_service_accumulate_t<CFG>::designate()
    {
        if (this->_p.service_id != _ok.state.chi.designate)
            throw machine::exit_panic_t {};
        const auto &omega = this->_p.m.regs();
        const auto o = omega[7];
        validators_data_t<CFG> v;
        for (size_t i = 0; i < v.size(); ++i) {
            decoder dec { this->_p.m.mem_read(o + i * 336, 336) };
            dec.process(v[i]);
        }
        _ok.state.iota.emplace(std::move(v));
        this->_p.m.set_reg(7, machine::host_call_res_t::ok);
    }

    template<typename CFG>
    void host_service_accumulate_t<CFG>::checkpoint()
    {
        _err = _ok;
        this->_p.m.set_reg(7, this->_p.m.gas());
    }

    template<typename CFG>
    void host_service_accumulate_t<CFG>::new_()
    {
        const auto &omega = this->_p.m.regs();
        const auto o = omega[7];
        const auto l = omega[8];
        const auto g = omega[9];
        const auto m = omega[10];
        if (l > std::numeric_limits<uint32_t>::max())
            throw machine::exit_panic_t {};
        const auto c = this->_p.m.mem_read(o, 32);
        const auto a_t = account_balance_threshold_raw(0, 0);
        if (this->_service.info.balance >= a_t) {
            static service_info_t empty_info {};
            service_info_update_t a {
                .base=empty_info,
                .code_hash=static_cast<buffer>(c),
                .balance=numeric_cast<int64_t>(a_t),
                .min_item_gas=numeric_cast<int64_t>(g),
                .min_memo_gas=numeric_cast<int64_t>(m),
                .bytes=0,
                .items=0
            };
            this->_service.info.balance -= a_t;
            const auto prev_id = _ok.new_service_id;
            _ok.new_service_id = _ok.check(_ok.gen_new_service_id(prev_id, 42));
            _ok.state.services.emplace(this->_p.service_id, std::move(a));
            this->_p.m.set_reg(7, prev_id);
        } else {
            this->_p.m.set_reg(7, machine::host_call_res_t::cash);
        }
    }

    template<typename CFG>
    void host_service_accumulate_t<CFG>::upgrade()
    {
        const auto &omega = this->_p.m.regs();
        const auto o = omega[7];
        const auto g = omega[8];
        const auto m = omega[9];
        const auto c = this->_p.m.mem_read(o, 32);
        this->_service.info.code_hash = static_cast<buffer>(c);
        // The next two items must be converted into deltas!
        this->_service.info.min_item_gas = numeric_cast<int64_t>(g) - numeric_cast<int64_t>(this->_service.info.base.min_item_gas);
        this->_service.info.min_memo_gas = numeric_cast<int64_t>(m) - numeric_cast<int64_t>(this->_service.info.base.min_memo_gas);
        this->_p.m.set_reg(7, machine::host_call_res_t::ok);
    }

    template<typename CFG>
    void host_service_accumulate_t<CFG>::transfer()
    {
        const auto &omega = this->_p.m.regs();
        const auto d = numeric_cast<service_id_t>(omega[7]);
        const auto a = omega[8];
        const auto l = omega[9];
        const auto o = omega[10];
        const auto m = this->_p.m.mem_read(o, sizeof(deferred_transfer_metadata_t<CFG>));
        this->_service.info.balance -= a;
        if (!this->_p.services.contains(d)) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::who);
            return;
        }
        const auto s_info = this->_service.info.combine();
        if (l < s_info.min_memo_gas) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::low);
            return;
        }
        if (const auto t = account_balance_threshold(this->_service.lookup_metas, this->_service.storage);
                s_info.balance < t) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::cash);
            return;
        }
        _ok.transfers.emplace_back(this->_p.service_id, d, a, static_cast<buffer>(m), l);
        this->_p.m.set_reg(7, machine::host_call_res_t::ok);
    }

    template<typename CFG>
    void host_service_accumulate_t<CFG>::eject()
    {
        const auto &omega = this->_p.m.regs();
        const auto d = numeric_cast<service_id_t>(omega[7]);
        const auto o = omega[8];
        const auto h = this->_p.m.mem_read(o, 32);
        auto *d_mut = this->_p.services.get_mutable_ptr(d);
        if (d == this->_p.service_id || !d_mut || d_mut->info.base.code_hash != h) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::who);
            return;
        }
        //const auto l = std::max(81ULL, )
        // Todo: make service statistics available for modification
        throw machine::exit_panic_t {};
    }

    template<typename CFG>
    void host_service_accumulate_t<CFG>::query()
    {
        const auto &omega = this->_p.m.regs();
        const auto o = omega[7];
        const auto z = omega[8];
        const auto h = this->_p.m.mem_read(o, 32);
        // static_cast<uint32_t> instead of numeric_cast to return NONE instead of throwing an exception
        const auto a = this->_service.lookup_metas.get(lookup_meta_map_key_t { static_cast<buffer>(h), static_cast<uint32_t>(z) });
        if (!a) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::none);
            return;
        }
        switch (a->size()) {
            case 0:
                this->_p.m.set_reg(7, 0ULL);
                this->_p.m.set_reg(8, 0ULL);
                break;
            case 1:
                this->_p.m.set_reg(1 + numeric_cast<machine::register_val_t>((*a)[0].slot()) << 32U, 0ULL);
                this->_p.m.set_reg(8, 0ULL);
                break;
            case 2:
                this->_p.m.set_reg(2 + numeric_cast<machine::register_val_t>((*a)[0].slot()) << 32U, 0ULL);
                this->_p.m.set_reg(8, numeric_cast<machine::register_val_t>((*a)[1].slot()));
                break;
            case 3:
                this->_p.m.set_reg(3 + numeric_cast<machine::register_val_t>((*a)[0].slot()) << 32U, 0ULL);
                this->_p.m.set_reg(8, numeric_cast<machine::register_val_t>((*a)[1].slot()) + numeric_cast<machine::register_val_t>((*a)[2].slot()) << 32U);
                break;
            [[unlikely]] default:
                throw machine::exit_panic_t {};
        }
    }

    template<typename CFG>
    void host_service_accumulate_t<CFG>::solicit()
    {
        const auto &omega = this->_p.m.regs();
        const auto o = omega[7];
        const auto z = omega[8];
        const auto h = this->_p.m.mem_read(o, 32);
        const lookup_meta_map_key_t l_key { static_cast<buffer>(h), static_cast<uint32_t>(z) };
        auto a_res = this->_service.lookup_metas.get(l_key);
        if (!a_res) {
            this->_service.lookup_metas.set(l_key, {});
        } else if (a_res->size() == 2) {
            a_res->emplace_back(this->_p.slot);
            this->_service.lookup_metas.set(l_key, std::move(*a_res));
        } else {
            this->_p.m.set_reg(7, machine::host_call_res_t::huh);
            return;
        }
        const auto s_info = this->_service.info.combine();
        if (const auto t = account_balance_threshold(this->_service.lookup_metas, this->_service.storage); s_info.balance < t) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::full);
            return;
        }
        this->_p.m.set_reg(7, machine::host_call_res_t::ok);
    }

    template<typename CFG>
    void host_service_accumulate_t<CFG>::forget()
    {
        const auto &omega = this->_p.m.regs();
        const auto o = omega[7];
        const auto z = omega[8];
        const auto h = this->_p.m.mem_read(o, 32);
        const lookup_meta_map_key_t l_key { static_cast<buffer>(h), static_cast<uint32_t>(z) };
        auto a_res = this->_service.lookup_metas.get(l_key);
        if (!a_res) {
            this->_p.m.set_reg(7, machine::host_call_res_t::huh);
            return;
        }
        switch (a_res->size()) {
            case 0:
                this->_service.lookup_metas.erase(l_key);
                this->_service.preimages.erase(static_cast<buffer>(h));
                break;
            case 1:
                a_res->emplace_back(this->_p.slot);
                this->_service.lookup_metas.set(l_key, std::move(*a_res));
                break;
            case 2:
                if ((*a_res)[1].slot() >= this->_p.slot.slot() - CFG::D_preimage_expunge_delay) {
                    this->_p.m.set_reg(7, machine::host_call_res_t::huh);
                    return;
                }
                this->_service.lookup_metas.erase(l_key);
                this->_service.preimages.erase(static_cast<buffer>(h));
                break;
            case 3:
                if ((*a_res)[1].slot() >= this->_p.slot.slot() - CFG::D_preimage_expunge_delay) {
                    this->_p.m.set_reg(7, machine::host_call_res_t::huh);
                    return;
                }
                this->_service.lookup_metas.set(l_key, { (*a_res)[2], this->_p.slot });
                break;
            [[unlikely]] default:
                throw machine::exit_panic_t {};
        }
        this->_p.m.set_reg(7, machine::host_call_res_t::ok);
    }

    template<typename CFG>
    void host_service_accumulate_t<CFG>::yield()
    {
        const auto &omega = this->_p.m.regs();
        const auto o = omega[7];
        const auto h = this->_p.m.mem_read(o, 32);
        _ok.result.emplace(static_cast<buffer>(h));
        this->_p.m.set_reg(7, machine::host_call_res_t::ok);
    }

    template<typename CFG>
    void host_service_accumulate_t<CFG>::provide()
    {
        const auto &omega = this->_p.m.regs();
        const auto o = omega[7];
        const auto z = omega[8];
        const auto [s_id, a] = this->_get_service(omega[7]);
        const auto i = this->_p.m.mem_read(o, z);
        if (!a) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::who);
            return;
        }
        const auto h = crypto::blake2b::digest<opaque_hash_t>(i);
        const lookup_meta_map_key_t l_key { h, static_cast<uint32_t>(z) };
        if (const auto l_res = a->lookup_metas.get(l_key); !l_res || !l_res->empty()) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::huh);
            return;
        }
        if (const auto p_res = a->preimages.get(h); p_res) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::huh);
            return;
        }
        this->_service.preimages.set(h, write_vector { i });
        this->_p.m.set_reg(7, machine::host_call_res_t::ok);
    }

    template struct host_service_accumulate_t<config_prod>;
    template struct host_service_accumulate_t<config_tiny>;

    template struct host_service_on_transfer_t<config_prod>;
    template struct host_service_on_transfer_t<config_tiny>;
}
