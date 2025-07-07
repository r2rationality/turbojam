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
            switch (static_cast<host_call_t>(id)) {
                case host_call_t::gas: this->gas(); break;
                case host_call_t::lookup: this->lookup(); break;
                case host_call_t::read: this->read(); break;
                case host_call_t::write: this->write(); break;
                case host_call_t::info: this->info(); break;
                case host_call_t::fetch: this->fetch(); break;
                case host_call_t::log:
                    this->log();
                    gas_used = 0;
                    break;
                [[unlikely]] default:
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
            switch (static_cast<host_call_t>(id)) {
                case host_call_t::gas: this->gas(); break;
                case host_call_t::fetch: this->fetch(); break;
                case host_call_t::log:
                    this->log();
                    gas_used = 0;
                    break;
                [[unlikely]] default:
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
            switch (static_cast<host_call_t>(id)) {
                // generic
                case host_call_t::gas: this->gas(); break;
                case host_call_t::lookup: this->lookup(); break;
                case host_call_t::read: this->read(); break;
                case host_call_t::write: this->write(); break;
                case host_call_t::info: this->info(); break;
                case host_call_t::fetch: this->fetch(); break;
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
                case host_call_t::log:
                    this->log();
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
        const auto s_func = [](encoder &enc, const work_item_t &w) {
            enc.process(w.service);
            enc.process(w.code_hash);
            enc.process(w.refine_gas_limit);
            enc.process(w.accumulate_gas_limit);
            enc.uint_fixed(2, w.export_count);
            enc.uint_fixed(2, w.import_segments.size());
            enc.uint_fixed(2, w.extrinsic.size());
            enc.uint_fixed(4, w.payload.size());
        };
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
            case 2:
                if (_p.fetch.auth_output)
                    v.emplace(*_p.fetch.auth_output);
                break;
            case 3:
                if (_p.fetch.exports && omega[11] < _p.fetch.exports->size()
                        && omega[12] < (*_p.fetch.exports)[omega[11]].size())
                    v.emplace((*_p.fetch.exports)[omega[11]][omega[12]]);
                break;
            case 4:
                if (_p.fetch.exports && _p.fetch.refined_item_index
                        && *_p.fetch.refined_item_index < _p.fetch.exports->size()
                        && omega[11] < (*_p.fetch.exports)[*_p.fetch.refined_item_index].size())
                    v.emplace((*_p.fetch.exports)[*_p.fetch.refined_item_index][omega[11]]);
                break;
            case 5:
                if (_p.fetch.imports && omega[11] < _p.fetch.imports->size()
                        && omega[12] < (*_p.fetch.imports)[omega[11]].size())
                    v.emplace((*_p.fetch.imports)[omega[11]][omega[12]]);
                break;
            case 6:
                if (_p.fetch.exports && _p.fetch.refined_item_index
                        && *_p.fetch.refined_item_index < _p.fetch.imports->size()
                        && omega[11] < (*_p.fetch.imports)[*_p.fetch.refined_item_index].size())
                    v.emplace((*_p.fetch.imports)[*_p.fetch.refined_item_index][omega[11]]);
                break;
            case 7:
                if (_p.fetch.package) {
                    encoder enc { *_p.fetch.package };
                    v.emplace(std::move(enc.bytes()));
                }
                break;
            case 8:
                if (_p.fetch.package) {
                    encoder enc { _p.fetch.package->authorizer };
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
            case 11:
                if (_p.fetch.package) {
                    encoder enc {};
                    enc.uint_varlen(_p.fetch.package->items.size());
                    for (const auto &w: _p.fetch.package->items)
                        s_func(enc, w);
                    v.emplace(std::move(enc.bytes()));
                }
                break;
            case 12:
                if (_p.fetch.package && omega[11] < _p.fetch.package->items.size()) {
                    encoder enc {};
                    s_func(enc, _p.fetch.package->items[omega[11]]);
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
            _p.m.mem_write(o, static_cast<buffer>(*v).subbuf(f, l));
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
        std::optional<uint8_vector> val {};
        if (a) {
            const auto p_k = a->preimages.make_key(key);
            val = a->preimages.get(p_k);
        }
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
        std::optional<uint8_vector> val {};
        if (a) {
            encoder enc {};
            enc.uint_fixed(4, s_id);
            const auto key = _p.m.mem_read(ko, kz);
            enc.next_bytes(key);
            const auto s_k = a->storage.make_key(crypto::blake2b::digest<opaque_hash_t>(enc.bytes()));
            val = a->storage.get(s_k);
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
    void host_service_base_t<CFG>::write() {
        const auto k_o = _p.m.regs()[7];
        const auto k_z = _p.m.regs()[8];
        const auto key_data = _p.m.mem_read(k_o, k_z);
        encoder enc {};
        enc.uint_fixed(4, _p.service_id);
        enc.next_bytes(key_data);
        const auto key_hash = crypto::blake2b::digest<opaque_hash_t>(enc.bytes());
        const auto v_o = _p.m.regs()[9];
        const auto v_z = _p.m.regs()[10];
        const auto val_data = _p.m.mem_read(v_o, v_z);
        const auto s_k = _service.storage.make_key(key_hash);
        const auto prev_val = _service.storage.get(s_k);
        // The threshold must be computed assuming that the new item is written
        auto [a_i, a_o] = account_balance_threshold_stats(_service.lookup_metas, _service.storage);
        if (!prev_val) {
            ++a_i;
            a_o += val_data.size();
        } else {
            a_o += val_data.size() - prev_val->size();
        }
        const auto balance_threshold = account_balance_threshold_raw(a_i, a_o);
        const auto info = _service.info.combine();
        if (info.balance >= balance_threshold) {
            if (v_z == 0) {
                if (prev_val) {
                    logger::trace("service {} write: delete key: {}", _p.service_id, key_data);
                    // move the stats update into the erase method?
                    _service.info.bytes -= sizeof(key_hash);
                    _service.info.bytes -= prev_val->size();
                    --_service.info.items;
                    _service.storage.erase(s_k);
                } else {
                    logger::trace("service {} attempt to delete a missing key: {}", _p.service_id, key_data);
                }
            } else {
                logger::trace("service {} write: set key: {} hash: {} val: {} new: {}", _p.service_id, key_data, key_hash, val_data, !static_cast<bool>(prev_val));
                if (prev_val) {
                    _service.info.bytes -= prev_val->size();
                } else {
                    _service.info.bytes += sizeof(key_hash);
                    ++_service.info.items;
                }
                _service.storage.set(s_k, static_cast<buffer>(val_data));
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

    template<typename CFG>
    void host_service_base_t<CFG>::log()
    {
        const auto &omega = _p.m.regs();
        const auto level = omega[7];
        std::optional<std::string> target {};
        if (omega[8] != 0 || omega[9] != 0)
            target.emplace(_p.m.mem_read(omega[8], omega[9]).str());
        const auto msg = _p.m.mem_read(omega[10], omega[11]);
        logger::trace("[PVM/{}] [level={}]: {}", target.value_or("default"), level, msg.str());
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
            void (host_service_accumulate_t<CFG>::*call_func)() = nullptr;
            gas_t::base_type gas_used = 10;
            switch (static_cast<host_call_t>(id)) {
                // generic
                case host_call_t::gas: call_func = &host_service_accumulate_t::gas; break;
                case host_call_t::lookup: call_func = &host_service_accumulate_t::lookup; break;
                case host_call_t::read: call_func = &host_service_accumulate_t::read; break;
                case host_call_t::write: call_func = &host_service_accumulate_t::write; break;
                case host_call_t::info: call_func = &host_service_accumulate_t::info; break;
                case host_call_t::fetch: call_func = &host_service_accumulate_t::fetch; break;
                // accumulate-specific
                case host_call_t::bless: call_func = &host_service_accumulate_t::bless; break;
                case host_call_t::assign: call_func = &host_service_accumulate_t::assign; break;
                case host_call_t::designate: call_func = &host_service_accumulate_t::designate; break;
                case host_call_t::checkpoint: call_func = &host_service_accumulate_t::checkpoint; break;
                case host_call_t::new_: call_func = &host_service_accumulate_t::new_; break;
                case host_call_t::upgrade: call_func = &host_service_accumulate_t::upgrade; break;
                case host_call_t::transfer:
                    gas_used += this->_p.m.regs()[9];
                    call_func = &host_service_accumulate_t::transfer;
                    break;
                case host_call_t::eject: call_func = &host_service_accumulate_t::eject; break;
                case host_call_t::query: call_func = &host_service_accumulate_t::query; break;
                case host_call_t::solicit: call_func = &host_service_accumulate_t::solicit; break;
                case host_call_t::forget: call_func = &host_service_accumulate_t::forget; break;
                case host_call_t::yield: call_func = &host_service_accumulate_t::yield; break;
                case host_call_t::provide: call_func = &host_service_accumulate_t::provide; break;
                case host_call_t::log:
                    gas_used = 0;
                    call_func = &host_service_accumulate_t::log;
                    break;
                default:
                    this->_p.m.set_reg(7, machine::host_call_res_t::what);
                    return;
            }
            this->_p.m.consume_gas(gas_used);
            (*this.*call_func)();
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
        const auto a_t = numeric_cast<int64_t>(account_balance_threshold_raw(0, 0));
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
        const auto l_k = this->_service.lookup_metas.make_key({ static_cast<buffer>(h), static_cast<uint32_t>(z) });
        logger::trace("service: {} query: h: {} l: {} key: {}", this->_p.service_id, h, z, l_k);
        const auto a = this->_service.lookup_metas.get(l_k);
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
                this->_p.m.set_reg(7, 1 + (numeric_cast<machine::register_val_t>((*a)[0].slot()) << 32U));
                this->_p.m.set_reg(8, 0ULL);
                break;
            case 2:
                this->_p.m.set_reg(7, 2 + (numeric_cast<machine::register_val_t>((*a)[0].slot()) << 32U));
                this->_p.m.set_reg(8, numeric_cast<machine::register_val_t>((*a)[1].slot()));
                break;
            case 3:
                this->_p.m.set_reg(7, 3 + (numeric_cast<machine::register_val_t>((*a)[0].slot()) << 32U));
                this->_p.m.set_reg(8, numeric_cast<machine::register_val_t>((*a)[1].slot()) + (numeric_cast<machine::register_val_t>((*a)[2].slot()) << 32U));
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
        const auto l_k = this->_service.lookup_metas.make_key({ static_cast<buffer>(h), static_cast<uint32_t>(z) });
        logger::trace("service: {} solicit: h: {} l: {} key: {}", this->_p.service_id, h, z, l_k);
        auto a_res = this->_service.lookup_metas.get(l_k);
        if (!a_res) {
            this->_service.lookup_metas.set(l_k, {});
            this->_service.info.items += 2;
            this->_service.info.bytes += 81 + z;
        } else if (a_res->size() == 2) {
            a_res->emplace_back(this->_p.slot);
            this->_service.lookup_metas.set(l_k, std::move(*a_res));
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
        const auto l_k = this->_service.lookup_metas.make_key({ static_cast<buffer>(h), static_cast<uint32_t>(z) });
        const auto p_k = this->_service.preimages.make_key(static_cast<buffer>(h));
        logger::trace("service: {} forget: h: {} l: {} l_key: {} p_key: {}", this->_p.service_id, h, z, l_k, p_k);
        auto l_res = this->_service.lookup_metas.get(l_k);
        if (!l_res) {
            this->_p.m.set_reg(7, machine::host_call_res_t::huh);
            return;
        }
        switch (l_res->size()) {
            case 2:
                if ((*l_res)[1].slot() + CFG::D_preimage_expunge_delay >= this->_p.slot.slot()) {
                    this->_p.m.set_reg(7, machine::host_call_res_t::huh);
                    return;
                }
                [[fallthrough]]; // Yes, fallthrough into case 0!
            case 0: {
                this->_service.info.items -= 2;
                this->_service.info.bytes -= 81 + z;
                this->_service.lookup_metas.erase(l_k);
                this->_service.preimages.erase(p_k);
                break;
            }
            case 1:
                l_res->emplace_back(this->_p.slot);
                this->_service.lookup_metas.set(l_k, std::move(*l_res));
                break;
            case 3:
                if ((*l_res)[1].slot() + CFG::D_preimage_expunge_delay >= this->_p.slot.slot()) {
                    this->_p.m.set_reg(7, machine::host_call_res_t::huh);
                    return;
                }
                this->_service.lookup_metas.set(l_k, { (*l_res)[2], this->_p.slot });
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
        const auto l_k = a->lookup_metas.make_key({ h, static_cast<uint32_t>(z) });
        logger::trace("provide: h: {} l: {} key: {}", h, z, l_k);
        if (const auto l_res = a->lookup_metas.get(l_k); !l_res || !l_res->empty()) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::huh);
            return;
        }
        const auto p_k = a->preimages.make_key(h);
        if (const auto p_res = a->preimages.get(p_k); p_res) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::huh);
            return;
        }
        ++this->_service.info.items;
        this->_service.info.bytes += 32 + i.size();
        this->_service.preimages.set(p_k, uint8_vector { i });
        this->_p.m.set_reg(7, machine::host_call_res_t::ok);
    }

    template struct host_service_base_t<config_prod>;
    template struct host_service_base_t<config_tiny>;

    template struct host_service_accumulate_t<config_prod>;
    template struct host_service_accumulate_t<config_tiny>;

    template struct host_service_on_transfer_t<config_prod>;
    template struct host_service_on_transfer_t<config_tiny>;
}
