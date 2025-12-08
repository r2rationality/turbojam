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
    host_service_base_t<CFG>::host_service_base_t(host_service_params_t<CFG> params):
        _p{std::move(params)}
    {
    }

    template<typename CFG>
    host_service_on_transfer_t<CFG>::host_service_on_transfer_t(host_service_params_t<CFG> params):
        host_service_base_t<CFG>{std::move(params)}
    {
        logger::trace("host service on-transfer started");
    }

    template<typename CFG>
    machine::host_call_res_t host_service_on_transfer_t<CFG>::call(const machine::register_val_t id) noexcept
    {
        return this->_safe_call([&] {
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
                    logger::trace("host_service::unknown");
                    this->_p.m.set_reg(7, machine::host_call_res_t::what);
                    break;
            }
            this->_p.m.consume_gas(gas_used);
        });
    }

    template<typename CFG>
    host_service_is_authorized_t<CFG>::host_service_is_authorized_t(host_service_params_t<CFG> params):
        host_service_base_t<CFG>{std::move(params)}
    {
        logger::trace("host service is_authorized started");
    }

    template<typename CFG>
    machine::host_call_res_t host_service_is_authorized_t<CFG>::call(const machine::register_val_t id) noexcept
    {
        return this->_safe_call([&] {
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
    host_service_refine_t<CFG>::host_service_refine_t(host_service_params_t<CFG> params):
        host_service_base_t<CFG>{std::move(params)}
    {
        logger::trace("host service refine started");
    }

    template<typename CFG>
    [[nodiscard]] machine::host_call_res_t host_service_refine_t<CFG>::call(const machine::register_val_t id) noexcept
    {
        return this->_safe_call([&] {
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
                    logger::trace("host_service::unknown");
                    this->_p.m.set_reg(7, machine::host_call_res_t::what);
                    break;
            }
            this->_p.m.consume_gas(gas_used);
        });
    }

    template<typename CFG>
    service_info_t<CFG> host_service_base_t<CFG>::_service_info() const {
        auto info = this->_p.services.info_get(this->_p.service_id);
        if (!info) [[unlikely]]
            throw machine::exit_panic_t{};
        return std::move(*info);
    }

    template<typename CFG>
    typename host_service_base_t<CFG>::service_lookup_res_t host_service_base_t<CFG>::_get_service(machine::register_val_t id)
    {
        if (id == std::numeric_limits<machine::register_val_t>::max())
            id = _p.service_id;
        if (id > std::numeric_limits<service_id_t>::max()) [[unlikely]]
            return {static_cast<service_id_t>(id), {}};
        return {static_cast<service_id_t>(id), _p.services.info_get(id)};
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
        logger::trace("host_service::gas");
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
        const auto &phi = _p.m.regs();
        logger::trace("host_service::fetch {}", phi[10]);
        std::optional<uint8_vector> v {};
        switch (phi[10]) {
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
                if (_p.fetch.exports && phi[11] < _p.fetch.exports->size()
                        && phi[12] < (*_p.fetch.exports)[phi[11]].size())
                    v.emplace((*_p.fetch.exports)[phi[11]][phi[12]]);
                break;
            case 4:
                if (_p.fetch.exports && _p.fetch.refined_item_index
                        && *_p.fetch.refined_item_index < _p.fetch.exports->size()
                        && phi[11] < (*_p.fetch.exports)[*_p.fetch.refined_item_index].size())
                    v.emplace((*_p.fetch.exports)[*_p.fetch.refined_item_index][phi[11]]);
                break;
            case 5:
                if (_p.fetch.imports && phi[11] < _p.fetch.imports->size()
                        && phi[12] < (*_p.fetch.imports)[phi[11]].size())
                    v.emplace((*_p.fetch.imports)[phi[11]][phi[12]]);
                break;
            case 6:
                if (_p.fetch.exports && _p.fetch.refined_item_index
                        && *_p.fetch.refined_item_index < _p.fetch.imports->size()
                        && phi[11] < (*_p.fetch.imports)[*_p.fetch.refined_item_index].size())
                    v.emplace((*_p.fetch.imports)[*_p.fetch.refined_item_index][phi[11]]);
                break;
            case 7:
                if (_p.fetch.package) {
                    encoder enc { *_p.fetch.package };
                    v.emplace(std::move(enc.bytes()));
                }
                break;
            case 8:
                if (_p.fetch.package) {
                    const encoder enc{_p.fetch.package->auth_code_hash, _p.fetch.package->authorizer_config};
                    v.emplace(std::move(enc.bytes()));
                }
                break;
            case 9:
                if (_p.fetch.package) {
                    const encoder enc{_p.fetch.package->authorization};
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
                if (_p.fetch.package && phi[11] < _p.fetch.package->items.size()) {
                    encoder enc {};
                    s_func(enc, _p.fetch.package->items[phi[11]]);
                    v.emplace(std::move(enc.bytes()));
                }
                break;
            case 13:
                if (_p.fetch.package && _p.fetch.package->items.size() > phi[11]) {
                    encoder enc { _p.fetch.package->items[phi[11]].payload };
                    v.emplace(std::move(enc.bytes()));
                }
                break;
            case 14:
                if (_p.fetch.inputs) {
                    encoder enc {*_p.fetch.inputs};
                    v.emplace(std::move(enc.bytes()));
                }
                break;
            case 15:
                if (_p.fetch.inputs && phi[11] < _p.fetch.inputs->size()) {
                    encoder enc{(*_p.fetch.inputs)[phi[11]]};
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
                if (_p.fetch.transfers && phi[11] < _p.fetch.transfers->size()) {
                    encoder enc { _p.fetch.transfers[phi[11]] };
                    v.emplace(std::move(enc.bytes()));
                }
                break;
            default:
                break;
        }
        if (v) {
            const auto o = phi[7];
            const auto f = std::min(phi[8], v->size());
            const auto l = std::min(phi[9], v->size() - f);
            _p.m.mem_write(o, static_cast<buffer>(*v).subbuf(f, l));
            _p.m.set_reg(7, v->size());
        } else {
            _p.m.set_reg(7, machine::host_call_res_t::none);
        }
    }

    template<typename CFG>
    void host_service_base_t<CFG>::lookup()
    {
        logger::trace("host_service::lookup");
        const auto &phi = _p.m.regs();
        const auto [s_id, a] = _get_service(phi[7]);
        const auto h = phi[8];
        const auto o = phi[9];
        const opaque_hash_t key{_p.m.mem_read(h, 32)};
        std::optional<uint8_vector> val{};
        if (a) {
            val = _p.services.preimage_get(s_id, key);
        }
        if (val) {
            const auto f = std::min(phi[10], val->size());
            const auto l = std::min(phi[11], val->size() - f);
            _p.m.mem_write(o, static_cast<buffer>(*val).subbuf(f, l));
            _p.m.set_reg(7, val->size());
        } else {
            _p.m.set_reg(7, machine::host_call_res_t::none);
        }
    }

    template<typename CFG>
    void host_service_base_t<CFG>::read() {
        const auto &phi = _p.m.regs();
        const auto [s_id, a] = _get_service(phi[7]);
        const auto ko = phi[8];
        const auto kz = phi[9];
        const auto o = phi[10];
        const auto key = _p.m.mem_read(ko, kz);
        std::optional<uint8_vector> val {};
        if (a) {
            val = _p.services.storage_get(s_id, key);
        }
        if (val) {
            logger::trace("host call: read: service_id: {} key: {} -> {} bytes", s_id, key, val->size());
            const auto f = std::min(phi[11], val->size());
            const auto l = std::min(phi[12], val->size() - f);
            _p.m.mem_write(o, static_cast<buffer>(*val).subbuf(f, l));
            _p.m.set_reg(7, val->size());
        } else {
            logger::trace("host call: read: service_id: {} key: {} -> NONE", s_id, key);
            _p.m.set_reg(7, machine::host_call_res_t::none);
        }
    }

    template<typename CFG>
    void host_service_base_t<CFG>::write() {
        const auto &phi = _p.m.regs();
        const auto key = _p.m.mem_read(phi[7], phi[8]);
        const auto val_data = _p.m.mem_read(phi[9], phi[10]);
        const auto prev_val = _p.services.storage_set(_p.service_id, key, std::move(val_data));
        logger::trace("gas: {} host_service::write service {} set key: {} new_val: {} prev_val: {}",
            _p.m.gas(), _p.service_id, key,
            val_data.size() <= 32 ? fmt::format("#{}", val_data) : fmt::format("{} bytes", val_data.size()),
            prev_val
                ? prev_val->size() <= 32 ? fmt::format("#{}", *prev_val) : fmt::format("{} bytes", prev_val->size())
                : fmt::format("none"));
        const auto info = _p.services.info_get(_p.service_id);
        if (info->balance >= info->threshold()) {
            const machine::register_val_t l = prev_val ? prev_val->size() : machine::host_call_res_t::none;
            _p.m.set_reg(7, l);
        } else {
            _p.m.set_reg(7, machine::host_call_res_t::full);
        }
    }

    template<typename CFG>
    void host_service_base_t<CFG>::info()
    {
        const auto &phi = _p.m.regs();
        logger::trace("host_service::info {}", phi[7]);
        const auto [a_id, a] = _get_service(phi[7]);
        std::optional<uint8_vector> v{};
        if (a) {
            encoder enc{a->code_hash};
            enc.uint_fixed(8, a->balance);
            enc.uint_fixed(8, a->threshold());
            enc.uint_fixed(8, a->min_item_gas);
            enc.uint_fixed(8, a->min_memo_gas);
            enc.uint_fixed(8, a->bytes);
            enc.uint_fixed(4, a->items);
            enc.uint_fixed(8, a->deposit_offset);
            enc.uint_fixed(4, a->creation_slot.slot());
            enc.uint_fixed(4, a->last_accumulation_slot.slot());
            enc.uint_fixed(4, a->parent_service);
            v.emplace(std::move(enc.bytes()));
        }
        if (v) {
            const auto o = phi[8];
            const auto f = std::min(phi[9], v->size());
            const auto l = std::min(phi[10], v->size() - f);
            _p.m.mem_write(o, static_cast<buffer>(*v).subbuf(f, l));
            _p.m.set_reg(7, v->size());
        } else {
            _p.m.set_reg(7, machine::host_call_res_t::none);
        }
    }

    template<typename CFG>
    void host_service_base_t<CFG>::log()
    {
        const auto &phi = _p.m.regs();
        const auto level = phi[7];
        std::optional<std::string> target {};
        if (phi[8] != 0 || phi[9] != 0)
            target.emplace(_p.m.mem_read(phi[8], phi[9]).str());
        const auto msg = _p.m.mem_read(phi[10], phi[11]);
        logger::trace("host_service::log target={} level={}: {}", target.value_or("default"), level, msg.str());
    }

    template<typename CFG>
    host_service_accumulate_t<CFG>::host_service_accumulate_t(host_service_params_t<CFG> params,
            accumulate_context_t<CFG> &ctx_ok, accumulate_context_t<CFG> &ctx_err):
        base_type{std::move(params)},
        _ok{ctx_ok},
        _err{ctx_err}
    {
        logger::trace("host service accumulate started");
    }

    template<typename CFG>
    [[nodiscard]] machine::host_call_res_t host_service_accumulate_t<CFG>::call(const machine::register_val_t id) noexcept
    {
        return this->_safe_call([&] {
            void (host_service_accumulate_t<CFG>::*call_func)() = nullptr;
            gas_t::base_type gas_used = 10;
            switch (static_cast<host_call_t>(id)) {
                // generic
                case host_call_t::gas: call_func = &host_service_accumulate_t::gas; break;
                case host_call_t::fetch: call_func = &host_service_accumulate_t::fetch; break;
                case host_call_t::read: call_func = &host_service_accumulate_t::read; break;
                case host_call_t::write: call_func = &host_service_accumulate_t::write; break;
                case host_call_t::lookup: call_func = &host_service_accumulate_t::lookup; break;
                case host_call_t::info: call_func = &host_service_accumulate_t::info; break;
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
                    logger::trace("host_service::unknown");
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
        logger::trace("host_service::bless");
        const auto &phi = this->_p.m.regs();
        const auto m = phi[7];
        const auto a = phi[8];
        const auto v = phi[9];
        const auto o = phi[10];
        const auto n = phi[11];

        auto new_chi = std::make_shared<privileges_t<CFG>>();

        const auto a_bytes = this->_p.m.mem_read(a, 4 * CFG::C_core_count);
        new_chi->assign = jam::from_bytes<assigners_t<CFG>>(a_bytes);

        {
            new_chi->always_acc.reserve(n);
            const auto bytes = this->_p.m.mem_read(o, n * 12U);
            decoder dec {bytes};
            for (size_t i = 0; i < n; ++i) {
                const auto s = dec.uint_fixed<service_id_t>(4);
                const gas_t g { dec.uint_fixed<gas_t::base_type>(8) };
                new_chi->always_acc.emplace_hint(new_chi->always_acc.end(), s, g);
            }
        }

        if (_ok.state.chi->bless != this->_p.service_id) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::huh);
            return;
        }
        if (std::max(m, v) > std::numeric_limits<service_id_t>::max()) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::who);
            return;
        }
        new_chi->bless = static_cast<service_id_t>(m);
        new_chi->designate = static_cast<service_id_t>(v);
        _ok.state.chi.set(std::move(new_chi));
        this->_p.m.set_reg(7, machine::host_call_res_t::ok);
    }

    template<typename CFG>
    void host_service_accumulate_t<CFG>::assign()
    {
        logger::trace("host_service::assign");
        const auto &phi = this->_p.m.regs();
        const auto c = phi[7];
        const auto o = phi[8];
        const auto a = phi[9];
        const auto q_bytes = this->_p.m.mem_read(o, 32 * CFG::Q_auth_queue_size);
        const auto q = jam::from_bytes<auth_queue_t<CFG>>(q_bytes);
        if (c >= CFG::C_core_count) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::core);
            return;
        }
        if (this->_p.service_id != _ok.state.chi->assign[c]) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::huh);
            return;
        }
        if (!this->_p.services.info_get(a)) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::who);
            return;
        }
        _ok.state.phi[c] = q;
        _ok.state.chi.get_mutable().assign[c] = a;
        this->_p.m.set_reg(7, machine::host_call_res_t::ok);
    }

    template<typename CFG>
    void host_service_accumulate_t<CFG>::designate()
    {
        logger::trace("host_service::designate");
        const auto &phi = this->_p.m.regs();
        const auto o = phi[7];
        static_assert(sizeof(validator_data_t) == 336U);
        const auto bytes = this->_p.m.mem_read(o, sizeof(validator_data_t) * CFG::V_validator_count);
        if (this->_p.service_id != _ok.state.chi->designate) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::huh);
            return;
        }
        _ok.state.iota = std::make_shared<validators_data_t<CFG>>(jam::from_bytes<validators_data_t<CFG>>(bytes));
        this->_p.m.set_reg(7, machine::host_call_res_t::ok);
    }

    template<typename CFG>
    void host_service_accumulate_t<CFG>::checkpoint()
    {
        logger::trace("host_service::checkpoint");
        _err = _ok;
        this->_p.m.set_reg(7, this->_p.m.gas());
    }

    template<typename CFG>
    void host_service_accumulate_t<CFG>::new_()
    {
        logger::trace("host_service::new");
        const auto &phi = this->_p.m.regs();
        const auto o = phi[7];
        const auto l = phi[8];
        const auto g = phi[9];
        const auto m = phi[10];
        const auto f = phi[11];
        if (l > std::numeric_limits<uint32_t>::max()) [[unlikely]]
            throw machine::exit_panic_t{};
        const auto c = this->_p.m.mem_read(o, 32);
        if  (f != 0 && this->_p.service_id != _ok.state.chi->bless) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::huh);
            return;
        }
        service_info_t<CFG> a {
            .code_hash=static_cast<buffer>(c),
            .min_item_gas=g,
            .min_memo_gas=m,
            .bytes=81 + l,
            .deposit_offset=f,
            .items=2,
            .creation_slot=this->_p.slot,
            .parent_service=this->_p.service_id
        };
        a.balance = a.threshold();
        auto info = this->_service_info();
        if (info.balance < a.balance + info.threshold()) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::cash);
            return;
        }
        info.balance -= a.balance;
        this->_p.services.info_set(this->_p.service_id, std::move(info));
        const auto created_id = _ok.new_service_id;
        _ok.new_service_id = _ok.check(_ok.gen_new_service_id(created_id - 0x100U + 42U));
        this->_p.services.info_set(created_id, std::move(a));
        this->_p.services.lookup_set(created_id, lookup_meta_map_key_t{static_cast<buffer>(c), static_cast<uint32_t>(l)}, lookup_meta_map_val_t<CFG>{});
        this->_p.m.set_reg(7, created_id);
    }

    template<typename CFG>
    void host_service_accumulate_t<CFG>::upgrade()
    {
        logger::trace("host_service::upgrade");
        const auto &phi = this->_p.m.regs();
        const auto o = phi[7];
        const auto g = phi[8];
        const auto m = phi[9];
        auto info = this->_service_info();
        this->_p.m.mem_read(info.code_hash, o);
        info.min_item_gas = g;
        info.min_memo_gas = m;
        this->_p.services.info_set(this->_p.service_id, std::move(info));
        this->_p.m.set_reg(7, machine::host_call_res_t::ok);
    }

    template<typename CFG>
    void host_service_accumulate_t<CFG>::transfer()
    {
        logger::trace("host_service::transfer");
        const auto &phi = this->_p.m.regs();
        const auto d_raw = phi[7];
        const auto a = phi[8];
        const auto l = phi[9];
        const auto o = phi[10];
        const auto m = this->_p.m.mem_read(o, sizeof(deferred_transfer_metadata_t<CFG>));
        if (d_raw > std::numeric_limits<service_id_t>::max()) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::who);
            return;
        }
        const auto d = static_cast<service_id_t>(d_raw);
        if (!this->_p.services.info_get(d)) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::who);
            return;
        }
        auto info = this->_service_info();
        if (l < info.min_memo_gas) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::low);
            return;
        }
        if (info.balance < a + info.threshold()) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::cash);
            return;
        }
        info.balance -= a;
        this->_p.services.info_set(this->_p.service_id, std::move(info));
        _ok.transfers.emplace_back(this->_p.service_id, d, a, static_cast<buffer>(m), l);
        this->_p.m.set_reg(7, machine::host_call_res_t::ok);
    }

    template<typename CFG>
    void host_service_accumulate_t<CFG>::eject()
    {
        logger::trace("host_service::eject");
        const auto &phi = this->_p.m.regs();
        if (phi[7] > std::numeric_limits<service_id_t>::max()) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::who);
            return;
        }
        const auto d = static_cast<service_id_t>(phi[7]);
        const auto o = phi[8];
        opaque_hash_t h;
        this->_p.m.mem_read(h, o);
        auto d_info = this->_p.services.info_get(d);
        opaque_hash_t exp_code_hash{};
        memcpy(exp_code_hash.data(), &this->_p.service_id, sizeof(this->_p.service_id));
        if (!d_info || d_info->code_hash != exp_code_hash) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::who);
            return;
        }
        const auto l = numeric_cast<uint32_t>(std::max(size_t{81}, d_info->bytes) - size_t{81});
        const lookup_meta_map_key_t lk{static_cast<buffer>(h), l};
        const auto lookup_res = this->_p.services.lookup_get(d, lk);
        if (d_info->items != 2 || !lookup_res) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::huh);
            return;
        }
        if (lookup_res->size() == 2 && (*lookup_res)[1].slot() + CFG::D_preimage_expunge_delay < this->_p.slot.slot()) [[likely]] {
            auto info = this->_service_info();
            info.balance += d_info->balance;
            this->_p.services.info_set(this->_p.service_id, std::move(info));
            this->_p.services.preimage_erase(d, h);
            this->_p.services.lookup_erase(d, lk);
            this->_p.services.info_erase(d);
            this->_p.m.set_reg(7, machine::host_call_res_t::ok);
            return;
        }
        this->_p.m.set_reg(7, machine::host_call_res_t::huh);
    }

    template<typename CFG>
    void host_service_accumulate_t<CFG>::query()
    {
        const auto &phi = this->_p.m.regs();
        lookup_meta_map_key_t key;
        this->_p.m.mem_read(key.hash, phi[7]);
        key.length = static_cast<uint32_t>(phi[8]);
        logger::trace("host_service::query service: {} h: {} l: {}", this->_p.service_id, key.hash, key.length);
        const auto a = this->_p.services.lookup_get(this->_p.service_id, key);
        if (!a) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::none);
            this->_p.m.set_reg(8, 0ULL);
            return;
        }
        switch (a->size()) {
            case 0:
                this->_p.m.set_reg(7, 0ULL);
                this->_p.m.set_reg(8, 0ULL);
                break;
            case 1:
                this->_p.m.set_reg(7, 1ULL + (numeric_cast<machine::register_val_t>((*a)[0].slot()) << 32U));
                this->_p.m.set_reg(8, 0ULL);
                break;
            case 2:
                this->_p.m.set_reg(7, 2ULL + (numeric_cast<machine::register_val_t>((*a)[0].slot()) << 32U));
                this->_p.m.set_reg(8, numeric_cast<machine::register_val_t>((*a)[1].slot()));
                break;
            case 3:
                this->_p.m.set_reg(7, 3ULL + (numeric_cast<machine::register_val_t>((*a)[0].slot()) << 32U));
                this->_p.m.set_reg(8, numeric_cast<machine::register_val_t>((*a)[1].slot()) + (numeric_cast<machine::register_val_t>((*a)[2].slot()) << 32U));
                break;
            [[unlikely]] default:
                throw machine::exit_panic_t{};
        }
    }

    template<typename CFG>
    void host_service_accumulate_t<CFG>::solicit()
    {
        const auto &phi = this->_p.m.regs();
        lookup_meta_map_key_t key;
        this->_p.m.mem_read(key.hash, phi[7]);
        key.length = static_cast<uint32_t>(phi[8]);
        logger::trace("host_service::solicit service: {} h: {} l: {}", this->_p.service_id, key.hash, key.length);
        auto info = this->_service_info();
        auto a_res = this->_p.services.lookup_get(this->_p.service_id, key);
        if (!a_res) {
            this->_p.services.lookup_set(this->_p.service_id, key, {});
            info.items += 2;
            info.bytes += 81 + key.length;
            this->_p.services.info_set(this->_p.service_id, std::move(info));
        } else if (a_res->size() == 2) {
            a_res->emplace_back(this->_p.slot);
            this->_p.services.lookup_set(this->_p.service_id, key, std::move(*a_res));
        } else {
            this->_p.m.set_reg(7, machine::host_call_res_t::huh);
            return;
        }
        if (info.balance < info.threshold()) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::full);
            return;
        }
        this->_p.m.set_reg(7, machine::host_call_res_t::ok);
    }

    template<typename CFG>
    void host_service_accumulate_t<CFG>::forget()
    {
        const auto &phi = this->_p.m.regs();
        lookup_meta_map_key_t key;
        this->_p.m.mem_read(key.hash, phi[7]);
        key.length = static_cast<uint32_t>(phi[8]);
        logger::trace("host_service::forget service: {} h: {} l: {}", this->_p.service_id, key.hash, key.length);
        auto l_res = this->_p.services.lookup_get(this->_p.service_id, key);
        if (l_res && (l_res->size() == 0 || (l_res->size() == 2 && (*l_res)[1].slot() + CFG::D_preimage_expunge_delay < this->_p.slot.slot()))) {
            auto info = this->_service_info();
            info.items -= 2;
            info.bytes -= 81 + key.length;
            this->_p.services.info_set(this->_p.service_id, std::move(info));
            this->_p.services.lookup_erase(this->_p.service_id, key);
            this->_p.services.preimage_erase(this->_p.service_id, key.hash);
        } else if (l_res && l_res->size() == 1) {
            l_res->emplace_back(this->_p.slot);
            this->_p.services.lookup_set(this->_p.service_id, key, std::move(*l_res));
        } else if (l_res && l_res->size() == 3 && (*l_res)[1].slot() + CFG::D_preimage_expunge_delay < this->_p.slot.slot()) {
            this->_p.services.lookup_set(this->_p.service_id, key, {(*l_res)[2], this->_p.slot});
        } else {
            this->_p.m.set_reg(7, machine::host_call_res_t::huh);
            return;
        }
        this->_p.m.set_reg(7, machine::host_call_res_t::ok);
    }

    template<typename CFG>
    void host_service_accumulate_t<CFG>::yield()
    {
        logger::trace("host_service::yield");
        const auto &phi = this->_p.m.regs();
        const auto o = phi[7];
        _ok.result.emplace();
        this->_p.m.mem_read(*_ok.result, o);
        this->_p.m.set_reg(7, machine::host_call_res_t::ok);
    }

    template<typename CFG>
    void host_service_accumulate_t<CFG>::provide()
    {
        const auto &phi = this->_p.m.regs();
        const auto o = phi[7];
        const auto z = phi[8];
        auto i = this->_p.m.mem_read(o, z);
        const auto h = crypto::blake2b::digest<opaque_hash_t>(i);
        auto [s_id, a] = this->_get_service(phi[7]);
        logger::trace("host_service::provide service {}: h: {} l: {}", s_id, h, z);
        if (!a) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::who);
            return;
        }
        const lookup_meta_map_key_t key{static_cast<buffer>(h), static_cast<uint32_t>(z)};
        if (const auto l_res = this->_p.services.lookup_get(s_id, key); !l_res || !l_res->empty()) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::huh);
            return;
        }
        if (const auto p_res = this->_p.services.preimage_get(s_id, h); p_res) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::huh);
            return;
        }
        ++a->items;
        a->bytes += 32 + i.size();
        this->_p.services.info_set(s_id, std::move(*a));
        this->_p.services.preimage_set(s_id, h, std::move(i));
        this->_p.m.set_reg(7, machine::host_call_res_t::ok);
    }

    template struct host_service_base_t<config_prod>;
    template struct host_service_base_t<config_tiny>;

    template struct host_service_accumulate_t<config_prod>;
    template struct host_service_accumulate_t<config_tiny>;

    template struct host_service_on_transfer_t<config_prod>;
    template struct host_service_on_transfer_t<config_tiny>;
}
