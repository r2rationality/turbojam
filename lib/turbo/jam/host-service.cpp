/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025-2026 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <array>
#include <utility>
#include <turbo/common/logger.hpp>
#include "host-service.hpp"

namespace turbo::jam {
    using namespace std::string_view_literals;

    template<typename CFG>
    host_service_base_t<CFG>::host_service_base_t(host_service_params_t<CFG> params):
        _p{std::move(params)}
    {
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
            switch (static_cast<host_call_t>(id)) {
                case host_call_t::gas: return this->gas();
                case host_call_t::grow_heap: return this->grow_heap();
                case host_call_t::fetch: return this->fetch();
                case host_call_t::log: return this->log();
                [[unlikely]] default:
                    logger::trace("host_service::unknown");
                    this->_p.m.set_reg(7, machine::host_call_res_t::what);
                    this->_p.m.consume_gas(1000U);
                    break;
            }
        });
    }

    template<typename CFG>
    host_service_refine_t<CFG>::host_service_refine_t(host_service_params_t<CFG> params, const uint16_t export_offset):
        host_service_base_t<CFG>{std::move(params)},
        _export_offset{export_offset}
    {
        logger::trace("host service refine started");
    }

    template<typename CFG>
    [[nodiscard]] machine::host_call_res_t host_service_refine_t<CFG>::call(const machine::register_val_t id) noexcept
    {
        return this->_safe_call([&] {
            switch (static_cast<host_call_t>(id)) {
                // generic
                case host_call_t::gas: return this->gas();
                case host_call_t::grow_heap: return this->grow_heap();
                case host_call_t::fetch: return this->fetch();
                case host_call_t::log: return this->log();
                // refine specific
                case host_call_t::historical_lookup: return this->historical_lookup();
                case host_call_t::export_: return this->export_();
                case host_call_t::machine: return this->machine();
                case host_call_t::peek: return this->peek();
                case host_call_t::poke: return this->poke();
                case host_call_t::pages: return this->pages();
                case host_call_t::invoke: return this->invoke();
                case host_call_t::expunge: return this->expunge();
                [[unlikely]] default:
                    logger::trace("host_service::unknown");
                    this->_p.m.set_reg(7, machine::host_call_res_t::what);
                    this->_p.m.consume_gas(1000U);
                    break;
            }
        });
    }

    template <typename CFG>
    void host_service_refine_t<CFG>::historical_lookup() {
        const auto [s, h, o, f0, z] = this->_p.m.regs(std::index_sequence<7, 8, 9, 10, 11>{});
        logger::trace("gas: {} service: {} host_service::historical_lookup s: {} h: 0x{:x} o: 0x{:x} f0: {} z: {}",
            this->_p.m.gas(), this->_p.service_id, s, h, o, f0, z);
        this->_consume_octet_rated_gas(264U, z, 1125U);
        opaque_hash_t preimage_hash;
        static_assert(sizeof(preimage_hash) == 32U);
        this->_p.m.mem_read(preimage_hash, h);
        const auto [s_id, a] = this->_get_service(s);
        std::optional<buffer> v{};
        if (a) {
            v = this->_p.services.historical_lookup(s_id, this->_p.slot, preimage_hash);
        }
        if (v) {
            const auto f = std::min(f0, v->size());
            const auto l = std::min(z, v->size() - f);
            this->_write_memory(o, v->subbuf(f, l));
            this->_p.m.set_reg(7, v->size());
        } else {
            this->_p.m.set_reg(7, machine::host_call_res_t::none);
        }
    }

    template <typename CFG>
    void host_service_refine_t<CFG>::export_() {
        const auto [p, requested_size] = this->_p.m.regs(std::index_sequence<7, 8>{});
        logger::trace("gas: {} service: {} host_service::export p: 0x{:x} requested_size: {}",
            this->_p.m.gas(), this->_p.service_id, p, requested_size);
        this->_p.m.consume_gas(3521U);
        const auto z = std::min(requested_size, CFG::WG_segment_size);
        segment_t<CFG> x{};
        static_assert(sizeof(x) == CFG::WG_segment_size);
        this->_p.m.mem_read(std::span{x.begin(), x.begin() + z}, p);
        const auto new_export_offset = this->_export_offset + this->_exports.size();
        if (new_export_offset >= CFG::WX_max_package_exports) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::full);
        } else {
            this->_exports.emplace_back(std::move(x));
            this->_p.m.set_reg(7, new_export_offset);
        }
    }

    template <typename CFG>
    void host_service_refine_t<CFG>::machine() {
        const auto [po, pz, i] = this->_p.m.regs(std::index_sequence<7, 8, 9>{});
        logger::trace("gas: {} service: {} host_service::machine po: 0x{:x} pz: {} i: 0x{:x}",
            this->_p.m.gas(), this->_p.service_id, po, pz, i);
        this->_consume_octet_rated_gas(112U, pz, 1862U);
        if (this->_machines.size() >= 63U) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::full);
            return;
        }
        auto p = this->_p.m.mem_read(po, pz);
        std::unique_ptr<machine::machine_t> new_machine{};
        try {
            new_machine = std::make_unique<machine::machine_t>(
                machine::code_t::from_bytes(std::move(p)),
                machine::state_t{
                    .pc=numeric_cast<machine::address_val_t>(i)
                },
                machine::pages_t{}
            );
        } catch (...) {
            this->_p.m.set_reg(7, machine::host_call_res_t::huh);
            return;
        }
        const auto n = this->_machines.add(std::move(new_machine));
        this->_p.m.set_reg(7, n);
    }

    template <typename CFG>
    void host_service_refine_t<CFG>::peek() {
        const auto [n, o, s, z] = this->_p.m.regs(std::index_sequence<7, 8, 9, 10>{});
        logger::trace("gas: {} service: {} host_service::peek n: {} o: 0x{:x} s: 0x{:x} z: {}",
            this->_p.m.gas(), this->_p.service_id, n, o, s, z);
        this->_consume_octet_rated_gas(336U, z, 377U);
        if (auto ex = this->_p.m.mem_writable(o, z); ex) [[unlikely]]
            throw std::move(*ex);
        auto *m = this->_machines.find(n);
        if (!m) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::who);
            return;
        }
        if (const auto ex = m->mem_readable(s, z); ex) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::oob);
            return;
        }
        this->_p.m.mem_copy(*m, o, s, z);
        this->_p.m.set_reg(7, machine::host_call_res_t::ok);
    }

    template <typename CFG>
    void host_service_refine_t<CFG>::poke() {
        const auto [n, s, o, z] = this->_p.m.regs(std::index_sequence<7, 8, 9, 10>{});
        logger::trace("gas: {} service: {} host_service::poke n: {} s: 0x{:x} o: 0x{:x} z: {}",
            this->_p.m.gas(), this->_p.service_id, n, s, o, z);
        this->_consume_octet_rated_gas(224U, z, 297U);
        if (auto ex = this->_p.m.mem_readable(s, z); ex) [[unlikely]]
            throw std::move(*ex);
        auto *m = this->_machines.find(n);
        if (!m) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::who);
            return;
        }
        if (const auto ex = m->mem_writable(o, z); ex) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::oob);
            return;
        }
        m->mem_copy(this->_p.m, o, s, z);
        this->_p.m.set_reg(7, machine::host_call_res_t::ok);
    }

    template <typename CFG>
    void host_service_refine_t<CFG>::pages() {
        const auto [n, p, c, r] = this->_p.m.regs(std::index_sequence<7, 8, 9, 10>{});
        logger::trace("gas: {} service: {} host_service::pages n: {} p: {} c: {} r: {}",
            this->_p.m.gas(), this->_p.service_id, n, p, c, r);
        switch (r) {
            case 0: // free
                this->_consume_count_rated_gas(118ULL, c, 212ULL);
                break;
            // alloc
            case 1:
            case 2:
                this->_consume_count_rated_gas(121ULL, c, 275ULL);
                break;
            case 3:
            case 4:
                this->_consume_count_rated_gas(29ULL, c, 130ULL);
                break;
            [[unlikely]] default:
                this->_p.m.consume_gas(80ULL);
                break;
        }
        auto *m = this->_machines.find(n);
        if (!m) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::who);
            return;
        }
        if (r > 4U || p < 16U || p + c < p || p + c >= (machine::register_val_t{1} << 32U) / CFG::ZP_pvm_page_size) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::huh);
            return;
        }
        if (r > 2U && m->mem_readable(p * CFG::ZP_pvm_page_size, c * CFG::ZP_pvm_page_size)) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::huh);
            return;
        }
        if (!m->set_pages(p, c, machine::page_init_method_t::from_code(r))) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::huh);
            return;
        }
        this->_p.m.set_reg(7, machine::host_call_res_t::ok);
    }

    template <typename CFG>
    void host_service_refine_t<CFG>::invoke() {
        const auto [n, o] = this->_p.m.regs(std::index_sequence<7, 8>{});
        logger::trace("gas: {} service: {} host_service::invoke n: {} o: 0x{:x}",
            this->_p.m.gas(), this->_p.service_id, n, o);
        this->_p.m.consume_gas(968U);
        if (auto ex = this->_p.m.mem_writable(o, 112U); ex) [[unlikely]]
            throw std::move(*ex);
        auto raw_args = this->_p.m.mem_read(o, 112U);
        decoder dec{raw_args};
        gas_t g;
        dec.process(g);
        this->_p.m.consume_gas(g);
        auto *m = this->_machines.find(n);
        if (!m) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::who);
            return;
        }
        {
            m->set_gas(g);
            machine::registers_t w;
            dec.process(w);
            m->set_regs(w);
        }
        const auto res = m->run();
        this->_p.m.set_gas(this->_p.m.gas() + m->gas());
        {
            encoder enc{};
            // reuse the previously allocated buffer
            raw_args.clear();
            enc.bytes() = std::move(raw_args);
            enc.process(m->gas());
            enc.process(m->regs());
            this->_write_memory(o, enc.bytes());
        }
        const auto ret = std::visit([&](const auto &rv) -> machine::register_val_t {
            using T = std::decay_t<decltype(rv)>;
            if constexpr (std::is_same_v<T, machine::exit_host_call_t>) {
                m->skip_op();
                this->_p.m.set_reg(8, rv.id);
                return machine::inner_pvm_res_t::host;
            } else if constexpr (std::is_same_v<T, machine::exit_page_fault_t>) {
                this->_p.m.set_reg(8, rv.addr);
                return machine::inner_pvm_res_t::fault;
            } else if constexpr (std::is_same_v<T, machine::exit_out_of_gas_t>) {
                return machine::inner_pvm_res_t::oog;
            } else if constexpr (std::is_same_v<T, machine::exit_panic_t>) {
                return machine::inner_pvm_res_t::panic;
            } else if constexpr (std::is_same_v<T, machine::exit_halt_t>) {
                return machine::inner_pvm_res_t::halt;
            } else {
                throw error(fmt::format("internal PVM invoke: unsupported result type: {}", typeid(rv).name()));
            }
        }, res);
        this->_p.m.set_reg(7, ret);
    }

    template <typename CFG>
    void host_service_refine_t<CFG>::expunge() {
        const auto [n] = this->_p.m.regs(std::index_sequence<7>{});
        logger::trace("gas: {} service: {} host_service::expunge n: {}",
            this->_p.m.gas(), this->_p.service_id, n);
        this->_p.m.consume_gas(335ULL);
        const auto pc = this->_machines.erase(n);
        if (!pc) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::who);
            return;
        }
        this->_p.m.set_reg(7, *pc);
    }

    template <typename CFG>
    service_info_t<CFG> host_service_base_t<CFG>::_service_info() const {
        auto info = this->_p.services.info_get(this->_p.service_id);
        if (!info) [[unlikely]]
            throw machine::exit_panic_t{};
        return std::move(*info);
    }

    template<typename CFG>
    host_service_base_t<CFG>::service_lookup_res_t host_service_base_t<CFG>::_get_service(machine::register_val_t id)
    {
        if (id == std::numeric_limits<machine::register_val_t>::max())
            id = _p.service_id;
        if (id > std::numeric_limits<service_id_t>::max()) [[unlikely]]
            return {static_cast<service_id_t>(id), {}};
        return {static_cast<service_id_t>(id), _p.services.info_get(id)};
    }

    template<typename CFG>
    void host_service_base_t<CFG>::gas()
    {
        logger::trace("gas: {} service: {} host_service::gas", this->_p.m.gas(), this->_p.service_id);
        _p.m.consume_gas(48U);
        _p.m.set_reg(7, _p.m.gas());
    }

    template<typename CFG>
    void host_service_base_t<CFG>::grow_heap()
    {
        const auto [new_heap_end] = this->_p.m.regs(std::index_sequence<7>{});
        logger::trace("gas: {} service: {} host_service::grow_heap new_heap_end: {}",
            this->_p.m.gas(), this->_p.service_id, new_heap_end);
        this->_p.m.consume_gas(275ULL);
        const auto bounds = this->_p.m.heap_bounds();
        if (new_heap_end <= bounds.current || new_heap_end > bounds.maximum) [[unlikely]] {
            this->_p.m.set_reg(7, bounds.current);
            return;
        }
        // cannot overflow because addresses are 32-bit
        this->_p.m.consume_gas(static_cast<gas_t>(new_heap_end - bounds.current) * 121ULL);
        static_cast<void>(this->_p.m.grow_heap(new_heap_end));
    }

    template<typename CFG>
    void host_service_base_t<CFG>::fetch()
    {
        const auto [o, f0, z, kind, index, subindex] = this->_p.m.regs(std::index_sequence<7, 8, 9, 10, 11, 12>{});
        logger::trace("gas: {} service: {} host_service::fetch o: 0x{:x} f0: {} z: {} kind: {} index: {} subindex: {}",
            this->_p.m.gas(), this->_p.service_id, o, f0, z, kind, index, subindex);
        static constexpr std::array<std::pair<uint32_t, uint32_t>, 16> gas_costs{{
            {390U, 0U}, {103U, 0U}, {80U, 96U}, {85U, 96U},
            {85U, 96U}, {171U, 0U}, {171U, 0U}, {85U, 96U},
            {84U, 0U}, {88U, 0U}, {111U, 0U}, {317U, 0U},
            {250U, 0U}, {95U, 96U}, {287U, 400U}, {355U, 344U}
        }};
        const auto [base_cost, octet_rate] = kind < gas_costs.size() ? gas_costs[kind] : std::pair{80U, 0U};
        this->_consume_octet_rated_gas(octet_rate, z, base_cost);
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
        std::optional<uint8_vector> v {};
        switch (kind) {
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
                enc.uint_fixed(2, CFG::O_auth_pool_max_size);
                enc.uint_fixed(2, CFG::P_slot_period);
                enc.uint_fixed(2, CFG::Q_auth_queue_size);
                enc.uint_fixed(2, CFG::R_core_assignment_rotation_period);
                enc.uint_fixed(2, CFG::T_max_package_extrinsics);
                enc.uint_fixed(2, CFG::U_reported_work_timeout);
                enc.uint_fixed(4, CFG::WA_max_is_authorized_code_size);
                enc.uint_fixed(4, CFG::WI_max_work_package_input_size);
                enc.uint_fixed(4, CFG::WC_max_service_code_size);
                enc.uint_fixed(4, CFG::WM_max_work_package_imports);
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
                if (_p.fetch.auth_output) {
                    v.emplace(*_p.fetch.auth_output);
                }
                break;
            case 3:
                if (_p.fetch.extrinsics && index < _p.fetch.extrinsics->size() && subindex < (*_p.fetch.extrinsics)[index].size()) {
                    v.emplace((*_p.fetch.extrinsics)[index][subindex]);
                }
                break;
            case 4:
                if (_p.fetch.extrinsics && _p.fetch.refined_item_index
                        && *_p.fetch.refined_item_index < _p.fetch.extrinsics->size()
                        && index < (*_p.fetch.extrinsics)[*_p.fetch.refined_item_index].size()) {
                    v.emplace((*_p.fetch.extrinsics)[*_p.fetch.refined_item_index][index]);
                }
                break;
            case 5:
                if (_p.fetch.imports && index < _p.fetch.imports->size()
                        && subindex < (*_p.fetch.imports)[index].size())
                    v.emplace((*_p.fetch.imports)[index][subindex]);
                break;
            case 6:
                if (_p.fetch.imports && _p.fetch.refined_item_index
                        && *_p.fetch.refined_item_index < _p.fetch.imports->size()
                        && index < (*_p.fetch.imports)[*_p.fetch.refined_item_index].size())
                    v.emplace((*_p.fetch.imports)[*_p.fetch.refined_item_index][index]);
                break;
            case 7:
                if (_p.fetch.package) {
                    encoder enc { *_p.fetch.package };
                    v.emplace(std::move(enc.bytes()));
                }
                break;
            case 8:
                if (_p.fetch.package) {
                    v.emplace(_p.fetch.package->authorizer_config);
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
                if (_p.fetch.package && index < _p.fetch.package->items.size()) {
                    encoder enc {};
                    s_func(enc, _p.fetch.package->items[index]);
                    v.emplace(std::move(enc.bytes()));
                }
                break;
            case 13:
                if (_p.fetch.package && _p.fetch.package->items.size() > index) {
                    v.emplace(_p.fetch.package->items[index].payload);
                }
                break;
            case 14:
                if (_p.fetch.inputs) {
                    encoder enc {*_p.fetch.inputs};
                    v.emplace(std::move(enc.bytes()));
                }
                break;
            case 15:
                if (_p.fetch.inputs && index < _p.fetch.inputs->size()) {
                    encoder enc{(*_p.fetch.inputs)[index]};
                    v.emplace(std::move(enc.bytes()));
                }
                break;
            default:
                break;
        }
        if (v) {
            const auto f = std::min(f0, v->size());
            const auto l = std::min(z, v->size() - f);
            this->_write_memory(o, static_cast<buffer>(*v).subbuf(f, l));
            _p.m.set_reg(7, v->size());
        } else {
            _p.m.set_reg(7, machine::host_call_res_t::none);
        }
    }

    template<typename CFG>
    void host_service_base_t<CFG>::lookup()
    {
        const auto [s, h, o, f0, z] = this->_p.m.regs(std::index_sequence<7, 8, 9, 10, 11>{});
        logger::trace("gas: {} service: {} host_service::lookup s: {} h: 0x{:x} o: 0x{:x} f0: {} z: {}",
            this->_p.m.gas(), this->_p.service_id, s, h, o, f0, z);
        this->_consume_octet_rated_gas(248U, z, 600U);
        const auto [s_id, a] = _get_service(s);
        const opaque_hash_t key{_p.m.mem_read(h, 32)};
        std::optional<uint8_vector> val{};
        if (a) {
            val = _p.services.preimage_get(s_id, key);
        }
        if (val) {
            const auto f = std::min(f0, val->size());
            const auto l = std::min(z, val->size() - f);
            this->_write_memory(o, static_cast<buffer>(*val).subbuf(f, l));
            _p.m.set_reg(7, val->size());
        } else {
            _p.m.set_reg(7, machine::host_call_res_t::none);
        }
    }

    template<typename CFG>
    void host_service_base_t<CFG>::read() {
        const auto [s, ko, kz, o, f0, vz] = this->_p.m.regs(std::index_sequence<7, 8, 9, 10, 11, 12>{});
        logger::trace("gas: {} service: {} host_service::read s: {} ko: 0x{:x} kz: {} o: 0x{:x} f0: {} vz: {}",
            this->_p.m.gas(), this->_p.service_id, s, ko, kz, o, f0, vz);
        this->_consume_octet_rated_gas(1736U, kz, 2407U);
        this->_consume_octet_rated_gas(248U, vz);
        const auto [s_id, a] = _get_service(s);
        const auto key = _p.m.mem_read(ko, kz);
        std::optional<uint8_vector> val {};
        if (a) {
            val = _p.services.storage_get(s_id, key);
        }
        if (val) {
            const auto f = std::min(f0, val->size());
            const auto l = std::min(vz, val->size() - f);
            this->_write_memory(o, static_cast<buffer>(*val).subbuf(f, l));
            _p.m.set_reg(7, val->size());
        } else {
            _p.m.set_reg(7, machine::host_call_res_t::none);
        }
    }

    template<typename CFG>
    void host_service_base_t<CFG>::write() {
        const auto [ko, kz, vo, vz] = this->_p.m.regs(std::index_sequence<7, 8, 9, 10>{});
        logger::trace("gas: {} service: {} host_service::write ko: 0x{:x} kz: {} vo: 0x{:x} vz: {}",
            this->_p.m.gas(), this->_p.service_id, ko, kz, vo, vz);
        this->_consume_octet_rated_gas(3358U, kz, 2442U);
        this->_consume_octet_rated_gas(216U, vz);
        const auto key = _p.m.mem_read(ko, kz);
        const auto val_data = _p.m.mem_read(vo, vz);
        const auto set_res = _p.services.storage_set(_p.service_id, key, std::move(val_data));
        if (set_res.ok) {
            _p.m.set_reg(7, set_res.prev_size.value_or(machine::host_call_res_t::none));
        } else {
            _p.m.set_reg(7, machine::host_call_res_t::full);
        }
    }

    template<typename CFG>
    void host_service_base_t<CFG>::info()
    {
        const auto [s, o, f0, z] = this->_p.m.regs(std::index_sequence<7, 8, 9, 10>{});
        logger::trace("gas: {} service: {} host_service::info s: {} o: 0x{:x} f0: {} z: {}",
            this->_p.m.gas(), this->_p.service_id, s, o, f0, z);
        _p.m.consume_gas(703U);
        const auto [a_id, a] = _get_service(s);
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
            const auto f = std::min(f0, v->size());
            const auto l = std::min(z, v->size() - f);
            this->_write_memory(o, static_cast<buffer>(*v).subbuf(f, l));
            _p.m.set_reg(7, v->size());
        } else {
            _p.m.set_reg(7, machine::host_call_res_t::none);
        }
    }

    template<typename CFG>
    void host_service_base_t<CFG>::log()
    {
        const auto [level, target_offset, target_size, message_offset, message_size] = this->_p.m.regs(std::index_sequence<7, 8, 9, 10, 11>{});
        logger::trace("gas: {} service: {} host_service::log level: {} target_offset: 0x{:x} target_size: {} message_offset: 0x{:x} message_size: {}",
            this->_p.m.gas(), this->_p.service_id, level, target_offset, target_size, message_offset, message_size);
        this->_p.m.consume_gas(1000U);
        std::optional<std::string> target {};
        if (target_offset != 0 || target_size != 0)
            target.emplace(_p.m.mem_read(target_offset, target_size).str());
        const auto msg = _p.m.mem_read(message_offset, message_size);
        logger::trace("gas: {} host_service::log target={} level={}: {}", this->_p.m.gas(), target.value_or("default"), level, msg.str());
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
            switch (static_cast<host_call_t>(id)) {
                // generic
                case host_call_t::gas: return this->gas();
                case host_call_t::grow_heap: return this->grow_heap();
                case host_call_t::fetch: return this->fetch();
                case host_call_t::read: return this->read();
                case host_call_t::write: return this->write();
                case host_call_t::lookup: return this->lookup();
                case host_call_t::info: return this->info();
                // accumulate-specific
                case host_call_t::bless: return this->bless();
                case host_call_t::assign: return this->assign();
                case host_call_t::designate: return this->designate();
                case host_call_t::checkpoint: return this->checkpoint();
                case host_call_t::new_: return this->new_();
                case host_call_t::upgrade: return this->upgrade();
                case host_call_t::transfer: return this->transfer();
                case host_call_t::eject: return this->eject();
                case host_call_t::query: return this->query();
                case host_call_t::solicit: return this->solicit();
                case host_call_t::forget: return this->forget();
                case host_call_t::yield: return this->yield();
                case host_call_t::provide: return this->provide();
                case host_call_t::log: return this->log();
                [[unlikely]] default:
                    logger::trace("host_service::unknown");
                    this->_p.m.set_reg(7, machine::host_call_res_t::what);
                    this->_p.m.consume_gas(1000U);
                    break;
            }
        });
    }

    // Temporary jam-test-vectors compatibility:
    // CHANGELOG.md documents permissive bless until GP #519/#558 adoption.
    template<typename CFG>
    void host_service_accumulate_t<CFG>::bless()
    {
        const auto [m, a, v, r, o, n] = this->_p.m.regs(std::index_sequence<7, 8, 9, 10, 11, 12>{});
        logger::trace("gas: {} service: {} host_service::bless m: {} a: 0x{:x} v: {} r: {} o: 0x{:x} n: {}",
            this->_p.m.gas(), this->_p.service_id, m, a, v, r, o, n);
        this->_consume_count_rated_gas(20ULL, n, 422ULL);

        auto new_chi = _ok.state.chi.get();
        const auto assign_bytes = this->_p.m.mem_read(a, 4 * CFG::C_core_count);
        new_chi.assign = jam::from_bytes<assigners_t<CFG>>(assign_bytes);

        if (n > std::numeric_limits<machine::register_val_t>::max() / 12U) [[unlikely]]
            throw machine::exit_page_fault_t{std::numeric_limits<machine::address_val_t>::max()};

        const auto acc_bytes = this->_p.m.mem_read(o, n * 12U);
        decoder dec{acc_bytes};
        new_chi.always_acc.clear();
        new_chi.always_acc.reserve(n);
        for (size_t i = 0; i < n; ++i) {
            const auto s = dec.uint_fixed<service_id_t>(4);
            const auto g = dec.uint_fixed<gas_t>(8);
            new_chi.always_acc.emplace_hint(new_chi.always_acc.end(), s, g);
        }

        if (std::max(std::max(m, v), r) > std::numeric_limits<service_id_t>::max()) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::who);
            return;
        }

        new_chi.bless = static_cast<service_id_t>(m);
        new_chi.designate = static_cast<service_id_t>(v);
        new_chi.registrar = static_cast<service_id_t>(r);
        _ok.state.chi.set(std::move(new_chi));
        this->_p.m.set_reg(7, machine::host_call_res_t::ok);
    }

    template<typename CFG>
    void host_service_accumulate_t<CFG>::assign()
    {
        const auto [c, o, a] = this->_p.m.regs(std::index_sequence<7, 8, 9>{});
        logger::trace("gas: {} service: {} host_service::assign c: {} o: 0x{:x} a: {}", this->_p.m.gas(), this->_p.service_id, c, o, a);
        this->_p.m.consume_gas(1818U);
        const auto q_bytes = this->_p.m.mem_read(o, 32 * CFG::Q_auth_queue_size);
        const auto q = jam::from_bytes<auth_queue_t<CFG>>(q_bytes);
        if (c >= CFG::C_core_count) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::core);
            return;
        }
        if (this->_p.service_id != _ok.state.chi.get().assign[c]) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::huh);
            return;
        }
        if (a > std::numeric_limits<service_id_t>::max()) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::who);
            return;
        }
        _ok.state.phi[c] = q;
        _ok.state.chi.update().assign[c] = a;
        this->_p.m.set_reg(7, machine::host_call_res_t::ok);
    }

    template<typename CFG>
    void host_service_accumulate_t<CFG>::designate()
    {
        const auto [o, z] = this->_p.m.regs(std::index_sequence<7, 8>{});
        logger::trace("gas: {} service: {} host_service::designate o: 0x{:x} z: {}",
            this->_p.m.gas(), this->_p.service_id, o, z);
        this->_consume_count_rated_gas(302U, z, 1100ULL);
        static_assert(sizeof(validator_data_t) == 336U);
        if (z > std::numeric_limits<machine::register_val_t>::max() / sizeof(validator_data_t)) [[unlikely]]
            throw machine::exit_page_fault_t{std::numeric_limits<machine::address_val_t>::max()};
        const auto bytes = this->_p.m.mem_read(o, sizeof(validator_data_t) * z);
        if (static_cast<int>(z < CFG::V_validator_count_min) | static_cast<int>(z > CFG::V_validator_count_max)
                | static_cast<int>(z % CFG::validator_factor != 0)) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::huh);
            return;
        }
        if (this->_p.service_id != _ok.state.chi.get().designate) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::huh);
            return;
        }
        {
            typename validators_data_t<CFG>::storage_type new_iota{};
            new_iota.reserve(z);
            decoder dec{bytes};
            while (new_iota.size() < z) {
                validator_data_t v;
                dec.process(v);
                new_iota.emplace_back(std::move(v));
            }
            _ok.state.iota = std::make_shared<validators_data_t<CFG>>(std::move(new_iota));
        }
        this->_p.m.set_reg(7, machine::host_call_res_t::ok);
    }

    template<typename CFG>
    void host_service_accumulate_t<CFG>::checkpoint()
    {
        logger::trace("gas: {} service: {} host_service::checkpoint", this->_p.m.gas(), this->_p.service_id);
        this->_p.m.consume_gas(103U);
        _err = _ok;
        this->_p.m.set_reg(7, this->_p.m.gas());
    }

    template<typename CFG>
    void host_service_accumulate_t<CFG>::new_()
    {
        const auto [o, l, g, m, f, i] = this->_p.m.regs(std::index_sequence<7, 8, 9, 10, 11, 12>{});
        logger::trace("gas: {} service: {} host_service::new o: 0x{:x} l: {} g: {} m: {} f: {} i: {}",
            this->_p.m.gas(), this->_p.service_id, o, l, g, m, f, i);
        this->_p.m.consume_gas(3855U);

        if (l > std::numeric_limits<uint32_t>::max()) [[unlikely]]
            throw machine::exit_panic_t{};
        const auto c = this->_p.m.mem_read(o, 32);

        service_info_t<CFG> a {
            .code_hash=static_cast<buffer>(c),
            .min_item_gas=g,
            .min_memo_gas=m,
            .bytes=uint64_t{81} + l,
            .deposit_offset=f,
            .items=2,
            .creation_slot=this->_p.slot,
            .parent_service=this->_p.service_id
        };
        a.balance = a.threshold();

        if  (f != 0 && this->_p.service_id != _ok.state.chi.get().bless) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::huh);
            return;
        }

        auto info = this->_service_info();
        // the two checks are separated to prevent numerical underflow in the substraction
        if (info.balance < a.balance || info.balance - a.balance < info.threshold()) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::cash);
            return;
        }
        info.balance -= a.balance;
        auto created_id = _ok.new_service_id;
        if (this->_p.service_id == _ok.state.chi.get().registrar && i < CFG::S_min_public_service_index) {
            // The registrar's requested ID is checked against the current invocation state.
            if (this->_p.services.contains(i)) [[unlikely]] {
                this->_p.m.set_reg(7, machine::host_call_res_t::full);
                return;
            }
            created_id = i;
        } else {
            _ok.new_service_id = _ok.check(_ok.gen_new_service_id(_ok.new_service_id - CFG::S_min_public_service_index + 42U));
        }

        // commit the updated balance of the current service
        this->_p.services.info_set(this->_p.service_id, std::move(info));
        this->_p.services.info_set(created_id, std::move(a));
        this->_p.services.lookup_set(created_id, lookup_meta_map_key_t{static_cast<buffer>(c), static_cast<uint32_t>(l)}, lookup_meta_map_val_t<CFG>{});
        _ok.new_ids.emplace(created_id);
        this->_p.m.set_reg(7, created_id);
    }

    template<typename CFG>
    void host_service_accumulate_t<CFG>::upgrade()
    {
        const auto [o, g, m] = this->_p.m.regs(std::index_sequence<7, 8, 9>{});
        logger::trace("gas: {} service: {} host_service::upgrade o: 0x{:x} g: {} m: {}",
            this->_p.m.gas(), this->_p.service_id, o, g, m);
        this->_p.m.consume_gas(1028ULL);
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
        const auto [d_raw, a, l, o] = this->_p.m.regs(std::index_sequence<7, 8, 9, 10>{});
        logger::trace("gas: {} service: {} host_service::transfer d_raw: {} a: {} l: {} o: 0x{:x}",
            this->_p.m.gas(), this->_p.service_id, d_raw, a, l, o);
        this->_p.m.consume_gas(575ULL);
        const auto m = this->_p.m.mem_read(o, sizeof(deferred_transfer_metadata_t<CFG>));
        if (d_raw > std::numeric_limits<service_id_t>::max()) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::who);
            return;
        }
        const auto d = static_cast<service_id_t>(d_raw);
        const auto d_info = this->_p.services.info_get(d);
        if (!d_info) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::who);
            return;
        }
        auto info = this->_service_info();
        if (l < d_info->min_memo_gas) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::low);
            return;
        }
        // the two checks are separated to prevent numerical underflow in the substraction
        if (info.balance < a || info.balance - a < info.threshold()) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::cash);
            return;
        }
        this->_p.m.consume_gas(l);
        info.balance -= a;
        this->_p.services.info_set(this->_p.service_id, std::move(info));
        _ok.transfers.emplace_back(this->_p.service_id, d, a, static_cast<buffer>(m), l);
        this->_p.m.set_reg(7, machine::host_call_res_t::ok);
    }

    template<typename CFG>
    void host_service_accumulate_t<CFG>::eject()
    {
        const auto [d, o] = this->_p.m.regs(std::index_sequence<7, 8>{});
        logger::trace("gas: {} service: {} host_service::eject d: {} o: 0x{:x}", this->_p.m.gas(), this->_p.service_id, d, o);
        this->_p.m.consume_gas(458U);
        opaque_hash_t h;
        this->_p.m.mem_read(h, o);
        std::optional<service_info_t<CFG>> d_info{};
        if (d <= std::numeric_limits<service_id_t>::max()) [[likely]]
            d_info = this->_p.services.info_get(d);
        opaque_hash_t exp_code_hash{};
        memcpy(exp_code_hash.data(), &this->_p.service_id, sizeof(this->_p.service_id));
        if (d == this->_p.service_id || !d_info || d_info->code_hash != exp_code_hash) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::who);
            return;
        }
        const auto l = std::max(uint64_t{81}, d_info->bytes) - uint64_t{81};
        if (d_info->items != 2 || l > std::numeric_limits<decltype(lookup_meta_map_key_t::length)>::max()) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::huh);
            return;
        }
        const lookup_meta_map_key_t lk{static_cast<buffer>(h), static_cast<uint32_t>(l)};
        const auto lookup_res = this->_p.services.lookup_get(d, lk);
        if (!lookup_res) [[unlikely]] {
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
            _ok.ejected_ids.emplace(d);
            this->_p.m.set_reg(7, machine::host_call_res_t::ok);
            return;
        }
        this->_p.m.set_reg(7, machine::host_call_res_t::huh);
    }

    template<typename CFG>
    void host_service_accumulate_t<CFG>::query()
    {
        const auto [o, z] = this->_p.m.regs(std::index_sequence<7, 8>{});
        logger::trace("gas: {} service: {} host_service::query o: 0x{:x} z: {}", this->_p.m.gas(), this->_p.service_id, o, z);
        this->_p.m.consume_gas(643ULL);
        lookup_meta_map_key_t key;
        if (z > std::numeric_limits<decltype(key.length)>::max()) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::huh);
            return;
        }
        this->_p.m.mem_read(key.hash, o);
        key.length = static_cast<uint32_t>(z);
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
        const auto [o, z] = this->_p.m.regs(std::index_sequence<7, 8>{});
        logger::trace("gas: {} service: {} host_service::solicit o: 0x{:x} z: {}", this->_p.m.gas(), this->_p.service_id, o, z);
        this->_p.m.consume_gas(2193ULL);
        lookup_meta_map_key_t key;
        if (z > std::numeric_limits<decltype(key.length)>::max()) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::huh);
            return;
        }
        this->_p.m.mem_read(key.hash, o);
        key.length = static_cast<uint32_t>(z);
        auto info = this->_service_info();
        auto a_res = this->_p.services.lookup_get(this->_p.service_id, key);
        if (!a_res) {
            const auto add_ok = info.add_items(2U) && info.add_bytes(81U) && info.add_bytes(key.length);
            if (!add_ok) [[unlikely]] {
                this->_p.m.set_reg(7, machine::host_call_res_t::full);
                return;
            }
            this->_p.services.lookup_set(this->_p.service_id, key, {});
            this->_p.services.info_set(this->_p.service_id, std::move(info));
        } else if (a_res->size() == 2) {
            a_res->emplace_back(this->_p.slot);
            this->_p.services.lookup_set(this->_p.service_id, key, std::move(*a_res));
        } else {
            this->_p.m.set_reg(7, machine::host_call_res_t::huh);
            return;
        }
        this->_p.m.set_reg(7, machine::host_call_res_t::ok);
    }

    template<typename CFG>
    void host_service_accumulate_t<CFG>::forget()
    {
        const auto [o, z] = this->_p.m.regs(std::index_sequence<7, 8>{});
        logger::trace("gas: {} service: {} host_service::forget o: 0x{:x} z: {}", this->_p.m.gas(), this->_p.service_id, o, z);
        this->_p.m.consume_gas(3250U);
        lookup_meta_map_key_t key;
        if (z > std::numeric_limits<decltype(key.length)>::max()) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::huh);
            return;
        }
        this->_p.m.mem_read(key.hash, o);
        key.length = static_cast<uint32_t>(z);
        auto l_res = this->_p.services.lookup_get(this->_p.service_id, key);
        if (l_res && (l_res->size() == 0 || (l_res->size() == 2 && (*l_res)[1].slot() + CFG::D_preimage_expunge_delay < this->_p.slot.slot()))) {
            auto info = this->_service_info();
            // this branch is activated only in the case of a numerical underflow and should never happen
            if (!(info.del_items(2U) && info.del_bytes(81U) && info.del_bytes(key.length))) [[unlikely]] {
                this->_p.m.set_reg(7, machine::host_call_res_t::huh);
                return;
            }
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
        const auto [o] = this->_p.m.regs(std::index_sequence<7>{});
        logger::trace("gas: {} service: {} host_service::yield o: 0x{:x}", this->_p.m.gas(), this->_p.service_id, o);
        this->_p.m.consume_gas(98ULL);
        opaque_hash_t h;
        this->_p.m.mem_read(h, o);
        _ok.result = std::move(h);
        this->_p.m.set_reg(7, machine::host_call_res_t::ok);
    }

    template<typename CFG>
    void host_service_accumulate_t<CFG>::provide()
    {
        const auto [s, o, z] = this->_p.m.regs(std::index_sequence<7, 8, 9>{});
        logger::trace("gas: {} service: {} host_service::provide s: {} o: 0x{:x} z: {}",
            this->_p.m.gas(), this->_p.service_id, s, o, z);
        this->_consume_octet_rated_gas(2264U, z, 3980U);
        if (z > std::numeric_limits<decltype(lookup_meta_map_key_t::length)>::max()) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::huh);
            return;
        }
        auto i = this->_p.m.mem_read(o, z);
        auto [s_id, a] = this->_get_service(s);
        if (!a) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::who);
            return;
        }
        const auto h = crypto::blake2b::digest<opaque_hash_t>(i);
        const lookup_meta_map_key_t key{static_cast<buffer>(h), static_cast<uint32_t>(z)};
        if (const auto l_res = this->_p.services.lookup_get(s_id, key); !l_res || !l_res->empty()) [[unlikely]] {
            this->_p.m.set_reg(7, machine::host_call_res_t::huh);
            return;
        }
        const auto [range_begin, range_end] = _ok.provisions.equal_range(s_id);
        for (auto it = range_begin; it != range_end; ++it) {
            if (it->second == i) [[unlikely]] {
                this->_p.m.set_reg(7, machine::host_call_res_t::huh);
                return;
            }
        }
        _ok.provisions.emplace(s_id, std::move(i));
        this->_p.m.set_reg(7, machine::host_call_res_t::ok);
    }

    template struct host_service_base_t<config_prod>;
    template struct host_service_base_t<config_tiny>;
    template struct host_service_base_t<config_fuzz>;

    template struct host_service_accumulate_t<config_prod>;
    template struct host_service_accumulate_t<config_tiny>;
    template struct host_service_accumulate_t<config_fuzz>;

    template struct host_service_is_authorized_t<config_prod>;
    template struct host_service_is_authorized_t<config_tiny>;
    template struct host_service_is_authorized_t<config_fuzz>;

    template struct host_service_refine_t<config_prod>;
    template struct host_service_refine_t<config_tiny>;
    template struct host_service_refine_t<config_fuzz>;
} // namespace turbo::jam
