/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <boost/container/flat_map.hpp>
#include "machine.hpp"

namespace turbo::jam::machine {
    struct machine_t::impl {
        explicit impl(const program_t &program, const state_t &init, const pages_t &page_map):
            _program { program },
            _regs { init.regs },
            _pc { init.pc },
            _gas { init.gas }
        {
            _pages.reserve(page_map.size());
            for (const auto &page: page_map) {
                const auto page_id = page.address / config_prod::pvm_page_size;
                const auto cnt = page.length / config_prod::pvm_page_size;
                for (size_t i = 0; i < cnt; i++) {
                    const auto p_it = _pages.emplace_hint(_pages.end(), page_id + i, page_info_t {
                        std::make_unique<uint8_t[]>(config_prod::pvm_page_size),
                        page.is_writable
                    });
                    memset(p_it->second.data.get(), 0, config_prod::pvm_page_size);
                }
            }
            for (const auto &mc: init.memory) {
                size_t addr = mc.address;
                for (const auto &b: mc.contents) {
                    _store_unsigned_init(addr++, b);
                }
            }
        }

        result_t run()
        {
            try {
                for (;;) {
                    if (!_program.bitmasks.test(_pc)) [[unlikely]]
                        throw exit_panic_t {};
                    const uint8_t opcode = _program.code.at(_pc);
                    const auto len = _skip_len(_pc, _program.bitmasks);
                    const auto data = _program.code.subbuf(_pc + 1, len);
                    const auto res = _exec(opcode, data);
                    _pc = res.new_pc.value_or(_pc + len + 1);
                    _gas -= res.gas_used;
                }
            } catch (exit_halt_t &&ex) {
                return { std::move(ex) };
            } catch (exit_panic_t &&ex) {
                return { std::move(ex) };
            } catch (exit_page_fault_t &&ex) {
                return { std::move(ex) };
            } catch (exit_out_of_gas_t &&ex) {
                return { std::move(ex) };
            } catch (exit_host_call_t &&ex) {
                return { std::move(ex) };
            } catch (...) {
                return { exit_panic_t {} };
            }
        }

        state_t state() const
        {
            memory_chunks_t mem {};
            memory_chunk_t chunk {};
            const auto flush_chunk = [&chunk, &mem](const register_val_t page_base, const size_t off) {
                if (!chunk.contents.empty()) {
                    chunk.address = numeric_cast<uint32_t>(page_base + off - chunk.contents.size());
                    mem.emplace_back(std::move(chunk));
                    chunk.contents.clear();
                }
            };
            for (const auto &[page_id, info]: _pages) {
                const register_val_t page_base = page_id * config_prod::pvm_page_size;
                for (size_t off = 0; off < config_prod::pvm_page_size; ++off) {
                    const auto b = info.data[off];
                    if (b) {
                        chunk.contents.emplace_back(b);
                    } else {
                        flush_chunk(page_base, off);
                    }
                }
                flush_chunk(page_base, config_prod::pvm_page_size);
            }
            return {
                _regs,
                _pc,
                _gas,
                std::move(mem)
            };
        }
    private:
        struct page_info_t {
            std::unique_ptr<uint8_t[]> data;
            bool is_writable = false;
        };

        using page_map_t = boost::container::flat_map<register_val_t, page_info_t>;

        const program_t &_program;
        fixed_sequence_t<uint64_t, 13> _regs {};
        uint32_t _pc {};
        int64_t _gas = 0;
        page_map_t _pages;

        struct op_res_t {
            std::optional<register_val_t> new_pc {};
            gas_remaining_t gas_used = 0;
        };

        static size_t _skip_len(const register_val_t opcode_pc, const bit_buffer_t &bitmasks)
        {
            const auto start_pc = opcode_pc + 1;
            auto pc = start_pc;
            while (!bitmasks.test(pc)) {
                ++pc;
            }
            return std::min(24ULL, pc - start_pc);
        }

        op_res_t _exec(const uint8_t opcode, const buffer data)
        {
            static std::array<op_res_t(impl::*)(buffer), 0x100> ops {
                // 0x00
                &impl::trap, &impl::fallthrough, &impl::trap, &impl::trap,
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,
                &impl::trap, &impl::trap, &impl::ecalli, &impl::trap,
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,

                // 0x10
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,
                &impl::load_imm64, &impl::trap, &impl::trap, &impl::trap,
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,

                // 0x20
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,
                &impl::jump, &impl::trap, &impl::trap, &impl::trap,
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,

                // 0x30
                &impl::trap, &impl::trap, &impl::jump_ind, &impl::load_imm,
                &impl::load_u8, &impl::load_i8, &impl::load_u16, &impl::load_i16,
                &impl::load_u32, &impl::load_i32, &impl::load_u64, &impl::store_u8,
                &impl::store_u16, &impl::store_u32, &impl::store_u64, &impl::trap,

                // 0x40
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,

                // 0x50
                &impl::trap, &impl::trap, &impl::branch_ne_imm, &impl::trap,
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,

                // 0x60
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,
                &impl::move_reg, &impl::trap, &impl::trap, &impl::trap,
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,

                // 0x70
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,
                &impl::store_ind_u8, &impl::store_ind_u16, &impl::store_ind_u32, &impl::store_ind_u64,
                &impl::load_ind_u8, &impl::load_ind_i8, &impl::load_ind_u16, &impl::load_ind_i16,

                // 0x80
                &impl::load_ind_u32, &impl::load_ind_i32, &impl::load_ind_u64, &impl::add_imm_32,
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,

                // 0x90
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,
                &impl::trap, &impl::add_imm_64, &impl::trap, &impl::shlo_l_imm_64,
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,

                // 0xA0
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,
                &impl::trap, &impl::trap, &impl::trap, &impl::branch_ne,
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,

                // 0xB0
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,

                // 0xC0
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,
                &impl::add_64, &impl::sub_64, &impl::mul_64, &impl::trap,
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,

                // 0xD0
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,

                // 0xE0
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,

                // 0xF0
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,
                &impl::trap, &impl::trap, &impl::trap, &impl::trap
            };
            const auto &op = ops[opcode];
            return (this->*op)(data);
        }

        // opcode helper functions

        static register_val_t _sign_extend(const size_t num_bytes, const register_val_t value)
        {
            if (num_bytes > 0) [[likely]] {
                const register_val_t mask = 1ULL << (num_bytes * 8U - 1ULL);
                return (value ^ mask) - mask;
            }
            return value;
        }

        static std::tuple<size_t, size_t, size_t> reg3(const buffer data)
        {
            const size_t r_a = std::min(12ULL, data.at(0ULL) & 0xFULL);
            const size_t r_b = std::min(12ULL, data.at(0ULL) / 16ULL);
            const size_t r_d = std::min(12ULL, data.at(1ULL) & 0xFULL);
            return std::make_tuple(r_a, r_b, r_d);
        }

        static std::tuple<size_t, size_t, register_val_t> reg2_imm1(const buffer data)
        {
            const size_t r_a = std::min(12ULL, data.at(0ULL) & 0xFULL);
            const size_t r_b = std::min(12ULL, data.at(0ULL) / 16ULL);
            const size_t l_x = !data.empty() ? std::min(4ULL, data.size() - 1) : 0;
            decoder dec { data.subbuf(1) };
            const auto nu_x = _sign_extend(l_x, dec.uint_fixed<register_val_t>(l_x));
            return std::make_tuple(r_a, r_b, nu_x);
        }

        static std::tuple<size_t, register_val_t> reg1_imm1(const buffer data, const size_t max_size=4ULL)
        {
            const size_t r_a = std::min(12ULL, data.at(0ULL) & 0xFULL);
            const size_t l_x = !data.empty() ? std::min(max_size, data.size() - 1) : 0;
            decoder dec { data.subbuf(1) };
            const auto nu_x = _sign_extend(l_x, dec.uint_fixed<register_val_t>(l_x));
            return std::make_tuple(r_a, nu_x);
        }

        std::tuple<size_t, size_t, register_val_t> reg1_imm1_off1(const buffer data)
        {
            const size_t r_a = std::min(12ULL, data.at(0ULL) & 0xFULL);
            const size_t l_x = std::min(4ULL, (data.at(0ULL) / 16ULL) % 8);
            const size_t l_y = data.size() > l_x ? std::min(4ULL, data.size() - l_x - 1) : 0;
            decoder dec { data.subbuf(1) };
            const auto nu_x = _sign_extend(l_x, dec.uint_fixed<register_val_t>(l_x));
            const auto nu_y_pre = _sign_extend(l_y, dec.uint_fixed<register_val_t>(l_y));
            const auto nu_y = static_cast<register_val_t>(static_cast<register_val_signed_t>(_pc) + static_cast<register_val_signed_t>(nu_y_pre));
            return std::make_tuple(r_a, nu_x, nu_y);
        }

        op_res_t load_imm_base(const buffer data, const size_t max_size)
        {
            const auto [r_a, nu_x] = reg1_imm1(data, max_size);
            _regs[r_a] = nu_x;
            return {};
        }

        op_res_t djump(const register_val_t addr)
        {
            if (addr == (1ULL << 32ULL) - (1ULL << 16ULL)) [[unlikely]]
                throw exit_halt_t {};
            if (addr == 0) [[unlikely]]
                throw exit_panic_t {};
            if (addr > _program.jump_table.size() * config_prod::pvm_address_alignment_factor) [[unlikely]]
                throw exit_panic_t {};
            if (addr % config_prod::pvm_address_alignment_factor != 0) [[unlikely]]
                throw exit_panic_t {};
            const auto ji = addr / config_prod::pvm_address_alignment_factor;
            const auto new_pc = _program.jump_table.at(ji - 1);
            if (!_program.bitmasks.test(new_pc)) [[unlikely]]
                throw exit_panic_t {};
            return { new_pc };
        }

        op_res_t branch_base(const register_val_t new_pc, const bool cond)
        {
            if (cond) {
                if (new_pc >= _program.code.size()) [[unlikely]]
                    throw exit_panic_t {};
                if (!_program.bitmasks.test(new_pc)) [[unlikely]]
                    throw exit_panic_t {};
                return { new_pc };
            }
            return {};
        }

        std::pair<size_t, page_map_t::const_iterator> _addr_check(const register_val_t addr, const size_t sz)
        {
            const auto page_off = addr % config_prod::pvm_page_size;
            if (page_off + sz > config_prod::pvm_page_size) [[unlikely]]
                throw exit_panic_t {};
            const auto page_it = _pages.find(addr / config_prod::pvm_page_size);
            if (page_it == _pages.end()) [[unlikely]]
                throw exit_page_fault_t { addr };
            return std::make_pair(page_off, page_it);
        }

        register_val_t _load_unsigned(const register_val_t addr, const size_t sz)
        {
            const auto [page_off, page_it] = _addr_check(addr, sz);
            switch (sz) {
                case 1: return page_it->second.data[page_off];
                case 2: return buffer { page_it->second.data.get() + page_off, sz }.to<uint16_t>();
                case 4: return buffer { page_it->second.data.get() + page_off, sz }.to<uint32_t>();
                case 8: return buffer { page_it->second.data.get() + page_off, sz }.to<uint64_t>();
                    [[unlikely]] default: throw exit_panic_t {};
            }
        }

        register_val_t _load_signed(const register_val_t addr, const size_t sz)
        {
            return _sign_extend(_load_unsigned(addr, sz), sz);
        }

        // used for the initialization so does not respect the is_writable false
        void _store_unsigned_init(const register_val_t addr, const auto val)
        {
            using T = std::decay_t<decltype(val)>;
            const auto [page_off, page_it] = _addr_check(addr, sizeof(val));
            *reinterpret_cast<T*>(page_it->second.data.get() + page_off) = val;
        }

        void _store_unsigned(const register_val_t addr, const auto val)
        {
            using T = std::decay_t<decltype(val)>;
            const auto [page_off, page_it] = _addr_check(addr, sizeof(val));
            if (!page_it->second.is_writable) [[unlikely]]
                throw exit_page_fault_t { addr };
            *reinterpret_cast<T*>(page_it->second.data.get() + page_off) = val;
        }

        // opcode implementations

        op_res_t trap(const buffer)
        {
            throw exit_panic_t {};
        }

        op_res_t fallthrough(const buffer)
        {
            // do nothing
            return {};
        }

        op_res_t ecalli(const buffer data)
        {
            const size_t l_x = std::min(4ULL, data.size());
            decoder dec { data };
            const auto nu_x = _sign_extend(l_x, dec.uint_fixed<register_val_t>(l_x));
            throw exit_host_call_t { nu_x };
        }

        op_res_t load_imm(const buffer data)
        {
            if (data.size() > 5) [[unlikely]]
                throw exit_panic_t {};
            return load_imm_base(data, 4);
        }

        op_res_t load_imm64(const buffer data)
        {
            if (data.size() != 9) [[unlikely]]
                throw exit_panic_t {};
            return load_imm_base(data, 8);
        }

        op_res_t move_reg(const buffer data)
        {
            const size_t r_d = std::min(12ULL, data.at(0ULL) & 0xFULL);
            const size_t r_a = std::min(12ULL, data.at(0ULL) / 16ULL);
            _regs[r_d] = _regs[r_a];
            return {};
        }

        op_res_t branch_ne(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            const auto new_pc = static_cast<register_val_t>(static_cast<register_val_signed_t>(_pc) + static_cast<register_val_signed_t>(nu_x));
            return branch_base(new_pc, _regs[r_a] != _regs[r_b]);
        }

        op_res_t add_imm_32(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _regs[r_a] = _sign_extend(4, (_regs[r_b] + nu_x) % (1ULL << 32ULL));
            return {};
        }

        op_res_t add_imm_64(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _regs[r_a] = _regs[r_b] + nu_x;
            return {};
        }

        op_res_t shlo_l_imm_64(const buffer data) {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _regs[r_a] = _regs[r_b] << nu_x;
            return {};
        }

        op_res_t branch_ne_imm(const buffer data)
        {
            const auto [r_a, nu_x, nu_y] = reg1_imm1_off1(data);
            return branch_base(nu_y, _regs[r_a] != nu_x);
        }

        op_res_t jump(const buffer data)
        {
            const size_t l_x = std::min(4ULL, data.size());
            decoder dec { data };
            const auto nu_x_pre = _sign_extend(l_x, dec.uint_fixed<register_val_t>(l_x));
            const auto nu_x = static_cast<register_val_t>(static_cast<register_val_signed_t>(_pc) + static_cast<register_val_signed_t>(nu_x_pre));
            return branch_base(nu_x, true);
        }

        op_res_t jump_ind(const buffer data)
        {
            const auto [r_a, nu_x] = reg1_imm1(data);
            return djump((_regs[r_a] + nu_x) % (1ULL << 32ULL));
        }

        op_res_t load_u8(const buffer data)
        {
            const auto [r_a, nu_x] = reg1_imm1(data);
            _regs[r_a] = _load_unsigned(nu_x, 1);
            return {};
        }

        op_res_t load_u16(const buffer data)
        {
            const auto [r_a, nu_x] = reg1_imm1(data);
            _regs[r_a] = _load_unsigned(nu_x, 2);
            return {};
        }

        op_res_t load_u32(const buffer data)
        {
            const auto [r_a, nu_x] = reg1_imm1(data);
            _regs[r_a] = _load_unsigned(nu_x, 4);
            return {};
        }

        op_res_t load_u64(const buffer data)
        {
            const auto [r_a, nu_x] = reg1_imm1(data);
            _regs[r_a] = _load_unsigned(nu_x, 8);
            return {};
        }

        op_res_t load_i8(const buffer data)
        {
            const auto [r_a, nu_x] = reg1_imm1(data);
            _regs[r_a] = _load_signed(nu_x, 1);
            return {};
        }

        op_res_t load_i16(const buffer data)
        {
            const auto [r_a, nu_x] = reg1_imm1(data);
            _regs[r_a] = _load_signed(nu_x, 2);
            return {};
        }

        op_res_t load_i32(const buffer data)
        {
            const auto [r_a, nu_x] = reg1_imm1(data);
            _regs[r_a] = _load_signed(nu_x, 4);
            return {};
        }

        op_res_t store_u8(const buffer data)
        {
            const auto [r_a, nu_x] = reg1_imm1(data);
            _store_unsigned(nu_x, static_cast<uint8_t>(_regs[r_a]));
            return {};
        }

        op_res_t store_u16(const buffer data)
        {
            const auto [r_a, nu_x] = reg1_imm1(data);
            _store_unsigned(nu_x, static_cast<uint16_t>(_regs[r_a]));
            return {};
        }

        op_res_t store_u32(const buffer data)
        {
            const auto [r_a, nu_x] = reg1_imm1(data);
            _store_unsigned(nu_x, static_cast<uint32_t>(_regs[r_a]));
            return {};
        }

        op_res_t store_u64(const buffer data)
        {
            const auto [r_a, nu_x] = reg1_imm1(data);
            _store_unsigned(nu_x, _regs[r_a]);
            return {};
        }

        op_res_t store_ind_u8(const buffer data) {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _store_unsigned(_regs[r_b] + nu_x, static_cast<uint8_t>(_regs[r_a]));
            return {};
        }

        op_res_t store_ind_u16(const buffer data) {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _store_unsigned(_regs[r_b] + nu_x, static_cast<uint16_t>(_regs[r_a]));
            return {};
        }

        op_res_t store_ind_u32(const buffer data) {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _store_unsigned(_regs[r_b] + nu_x, static_cast<uint32_t>(_regs[r_a]));
            return {};
        }

        op_res_t store_ind_u64(const buffer data) {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _store_unsigned(_regs[r_b] + nu_x, _regs[r_a]);
            return {};
        }

        op_res_t load_ind_u8(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _regs[r_a] = _load_unsigned(_regs[r_b] + nu_x, 1);
            return {};
        }

        op_res_t load_ind_u16(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _regs[r_a] = _load_unsigned(_regs[r_b] + nu_x, 2);
            return {};
        }

        op_res_t load_ind_u32(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _regs[r_a] = _load_unsigned(_regs[r_b] + nu_x, 4);
            return {};
        }

        op_res_t load_ind_u64(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _regs[r_a] = _load_unsigned(_regs[r_b] + nu_x, 8);
            return {};
        }

        op_res_t load_ind_i8(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _regs[r_a] = _load_signed(_regs[r_b] + nu_x, 1);
            return {};
        }

        op_res_t load_ind_i16(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _regs[r_a] = _load_signed(_regs[r_b] + nu_x, 2);
            return {};
        }

        op_res_t load_ind_i32(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _regs[r_a] = _load_signed(_regs[r_b] + nu_x, 4);
            return {};
        }

        op_res_t add_64(const buffer data)
        {
            const auto [r_a, r_b, r_d] = reg3(data);
            _regs[r_d] = _regs[r_a] + _regs[r_b];
            return {};
        }

        op_res_t sub_64(const buffer data)
        {
            const auto [r_a, r_b, r_d] = reg3(data);
            _regs[r_d] = _regs[r_a] - _regs[r_b];
            return {};
        }

        op_res_t mul_64(const buffer data)
        {
            const auto [r_a, r_b, r_d] = reg3(data);
            _regs[r_d] = _regs[r_a] * _regs[r_b];
            return {};
        }
    };

    machine_t::machine_t(const program_t &program, const state_t &init, const pages_t &page_map)
    {
        new (_impl_ptr()) impl { program, init, page_map };
    }

    machine_t::~machine_t()
    {
        _impl_ptr()->~impl();
    }

    machine_t::impl *machine_t::_impl_ptr()
    {
        static_assert(sizeof(_impl_storage) >= sizeof(impl));
        return reinterpret_cast<impl *>(_impl_storage.data());
    }

    result_t machine_t::run()
    {
        return _impl_ptr()->run();
    }

    state_t machine_t::state() const
    {
        return const_cast<machine_t *>(this)->_impl_ptr()->state();
    }

}
