/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#if defined(_MSC_VER)
#   include <intrin.h>
#endif
#include <boost/container/flat_map.hpp>
#include "machine.hpp"

namespace turbo::jam::machine {
#if defined(__GNUC__) || defined(__clang__)
#   pragma GCC diagnostic push
#   pragma GCC diagnostic ignored "-Wpedantic"
    using int128_t = __int128;
    using uint128_t = unsigned __int128;
#   pragma GCC diagnostic pop
#endif

    /*static constexpr register_val_t host_res_none = std::numeric_limits<register_val_t>::max();
    static constexpr register_val_t host_res_what = std::numeric_limits<register_val_t>::max() - 1;
    static constexpr register_val_t host_res_oob = std::numeric_limits<register_val_t>::max() - 2;
    static constexpr register_val_t host_res_who = std::numeric_limits<register_val_t>::max() - 3;
    static constexpr register_val_t host_res_full = std::numeric_limits<register_val_t>::max() - 4;
    static constexpr register_val_t host_res_core = std::numeric_limits<register_val_t>::max() - 5;
    static constexpr register_val_t host_res_cash = std::numeric_limits<register_val_t>::max() - 6;
    static constexpr register_val_t host_res_low = std::numeric_limits<register_val_t>::max() - 7;
    static constexpr register_val_t host_res_huh = std::numeric_limits<register_val_t>::max() - 8;
    static constexpr register_val_t host_res_ok = 0;*/

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
                    if (_pc >= _program.code.size()) [[unlikely]]
                        throw exit_panic_t {}; // equivalent to executing the trap instruction
                    if (!_program.bitmasks.test(_pc)) [[unlikely]]
                        throw exit_panic_t {};
                    const uint8_t opcode = _program.code[_pc];
                    const auto len = _skip_len(_pc, _program.bitmasks);
                    const auto data = _program.code.subbuf(_pc + 1, len);
                    const auto res = _exec(opcode, data);
                    _pc = res.new_pc.value_or(_pc + len + 1);
                    _gas -= res.gas_used;
                }
            } catch (exit_halt_t &ex) {
                return { std::move(ex) };
            } catch (exit_panic_t &ex) {
                return { std::move(ex) };
            } catch (exit_page_fault_t &ex) {
                return { std::move(ex) };
            } catch (exit_out_of_gas_t &ex) {
                return { std::move(ex) };
            } catch (exit_host_call_t &ex) {
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
            return std::min(size_t { 24 }, static_cast<size_t>(pc - start_pc));
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
                &impl::load_imm_64, &impl::trap, &impl::trap, &impl::trap,
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,
                &impl::trap, &impl::trap, &impl::store_imm_u8, &impl::store_imm_u16,

                // 0x20
                &impl::store_imm_u32, &impl::store_imm_u64, &impl::trap, &impl::trap,
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
                &impl::trap, &impl::trap, &impl::store_imm_ind_u8, &impl::store_imm_ind_u16,
                &impl::store_imm_ind_u32, &impl::store_imm_ind_u64, &impl::trap, &impl::trap,
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,

                // 0x50
                &impl::load_imm_jump, &impl::branch_eq_imm, &impl::branch_ne_imm, &impl::branch_lt_u_imm,
                &impl::branch_le_u_imm, &impl::branch_ge_u_imm, &impl::branch_gt_u_imm, &impl::branch_lt_s_imm,
                &impl::branch_le_s_imm, &impl::branch_ge_s_imm, &impl::branch_ge_s_imm, &impl::trap,
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,

                // 0x60
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,
                &impl::move_reg, &impl::sbrk, &impl::count_set_bits_64, &impl::count_set_bits_32,
                &impl::leading_zero_bits_64, &impl::leading_zero_bits_32, &impl::trailing_zero_bits_64, &impl::trailing_zero_bits_32,
                &impl::sign_extend_8, &impl::sign_extend_16, &impl::zero_extend_16, &impl::reverse_bytes,

                // 0x70
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,
                &impl::store_ind_u8, &impl::store_ind_u16, &impl::store_ind_u32, &impl::store_ind_u64,
                &impl::load_ind_u8, &impl::load_ind_i8, &impl::load_ind_u16, &impl::load_ind_i16,

                // 0x80
                &impl::load_ind_u32, &impl::load_ind_i32, &impl::load_ind_u64, &impl::add_imm_32,
                &impl::and_imm, &impl::xor_imm, &impl::or_imm, &impl::mul_imm_32,
                &impl::set_lt_u_imm, &impl::set_lt_s_imm, &impl::shlo_l_imm_32, &impl::shlo_r_imm_32,
                &impl::shar_r_imm_32, &impl::neg_add_imm_32, &impl::set_gt_u_imm, &impl::set_gt_s_imm,

                // 0x90
                &impl::shlo_l_imm_alt_32, &impl::shlo_r_imm_alt_32, &impl::shar_r_imm_alt_32, &impl::cmov_iz_imm,
                &impl::cmov_nz_imm, &impl::add_imm_64, &impl::mul_imm_64, &impl::shlo_l_imm_64,
                &impl::shlo_r_imm_64, &impl::shar_r_imm_64, &impl::neg_add_imm_64, &impl::shlo_l_imm_alt_64,
                &impl::shlo_r_imm_alt_64, &impl::shar_r_imm_alt_64, &impl::rot_r_64_imm, &impl::rot_r_64_imm_alt,

                // 0xA0
                &impl::rot_r_32_imm, &impl::rot_r_32_imm_alt, &impl::trap, &impl::trap,
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,
                &impl::trap, &impl::trap, &impl::branch_eq, &impl::branch_ne,
                &impl::branch_lt_u, &impl::branch_lt_s, &impl::branch_ge_u, &impl::branch_ge_s,

                // 0xB0
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,
                &impl::load_imm_jump_ind, &impl::trap, &impl::trap, &impl::trap,
                &impl::trap, &impl::trap, &impl::trap, &impl::trap,
                &impl::trap, &impl::trap, &impl::add_32, &impl::sub_32,

                // 0xC0
                &impl::mul_32, &impl::div_u_32, &impl::div_s_32, &impl::rem_u_32,
                &impl::rem_s_32, &impl::shlo_l_32, &impl::shlo_r_32, &impl::shar_r_32,
                &impl::add_64, &impl::sub_64, &impl::mul_64, &impl::div_u_64,
                &impl::div_s_64, &impl::rem_u_64, &impl::rem_s_64, &impl::shlo_l_64,

                // 0xD0
                &impl::shlo_r_64, &impl::shar_r_64, &impl::and_, &impl::xor_,
                &impl::or_, &impl::mul_upper_s_s, &impl::mul_upper_u_u, &impl::mul_upper_s_u,
                &impl::set_lt_u, &impl::set_lt_s, &impl::cmov_iz, &impl::cmov_nz,
                &impl::rot_l_64, &impl::rot_l_32, &impl::rot_r_64, &impl::rot_r_32,

                // 0xE0
                &impl::and_inv, &impl::or_inv, &impl::xnor, &impl::max,
                &impl::max_u, &impl::min, &impl::min_u, &impl::trap,
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
            if (num_bytes > 8) [[unlikely]]
                throw exit_panic_t {};    
            if (num_bytes == 0) [[unlikely]]
                return 0;
            const auto attention_mask = static_cast<register_val_t>(-1) >> ((8 - num_bytes) * 8);
            const auto val = value & attention_mask;
            const register_val_t mask = 1ULL << (num_bytes * 8U - 1U);
            return static_cast<register_val_t>(static_cast<register_val_signed_t>(val ^ mask) - static_cast<register_val_signed_t>(mask));
        }

        static std::tuple<size_t, size_t, size_t> reg3(const buffer data)
        {
            const size_t r_a = std::min(12ULL, data.at(0ULL) & 0xFULL);
            const size_t r_b = std::min(12ULL, data.at(0ULL) / 16ULL);
            const size_t r_d = std::min(12ULL, data.at(1ULL) & 0xFULL);
            return std::make_tuple(r_a, r_b, r_d);
        }

        static std::tuple<size_t, size_t> reg2(const buffer data)
        {
            const size_t r_d = std::min(12ULL, data.at(0ULL) & 0xFULL);
            const size_t r_a = std::min(12ULL, data.at(0ULL) / 16ULL);
            return std::make_tuple(r_d, r_a);
        }

        static std::tuple<size_t, size_t, register_val_t> reg2_imm1(const buffer data)
        {
            const size_t r_a = std::min(12ULL, data.at(0ULL) & 0xFULL);
            const size_t r_b = std::min(12ULL, data.at(0ULL) / 16ULL);
            const size_t l_x = !data.empty() ? std::min(size_t { 4 }, data.size() - 1) : 0;
            decoder dec { data.subbuf(1) };
            const auto nu_x = _sign_extend(l_x, dec.uint_fixed<register_val_t>(l_x));
            return std::make_tuple(r_a, r_b, nu_x);
        }

        static std::tuple<size_t, size_t, register_val_t, register_val_t> reg2_imm2(const buffer data)
        {
            const size_t r_a = std::min(12ULL, data.at(0ULL) & 0xFULL);
            const size_t r_b = std::min(12ULL, data.at(0ULL) / 16ULL);
            const size_t l_x = std::min(4ULL, data.at(1ULL) % 8ULL);
            const size_t l_y = data.size() > l_x + 1 ? std::min(size_t { 4 }, data.size() - l_x - 2) : 0;
            decoder dec { data.subbuf(2) };
            const auto nu_x = _sign_extend(l_x, dec.uint_fixed<register_val_t>(l_x));
            const auto nu_y = _sign_extend(l_y, dec.uint_fixed<register_val_t>(l_y));
            return std::make_tuple(r_a, r_b, nu_x, nu_y);
        }

        std::tuple<size_t, size_t, register_val_t> reg2_off1(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            const auto new_pc = static_cast<register_val_t>(static_cast<register_val_signed_t>(_pc) + static_cast<register_val_signed_t>(nu_x));
            return std::make_tuple(r_a, r_b, new_pc);
        }

        static std::tuple<size_t, register_val_t> reg1_imm1(const buffer data, const size_t max_size=4ULL)
        {
            const size_t r_a = std::min(12ULL, data.at(0ULL) & 0xFULL);
            const size_t l_x = !data.empty() ? std::min(max_size, data.size() - 1) : 0;
            decoder dec { data.subbuf(1) };
            const auto nu_x = _sign_extend(l_x, dec.uint_fixed<register_val_t>(l_x));
            return std::make_tuple(r_a, nu_x);
        }

        std::tuple<size_t, register_val_t, register_val_t> reg1_imm2(const buffer data)
        {
            const size_t r_a = std::min(12ULL, data.at(0ULL) & 0xFULL);
            const size_t l_x = std::min(4ULL, (data.at(0ULL) / 16ULL) % 8);
            const size_t l_y = data.size() > l_x ? std::min(size_t { 4 }, data.size() - l_x - 1) : 0;
            decoder dec { data.subbuf(1) };
            const auto nu_x = _sign_extend(l_x, dec.uint_fixed<register_val_t>(l_x));
            const auto nu_y = _sign_extend(l_y, dec.uint_fixed<register_val_t>(l_y));
            return std::make_tuple(r_a, nu_x, nu_y);
        }

        std::tuple<size_t, size_t, register_val_t> reg1_imm1_off1(const buffer data)
        {
            const size_t r_a = std::min(12ULL, data.at(0ULL) & 0xFULL);
            const size_t l_x = std::min(4ULL, (data.at(0ULL) / 16ULL) % 8);
            const size_t l_y = data.size() > l_x ? std::min(size_t { 4 }, data.size() - l_x - 1) : 0;
            decoder dec { data.subbuf(1) };
            const auto nu_x = _sign_extend(l_x, dec.uint_fixed<register_val_t>(l_x));
            const auto nu_y_pre = _sign_extend(l_y, dec.uint_fixed<register_val_t>(l_y));
            const auto nu_y = static_cast<register_val_t>(static_cast<register_val_signed_t>(_pc) + static_cast<register_val_signed_t>(nu_y_pre));
            return std::make_tuple(r_a, nu_x, nu_y);
        }

        static std::tuple<register_val_t, register_val_t> imm2(const buffer data)
        {
            const size_t l_x = std::min(4ULL, data.at(0ULL) % 8ULL);
            const size_t l_y = !data.empty() ? std::min(size_t { 4 }, data.size() - l_x - 1) : 0;
            decoder dec { data.subbuf(1) };
            const auto nu_x = _sign_extend(l_x, dec.uint_fixed<register_val_t>(l_x));
            const auto nu_y = _sign_extend(l_y, dec.uint_fixed<register_val_t>(l_y));
            return std::make_tuple(nu_x, nu_y);
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
                throw exit_page_fault_t { addr - page_off + config_prod::pvm_page_size };
            const auto page_id = addr / config_prod::pvm_page_size;
            const auto page_it = _pages.find(page_id);
            if (page_it == _pages.end()) [[unlikely]]
                throw exit_page_fault_t { page_id * config_prod::pvm_page_size };
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
            return _sign_extend(sz, _load_unsigned(addr, sz));
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
            const size_t l_x = std::min(size_t { 4 }, data.size());
            decoder dec { data };
            const auto nu_x = _sign_extend(l_x, dec.uint_fixed<register_val_t>(l_x));
            throw exit_host_call_t { nu_x };
        }

        op_res_t store_imm_u8(const buffer data)
        {
            const auto [nu_x, nu_y] = imm2(data);
            _store_unsigned(nu_x, static_cast<uint8_t>(nu_y));
            return {};
        }

        op_res_t store_imm_u16(const buffer data)
        {
            const auto [nu_x, nu_y] = imm2(data);
            _store_unsigned(nu_x, static_cast<uint16_t>(nu_y));
            return {};
        }

        op_res_t store_imm_u32(const buffer data)
        {
            const auto [nu_x, nu_y] = imm2(data);
            _store_unsigned(nu_x, static_cast<uint32_t>(nu_y));
            return {};
        }

        op_res_t store_imm_u64(const buffer data)
        {
            const auto [nu_x, nu_y] = imm2(data);
            _store_unsigned(nu_x, nu_y);
            return {};
        }

        op_res_t load_imm(const buffer data)
        {
            if (data.size() > 5) [[unlikely]]
                throw exit_panic_t {};
            return load_imm_base(data, 4);
        }

        op_res_t load_imm_64(const buffer data)
        {
            if (data.size() != 9) [[unlikely]]
                throw exit_panic_t {};
            return load_imm_base(data, 8);
        }

        op_res_t move_reg(const buffer data)
        {
            const auto [r_d, r_a] = reg2(data);
            _regs[r_d] = _regs[r_a];
            return {};
        }

        op_res_t sbrk(const buffer /*data*/)
        {
            //const auto [r_d, r_a] = reg2(data);
            // not implemented yet
            throw exit_panic_t {};
        }

        op_res_t count_set_bits_64(const buffer data)
        {
            const auto [r_d, r_a] = reg2(data);
            _regs[r_d] = std::popcount(_regs[r_a]);
            return {};
        }

        op_res_t count_set_bits_32(const buffer data)
        {
            const auto [r_d, r_a] = reg2(data);
            _regs[r_d] = std::popcount(static_cast<uint32_t>(_regs[r_a]));
            return {};
        }

        op_res_t leading_zero_bits_64(const buffer data)
        {
            const auto [r_d, r_a] = reg2(data);
            _regs[r_d] = std::countl_zero(_regs[r_a]);
            return {};
        }

        op_res_t leading_zero_bits_32(const buffer data)
        {
            const auto [r_d, r_a] = reg2(data);
            _regs[r_d] = std::countl_zero(static_cast<uint32_t>(_regs[r_a]));
            return {};
        }

        op_res_t trailing_zero_bits_64(const buffer data)
        {
            const auto [r_d, r_a] = reg2(data);
            _regs[r_d] = std::countr_zero(_regs[r_a]);
            return {};
        }

        op_res_t trailing_zero_bits_32(const buffer data)
        {
            const auto [r_d, r_a] = reg2(data);
            _regs[r_d] = std::countr_zero(static_cast<uint32_t>(_regs[r_a]));
            return {};
        }

        op_res_t sign_extend_8(const buffer data)
        {
            const auto [r_d, r_a] = reg2(data);
            _regs[r_d] = _sign_extend(1, _regs[r_a]);
            return {};
        }

        op_res_t sign_extend_16(const buffer data)
        {
            const auto [r_d, r_a] = reg2(data);
            _regs[r_d] = _sign_extend(2, _regs[r_a]);
            return {};
        }

        op_res_t zero_extend_16(const buffer data)
        {
            const auto [r_d, r_a] = reg2(data);
            _regs[r_d] = _regs[r_a] & 0xFFFF;
            return {};
        }

        op_res_t reverse_bytes(const buffer data)
        {
            const auto [r_d, r_a] = reg2(data);
            _regs[r_d] = std::byteswap(_regs[r_a]);
            return {};
        }

        op_res_t branch_eq(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_off1(data);
            return branch_base(nu_x, _regs[r_a] == _regs[r_b]);
        }

        op_res_t branch_ne(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_off1(data);
            return branch_base(nu_x, _regs[r_a] != _regs[r_b]);
        }

        op_res_t branch_lt_u(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_off1(data);
            return branch_base(nu_x, _regs[r_a] < _regs[r_b]);
        }

        op_res_t branch_lt_s(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_off1(data);
            return branch_base(nu_x, static_cast<register_val_signed_t>(_regs[r_a]) < static_cast<register_val_signed_t>(_regs[r_b]));
        }

        op_res_t branch_ge_u(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_off1(data);
            return branch_base(nu_x, _regs[r_a] >= _regs[r_b]);
        }

        op_res_t branch_ge_s(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_off1(data);
            return branch_base(nu_x, static_cast<register_val_signed_t>(_regs[r_a]) >= static_cast<register_val_signed_t>(_regs[r_b]));
        }

        op_res_t add_imm_32(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _regs[r_a] = _sign_extend(4, static_cast<uint32_t>(_regs[r_b] + nu_x));
            return {};
        }

        op_res_t and_imm(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _regs[r_a] = _regs[r_b] & nu_x;
            return {};
        }

        op_res_t xor_imm(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _regs[r_a] = _regs[r_b] ^ nu_x;
            return {};
        }

        op_res_t or_imm(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _regs[r_a] = _regs[r_b] | nu_x;
            return {};
        }

        op_res_t mul_imm_32(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _regs[r_a] = _sign_extend(4, _regs[r_b] * nu_x);
            return {};
        }

        op_res_t set_lt_u_imm(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _regs[r_a] = _regs[r_b] < nu_x;
            return {};
        }

        op_res_t set_lt_s_imm(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _regs[r_a] = static_cast<register_val_signed_t>(_regs[r_b]) < static_cast<register_val_signed_t>(nu_x);
            return {};
        }

        op_res_t shlo_l_imm_32(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _regs[r_a] = _sign_extend(4, static_cast<uint32_t>(_regs[r_b]) << static_cast<uint32_t>(nu_x));
            return {};
        }

        op_res_t shlo_r_imm_32(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _regs[r_a] = _sign_extend(4, static_cast<uint32_t>(_regs[r_b]) >> static_cast<uint32_t>(nu_x));
            return {};
        }

        op_res_t shar_r_imm_32(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _regs[r_a] = static_cast<register_val_t>(static_cast<int32_t>(_regs[r_b]) >> static_cast<uint32_t>(nu_x));
            return {};
        }

        op_res_t neg_add_imm_32(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _regs[r_a] = _sign_extend(4, static_cast<uint32_t>(nu_x + (1ULL << 32ULL) - _regs[r_b]));
            return {};
        }

        op_res_t set_gt_u_imm(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _regs[r_a] = _regs[r_b] > nu_x;
            return {};
        }

        op_res_t set_gt_s_imm(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _regs[r_a] = static_cast<register_val_signed_t>(_regs[r_b]) > static_cast<register_val_signed_t>(nu_x);
            return {};
        }

        op_res_t shlo_l_imm_alt_32(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _regs[r_a] = _sign_extend(4, static_cast<uint32_t>(nu_x) << static_cast<uint32_t>(_regs[r_b]));
            return {};
        }

        op_res_t shlo_r_imm_alt_32(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _regs[r_a] = _sign_extend(4, static_cast<uint32_t>(nu_x) >> static_cast<uint32_t>(_regs[r_b]));
            return {};
        }

        op_res_t shar_r_imm_alt_32(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _regs[r_a] = static_cast<register_val_t>(static_cast<int32_t>(nu_x) >> static_cast<uint32_t>(_regs[r_b]));
            return {};
        }

        op_res_t cmov_iz_imm(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _regs[r_a] = _regs[r_b] == 0 ?  nu_x : _regs[r_a];
            return {};
        }

        op_res_t cmov_nz_imm(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _regs[r_a] = _regs[r_b] != 0 ?  nu_x : _regs[r_a];
            return {};
        }

        op_res_t add_imm_64(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _regs[r_a] = _regs[r_b] + nu_x;
            return {};
        }

        op_res_t mul_imm_64(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _regs[r_a] = _regs[r_b] * nu_x;
            return {};
        }

        op_res_t shlo_l_imm_64(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _regs[r_a] = _regs[r_b] << nu_x;
            return {};
        }

        op_res_t shlo_r_imm_64(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _regs[r_a] = _regs[r_b] >> nu_x;
            return {};
        }

        op_res_t shar_r_imm_64(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _regs[r_a] = static_cast<register_val_t>(static_cast<register_val_signed_t>(_regs[r_b]) >> static_cast<register_val_signed_t>(nu_x));
            return {};
        }

        op_res_t neg_add_imm_64(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _regs[r_a] = nu_x - _regs[r_b];
            return {};
        }

        op_res_t shlo_l_imm_alt_64(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _regs[r_a] = nu_x << _regs[r_b];
            return {};
        }

        op_res_t shlo_r_imm_alt_64(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _regs[r_a] = nu_x >> _regs[r_b];
            return {};
        }

        op_res_t shar_r_imm_alt_64(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _regs[r_a] = static_cast<register_val_t>(static_cast<register_val_signed_t>(nu_x) >> static_cast<register_val_signed_t>(_regs[r_b]));
            return {};
        }

        op_res_t rot_r_64_imm(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _regs[r_a] = std::rotr(_regs[r_b], nu_x);
            return {};
        }

        op_res_t rot_r_64_imm_alt(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _regs[r_a] = std::rotr(nu_x, _regs[r_b]);
            return {};
        }

        op_res_t rot_r_32_imm(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _regs[r_a] = _sign_extend(4, std::rotr(static_cast<uint32_t>(_regs[r_b]), static_cast<uint32_t>(nu_x)));
            return {};
        }

        op_res_t rot_r_32_imm_alt(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _regs[r_a] = _sign_extend(4, std::rotr(static_cast<uint32_t>(nu_x), static_cast<uint32_t>(_regs[r_b])));
            return {};
        }

        op_res_t load_imm_jump(const buffer data)
        {
            const auto [r_a, nu_x, nu_y] = reg1_imm1_off1(data);
            _regs[r_a] = nu_x;
            return branch_base(nu_y, true);
        }

        op_res_t load_imm_jump_ind(const buffer data)
        {
            const auto [r_a, r_b, nu_x, nu_y] = reg2_imm2(data);
            const auto jt_idx = (_regs[r_b] + nu_y) % (1ULL << 32ULL);
            _regs[r_a] = nu_x;
            return djump(jt_idx);
        }

        op_res_t branch_eq_imm(const buffer data)
        {
            const auto [r_a, nu_x, nu_y] = reg1_imm1_off1(data);
            return branch_base(nu_y, _regs[r_a] == nu_x);
        }

        op_res_t branch_ne_imm(const buffer data)
        {
            const auto [r_a, nu_x, nu_y] = reg1_imm1_off1(data);
            return branch_base(nu_y, _regs[r_a] != nu_x);
        }

        op_res_t branch_lt_u_imm(const buffer data)
        {
            const auto [r_a, nu_x, nu_y] = reg1_imm1_off1(data);
            return branch_base(nu_y, _regs[r_a] < nu_x);
        }

        op_res_t branch_le_u_imm(const buffer data)
        {
            const auto [r_a, nu_x, nu_y] = reg1_imm1_off1(data);
            return branch_base(nu_y, _regs[r_a] <= nu_x);
        }

        op_res_t branch_ge_u_imm(const buffer data)
        {
            const auto [r_a, nu_x, nu_y] = reg1_imm1_off1(data);
            return branch_base(nu_y, _regs[r_a] >= nu_x);
        }

        op_res_t branch_gt_u_imm(const buffer data)
        {
            const auto [r_a, nu_x, nu_y] = reg1_imm1_off1(data);
            return branch_base(nu_y, _regs[r_a] > nu_x);
        }

        op_res_t branch_lt_s_imm(const buffer data)
        {
            const auto [r_a, nu_x, nu_y] = reg1_imm1_off1(data);
            return branch_base(nu_y, static_cast<register_val_signed_t>(_regs[r_a]) < static_cast<register_val_signed_t>(nu_x));
        }

        op_res_t branch_le_s_imm(const buffer data)
        {
            const auto [r_a, nu_x, nu_y] = reg1_imm1_off1(data);
            return branch_base(nu_y, static_cast<register_val_signed_t>(_regs[r_a]) <= static_cast<register_val_signed_t>(nu_x));
        }

        op_res_t branch_ge_s_imm(const buffer data)
        {
            const auto [r_a, nu_x, nu_y] = reg1_imm1_off1(data);
            return branch_base(nu_y, static_cast<register_val_signed_t>(_regs[r_a]) >= static_cast<register_val_signed_t>(nu_x));
        }

        op_res_t branch_gt_s_imm(const buffer data)
        {
            const auto [r_a, nu_x, nu_y] = reg1_imm1_off1(data);
            return branch_base(nu_y, static_cast<register_val_signed_t>(_regs[r_a]) > static_cast<register_val_signed_t>(nu_x));
        }

        op_res_t jump(const buffer data)
        {
            const size_t l_x = std::min(size_t { 4 }, data.size());
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

        op_res_t store_imm_ind_u8(const buffer data)
        {
            const auto [r_a, nu_x, nu_y] = reg1_imm2(data);
            _store_unsigned(_regs[r_a] + nu_x, static_cast<uint8_t>(nu_y));
            return {};
        }

        op_res_t store_imm_ind_u16(const buffer data)
        {
            const auto [r_a, nu_x, nu_y] = reg1_imm2(data);
            const auto addr = _regs[r_a] + nu_x;
            _store_unsigned(addr, static_cast<uint16_t>(nu_y));
            return {};
        }

        op_res_t store_imm_ind_u32(const buffer data)
        {
            const auto [r_a, nu_x, nu_y] = reg1_imm2(data);
            _store_unsigned(_regs[r_a] + nu_x, static_cast<uint32_t>(nu_y));
            return {};
        }

        op_res_t store_imm_ind_u64(const buffer data)
        {
            const auto [r_a, nu_x, nu_y] = reg1_imm2(data);
            _store_unsigned(_regs[r_a] + nu_x, nu_y);
            return {};
        }

        op_res_t store_ind_u8(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _store_unsigned(_regs[r_b] + nu_x, static_cast<uint8_t>(_regs[r_a]));
            return {};
        }

        op_res_t store_ind_u16(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _store_unsigned(_regs[r_b] + nu_x, static_cast<uint16_t>(_regs[r_a]));
            return {};
        }

        op_res_t store_ind_u32(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _store_unsigned(_regs[r_b] + nu_x, static_cast<uint32_t>(_regs[r_a]));
            return {};
        }

        op_res_t store_ind_u64(const buffer data)
        {
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

        op_res_t add_32(const buffer data)
        {
            const auto [r_a, r_b, r_d] = reg3(data);
            _regs[r_d] = _sign_extend(4, static_cast<uint32_t>(_regs[r_a] + _regs[r_b]));
            return {};
        }

        op_res_t sub_32(const buffer data)
        {
            const auto [r_a, r_b, r_d] = reg3(data);
            _regs[r_d] = _sign_extend(4, static_cast<uint32_t>(_regs[r_a] - _regs[r_b]));
            return {};
        }

        op_res_t mul_32(const buffer data)
        {
            const auto [r_a, r_b, r_d] = reg3(data);
            _regs[r_d] = _sign_extend(4, static_cast<uint32_t>(_regs[r_a] * _regs[r_b]));
            return {};
        }

        op_res_t div_u_32(const buffer data)
        {
            const auto [r_a, r_b, r_d] = reg3(data);
            _regs[r_d] = _regs[r_b] != 0 ? _sign_extend(4, static_cast<uint32_t>(_regs[r_a] / _regs[r_b])) : std::numeric_limits<uint64_t>::max();
            return {};
        }

        op_res_t div_s_32(const buffer data)
        {
            const auto [r_a, r_b, r_d] = reg3(data);
            const auto reg_a_s32 = static_cast<int32_t>(_regs[r_a]);
            const auto reg_b_s32 = static_cast<int32_t>(_regs[r_b]);
            if (_regs[r_b] != 0) {
                if (reg_a_s32 != std::numeric_limits<int32_t>::min() || reg_b_s32 != -1) {
                    _regs[r_d] = static_cast<register_val_t>(reg_a_s32 / reg_b_s32);
                } else {
                    _regs[r_d] = static_cast<register_val_t>(reg_a_s32);
                }
            } else {
                _regs[r_d] = std::numeric_limits<uint64_t>::max();
            }
            return {};
        }

        op_res_t rem_u_32(const buffer data)
        {
            const auto [r_a, r_b, r_d] = reg3(data);
            const auto reg_a_u32 = static_cast<uint32_t>(_regs[r_a]);
            const auto reg_b_u32 = static_cast<uint32_t>(_regs[r_b]);
            _regs[r_d] = _sign_extend(4, reg_b_u32 != 0 ? reg_a_u32 % reg_b_u32 : reg_a_u32);
            return {};
        }

        op_res_t rem_s_32(const buffer data)
        {
            const auto [r_a, r_b, r_d] = reg3(data);
            const auto reg_a_s32 = static_cast<int32_t>(_regs[r_a]);
            const auto reg_b_s32 = static_cast<int32_t>(_regs[r_b]);
            if (reg_a_s32 != std::numeric_limits<int32_t>::min() || reg_b_s32 != -1)
                _regs[r_d] = reg_b_s32 != 0 ? static_cast<register_val_t>(reg_a_s32 % reg_b_s32) : reg_a_s32;
            else {
                _regs[r_d] = 0;
            }
            return {};
        }

        op_res_t shlo_l_32(const buffer data)
        {
            const auto [r_a, r_b, r_d] = reg3(data);
            _regs[r_d] = _sign_extend(4, static_cast<uint32_t>(_regs[r_a]) << static_cast<uint32_t>(_regs[r_b]));
            return {};
        }

        op_res_t shlo_r_32(const buffer data)
        {
            const auto [r_a, r_b, r_d] = reg3(data);
            _regs[r_d] = _sign_extend(4, static_cast<uint32_t>(_regs[r_a]) >> static_cast<uint32_t>(_regs[r_b] % 32U));
            return {};
        }

        op_res_t shar_r_32(const buffer data)
        {
            const auto [r_a, r_b, r_d] = reg3(data);
            const auto reg_a_s32 = static_cast<int32_t>(_regs[r_a]);
            const auto reg_b_s32 = static_cast<int32_t>(_regs[r_b] % 32U);
            _regs[r_d] = _sign_extend(4, reg_a_s32 >> reg_b_s32);
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

        op_res_t div_u_64(const buffer data)
        {
            const auto [r_a, r_b, r_d] = reg3(data);
            _regs[r_d] = _regs[r_b] != 0 ? _regs[r_a] / _regs[r_b] : std::numeric_limits<uint64_t>::max();
            return {};
        }

        op_res_t div_s_64(const buffer data)
        {
            const auto [r_a, r_b, r_d] = reg3(data);
            const auto reg_a_s64 = static_cast<register_val_signed_t>(_regs[r_a]);
            const auto reg_b_s64 = static_cast<register_val_signed_t>(_regs[r_b]);
            if (_regs[r_b] != 0) {
                if (reg_a_s64 != std::numeric_limits<register_val_signed_t>::min() || reg_b_s64 != -1) {
                    _regs[r_d] = static_cast<register_val_t>(reg_a_s64 / reg_b_s64);
                } else {
                    _regs[r_d] = _regs[r_a];
                }
            } else {
                _regs[r_d] = std::numeric_limits<uint64_t>::max();
            }
            return {};
        }

        op_res_t rem_u_64(const buffer data)
        {
            const auto [r_a, r_b, r_d] = reg3(data);
            _regs[r_d] = _regs[r_b] != 0 ? _regs[r_a] % _regs[r_b] : _regs[r_a];
            return {};
        }

        op_res_t rem_s_64(const buffer data)
        {
            const auto [r_a, r_b, r_d] = reg3(data);
            const auto reg_a_s64 = static_cast<register_val_signed_t>(_regs[r_a]);
            const auto reg_b_s64 = static_cast<register_val_signed_t>(_regs[r_b]);
            if (reg_a_s64 != std::numeric_limits<register_val_signed_t>::min() || reg_b_s64 != -1)
                _regs[r_d] = reg_b_s64 != 0 ? static_cast<register_val_t>(reg_a_s64 % reg_b_s64) : reg_a_s64;
            else {
                _regs[r_d] = 0;
            }
            return {};
        }

        op_res_t shlo_l_64(const buffer data)
        {
            const auto [r_a, r_b, r_d] = reg3(data);
            _regs[r_d] = _regs[r_a] << (_regs[r_b] % 64U);
            return {};
        }

        op_res_t shlo_r_64(const buffer data)
        {
            const auto [r_a, r_b, r_d] = reg3(data);
            _regs[r_d] = _regs[r_a] >> (_regs[r_b] % 64U);
            return {};
        }

        op_res_t shar_r_64(const buffer data)
        {
            const auto [r_a, r_b, r_d] = reg3(data);
            _regs[r_d] = static_cast<register_val_t>(static_cast<register_val_signed_t>(_regs[r_a]) >> (static_cast<register_val_signed_t>(_regs[r_b] % 64U)));
            return {};
        }

        op_res_t and_(const buffer data)
        {
            const auto [r_a, r_b, r_d] = reg3(data);
            _regs[r_d] = _regs[r_a] & _regs[r_b];
            return {};
        }

        op_res_t xor_(const buffer data)
        {
            const auto [r_a, r_b, r_d] = reg3(data);
            _regs[r_d] = _regs[r_a] ^ _regs[r_b];
            return {};
        }

        op_res_t or_(const buffer data)
        {
            const auto [r_a, r_b, r_d] = reg3(data);
            _regs[r_d] = _regs[r_a] | _regs[r_b];
            return {};
        }

        op_res_t mul_upper_s_s(const buffer data)
        {
            const auto [r_a, r_b, r_d] = reg3(data);
#if defined(_MSC_VER)
            _mul128(static_cast<register_val_signed_t>(_regs[r_a]), static_cast<register_val_signed_t>(_regs[r_b]), reinterpret_cast<register_val_signed_t *>(&_regs[r_d]));
#elif defined(__GNUC__) || defined(__clang__)
            auto sign_extend_u64_to_i128 = [](uint64_t x) -> int128_t {
                return (x & (1ULL << 63)) ? static_cast<int128_t>(x) - (int128_t(1) << 64) : static_cast<int128_t>(x);
            };

            int128_t lhs = sign_extend_u64_to_i128(_regs[r_a]);
            int128_t rhs = sign_extend_u64_to_i128(_regs[r_b]);
            int128_t product = lhs * rhs;

            _regs[r_d] = static_cast<register_val_t>(product >> 64);
            //_regs[r_d] = static_cast<register_val_t>((static_cast<int128_t>(_regs[r_a]) * static_cast<int128_t>(_regs[r_b])) >> 64U);
#else
#   error "MULH operation implemented only for Visual C++, GCC, and Clang compilers"
#endif
            return {};
        }

        op_res_t mul_upper_u_u(const buffer data)
        {
            const auto [r_a, r_b, r_d] = reg3(data);
#if defined(_MSC_VER)
            _umul128(_regs[r_a], _regs[r_b], &_regs[r_d]);
#elif defined(__GNUC__) || defined(__clang__)
            _regs[r_d] = static_cast<register_val_t>((static_cast<uint128_t>(_regs[r_a]) * static_cast<uint128_t>(_regs[r_b])) >> 64U);
#else
#   error "MULH operation implemented only for Visual C++, GCC, and Clang compilers"
#endif
            return {};
        }

        op_res_t mul_upper_s_u(const buffer data)
        {
            const auto [r_a, r_b, r_d] = reg3(data);
            const auto reg_a_s64 = static_cast<register_val_signed_t>(_regs[r_a]);
            const bool reg_a_neg = reg_a_s64 < 0;
            const uint64_t reg_a_u64 = static_cast<uint64_t>(reg_a_neg ? -reg_a_s64 : reg_a_s64);
#if defined(_MSC_VER)            
            const uint64_t lo = _umul128(reg_a_u64, _regs[r_b], &_regs[r_d]);
#elif defined(__GNUC__) || defined(__clang__)
            const auto res = static_cast<int128_t>(reg_a_u64) * static_cast<uint128_t>(_regs[r_b]);
            const auto lo = static_cast<uint64_t>(res);
            _regs[r_d] = res >> 64U;
#else
#   error "MULH operation implemented only for Visual C++, GCC, and Clang compilers"
#endif
            if (reg_a_neg) {
                _regs[r_d] = ~_regs[r_d];
                if (lo == 0) {
                    _regs[r_d] += 1;
                }
            }
            return {};
        }

        op_res_t set_lt_u(const buffer data)
        {
            const auto [r_a, r_b, r_d] = reg3(data);
            _regs[r_d] = _regs[r_a] < _regs[r_b];
            return {};
        }

        op_res_t set_lt_s(const buffer data)
        {
            const auto [r_a, r_b, r_d] = reg3(data);
            _regs[r_d] = static_cast<register_val_signed_t>(_regs[r_a]) < static_cast<register_val_signed_t>(_regs[r_b]);
            return {};
        }

        op_res_t cmov_iz(const buffer data)
        {
            const auto [r_a, r_b, r_d] = reg3(data);
            _regs[r_d] = _regs[r_b] == 0 ? _regs[r_a] : _regs[r_d];
            return {};
        }

        op_res_t cmov_nz(const buffer data)
        {
            const auto [r_a, r_b, r_d] = reg3(data);
            _regs[r_d] = _regs[r_b] != 0 ? _regs[r_a] : _regs[r_d];
            return {};
        }

        op_res_t rot_l_64(const buffer data)
        {
            const auto [r_a, r_b, r_d] = reg3(data);
            _regs[r_d] = std::rotl(_regs[r_a], _regs[r_b]);
            return {};
        }

        op_res_t rot_l_32(const buffer data)
        {
            const auto [r_a, r_b, r_d] = reg3(data);
            _regs[r_d] = _sign_extend(4, std::rotl(static_cast<uint32_t>(_regs[r_a]), static_cast<uint32_t>(_regs[r_b])));
            return {};
        }

        op_res_t rot_r_64(const buffer data)
        {
            const auto [r_a, r_b, r_d] = reg3(data);
            _regs[r_d] = std::rotr(_regs[r_a], _regs[r_b]);
            return {};
        }

        op_res_t rot_r_32(const buffer data)
        {
            const auto [r_a, r_b, r_d] = reg3(data);
            _regs[r_d] = _sign_extend(4, std::rotr(static_cast<uint32_t>(_regs[r_a]), static_cast<uint32_t>(_regs[r_b])));
            return {};
        }

        op_res_t and_inv(const buffer data)
        {
            const auto [r_a, r_b, r_d] = reg3(data);
            _regs[r_d] = _regs[r_a] & (~_regs[r_b]);
            return {};
        }

        op_res_t or_inv(const buffer data)
        {
            const auto [r_a, r_b, r_d] = reg3(data);
            _regs[r_d] = _regs[r_a] | (~_regs[r_b]);
            return {};
        }

        op_res_t xnor(const buffer data)
        {
            const auto [r_a, r_b, r_d] = reg3(data);
            _regs[r_d] = ~(_regs[r_a] ^ _regs[r_b]);
            return {};
        }

        op_res_t max(const buffer data)
        {
            const auto [r_a, r_b, r_d] = reg3(data);
            _regs[r_d] = static_cast<register_val_t>(std::max(static_cast<register_val_signed_t>(_regs[r_a]), static_cast<register_val_signed_t>(_regs[r_b])));
            return {};
        }

        op_res_t max_u(const buffer data)
        {
            const auto [r_a, r_b, r_d] = reg3(data);
            _regs[r_d] = std::max(_regs[r_a], _regs[r_b]);
            return {};
        }

        op_res_t min(const buffer data)
        {
            const auto [r_a, r_b, r_d] = reg3(data);
            _regs[r_d] = static_cast<register_val_t>(std::min(static_cast<register_val_signed_t>(_regs[r_a]), static_cast<register_val_signed_t>(_regs[r_b])));
            return {};
        }

        op_res_t min_u(const buffer data)
        {
            const auto [r_a, r_b, r_d] = reg3(data);
            _regs[r_d] = std::min(_regs[r_a], _regs[r_b]);
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