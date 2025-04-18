#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <cstdint>
#include <variant>
#include "constants.hpp"
#include "encoding.hpp"

namespace turbo::jam::machine {
    using register_val_t = uint64_t;
    using address_val_t = uint64_t;
    using gas_remaining_t = int64_t;

    struct bit_buffer_t: buffer {
        using base_type = buffer;
        using base_type::base_type;

        bool test(const size_t pos) const
        {
            const auto max_pos = size() << 3U;
            if (pos >= max_pos) [[unlikely]]
                throw error(fmt::format("the requested bit index: {} is out of range: [0;{})", pos, max_pos));
            const auto byte_pos = pos >> 3;
            const auto bit_pos = pos & 7;
            return (*this)[byte_pos] & (1 << bit_pos);
        }
    };

    struct exit_halt_t {
        bool operator==(const exit_halt_t &) const {
            return true;
        }
    };
    struct exit_panic_t {
        bool operator==(const exit_panic_t &) const {
            return true;
        }
    };
    struct exit_out_of_gas_t {
        bool operator==(const exit_out_of_gas_t &) const {
            return true;
        }
    };
    struct exit_page_fault_t {
        bool operator==(const exit_page_fault_t &) const {
            return true;
        }
    };
    struct exit_host_call_t {
        bool operator==(const exit_host_call_t &) const {
            return true;
        }
    };

    using result_base_t = std::variant<register_val_t, exit_halt_t, exit_panic_t, exit_out_of_gas_t, exit_page_fault_t, exit_host_call_t>;
    struct result_t: result_base_t {
        using base_type = result_base_t;
        using base_type::base_type;
    };

    struct program_t {
        using offset_list = std::vector<uint32_t>;

        offset_list jump_table;
        buffer code;
        bit_buffer_t bitmasks;

        static program_t from_bytes(const buffer bytes)
        {
            decoder dec { bytes };
            const auto jt_sz = dec.uint_varlen();
            const auto jt_offset_sz = dec.uint_fixed<uint8_t>(1);
            const auto code_sz = dec.uint_varlen();
            offset_list jt {};
            jt.reserve(jt_sz);
            while (jt.size() < jt_sz) {
                jt.emplace_back(dec.uint_fixed<uint32_t>(jt_offset_sz));
            }
            const auto code = dec.next_bytes(code_sz);
            // TODO: JAM (A.4) zero pad the code to ensure the last intruction is valid
            const bit_buffer_t bitmasks { dec.next_bytes((code_sz + 7) / 8) };
            if (!dec.empty()) [[unlikely]]
                throw error("failed to decode all bytes of the program blob");
            return {
                std::move(jt),
                code,
                bitmasks
            };
        }
    };

    struct machine_t {
        void run(const program_t &program)
        {
            _pc = 0;
            for (;;) {
                const uint8_t opcode = program.code.at(_pc);
                const auto len = _skip_len(_pc, program.bitmasks);
                const auto data = program.code.subbuf(_pc + 1, len);
                exec(opcode, data);
            }
        }

    private:
        std::array<register_val_t, 13> _regs {};
        register_val_t _pc = 0;
        gas_remaining_t _gas_remaining = 0;

        static size_t _skip_len(const register_val_t opcode_pc, const bit_buffer_t &bitmasks)
        {
            const auto start_pc = opcode_pc + 1;
            auto pc = start_pc;
            while (!bitmasks.test(pc)) {
                ++pc;
            }
            return std::min(24ULL, pc - start_pc);
        }

        bool mem_readable(const address_val_t addr)
        {
            return false;
        }

        void mem_access_valid(const address_val_t x)
        {
            const auto x_m = x % (1ULL << 32U);
            if (x_m < config_prod::pvm_init_zone_size) [[unlikely]]
                throw exit_panic_t {};
            if (!mem_readable(x))
                throw exit_page_fault_t {};
            // JAM Paper (A.7)

        }

        void opcodes(const uint8_t i)
        {
            /*std::vector<void(machine::*)()> ops {};
            ops.reserve(256);
            // 0 ... 9
            ops.emplace_back(trap);
            ops.emplace_back(fallthrough());
            while (ops.size() < 10)
                ops.emplace_back(trap);
            // 10 ... 19
            ops.emplace_back(ecalli);
            while (ops.size() < 20)
                ops.emplace_back(trap);
            // 20 ... 29
            ops.emplace_back(load_imm_64);
            while (ops.size() < 30)
                ops.emplace_back(trap);
            // 30 ... 39
            ops.emplace_back(store_imm_u8);
            ops.emplace_back(store_imm_u16);
            ops.emplace_back(store_imm_u32);
            ops.emplace_back(store_imm_u33);
            while (ops.size() < 40)
                ops.emplace_back(trap);
            // 40 ... 49
            ops.emplace_back(jump);
            while (ops.size() < 50)
                ops.emplace_back(trap);
            // 50 ... 59
            ops.emplace_back(jump_ind);
            ops.emplace_back(load_imm);
            ops.emplace_back(load_u8);
            ops.emplace_back(load_i8);
            ops.emplace_back(load_u16);
            ops.emplace_back(load_i16);
            ops.emplace_back(load_u32);
            ops.emplace_back(load_i32);
            ops.emplace_back(load_u64);
            ops.emplace_back(store_u8);
            // 60 ... 69
            ops.emplace_back(store_u16);
            ops.emplace_back(store_u32);
            ops.emplace_back(store_u64);
            while (ops.size() < 70)
                ops.emplace_back(trap);

            // 60 ... 79
            // one register and two immediate
            ops.emplace_back(store_imm_ind_u8);
            ops.emplace_back(store_imm_ind_u16);
            ops.emplace_back(store_imm_ind_u32);
            ops.emplace_back(store_imm_ind_u64);
            while (ops.size() < 80)
                ops.emplace_back(trap);

            // 80 ... 89
            // one register, one immediate and one offset
            ops.emplace_back(load_imm_jump);
            ops.emplace_back(branch_eq_imm);
            ops.emplace_back(branch_ne_imm);
            ops.emplace_back(branch_lt_u_imm);
            ops.emplace_back(branch_le_u_imm);
            ops.emplace_back(branch_ge_u_imm);
            ops.emplace_back(branch_gt_u_imm);
            ops.emplace_back(branch_lt_s_imm);
            ops.emplace_back(branch_le_s_imm);
            ops.emplace_back(branch_ge_s_imm);

            // 90 ... 99
            ops.emplace_back(branch_gt_s_imm);
            while (ops.size() < 100)
                ops.emplace_back(trap);

            // 100 ... 199
            // two registers
            ops.emplace_back(move_reg);
            ops.emplace_back(sbrk);
            ops.emplace_back(count_set_bits_64);
            ops.emplace_back(count_set_bits_32);
            ops.emplace_back(leading_zero_bits_64);
            ops.emplace_back(leading_zero_bits_32);
            ops.emplace_back(trailing_zero_bits_64);
            ops.emplace_back(trailing_zero_bits_32);
            ops.emplace_back(sign_extend_8);
            ops.emplace_back(sign_extend_16);

            // 110 ... 119
            ops.emplace_back(zero_extend_16);
            ops.emplace_back(reverse_bytes);
            while (ops.size() < 120)
                ops.emplace_back(trap);

            // 120 ... 129
            // two registers and an immediate
            ops.emplace_back(store_ind_u8);
            ops.emplace_back(store_ind_u16);
            ops.emplace_back(store_ind_u32);
            ops.emplace_back(store_ind_u64);
            ops.emplace_back(load_ind_u8);
            ops.emplace_back(load_ind_i8);
            ops.emplace_back(load_ind_u16);
            ops.emplace_back(load_ind_i16);
            ops.emplace_back(load_ind_u32);
            ops.emplace_back(load_ind_i32);

            // 130 ... 139
            ops.emplace_back(load_ind_u64);
            ops.emplace_back(add_imm_32);
            ops.emplace_back(add_imm);
            ops.emplace_back(xor_imm);
            ops.emplace_back(or_imm);
            ops.emplace_back(mul_imm_32);
            ops.emplace_back(set_lt_u_imm);
            ops.emplace_back(set_lt_s_imm);
            ops.emplace_back(shlo_l_imm_32);
            ops.emplace_back(shlo_r_imm_32);

            // 140 ... 149
            ops.emplace_back(shar_r_imm_32);
            ops.emplace_back(neg_add_imm_32);
            ops.emplace_back(set_gt_u_imm);
            ops.emplace_back(set_gt_s_imm);
            ops.emplace_back(shlo_l_imm_alt_32);
            ops.emplace_back(shlo_r_imm_alt_32);
            ops.emplace_back(shar_r_imm_alt_32);
            ops.emplace_back(cmov_iz_imm);
            ops.emplace_back(cmov_nz_imm);
            ops.emplace_back(add_imm_64);

            // 150 ... 159
            ops.emplace_back(mul_imm_64);
            ops.emplace_back(shlo_l_imm_64);
            ops.emplace_back(shlo_r_imm_64);
            ops.emplace_back(shar_r_imm_64);
            ops.emplace_back(neg_add_imm_64);
            ops.emplace_back(shlo_l_imm_alt_64);
            ops.emplace_back(shlo_r_imm_alt_64);
            ops.emplace_back(shar_r_imm_alt_64);
            ops.emplace_back(rot_r_64_imm);
            ops.emplace_back(rot_r_64_imm_alt);

            // 160 ... 169
            ops.emplace_back(rot_r_32_imm);
            ops.emplace_back(rot_r_32_imm_alt);
            while (ops.size() < 170)
                ops.emplace_back(trap);

            // 170 ... 179
            ops.emplace_back(branch_eq);
            ops.emplace_back(branch_ne);
            ops.emplace_back(branch_lt_u);
            ops.emplace_back(branch_lt_s);
            ops.emplace_back(branch_ge_u);
            ops.emplace_back(branch_ge_s);
            while (ops.size() < 180)
                ops.emplace_back(trap);

            // 180 ... 189
            ops.emplace_back(load_imm_jump_ind);
            while (ops.size() < 190)
                ops.emplace_back(trap);

            // 190 ... 199
            ops.emplace_back(add_32);
            ops.emplace_back(sub_32);
            ops.emplace_back(mul_32);
            ops.emplace_back(div_u_32);
            ops.emplace_back(div_s_32);
            ops.emplace_back(rem_u_32);
            ops.emplace_back(rem_s_32);
            ops.emplace_back(shlo_l_32);
            ops.emplace_back(shlo_r_32);
            ops.emplace_back(shar_r_32);

            // 200 ... 209
            ops.emplace_back(add_64);
            ops.emplace_back(sub_64);
            ops.emplace_back(mul_64);
            ops.emplace_back(div_u_64);
            ops.emplace_back(div_s_64);
            ops.emplace_back(rem_u_64);
            ops.emplace_back(rem_s_64);
            ops.emplace_back(shlo_l_64);
            ops.emplace_back(shlo_r_64);
            ops.emplace_back(shar_r_64);

            // 210 ... 219
            ops.emplace_back(and_);
            ops.emplace_back(xor_);
            ops.emplace_back(or_);
            ops.emplace_back(mul_upper_s_s);
            ops.emplace_back(mul_upper_u_u);
            ops.emplace_back(mul_upper_s_u);
            ops.emplace_back(set_lt_u);
            ops.emplace_back(set_lt_s);
            ops.emplace_back(cmov_iz);
            ops.emplace_back(cmov_nz);

            // 220 ... 229
            ops.emplace_back(rot_l_64);
            ops.emplace_back(rot_l_32);
            ops.emplace_back(rot_r_64;
            ops.emplace_back(rot_r_32);
            ops.emplace_back(and_inv);
            ops.emplace_back(or_inv);
            ops.emplace_back(xnor);
            ops.emplace_back(max);
            ops.emplace_back(max_u);
            ops.emplace_back(min);

            // 230 ... 239
            ops.emplace_back(min_u);
            while (ops.size() < 256)
                ops.emplace_back(trap);*/
        }

        // execution flow altering opcodes - T

        void exec(const uint8_t opcode, const buffer data)
        {
            switch (opcode) {
                case 51: load_imm(data); break;
                [[unlikely]] default: throw exit_panic_t {};
            }
        }

        static register_val_t _sign_extend(const size_t num_bytes, const register_val_t value)
        {
            if (num_bytes > 0) [[likely]] {
                const register_val_t mask = 1ULL << (num_bytes * 8U - 1ULL);
                return (value ^ mask) - mask;
            }
            return value;
        }

        void load_imm(const buffer data)
        {
            const size_t r_a = std::min(12ULL, data.at(0ULL) & 0xFULL);
            const size_t l_x = data.size() > 0 ? std::min(4ULL, data.size() - 1) : 0;
            decoder dec { data.subbuf(1) };
            const auto nu_x = _sign_extend(l_x, dec.uint_fixed<register_val_t>(l_x));
            _regs[r_a] = nu_x;
        }

        void trap();
        void fallthrough();
        void jump();
        void jump_ind();
        void load_imm_jump();
        void load_imm_jump_ind();
        void branch_eq();
        void branch_ne();
        void branch_ge_u();
        void branch_ge_s();
        void branch_lt_u();
        void branch_lt_s();
        void branch_eq_imm();
        void branch_ne_imm();
        void branch_lt_u_imm();
        void branch_lt_s_imm();
        void branch_le_u_imm();
        void branch_le_s_imm();
        void branch_ge_u_imm();
        void branch_ge_s_imm();
        void branch_gt_u_imm();
        void branch_gt_s_imm();

    };
}
