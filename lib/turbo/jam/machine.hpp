#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <cstdint>
#include <variant>
#include "constants.hpp"
#include "encoding.hpp"
#include "types.hpp"

namespace turbo::jam::machine {
    using register_val_t = uint64_t;
    using register_val_signed_t = int64_t;
    using address_val_t = register_val_t;
    using gas_remaining_t = register_val_signed_t;

    struct memory_chunk_t: codec::serializable_t<memory_chunk_t> {
        uint32_t address = 0;
        sequence_t<uint8_t> contents {};

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("address"sv, address);
            archive.process("contents"sv, contents);
        }

        bool operator==(const memory_chunk_t &o) const noexcept
        {
            if (address != o.address)
                return false;
            if (contents != o.contents)
                return false;
            return true;
        }
    };
    using memory_chunks_t = sequence_t<memory_chunk_t>;

    struct page_t: codec::serializable_t<page_t> {
        uint32_t address = 0;
        uint32_t length = 0;
        bool is_writable = false;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("address"sv, address);
            archive.process("length"sv, length);
            archive.process("is-writable"sv, is_writable);
        }
    };
    using pages_t = sequence_t<page_t>;

    struct state_t {
        fixed_sequence_t<uint64_t, 13> regs {};
        uint32_t pc {};
        memory_chunks_t memory {};
        int64_t gas = 0;

        bool operator==(const state_t &o) const noexcept
        {
            if (regs != o.regs)
                return false;
            if (memory != o.memory)
                return false;
            if (pc != o.pc)
                return false;
            /*if (gas != o.gas)
                return false;*/
            return true;
        }
    };

    struct bit_buffer_t: buffer {
        using base_type = buffer;

        bit_buffer_t(const buffer bytes, const size_t num_bits):
            buffer { bytes },
            _bit_size { num_bits }
        {
        }

        size_t size() const
        {
            return _bit_size;
        }

        bool test(const size_t pos) const
        {
            if (pos >= _bit_size) [[unlikely]]
                return true;
            const auto byte_pos = pos >> 3;
            const auto bit_pos = pos & 7;
            return (*this)[byte_pos] & (1 << bit_pos);
        }
    private:
        size_t _bit_size;
    };

    struct exit_halt_t final {
        bool operator==(const exit_halt_t &) const
        {
            return true;
        }
    };
    struct exit_panic_t final {
        bool operator==(const exit_panic_t &) const
        {
            return true;
        }
    };
    struct exit_out_of_gas_t final {
        bool operator==(const exit_out_of_gas_t &) const
        {
            return true;
        }
    };
    struct exit_page_fault_t final {
        bool operator==(const exit_page_fault_t &) const
        {
            return true;
        }
    };
    struct exit_host_call_t final {
        bool operator==(const exit_host_call_t &) const
        {
            return true;
        }
    };

    using result_base_t = std::variant<exit_halt_t, exit_panic_t, exit_out_of_gas_t, exit_page_fault_t, exit_host_call_t>;
    struct result_t: result_base_t {
        using base_type = result_base_t;
        using base_type::base_type;

        static result_t from_json(const boost::json::value &j)
        {
            using namespace std::string_view_literals;
            const auto val = boost::json::value_to<std::string_view>(j);
            if (val == "panic"sv)
                return { machine::exit_panic_t {} };
            if (val == "halt"sv)
                return { machine::exit_halt_t {} };
            if (val == "page-fault"sv)
                return { machine::exit_page_fault_t {} };
            throw error(fmt::format("unsupported machine_status_t value '{}'", val));
        }
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
            const bit_buffer_t bitmasks { dec.next_bytes((code_sz + 7) / 8), code_sz };
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
        machine_t(const state_t &init, const program_t &program):
            _program { program },
            _state { init }
        {
        }

        result_t run()
        {
            try {
                for (;;) {
                    if (!_program.bitmasks.test(_state.pc)) [[unlikely]]
                        throw exit_panic_t {};
                    const uint8_t opcode = _program.code.at(_state.pc);
                    const auto len = _skip_len(_state.pc, _program.bitmasks);
                    const auto data = _program.code.subbuf(_state.pc + 1, len);
                    const auto res = exec(opcode, data);
                    _state.pc = res.new_pc.value_or(_state.pc + len + 1);
                    _state.gas -= res.gas_used;
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

        const state_t &state() const
        {
            return _state;
        }
    private:
        const program_t &_program;
        state_t _state;

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

        op_res_t exec(const uint8_t opcode, const buffer data)
        {
            static std::array<op_res_t(machine_t::*)(buffer), 0x100> ops {
                // 0x00
                &machine_t::trap, &machine_t::fallthrough, &machine_t::trap, &machine_t::trap,
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,

                // 0x10
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,
                &machine_t::load_imm64, &machine_t::trap, &machine_t::trap, &machine_t::trap,
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,

                // 0x20
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,
                &machine_t::jump, &machine_t::trap, &machine_t::trap, &machine_t::trap,
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,

                // 0x30
                &machine_t::trap, &machine_t::trap, &machine_t::jump_ind, &machine_t::load_imm,
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,

                // 0x40
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,

                // 0x50
                &machine_t::trap, &machine_t::trap, &machine_t::branch_ne_imm, &machine_t::trap,
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,

                // 0x60
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,
                &machine_t::move_reg, &machine_t::trap, &machine_t::trap, &machine_t::trap,
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,

                // 0x70
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,

                // 0x80
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::add_imm_32,
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,

                // 0x90
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,
                &machine_t::trap, &machine_t::add_imm_64, &machine_t::trap, &machine_t::shlo_l_imm_64,
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,

                // 0xA0
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::branch_ne,
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,

                // 0xB0
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,

                // 0xC0
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,

                // 0xD0
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,

                // 0xE0
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,

                // 0xF0
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap,
                &machine_t::trap, &machine_t::trap, &machine_t::trap, &machine_t::trap
            };
            const auto &op = ops[opcode];
            return (this->*op)(data);
        }

        static register_val_t _sign_extend(const size_t num_bytes, const register_val_t value)
        {
            if (num_bytes > 0) [[likely]] {
                const register_val_t mask = 1ULL << (num_bytes * 8U - 1ULL);
                return (value ^ mask) - mask;
            }
            return value;
        }

        op_res_t trap(const buffer)
        {
            // no gas consumption
            throw exit_panic_t {};
        }

        op_res_t fallthrough(const buffer)
        {
            // no gas consumption
            // do nothing
            return {};
        }

        op_res_t ecalli(const buffer data)
        {
            // no gas consumption
            const size_t l_x = std::min(4ULL, data.size());
            decoder dec { data };
            const auto nu_x = _sign_extend(l_x, dec.uint_fixed<register_val_t>(l_x));
            throw error { "ecalli not implemented" };
        }

        op_res_t load_imm_base(const buffer data, const size_t max_size)
        {
            const size_t r_a = std::min(12ULL, data.at(0ULL) & 0xFULL);
            const size_t l_x = !data.empty() ? std::min(max_size, data.size() - 1) : 0;
            decoder dec { data.subbuf(1) };
            const auto nu_x = _sign_extend(l_x, dec.uint_fixed<register_val_t>(l_x));
            _state.regs[r_a] = nu_x;
            return {};
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
            _state.regs[r_d] = _state.regs[r_a];
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

        static std::tuple<size_t, size_t, register_val_t> reg2_imm1(const buffer data)
        {
            const size_t r_a = std::min(12ULL, data.at(0ULL) & 0xFULL);
            const size_t r_b = std::min(12ULL, data.at(0ULL) / 16ULL);
            const size_t l_x = !data.empty() ? std::min(4ULL, data.size() - 1) : 0;
            decoder dec { data.subbuf(1) };
            const auto nu_x = _sign_extend(l_x, dec.uint_fixed<register_val_t>(l_x));
            return std::make_tuple(r_a, r_b, nu_x);
        }

        static std::tuple<size_t, register_val_t> reg1_imm1(const buffer data)
        {
            const size_t r_a = std::min(12ULL, data.at(0ULL) & 0xFULL);
            const size_t l_x = !data.empty() ? std::min(4ULL, data.size() - 1) : 0;
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
            const auto nu_y = static_cast<register_val_t>(static_cast<register_val_signed_t>(_state.pc) + static_cast<register_val_signed_t>(nu_y_pre));
            return std::make_tuple(r_a, nu_x, nu_y);
        }

        op_res_t branch_ne(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            const auto new_pc = static_cast<register_val_t>(static_cast<register_val_signed_t>(_state.pc) + static_cast<register_val_signed_t>(nu_x));
            return branch_base(new_pc, _state.regs[r_a] != _state.regs[r_b]);
        }

        op_res_t add_imm_32(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _state.regs[r_a] = _sign_extend(4, (_state.regs[r_b] + nu_x) % (1ULL << 32ULL));
            return {};
        }

        op_res_t add_imm_64(const buffer data)
        {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _state.regs[r_a] = _state.regs[r_b] + nu_x;
            return {};
        }

        op_res_t shlo_l_imm_64(const buffer data) {
            const auto [r_a, r_b, nu_x] = reg2_imm1(data);
            _state.regs[r_a] = _state.regs[r_b] << nu_x;
            return {};
        }

        op_res_t branch_ne_imm(const buffer data)
        {
            const auto [r_a, nu_x, nu_y] = reg1_imm1_off1(data);
            return branch_base(nu_y, _state.regs[r_a] != nu_x);
        }

        op_res_t jump(const buffer data)
        {
            const size_t l_x = std::min(4ULL, data.size());
            decoder dec { data };
            const auto nu_x_pre = _sign_extend(l_x, dec.uint_fixed<register_val_t>(l_x));
            const auto nu_x = static_cast<register_val_t>(static_cast<register_val_signed_t>(_state.pc) + static_cast<register_val_signed_t>(nu_x_pre));
            return branch_base(nu_x, true);
        }

        op_res_t jump_ind(const buffer data)
        {
            const auto [r_a, nu_x] = reg1_imm1(data);
            return djump((_state.regs[r_a] + nu_x) % (1ULL << 32ULL));
        }
    };
}
