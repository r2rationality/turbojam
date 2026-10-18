#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2026 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include "opcodes.hpp"

namespace turbo::jam::machine {
    struct bit_vector_t {
        bit_vector_t() =delete;
        bit_vector_t(const bit_vector_t &o) =delete;

        bit_vector_t(const buffer bytes, const size_t num_bits):
            _num_bits{num_bits}
        {
            if (_num_bits > bytes.size() * 8U) [[unlikely]]
                throw error(fmt::format("too many bits for bit vector of {} bytes: {}", bytes.size(), _num_bits));
            _bytes.reserve(bytes.size() + 3U);
            _bytes.insert(_bytes.end(), bytes.begin(), bytes.end());
            _bytes.insert(_bytes.end(), 3U, uint8_t{0});
        }

        bit_vector_t(bit_vector_t &&o) noexcept:
            _num_bits{o._num_bits},
            _bytes{std::move(o._bytes)}
        {
        }

        [[nodiscard]] size_t size() const noexcept
        {
            return _num_bits;
        }

        [[nodiscard]] bool test(const size_t pos) const noexcept
        {
            if (pos >= _num_bits) [[unlikely]]
                return true;
            return test_unchecked(pos);
        }

        [[nodiscard]] bool test_unchecked(const size_t pos) const noexcept
        {
            return ((_bytes[pos >> 3U] >> (pos & 7U)) & 0x1U) != 0U;
        }

        template<size_t MAX>
        [[nodiscard]] size_t count_zeros(const size_t pos) const noexcept
        {
            static_assert(std::endian::native == std::endian::little);
            static_assert(MAX + 7U <= 32U, "requested bits must fit in one 32-bit window");
            // Interpret any bit beyond _num_bits as a 1 to comply with the spec's (A.3)
            if (pos >= _num_bits) [[unlikely]]
                return 0;
            // The constructor appends three bytes, making this read safe.
            const auto *ptr = _bytes.data() + (pos >> 3U);
            uint32_t bits;
            static_assert(sizeof(bits) == 4U, "uint32_t must take 4 bytes!");
            memcpy(&bits, ptr, sizeof(bits));
            const auto shifted = bits >> (pos & 7U);
            const auto zeros = static_cast<size_t>(std::countr_zero(shifted));
            return std::min(zeros, std::min(MAX, _num_bits - pos));
        }

        /*template<size_t MAX>
        [[nodiscard]] std::optional<size_t> previous_set_bit(const size_t pos) const noexcept
        {
            static_assert(std::endian::native == std::endian::little);
            static_assert(MAX > 0 && MAX <= 25, "requested bits must fit in one 32-bit window");
            const auto begin = pos > MAX ? pos - MAX : 0U;
            const auto end = std::min(pos, _num_bits);
            if (begin >= end)
                return {};
            const auto length = end - begin;
            uint32_t bits;
            static_assert(sizeof(bits) == 4U, "uint32_t must take 4 bytes!");
            // Three padding bytes make the read safe even near the logical end.
            std::memcpy(&bits, _bytes.data() + (begin >> 3U), sizeof(bits));
            // Align bit end - 1 with the MSB, discarding all bits at or after end.
            bits <<= 32U - ((begin & 7U) + length);
            const auto zeros = static_cast<size_t>(std::countl_zero(bits));
            if (zeros >= length)
                return {};
            return end - 1U - zeros;
        }*/

        [[nodiscard]] uint8_t skip_len(const register_val_t opcode_pc) const noexcept
        {
            return count_zeros<max_skip_len>(static_cast<size_t>(opcode_pc) + 1U);
        }
    private:
        size_t _num_bits;
        uint8_vector _bytes;
    };

    struct exit_halt_t final: error {
        exit_halt_t(): error{"exit_halt_t"}
        {}

        bool operator==(const exit_halt_t &) const {
            return true;
        }

        void serialize(auto &) {
        }
    };
    struct exit_panic_t final: error {
        exit_panic_t(): error{"exit_panic_t"}
        {}

        bool operator==(const exit_panic_t &) const {
            return true;
        }

        void serialize(auto &) {
        }
    };
    struct exit_out_of_gas_t final: error {
        exit_out_of_gas_t(): error{"exit_out_of_gas_t"}
        {}

        bool operator==(const exit_out_of_gas_t &) const {
            return true;
        }

        void serialize(auto &) {
        }
    };
    struct exit_page_fault_t final: error {
        address_val_t addr;

        exit_page_fault_t(const address_val_t a=0):
            error{"exit_page_fault_t"},
            addr{a}
        {}

        bool operator==(const exit_page_fault_t &o) const {
            if (addr != o.addr)
                return false;
            return true;
        }

        void serialize(auto &archive) {
            using namespace std::string_view_literals;
            archive.process("addr"sv, addr);
        }
    };
    struct exit_host_call_t final: error {
        register_val_t id;

        exit_host_call_t(const register_val_t id):
            error{"exit_host_call_t"},
            id{id}
        {}

        exit_host_call_t():
            exit_host_call_t{0U}
        {}

        bool operator==(const exit_host_call_t &o) const {
            if (id != o.id)
                return false;
            return true;
        }

        void serialize(auto &archive) {
            using namespace std::string_view_literals;
            archive.process("id"sv, id);
        }
    };

    struct code_t {
        using offset_list_t = std::vector<address_val_t>;

        struct opcode_t {
            uint64_t id       : 8 = 0;
            uint64_t skip_len : 5 = 0;
            uint64_t alu      : 2 = 0;
            uint64_t load     : 1 = 0;
            uint64_t store    : 1 = 0;
            uint64_t mul      : 1 = 0;
            uint64_t div      : 1 = 0;
            uint64_t reg_1    : 4 = 0;
            uint64_t reg_2    : 4 = 0;
            uint64_t reg_3    : 4 = 0;
            uint64_t reg_dst  : 4 = 0xF;
            uint64_t regs_src : 13 = 0;
            uint64_t e_cycles : 7 = 0;
            uint64_t d_cycles : 3 = 0;
            register_val_t imm_1 = 0;
            register_val_t imm_2 = 0;

            opcode_t(const code_t &c, const address_val_t pc, const address_val_t pc_end):
                id{c.instrs[pc]},
                skip_len{numeric_cast<uint8_t>(c.bitmasks.skip_len(pc))}
            {
                const buffer data{c.instrs.subbuf(pc + 1, skip_len)};
                if (pc >= pc_end) [[unlikely]]
                    throw error{"opcode decoder requires at least a single byte!"};
                if (pc >= std::numeric_limits<decltype(pc)>::max() - 1U - skip_len) [[unlikely]]
                    throw error{"pc is too big that it overflows: {}", pc};
                if (pc + skip_len >= pc_end) [[unlikely]]
                    throw error{"opcode decoding error: instruction of {} bytes but have only {}", 1 + skip_len, pc_end - pc};
                const auto next_pc = pc + skip_len + 1U;
                const auto meta = opcodes()[c.instrs[pc]];
                alu = meta.alu;
                load = meta.load;
                store = meta.store;
                mul = meta.mul;
                div = meta.div;
                switch (static_cast<opcode_meta_t::args_t>(meta.args_typ)) {
                    case opcode_meta_t::none: break;
                    case opcode_meta_t::imm1: _args_imm1(data); break;
                    case opcode_meta_t::off1: _args_off1(data, pc); break;
                    case opcode_meta_t::imm2: _args_imm2(data); break;
                    case opcode_meta_t::reg1_imm1_s32: _args_reg1_imm1_signed(data, 4U); break;
                    case opcode_meta_t::reg1_imm1_u32: _args_reg1_imm1_unsigned(data, 4U); break;
                    case opcode_meta_t::reg1_imm1_s64: _args_reg1_imm1_s64(data); break;
                    case opcode_meta_t::reg1_imm1_u64: _args_reg1_imm1_unsigned(data, 8U); break;
                    case opcode_meta_t::reg1_imm1_off1: _args_reg1_imm1_off1(data, pc); break;
                    case opcode_meta_t::reg1_imm2: _args_reg1_imm2(data); break;
                    case opcode_meta_t::reg2: _args_reg2(data); break;
                    case opcode_meta_t::reg2_imm1: _args_reg2_imm1(data); break;
                    case opcode_meta_t::reg2_off1: _args_reg2_off1(data, pc); break;
                    case opcode_meta_t::reg2_imm2: _args_reg2_imm2(data); break;
                    case opcode_meta_t::reg3: _args_reg3(data); break;
                    [[unlikely]] default: throw error{"unsupported opcode argument format: {}", meta.args_typ};
                }
                switch (static_cast<opcode_meta_t::args_t>(meta.args_typ)) {
                    case opcode_meta_t::none:
                    case opcode_meta_t::imm1:
                    case opcode_meta_t::imm2:
                    case opcode_meta_t::off1:
                        // do nothing
                        break;
                    case opcode_meta_t::reg1_imm1_s64:
                    case opcode_meta_t::reg1_imm1_u64:
                    case opcode_meta_t::reg1_imm1_s32:
                    case opcode_meta_t::reg1_imm1_u32:
                    case opcode_meta_t::reg1_imm1_off1:
                    case opcode_meta_t::reg1_imm2:
                        if (meta.dst_reg == 0)
                            reg_dst = reg_1;
                        else
                            regs_src = static_cast<uint16_t>(register_set_t::from_reg(reg_1));
                        break;
                    case opcode_meta_t::reg2:
                    case opcode_meta_t::reg2_imm1:
                    case opcode_meta_t::reg2_off1:
                    case opcode_meta_t::reg2_imm2:
                        if (meta.dst_reg == 0) {
                            reg_dst = reg_1;
                            regs_src = static_cast<uint16_t>(register_set_t::from_reg(reg_2));
                        } else if (meta.dst_reg == 1) {
                            reg_dst = reg_2;
                            regs_src = static_cast<uint16_t>(register_set_t::from_reg(reg_1));
                        } else {
                            regs_src = static_cast<uint16_t>(register_set_t::from_regs({reg_1, reg_2}));
                        }
                        break;
                    case opcode_meta_t::reg3:
                        if (meta.dst_reg == 0) {
                            reg_dst = reg_1;
                            regs_src = static_cast<uint16_t>(register_set_t::from_regs({reg_2, reg_3}));
                        } else if (meta.dst_reg == 1) {
                            reg_dst = reg_2;
                            regs_src = static_cast<uint16_t>(register_set_t::from_regs({reg_1, reg_3}));
                        } else if (meta.dst_reg == 2) {
                            reg_dst = reg_3;
                            regs_src = static_cast<uint16_t>(register_set_t::from_regs({reg_1, reg_2}));
                        } else {
                            regs_src = static_cast<uint16_t>(register_set_t::from_regs({reg_1, reg_2, reg_3}));
                        }
                        break;
                    [[unlikely]] default: throw error{"unsupported register-based cost argument format: {}", static_cast<int>(meta.args_typ)};
                }
                if (meta.dst_is_src && reg_dst != 0xF) {
                    auto rs = register_set_t::from_bits(regs_src);
                    rs.add(reg_dst);
                    regs_src = static_cast<uint16_t>(rs);
                }
                switch (meta.cycles_typ) {
                    case 0: e_cycles = meta.cycles_a; break;
                    case 1: {
                        // intentionally read past size into the 0-padded area
                        const auto next_op = static_cast<opcode_id_t>(c.instrs.data()[next_pc]);
                        switch (static_cast<opcode_meta_t::args_t>(meta.args_typ)) {
                            case opcode_meta_t::reg2_off1:
                                e_cycles = cycles_branch_t::cost(meta.cycles_a, meta.cycles_b, next_op, static_cast<opcode_id_t>(imm_1 < c.instrs.size() ? c.instrs[imm_1] : 0));
                                break;
                            case opcode_meta_t::reg1_imm1_off1:
                                e_cycles = cycles_branch_t::cost(meta.cycles_a, meta.cycles_b, next_op, static_cast<opcode_id_t>(imm_2 < c.instrs.size() ? c.instrs[imm_2] : 0));
                                break;
                            [[unlikely]] default: throw error{"unsupported branch argument format: {}", meta.args_typ};
                        }
                        break;
                    }
                    [[unlikely]] default: throw error{"unsupported cycles_typ: {}", meta.cycles_typ};
                }
                switch (meta.decode_typ) {
                    case 0: d_cycles = meta.decode_a; break;
                    case 1:
                        switch (static_cast<opcode_meta_t::args_t>(meta.args_typ)) {
                            case opcode_meta_t::reg2:
                            case opcode_meta_t::reg2_imm1:
                            case opcode_meta_t::reg3:
                                d_cycles = decode_regs_t::cost(meta.decode_a, meta.decode_b, src_regs(), dst_regs());
                                break;
                            [[unlikely]] default: throw error{"unsupported register-based cost argument format: {}", meta.args_typ};
                        }
                        break;
                    case 2: d_cycles = decode_shift_t::cost(meta.decode_a, meta.decode_b, reg_1, reg_3); break;
                    [[unlikely]] default: throw error{"unsupported cycles_typ: {}", meta.decode_typ};
                }
            }

            [[nodiscard]] register_set_t dst_regs() const {
                if (reg_dst != 0xF)
                    return register_set_t::from_reg(reg_dst);
                return {};
            }

            [[nodiscard]] register_set_t src_regs() const {
                return register_set_t::from_bits(regs_src);
            }

            // c-v
            [[nodiscard]] size_t cycle_cost() const {
                return e_cycles;
            }

            // d-v
            [[nodiscard]] size_t decode_cost() const {
                return d_cycles;
            }

            // x-v
            [[nodiscard]] execution_units_t uint_cost() const {
                return {alu, load, store, mul, div};
            }
        private:
            static register_val_t _read_uint_le_unchecked(const uint8_t *ptr, const size_t num_bytes) noexcept
            {
                switch (num_bytes) {
                    case 0:
                        return 0;
                    case 1:
                        return static_cast<register_val_t>(ptr[0]);
                    case 2:
                        return static_cast<register_val_t>(ptr[0])
                            | (static_cast<register_val_t>(ptr[1]) << 8U);
                    case 3:
                        return static_cast<register_val_t>(ptr[0])
                            | (static_cast<register_val_t>(ptr[1]) << 8U)
                            | (static_cast<register_val_t>(ptr[2]) << 16U);
                    case 4:
                        return static_cast<register_val_t>(ptr[0])
                            | (static_cast<register_val_t>(ptr[1]) << 8U)
                            | (static_cast<register_val_t>(ptr[2]) << 16U)
                            | (static_cast<register_val_t>(ptr[3]) << 24U);
                    default: {
                        register_val_t x = 0;
                        for (size_t i = 0; i < num_bytes; ++i)
                            x |= static_cast<register_val_t>(ptr[i]) << (i * 8U);
                        return x;
                    }
                }
            }

            static uint32_t _read_u32_prefix_le_unchecked(const uint8_t *ptr, const size_t num_bytes) noexcept
            {
                switch (num_bytes) {
                    case 0:
                        return 0;
                    case 1:
                        return static_cast<uint32_t>(ptr[0]);
                    case 2:
                        return static_cast<uint32_t>(static_cast<uint16_t>(ptr[0]) | (static_cast<uint16_t>(ptr[1]) << 8U));
                    case 3:
                        return static_cast<uint32_t>(ptr[0])
                            | (static_cast<uint32_t>(ptr[1]) << 8U)
                            | (static_cast<uint32_t>(ptr[2]) << 16U);
                    default:
                        return static_cast<uint32_t>(ptr[0])
                            | (static_cast<uint32_t>(ptr[1]) << 8U)
                            | (static_cast<uint32_t>(ptr[2]) << 16U)
                            | (static_cast<uint32_t>(ptr[3]) << 24U);
                }
            }

            static register_val_t _sign_extend_imm32_unchecked(const uint32_t x, const size_t num_bytes) noexcept
            {
                switch (num_bytes) {
                    case 0:
                        return 0;
                    case 1:
                        return static_cast<register_val_t>(static_cast<register_val_signed_t>(static_cast<int8_t>(x)));
                    case 2:
                        return static_cast<register_val_t>(static_cast<register_val_signed_t>(static_cast<int16_t>(x)));
                    case 3: {
                        auto extended = x;
                        if (extended & 0x00800000U)
                            extended |= 0xFF000000U;
                        return static_cast<register_val_t>(static_cast<register_val_signed_t>(static_cast<int32_t>(extended)));
                    }
                    default:
                        return static_cast<register_val_t>(static_cast<register_val_signed_t>(static_cast<int32_t>(x)));
                }
            }

            static register_val_t _read_uint32_le_unchecked(const uint8_t *ptr, const size_t num_bytes) noexcept
            {
                return static_cast<register_val_t>(_read_u32_prefix_le_unchecked(ptr, num_bytes));
            }

            static register_val_t _read_signed_imm32_unchecked(const uint8_t *ptr, const size_t num_bytes) noexcept
            {
                return _sign_extend_imm32_unchecked(_read_u32_prefix_le_unchecked(ptr, num_bytes), num_bytes);
            }

            void _args_imm1(const buffer data) {
                const size_t l_x = std::min(size_t{4}, data.size());
                imm_1 = _read_signed_imm32_unchecked(data.data(), l_x);
            }

            void _args_off1(const buffer data, const register_val_t pc)
            {
                const size_t l_x = std::min(size_t{4}, data.size());
                const auto imm_pre = _read_signed_imm32_unchecked(data.data(), l_x);
                imm_1 = static_cast<register_val_t>(static_cast<register_val_signed_t>(pc) + static_cast<register_val_signed_t>(imm_pre));
            }

            void _args_imm2(const buffer data)
            {
                const auto *ptr = data.data();
                const size_t l_x = std::min(4ULL, ptr[0] % 8ULL);
                const size_t base_y = 1U + l_x;
                const size_t l_y = data.size() > base_y ? std::min(size_t{4}, data.size() - base_y) : 0U;
                imm_1 = _read_signed_imm32_unchecked(ptr + 1U, l_x);
                imm_2 = _read_signed_imm32_unchecked(ptr + base_y, l_y);
            }

            void _args_reg1_imm1_signed(const buffer data, const size_t max_size) {
                const auto *ptr = data.data();
                const auto b0 = ptr[0];
                reg_1 = std::min(12ULL, b0 & 0xFULL);
                const size_t l_x = data.empty() ? 0U : std::min(max_size, data.size() - 1U);
                imm_1 = max_size <= 4U
                    ? _read_signed_imm32_unchecked(ptr + 1U, l_x)
                    : sign_extend(l_x, _read_uint_le_unchecked(ptr + 1U, l_x));
            }

            void _args_reg1_imm1_unsigned(const buffer data, const size_t max_size)
            {
                const auto *ptr = data.data();
                const auto b0 = ptr[0];
                reg_1 = std::min(12ULL, b0 & 0xFULL);
                const size_t l_x = data.empty() ? 0U : std::min(max_size, data.size() - 1U);
                imm_1 = max_size <= 4U
                    ? _read_uint32_le_unchecked(ptr + 1U, l_x)
                    : _read_uint_le_unchecked(ptr + 1U, l_x);
            }

            void _args_reg1_imm1_s64(const buffer data)
            {
                const auto *ptr = data.data();
                reg_1 = std::min(12ULL, ptr[0] & 0xFULL);
                imm_1 = _read_uint_le_unchecked(ptr + 1U, 8U);
            }

            void _args_reg1_imm1_off1(const buffer data, const register_val_t pc)
            {
                const auto *ptr = data.data();
                const auto b0 = ptr[0];
                reg_1 = std::min(12ULL, b0 & 0xFULL);
                const size_t l_x = std::min(4ULL, (b0 / 16ULL) % 8ULL);
                const size_t base_y = 1U + l_x;
                const size_t l_y = data.size() > base_y ? std::min(size_t{4}, data.size() - base_y) : 0U;
                imm_1 = _read_signed_imm32_unchecked(ptr + 1U, l_x);
                const auto nu_y_pre = _read_signed_imm32_unchecked(ptr + base_y, l_y);
                imm_2 = static_cast<register_val_t>(static_cast<register_val_signed_t>(pc) + static_cast<register_val_signed_t>(nu_y_pre));
            }

            void _args_reg1_imm2(const buffer data)
            {
                const auto *ptr = data.data();
                const auto b0 = ptr[0];
                reg_1 = std::min(12ULL, b0 & 0xFULL);
                const size_t l_x = std::min(4ULL, (b0 / 16ULL) % 8ULL);
                const size_t base_y = 1U + l_x;
                const size_t l_y = data.size() > base_y ? std::min(size_t{4}, data.size() - base_y) : 0U;
                imm_1 = _read_signed_imm32_unchecked(ptr + 1U, l_x);
                imm_2 = _read_signed_imm32_unchecked(ptr + base_y, l_y);
            }

            void _args_reg2_imm1(const buffer data)
            {
                const auto *ptr = data.data();
                const auto b0 = ptr[0];
                reg_1 = std::min(12ULL, b0 & 0xFULL);
                reg_2 = std::min(12ULL, b0 / 16ULL);
                imm_1 = [&]() noexcept -> register_val_t {
                    switch (data.size()) {
                    case 0:
                    case 1:
                        return 0;
                    case 2:
                        return static_cast<register_val_t>(static_cast<register_val_signed_t>(static_cast<int8_t>(ptr[1])));
                    case 3: {
                        const auto x = static_cast<uint16_t>(ptr[1]) | (static_cast<uint16_t>(ptr[2]) << 8U);
                        return static_cast<register_val_t>(static_cast<register_val_signed_t>(static_cast<int16_t>(x)));
                    }
                    case 4: {
                        auto x = static_cast<uint32_t>(ptr[1])
                            | (static_cast<uint32_t>(ptr[2]) << 8U)
                            | (static_cast<uint32_t>(ptr[3]) << 16U);
                        if (x & 0x00800000U)
                            x |= 0xFF000000U;
                        return static_cast<register_val_t>(static_cast<register_val_signed_t>(static_cast<int32_t>(x)));
                    }
                    default: {
                        const auto x = static_cast<uint32_t>(ptr[1])
                            | (static_cast<uint32_t>(ptr[2]) << 8U)
                            | (static_cast<uint32_t>(ptr[3]) << 16U)
                            | (static_cast<uint32_t>(ptr[4]) << 24U);
                        return static_cast<register_val_t>(static_cast<register_val_signed_t>(static_cast<int32_t>(x)));
                    }
                    }
                }();
            }

            void _args_reg2_imm2(const buffer data)
            {
                const auto *ptr = data.data();
                const auto b0 = ptr[0];
                const auto b1 = ptr[1];
                reg_1 = std::min(12ULL, b0 & 0xFULL);
                reg_2 = std::min(12ULL, b0 / 16ULL);
                const size_t l_x = std::min(4ULL, b1 % 8ULL);
                const size_t base_y = 2U + l_x;
                const size_t l_y = data.size() > base_y ? std::min(size_t{4}, data.size() - base_y) : 0U;
                imm_1 = _read_signed_imm32_unchecked(ptr + 2U, l_x);
                imm_2 = _read_signed_imm32_unchecked(ptr + base_y, l_y);
            }

            void _args_reg2_off1(const buffer data, const register_val_t pc)
            {
                _args_reg2_imm1(data);
                imm_1 = static_cast<register_val_t>(static_cast<register_val_signed_t>(pc) + static_cast<register_val_signed_t>(imm_1));
            }

            void _args_reg2(const buffer data)
            {
                // intentionally read past size into the 0-padded area
                const auto b0 = data.data()[0];
                reg_1 = std::min(12ULL, b0 & 0xFULL);
                reg_2 = std::min(12ULL, b0 / 16ULL);
            }

            void _args_reg3(const buffer data)
            {
                const auto *ptr = data.data();
                const auto b0 = ptr[0];
                const auto b1 = ptr[1];
                reg_1 = std::min(12ULL, b0 & 0xFULL);
                reg_2 = std::min(12ULL, b0 / 16ULL);
                reg_3 = std::min(uint8_t{12}, b1);
            }
        };
        static_assert(sizeof(opcode_t) == 24, "opcode_t must be 24 bytes!");

        struct block_t {
            gas_t cost = 0;
            sequence_t<opcode_t> opcodes{};
        };

        using blocks_t = boost::container::flat_map<address_val_t, block_t>;

        static register_val_t sign_extend(const size_t num_bytes, const register_val_t value)
        {
            if (num_bytes > 8) [[unlikely]]
                throw exit_panic_t{};
            if (num_bytes == 0) [[unlikely]]
                return 0;
            const size_t bit_count = num_bytes << 3U;
            const size_t extend_bits = 64U - bit_count;
            return static_cast<register_val_t>(static_cast<register_val_signed_t>(value << extend_bits) >> extend_bits);
        }

        [[nodiscard]] static constexpr bool is_block_end_opcode(const uint8_t opcode) noexcept {
            static constexpr auto block_end_opcodes = [] {
                std::array<bool, 0x100> res{};
                res[0] = true; // trap
                res[1] = true; // fallthrough
                res[40] = true; // jump
                res[50] = true; // jump_ind
                res[80] = true; // load_imm_jump
                res[81] = true; // branch_eq_imm
                res[82] = true; // branch_ne_imm
                res[83] = true; // branch_lt_u_imm
                res[84] = true; // branch_le_u_imm
                res[85] = true; // branch_ge_u_imm
                res[86] = true; // branch_gt_u_imm
                res[87] = true; // branch_lt_s_imm
                res[88] = true; // branch_le_s_imm
                res[89] = true; // branch_ge_s_imm
                res[90] = true; // branch_gt_s_imm
                res[170] = true; // branch_eq
                res[171] = true; // branch_ne
                res[172] = true; // branch_lt_u
                res[173] = true; // branch_lt_s
                res[174] = true; // branch_ge_u
                res[175] = true; // branch_ge_s
                res[180] = true; // load_imm_jump_ind
                return res;
            }();
            return block_end_opcodes[opcode];
        }

        [[nodiscard]] static bool is_opcode(uint8_t opcode);

        bit_vector_t bitmasks;
        buffer instrs;
        offset_list_t jump_table;

        // (A.2) deblob
        static code_t from_bytes(uint8_vector bytes)
        {
            decoder dec{bytes};
            const auto jt_sz = dec.uint_varlen();
            const auto jt_offset_sz = dec.uint_fixed<uint8_t>(1);
            const auto instrs_size = dec.uint_varlen();
            offset_list_t jt{};
            jt.reserve(jt_sz);
            while (jt.size() < jt_sz) {
                jt.emplace_back(dec.uint_fixed<address_val_t>(jt_offset_sz));
            }
            const auto instrs_offset = numeric_cast<size_t>(dec.consumed());

            (void)dec.next_bytes(instrs_size);
            // bitmask.size() equals the instrs_size by construction!
            bit_vector_t bitmasks{dec.next_bytes((instrs_size + 7) / 8), instrs_size};
            if (!dec.empty()) [[unlikely]]
                throw error("failed to decode all bytes of the code blob");
            // reuse the pre-allocated buffer
            bytes.erase(bytes.begin(), bytes.begin() + numeric_cast<ptrdiff_t>(instrs_offset));
            bytes.resize(instrs_size);
            return {
                std::move(bitmasks),
                std::move(bytes),
                std::move(jt)
            };
        }

        code_t() =delete;
        code_t(const code_t &o) =delete;

        code_t(bit_vector_t &&b, uint8_vector &&c, offset_list_t &&jt):
            bitmasks{std::move(b)},
            jump_table{std::move(jt)},
            _raw{std::move(c)}
        {
            if (bitmasks.size() != _raw.size()) [[unlikely]]
                throw error(fmt::format("the code bitmask size must match the number of instructions!"));
            // GP's zero suffix permits operand reads beyond the logical end of code.
            _raw.insert(_raw.end(), 16U, uint8_t{0});
            instrs = buffer{_raw.data(), bitmasks.size()};
            _validate();
        }

        // Moving _raw preserves the allocation referenced by instrs.
        code_t(code_t &&) =default;

        [[nodiscard]] const blocks_t &blocks() const noexcept {
            return _blocks;
        }
    private:
        uint8_vector _raw;
        blocks_t _blocks{};

        struct reorder_item_t {
            enum state_t { dec, wait, exe, fin, none };
            state_t state; // s
            size_t cycles; // c
            boost::container::flat_set<size_t> deps; // p
            register_set_t clob_regs; // r
            execution_units_t used_units; // t
        };

        struct gas_model_t {
            gas_model_t(const code_t &c, const address_val_t block_begin, const address_val_t block_end):
                _code{c},
                _pc{block_begin},
                _pc_end{block_end}
            {
                if (_pc >= _pc_end) [[unlikely]]
                    throw error{"block's code must have at least a single byte but got [{}:{})!", _pc, _pc_end};
            }

            [[nodiscard]] block_t simulate() {
                _simulate();
                if (_opcodes.empty()) [[unlikely]]
                    throw error{"internal error: a simulation returned a block without any instructions!"};
                return {_cycles > 3U ? _cycles - 3U : 1U, std::move(_opcodes)};
            }
        private:
            const code_t &_code;
            address_val_t _pc; // i
            address_val_t _pc_end;
            gas_t _cycles = 0; // c
            size_t _decode_slots = 4; // d
            size_t _max_instructions = 5; // e
            execution_units_t _exec_units{4, 4, 4, 1, 1}; // t
            sequence_t<reorder_item_t> _reorder_buffer{};
            sequence_t<opcode_t> _opcodes{};
            size_t _reorder_buffer_active = 0; // all items of reorder buffer with .state != none

            [[nodiscard]] reorder_item_t *_ready() {
                for (auto &r: _reorder_buffer) {
                    if (r.state == reorder_item_t::wait && r.used_units <= _exec_units) {
                        bool ready = true;
                        for (const auto &d: r.deps) {
                            if (_reorder_buffer.at(d).cycles > 0) {
                                ready = false;
                                break;
                            }
                        }
                        if (ready)
                            return &r;
                    }
                }
                return nullptr;
            }

            [[nodiscard]] opcode_t _opcode(const address_val_t pc) const {
                return {_code, pc, _pc_end};
            }

            // X'
            void _decode(const opcode_t &op) {
                if (static_cast<opcode_id_t>(op.id) == opcode_id_t::move_reg) {
                    _simulate_move(op);
                } else {
                    _simulate_decode(op);
                }
                _opcodes.emplace_back(op);
            }

            // X_mov
            void _simulate_move(const opcode_t &op) {
                if (_pc >= _pc_end) [[unlikely]]
                    throw error{"cannot simulate move when no instruction is scheduled"};
                _pc += 1U + op.skip_len;
                if (_decode_slots == 0) [[unlikely]]
                    throw error{"cannot decrement 0 decode slots"};
                --_decode_slots;
                for (auto &ri: _reorder_buffer) {
                    if (ri.clob_regs.intersect(op.src_regs()).size() > 0) {
                        ri.clob_regs.add(op.dst_regs());
                    } else {
                        ri.clob_regs.del(op.dst_regs());
                    }
                }
            }

            // X_dec
            void _simulate_decode(const opcode_t &op) {
                if (is_block_end_opcode(op.id)) {
                    _pc = _pc_end;
                } else {
                    _pc += 1U + op.skip_len;
                }
                const auto d_cost = op.decode_cost();
                if (_decode_slots < d_cost) [[unlikely]]
                    throw error{"cannot decrement 0 decode slots"};
                _decode_slots -= d_cost;
                decltype(reorder_item_t::deps) deps{};
                for (auto [i, r]: _reorder_buffer | std::views::enumerate) {
                    if (op.src_regs().intersect(r.clob_regs).size() > 0)
                        deps.emplace_hint(deps.end(), i);
                    r.clob_regs.del(op.dst_regs());
                }
                _reorder_buffer.emplace_back(reorder_item_t::dec, op.cycle_cost(), std::move(deps), op.dst_regs(), op.uint_cost());
                ++_reorder_buffer_active;
            }

            // X''
            void _simulate_next() {
                if (_max_instructions == 0) [[unlikely]]
                    throw error{"cannot simulate next when no instruction slots remain!"};
                --_max_instructions;
                auto n = _ready();
                if (!n) [[unlikely]]
                    throw error{"cannot simulate next when no instruction is ready!"};
                _exec_units -= n->used_units;
                n->state = reorder_item_t::exe;
            }

            // X'''
            void _simulate_rest() {
                _decode_slots = 4;
                _max_instructions = 5;
                if (_cycles == std::numeric_limits<decltype(_cycles)>::max()) [[unlikely]]
                    throw error{"cannot increment the cycle count; numeric overflow!"};
                ++_cycles;
                for (const auto &r: _reorder_buffer) {
                    if (r.state == reorder_item_t::exe && r.cycles == 1)
                        _exec_units += r.used_units;
                }

                bool all_prev_done = true;
                for (auto &r: _reorder_buffer) {
                    if (r.state != reorder_item_t::fin && r.state != reorder_item_t::none)
                        all_prev_done = false;
                    if (all_prev_done) {
                        if (r.state != reorder_item_t::none) {
                            r.state = reorder_item_t::none;
                            if (_reorder_buffer_active == 0) [[unlikely]]
                                throw error{"internal error: reorder_buffer size tracking broke unexpectedly!"};
                            --_reorder_buffer_active;
                        }
                    } else if (r.state == reorder_item_t::dec) {
                        r.state = reorder_item_t::wait;
                    } else if (r.state == reorder_item_t::exe) {
                        if (r.cycles == 0) {
                            r.state = reorder_item_t::fin;
                        } else {
                            r.cycles--;
                        }
                    }
                }
            }

            void _simulate() {
                for (;;) {
                    std::optional<opcode_t> op{};
                    if (_pc < _pc_end)
                        op.emplace(_opcode(_pc));
                    if (op && op->decode_cost() <= _decode_slots && _reorder_buffer_active < 32U) {
                        _decode(*op);
                    } else if (const auto r = _ready(); r && _max_instructions > 0) {
                        _simulate_next();
                    } else if (_pc >= _pc_end && _reorder_buffer_active == 0) {
                        break;
                    } else {
                        _simulate_rest();
                    }
                }
            }
        };

        [[nodiscard]] bool _validate_blob(address_val_t pc) {
            address_val_t block_start = pc;
            for (;;) {
                if (pc > 0 && pc == bitmasks.size())
                    return true;
                const auto skip = bitmasks.skip_len(pc);
                if (pc > std::numeric_limits<address_val_t>::max() - 1U - skip) [[unlikely]]
                    throw error{"instruction counter is too big: {}", pc};
                const auto next_pc = pc + static_cast<address_val_t>(skip + static_cast<uint8_t>(1));
                const auto op = instrs.at(pc);
                if (next_pc == bitmasks.size() && !is_block_end_opcode(op)) [[unlikely]]
                    return false;
                if (pc >= bitmasks.size()) [[unlikely]]
                    return false;
                if (!bitmasks.test(pc)) [[unlikely]]
                    return false;
                if (!is_opcode(op)) [[unlikely]] // v_inst
                    return false;
                if (is_block_end_opcode(op)) {
                    gas_model_t m{*this, block_start, next_pc};
                    _blocks.emplace_hint(_blocks.end(), block_start, m.simulate());
                    block_start = next_pc;
                }
                pc = next_pc;
            }
            return false;
        }

        void _validate() {
            if (!_validate_blob(0)) [[unlikely]]
                throw error{"invalid program blob: opcode validation failed"};
        }
    };
}