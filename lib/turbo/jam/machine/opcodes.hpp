#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2026 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <array>
#include <variant>
#include "common.hpp"

namespace turbo::jam::machine {
    enum class opcode_id_t: uint8_t {
        trap = 0,
        fallthrough = 1,
        unlikely = 2,
        ecalli = 10,
        load_imm_64 = 20,
        store_imm_u8 = 30,
        store_imm_u16 = 31,
        store_imm_u32 = 32,
        store_imm_u64 = 33,
        jump = 40,
        jump_ind = 50,
        load_imm = 51,
        load_u8 = 52,
        load_i8 = 53,
        load_u16 = 54,
        load_i16 = 55,
        load_u32 = 56,
        load_i32 = 57,
        load_u64 = 58,
        store_u8 = 59,
        store_u16 = 60,
        store_u32 = 61,
        store_u64 = 62,
        store_imm_ind_u8 = 70,
        store_imm_ind_u16 = 71,
        store_imm_ind_u32 = 72,
        store_imm_ind_u64 = 73,
        load_imm_jump = 80,
        branch_eq_imm = 81,
        branch_ne_imm = 82,
        branch_lt_u_imm = 83,
        branch_le_u_imm = 84,
        branch_ge_u_imm = 85,
        branch_gt_u_imm = 86,
        branch_lt_s_imm = 87,
        branch_le_s_imm = 88,
        branch_ge_s_imm = 89,
        branch_gt_s_imm = 90,
        move_reg = 100,
        count_set_bits_64 = 101,
        count_set_bits_32 = 102,
        leading_zero_bits_64 = 103,
        leading_zero_bits_32 = 104,
        trailing_zero_bits_64 = 105,
        trailing_zero_bits_32 = 106,
        sign_extend_8 = 107,
        sign_extend_16 = 108,
        zero_extend_16 = 109,
        reverse_bytes = 110,
        store_ind_u8 = 120,
        store_ind_u16 = 121,
        store_ind_u32 = 122,
        store_ind_u64 = 123,
        load_ind_u8 = 124,
        load_ind_i8 = 125,
        load_ind_u16 = 126,
        load_ind_i16 = 127,
        load_ind_u32 = 128,
        load_ind_i32 = 129,
        load_ind_u64 = 130,
        add_imm_32 = 131,
        and_imm = 132,
        xor_imm = 133,
        or_imm = 134,
        mul_imm_32 = 135,
        set_lt_u_imm = 136,
        set_lt_s_imm = 137,
        shlo_l_imm_32 = 138,
        shlo_r_imm_32 = 139,
        shar_r_imm_32 = 140,
        neg_add_imm_32 = 141,
        set_gt_u_imm = 142,
        set_gt_s_imm = 143,
        shlo_l_imm_alt_32 = 144,
        shlo_r_imm_alt_32 = 145,
        shar_r_imm_alt_32 = 146,
        cmov_iz_imm = 147,
        cmov_nz_imm = 148,
        add_imm_64 = 149,
        mul_imm_64 = 150,
        shlo_l_imm_64 = 151,
        shlo_r_imm_64 = 152,
        shar_r_imm_64 = 153,
        neg_add_imm_64 = 154,
        shlo_l_imm_alt_64 = 155,
        shlo_r_imm_alt_64 = 156,
        shar_r_imm_alt_64 = 157,
        rot_r_64_imm = 158,
        rot_r_64_imm_alt = 159,
        rot_r_32_imm = 160,
        rot_r_32_imm_alt = 161,
        branch_eq = 170,
        branch_ne = 171,
        branch_lt_u = 172,
        branch_lt_s = 173,
        branch_ge_u = 174,
        branch_ge_s = 175,
        load_imm_jump_ind = 180,
        add_32 = 190,
        sub_32 = 191,
        mul_32 = 192,
        div_u_32 = 193,
        div_s_32 = 194,
        rem_u_32 = 195,
        rem_s_32 = 196,
        shlo_l_32 = 197,
        shlo_r_32 = 198,
        shar_r_32 = 199,
        add_64 = 200,
        sub_64 = 201,
        mul_64 = 202,
        div_u_64 = 203,
        div_s_64 = 204,
        rem_u_64 = 205,
        rem_s_64 = 206,
        shlo_l_64 = 207,
        shlo_r_64 = 208,
        shar_r_64 = 209,
        and_ = 210,
        xor_ = 211,
        or_ = 212,
        mul_upper_s_s = 213,
        mul_upper_u_u = 214,
        mul_upper_s_u = 215,
        set_lt_u = 216,
        set_lt_s = 217,
        cmov_iz = 218,
        cmov_nz = 219,
        rot_l_64 = 220,
        rot_l_32 = 221,
        rot_r_64 = 222,
        rot_r_32 = 223,
        and_inv = 224,
        or_inv = 225,
        xnor = 226,
        max = 227,
        max_u = 228,
        min = 229,
        min_u = 230,
    };

    static constexpr register_idx_t max_register_idx = 12;

    struct register_set_t {
        static register_set_t from_reg(const register_idx_t reg) {
            register_set_t rs{};
            rs.add(reg);
            return rs;
        }

        static register_set_t from_regs(const std::initializer_list<register_idx_t> regs) {
            register_set_t rs{};
            for (const auto reg: regs)
                rs.add(reg);
            return rs;
        }

        static register_set_t from_bits(const uint16_t bits) {
            return {bits};
        }

        register_set_t() = default;
        register_set_t(const register_set_t &o) = default;

        void add(const register_idx_t reg) {
            if (reg > max_register_idx) [[unlikely]]
                throw error{"unsupported register idx: {}", reg};
            _bits |= 1U << reg;
        }

        void add(const register_set_t o) {
            _bits |= o._bits;
        }

        void del(const register_idx_t reg) {
            if (reg > max_register_idx) [[unlikely]]
                throw error{"unsupported register idx: {}", reg};
            _bits &= all ^ (1U << reg);
        }

        void del(const register_set_t o) {
            _bits ^= _bits & o._bits;
        }

        [[nodiscard]] bool test(const register_idx_t reg) const {
            return (_bits & (1U << reg)) > 0;
        }

        [[nodiscard]] register_set_t intersect(const register_set_t o) const {
            return {static_cast<uint16_t>(_bits & o._bits)};
        }

        [[nodiscard]] size_t size() const {
            return static_cast<size_t>(std::popcount(_bits));
        }

        [[nodiscard]] operator uint16_t() const {
            return _bits;
        }
    private:
        static constexpr uint16_t all = (1U << (max_register_idx + 1)) - 1U;

        register_set_t(const uint16_t bits):
            _bits{bits}
        {}

        uint16_t _bits = 0;
    };

    struct decode_const_t {
        uint8_t a: 7;
        uint8_t b: 1 = 0;
    };

    struct decode_regs_t {
        uint8_t a: 4;
        uint8_t b: 4;

        [[nodiscard]] static uint8_t cost(const uint8_t a, const uint8_t b, const register_set_t src_regs, const register_set_t dst_regs) {
            if (src_regs.intersect(dst_regs).size() > 0)
                return a;
            return b;
        }
    };

    struct decode_shift_t {
        uint8_t a: 4;
        uint8_t b: 4;

        [[nodiscard]] static uint8_t cost(const uint8_t a, const uint8_t b, const register_idx_t reg_a, const register_idx_t reg_d) {
            if (reg_a == reg_d)
                return a;
            return b;
        }
    };

    using decode_cost_t = std::variant<decode_const_t, decode_regs_t, decode_shift_t>;

    struct cycles_const_t {
        uint8_t a : 7 = 1;
        uint8_t b : 1 = 0;
    };

    struct cycles_branch_t {
        uint8_t a : 7 = 20;
        uint8_t b : 1 = 1;

        [[nodiscard]] static uint8_t cost(const uint8_t a, const uint8_t b, const opcode_id_t next_op, const opcode_id_t target_op) {
            if (static_cast<int>(next_op == opcode_id_t::trap)
                | static_cast<int>(next_op == opcode_id_t::unlikely)
                | static_cast<int>(target_op == opcode_id_t::trap)
                | static_cast<int>(target_op == opcode_id_t::unlikely)) {
                return b;
            }
            return a;
        }
    };

    using cycles_cost_t = std::variant<cycles_const_t, cycles_branch_t>;

    struct execution_units_t {
        size_t alu = 0;
        size_t load = 0;
        size_t store = 0;
        size_t mul = 0;
        size_t div = 0;

        execution_units_t &operator+=(const execution_units_t &o) {
            if (alu > std::numeric_limits<decltype(alu)>::max() - o.alu) [[unlikely]]
                throw error{"numeric overflow in alu: {} + {}", alu, o.alu};
            alu += o.alu;
            if (load > std::numeric_limits<decltype(load)>::max() - o.load) [[unlikely]]
                throw error{"numeric overflow in load: {} + {}", load, o.load};
            load += o.load;
            if (store > std::numeric_limits<decltype(store)>::max() - o.store) [[unlikely]]
                throw error{"numeric overflow in store: {} + {}", store, o.store};
            store += o.store;
            if (mul > std::numeric_limits<decltype(mul)>::max() - o.mul) [[unlikely]]
                throw error{"numeric overflow in mul: {} + {}", mul, o.mul};
            mul += o.mul;
            if (div > std::numeric_limits<decltype(div)>::max() - o.div) [[unlikely]]
                throw error{"numeric overflow in mul: {} + {}", div, o.div};
            div += o.div;
            return *this;
        }

        execution_units_t &operator-=(const execution_units_t &o) {
            if (o.alu > alu) [[unlikely]]
                throw error{"numeric underflow in alu: {} - {}", alu, o.alu};
            alu -= o.alu;
            if (o.load > load) [[unlikely]]
                throw error{"numeric underflow in load: {} - {}", load, o.load};
            load -= o.load;
            if (o.store > store) [[unlikely]]
                throw error{"numeric underflow in store: {} - {}", store, o.store};
            store -= o.store;
            if (o.mul > mul) [[unlikely]]
                throw error{"numeric underflow in mul: {} - {}", mul, o.mul};
            mul -= o.mul;
            if (o.div > div) [[unlikely]]
                throw error{"numeric underflow in div: {} - {}", div, o.div};
            div -= o.div;
            return *this;
        }

        [[nodiscard]] bool operator<=(const execution_units_t &o) const {
            return static_cast<int>(alu <= o.alu)
                & static_cast<int>(load <= o.load)
                & static_cast<int>(store <= o.store)
                & static_cast<int>(mul <= o.mul)
                & static_cast<int>(div <= o.div);
        }
    };

    struct opcode_t;

    struct opcode_meta_t {
        enum args_t: uint8_t {
            none, imm1, off1, imm2,
            reg1_imm1_s32, reg1_imm1_u32, reg1_imm1_s64, reg1_imm1_u64, reg1_imm1_off1, reg1_imm2,
            reg2, reg2_imm1, reg2_off1, reg2_imm2,
            reg3
        };

        using decode_func_t = opcode_t(*)(address_val_t pc, buffer data);
        using exec_func_t = void(*)(void *machine, const opcode_t &op);

        uint32_t args_typ   : 4 = 0;
        uint32_t cycles_typ : 1 = 0; // 0 - const, 1 - branch
        uint32_t cycles_a   : 7 = 0;
        uint32_t cycles_b   : 1 = 0;
        uint32_t decode_typ : 2 = 0; // 0 - constant, 1 - reg set, 2 - shift
        uint32_t decode_a   : 3 = 0;
        uint32_t decode_b   : 3 = 0;
        uint32_t alu        : 2 = 0;
        uint32_t load       : 1 = 0;
        uint32_t store      : 1 = 0;
        uint32_t mul        : 1 = 0;
        uint32_t div        : 1 = 0;
        uint32_t dst_reg    : 2 = 3; // 0 - 2 - register index, 3 - no value
        uint32_t dst_is_src : 1 = 0;

        constexpr opcode_meta_t() =default;

        constexpr opcode_meta_t(const args_t a_typ, const cycles_cost_t c_cost, const decode_cost_t d_cost, const execution_units_t &units, const std::optional<uint8_t> d_reg={}, const bool dst_is_src_=false):
            args_typ{a_typ},
            cycles_typ{static_cast<uint16_t>(c_cost.index())},
            decode_typ{static_cast<uint16_t>(d_cost.index())},
            dst_reg{d_reg ? std::min(uint8_t{2}, *d_reg) : uint8_t{3}},
            dst_is_src{dst_is_src_}
        {
            if (args_typ != a_typ) [[unlikely]]
                throw error{"opcode_t has insufficient storage for an args_typ value: {}", static_cast<int>(a_typ)};
            if (cycles_typ != c_cost.index()) [[unlikely]]
                throw error{"opcode_t has insufficient storage for a c_cost.index() value: {}", c_cost.index()};
            if (decode_typ != d_cost.index()) [[unlikely]]
                throw error{"opcode_t has insufficient storage for a d_cost.index() value: {}", d_cost.index()};
            if ((d_reg && dst_reg != *d_reg) || (!d_reg && dst_reg != 3)) [[unlikely]]
                throw error{"opcode_t has an incorrect encoding of dst_reg: {}", d_reg};
            std::visit([&](auto &d) {
                decode_a = d.a;
                if (decode_a != d.a) [[unlikely]]
                    throw error{"opcode_t has insufficient storage for a d_cost.a value: {}", d.a};
                decode_b = d.b;
                if (decode_b != d.b) [[unlikely]]
                    throw error{"opcode_t has insufficient storage for a d_cost.b value: {}", d.b};
            }, d_cost);

            std::visit([&](auto &c) {
                cycles_a = c.a;
                if (cycles_a != c.a) [[unlikely]]
                    throw error{"opcode_t has insufficient storage for a c_cost.a value: {}", c.a};
                cycles_b = c.b;
                if (cycles_b != c.b) [[unlikely]]
                    throw error{"opcode_t has insufficient storage for a c_cost.b value: {}", c.b};
            }, c_cost);
            alu = units.alu;
            if (alu != units.alu) [[unlikely]]
                throw error{"opcode_t has insufficient storage for a units.alu value: {}", units.alu};
            load = units.load;
            if (load != units.load) [[unlikely]]
                throw error{"opcode_t has insufficient storage for a units.load value: {}", units.load};
            store = units.store;
            if (store != units.store) [[unlikely]]
                throw error{"opcode_t has insufficient storage for a units.store value: {}", units.store};
            mul = units.mul;
            if (mul != units.mul) [[unlikely]]
                throw error{"opcode_t has insufficient storage for a units.mul value: {}", units.mul};
            div = units.div;
            if (div != units.div) [[unlikely]]
                throw error{"opcode_t has insufficient storage for a units.div value: {}", units.div};
        }

        [[nodiscard]] bool invalid() const noexcept {
            return decode_a + decode_b + cycles_a + cycles_b == 0;
        }
    };
    static_assert(sizeof(opcode_meta_t) == 4);

    static constexpr const std::array<opcode_meta_t, 0x100> &opcodes() {
        static constexpr uint8_t m = 25;

        constexpr auto make_cost_table = [] {
            struct opcode_cfg_t {
                opcode_id_t id;
                opcode_meta_t::args_t args_typ;
                cycles_cost_t cycles_cost;
                decode_cost_t decode_cost;
                execution_units_t exec_units;
                std::optional<uint8_t> dst_reg_idx{};
                bool dst_is_src = false;
            };

            constexpr auto opcodes = std::to_array<opcode_cfg_t>({
                {opcode_id_t::move_reg, opcode_meta_t::reg2, cycles_const_t{0}, decode_const_t{1}, {}, 0},

                {opcode_id_t::and_,     opcode_meta_t::reg3, cycles_const_t{1}, decode_regs_t{1, 2}, {.alu=1}, {2}},
                {opcode_id_t::xor_,     opcode_meta_t::reg3, cycles_const_t{1}, decode_regs_t{1, 2}, {.alu=1}, {2}},
                {opcode_id_t::or_,      opcode_meta_t::reg3, cycles_const_t{1}, decode_regs_t{1, 2}, {.alu=1}, {2}},
                {opcode_id_t::add_64,   opcode_meta_t::reg3, cycles_const_t{1}, decode_regs_t{1, 2}, {.alu=1}, {2}},
                {opcode_id_t::sub_64,   opcode_meta_t::reg3, cycles_const_t{1}, decode_regs_t{1, 2}, {.alu=1}, {2}},

                {opcode_id_t::add_32, opcode_meta_t::reg3, cycles_const_t{2}, decode_regs_t{2, 3}, {.alu=1}, {2}},
                {opcode_id_t::sub_32, opcode_meta_t::reg3, cycles_const_t{2}, decode_regs_t{2, 3}, {.alu=1}, {2}},

                {opcode_id_t::and_imm,       opcode_meta_t::reg2_imm1, cycles_const_t{1}, decode_regs_t{1, 2}, {.alu=1}, {0}},
                {opcode_id_t::xor_imm,       opcode_meta_t::reg2_imm1, cycles_const_t{1}, decode_regs_t{1, 2}, {.alu=1}, {0}},
                {opcode_id_t::or_imm,        opcode_meta_t::reg2_imm1, cycles_const_t{1}, decode_regs_t{1, 2}, {.alu=1}, {0}},
                {opcode_id_t::add_imm_64,    opcode_meta_t::reg2_imm1, cycles_const_t{1}, decode_regs_t{1, 2}, {.alu=1}, {0}},
                {opcode_id_t::shlo_r_imm_64, opcode_meta_t::reg2_imm1, cycles_const_t{1}, decode_regs_t{1, 2}, {.alu=1}, {0}},
                {opcode_id_t::shar_r_imm_64, opcode_meta_t::reg2_imm1, cycles_const_t{1}, decode_regs_t{1, 2}, {.alu=1}, {0}},
                {opcode_id_t::shlo_l_imm_64, opcode_meta_t::reg2_imm1, cycles_const_t{1}, decode_regs_t{1, 2}, {.alu=1}, {0}},
                {opcode_id_t::rot_r_64_imm,  opcode_meta_t::reg2_imm1, cycles_const_t{1}, decode_regs_t{1, 2}, {.alu=1}, {0}},
                {opcode_id_t::reverse_bytes, opcode_meta_t::reg2,      cycles_const_t{1}, decode_regs_t{1, 2}, {.alu=1}, {0}},

                {opcode_id_t::add_imm_32,    opcode_meta_t::reg2_imm1, cycles_const_t{2}, decode_regs_t{2, 3}, {.alu=1}, {0}},
                {opcode_id_t::shlo_r_imm_32, opcode_meta_t::reg2_imm1, cycles_const_t{2}, decode_regs_t{2, 3}, {.alu=1}, {0}},
                {opcode_id_t::shar_r_imm_32, opcode_meta_t::reg2_imm1, cycles_const_t{2}, decode_regs_t{2, 3}, {.alu=1}, {0}},
                {opcode_id_t::shlo_l_imm_32, opcode_meta_t::reg2_imm1, cycles_const_t{2}, decode_regs_t{2, 3}, {.alu=1}, {0}},
                {opcode_id_t::rot_r_32_imm,  opcode_meta_t::reg2_imm1, cycles_const_t{2}, decode_regs_t{2, 3}, {.alu=1}, {0}},

                {opcode_id_t::count_set_bits_64,    opcode_meta_t::reg2, cycles_const_t{1}, decode_const_t{1}, {.alu=1}, {0}},
                {opcode_id_t::count_set_bits_32,    opcode_meta_t::reg2, cycles_const_t{1}, decode_const_t{1}, {.alu=1}, {0}},
                {opcode_id_t::leading_zero_bits_64, opcode_meta_t::reg2, cycles_const_t{1}, decode_const_t{1}, {.alu=1}, {0}},
                {opcode_id_t::leading_zero_bits_32, opcode_meta_t::reg2, cycles_const_t{1}, decode_const_t{1}, {.alu=1}, {0}},
                {opcode_id_t::sign_extend_8,        opcode_meta_t::reg2, cycles_const_t{1}, decode_const_t{1}, {.alu=1}, {0}},
                {opcode_id_t::sign_extend_16,       opcode_meta_t::reg2, cycles_const_t{1}, decode_const_t{1}, {.alu=1}, {0}},
                {opcode_id_t::zero_extend_16,       opcode_meta_t::reg2, cycles_const_t{1}, decode_const_t{1}, {.alu=1}, {0}},

                {opcode_id_t::trailing_zero_bits_64, opcode_meta_t::reg2, cycles_const_t{2}, decode_const_t{1}, {.alu=2}, {0}},
                {opcode_id_t::trailing_zero_bits_32, opcode_meta_t::reg2, cycles_const_t{2}, decode_const_t{1}, {.alu=2}, {0}},

                {opcode_id_t::shlo_l_64, opcode_meta_t::reg3, cycles_const_t{1}, decode_shift_t{2, 3}, {.alu=1}, {2}},
                {opcode_id_t::shlo_r_64, opcode_meta_t::reg3, cycles_const_t{1}, decode_shift_t{2, 3}, {.alu=1}, {2}},
                {opcode_id_t::shar_r_64, opcode_meta_t::reg3, cycles_const_t{1}, decode_shift_t{2, 3}, {.alu=1}, {2}},
                {opcode_id_t::rot_l_64,  opcode_meta_t::reg3, cycles_const_t{1}, decode_shift_t{2, 3}, {.alu=1}, {2}},
                {opcode_id_t::rot_r_64,  opcode_meta_t::reg3, cycles_const_t{1}, decode_shift_t{2, 3}, {.alu=1}, {2}},

                {opcode_id_t::shlo_l_32, opcode_meta_t::reg3, cycles_const_t{2}, decode_shift_t{3, 4}, {.alu=1}, {2}},
                {opcode_id_t::shlo_r_32, opcode_meta_t::reg3, cycles_const_t{2}, decode_shift_t{3, 4}, {.alu=1}, {2}},
                {opcode_id_t::shar_r_32, opcode_meta_t::reg3, cycles_const_t{2}, decode_shift_t{3, 4}, {.alu=1}, {2}},
                {opcode_id_t::rot_l_32,  opcode_meta_t::reg3, cycles_const_t{2}, decode_shift_t{3, 4}, {.alu=1}, {2}},
                {opcode_id_t::rot_r_32,  opcode_meta_t::reg3, cycles_const_t{2}, decode_shift_t{3, 4}, {.alu=1}, {2}},

                {opcode_id_t::shlo_l_imm_alt_64, opcode_meta_t::reg2_imm1, cycles_const_t{1}, decode_const_t{3}, {.alu=1}, {0}},
                {opcode_id_t::shlo_r_imm_alt_64, opcode_meta_t::reg2_imm1, cycles_const_t{1}, decode_const_t{3}, {.alu=1}, {0}},
                {opcode_id_t::shar_r_imm_alt_64, opcode_meta_t::reg2_imm1, cycles_const_t{1}, decode_const_t{3}, {.alu=1}, {0}},
                {opcode_id_t::rot_r_64_imm_alt,  opcode_meta_t::reg2_imm1, cycles_const_t{1}, decode_const_t{3}, {.alu=1}, {0}},

                {opcode_id_t::shlo_l_imm_alt_32, opcode_meta_t::reg2_imm1, cycles_const_t{2}, decode_const_t{4}, {.alu=1}, {0}},
                {opcode_id_t::shlo_r_imm_alt_32, opcode_meta_t::reg2_imm1, cycles_const_t{2}, decode_const_t{4}, {.alu=1}, {0}},
                {opcode_id_t::shar_r_imm_alt_32, opcode_meta_t::reg2_imm1, cycles_const_t{2}, decode_const_t{4}, {.alu=1}, {0}},
                {opcode_id_t::rot_r_32_imm_alt,  opcode_meta_t::reg2_imm1, cycles_const_t{2}, decode_const_t{4}, {.alu=1}, {0}},

                {opcode_id_t::set_lt_u, opcode_meta_t::reg3, cycles_const_t{3}, decode_const_t{3}, {.alu=1}, {2}},
                {opcode_id_t::set_lt_s, opcode_meta_t::reg3, cycles_const_t{3}, decode_const_t{3}, {.alu=1}, {2}},

                {opcode_id_t::set_lt_u_imm, opcode_meta_t::reg2_imm1, cycles_const_t{3}, decode_const_t{3}, {.alu=1}, {0}},
                {opcode_id_t::set_lt_s_imm, opcode_meta_t::reg2_imm1, cycles_const_t{3}, decode_const_t{3}, {.alu=1}, {0}},
                {opcode_id_t::set_gt_u_imm, opcode_meta_t::reg2_imm1, cycles_const_t{3}, decode_const_t{3}, {.alu=1}, {0}},
                {opcode_id_t::set_gt_s_imm, opcode_meta_t::reg2_imm1, cycles_const_t{3}, decode_const_t{3}, {.alu=1}, {0}},

                {opcode_id_t::cmov_iz, opcode_meta_t::reg3, cycles_const_t{2}, decode_const_t{2}, {.alu=1}, {2}, true},
                {opcode_id_t::cmov_nz, opcode_meta_t::reg3, cycles_const_t{2}, decode_const_t{2}, {.alu=1}, {2}, true},

                {opcode_id_t::cmov_iz_imm, opcode_meta_t::reg2_imm1, cycles_const_t{2}, decode_const_t{3}, {.alu=1}, {0}, true},
                {opcode_id_t::cmov_nz_imm, opcode_meta_t::reg2_imm1, cycles_const_t{2}, decode_const_t{3}, {.alu=1}, {0}, true},

                {opcode_id_t::max,   opcode_meta_t::reg3, cycles_const_t{3}, decode_regs_t{2, 3}, {.alu=1}, {2}},
                {opcode_id_t::max_u, opcode_meta_t::reg3, cycles_const_t{3}, decode_regs_t{2, 3}, {.alu=1}, {2}},
                {opcode_id_t::min,   opcode_meta_t::reg3, cycles_const_t{3}, decode_regs_t{2, 3}, {.alu=1}, {2}},
                {opcode_id_t::min_u, opcode_meta_t::reg3, cycles_const_t{3}, decode_regs_t{2, 3}, {.alu=1}, {2}},

                {opcode_id_t::load_ind_u8,  opcode_meta_t::reg2_imm1, cycles_const_t{m}, decode_const_t{1}, {.alu=1, .load=1}, {0}},
                {opcode_id_t::load_ind_i8,  opcode_meta_t::reg2_imm1, cycles_const_t{m}, decode_const_t{1}, {.alu=1, .load=1}, {0}},
                {opcode_id_t::load_ind_u16, opcode_meta_t::reg2_imm1, cycles_const_t{m}, decode_const_t{1}, {.alu=1, .load=1}, {0}},
                {opcode_id_t::load_ind_i16, opcode_meta_t::reg2_imm1, cycles_const_t{m}, decode_const_t{1}, {.alu=1, .load=1}, {0}},
                {opcode_id_t::load_ind_u32, opcode_meta_t::reg2_imm1, cycles_const_t{m}, decode_const_t{1}, {.alu=1, .load=1}, {0}},
                {opcode_id_t::load_ind_i32, opcode_meta_t::reg2_imm1, cycles_const_t{m}, decode_const_t{1}, {.alu=1, .load=1}, {0}},
                {opcode_id_t::load_ind_u64, opcode_meta_t::reg2_imm1, cycles_const_t{m}, decode_const_t{1}, {.alu=1, .load=1}, {0}},

                {opcode_id_t::load_u8,  opcode_meta_t::reg1_imm1_s32, cycles_const_t{m}, decode_const_t{1}, {.alu=1, .load=1}, {0}},
                {opcode_id_t::load_i8,  opcode_meta_t::reg1_imm1_s32, cycles_const_t{m}, decode_const_t{1}, {.alu=1, .load=1}, {0}},
                {opcode_id_t::load_u16, opcode_meta_t::reg1_imm1_s32, cycles_const_t{m}, decode_const_t{1}, {.alu=1, .load=1}, {0}},
                {opcode_id_t::load_i16, opcode_meta_t::reg1_imm1_s32, cycles_const_t{m}, decode_const_t{1}, {.alu=1, .load=1}, {0}},
                {opcode_id_t::load_u32, opcode_meta_t::reg1_imm1_s32, cycles_const_t{m}, decode_const_t{1}, {.alu=1, .load=1}, {0}},
                {opcode_id_t::load_i32, opcode_meta_t::reg1_imm1_s32, cycles_const_t{m}, decode_const_t{1}, {.alu=1, .load=1}, {0}},
                {opcode_id_t::load_u64, opcode_meta_t::reg1_imm1_s32, cycles_const_t{m}, decode_const_t{1}, {.alu=1, .load=1}, {0}},

                {opcode_id_t::store_imm_ind_u8,  opcode_meta_t::reg1_imm2, cycles_const_t{m}, decode_const_t{1}, {.alu=1, .store=1}},
                {opcode_id_t::store_imm_ind_u16, opcode_meta_t::reg1_imm2, cycles_const_t{m}, decode_const_t{1}, {.alu=1, .store=1}},
                {opcode_id_t::store_imm_ind_u32, opcode_meta_t::reg1_imm2, cycles_const_t{m}, decode_const_t{1}, {.alu=1, .store=1}},
                {opcode_id_t::store_imm_ind_u64, opcode_meta_t::reg1_imm2, cycles_const_t{m}, decode_const_t{1}, {.alu=1, .store=1}},

                {opcode_id_t::store_ind_u8,  opcode_meta_t::reg2_imm1, cycles_const_t{m}, decode_const_t{1}, {.alu=1, .store=1}},
                {opcode_id_t::store_ind_u16, opcode_meta_t::reg2_imm1, cycles_const_t{m}, decode_const_t{1}, {.alu=1, .store=1}},
                {opcode_id_t::store_ind_u32, opcode_meta_t::reg2_imm1, cycles_const_t{m}, decode_const_t{1}, {.alu=1, .store=1}},
                {opcode_id_t::store_ind_u64, opcode_meta_t::reg2_imm1, cycles_const_t{m}, decode_const_t{1}, {.alu=1, .store=1}},

                {opcode_id_t::store_imm_u8,  opcode_meta_t::imm2, cycles_const_t{m}, decode_const_t{1}, {.alu=1, .store=1}},
                {opcode_id_t::store_imm_u16, opcode_meta_t::imm2, cycles_const_t{m}, decode_const_t{1}, {.alu=1, .store=1}},
                {opcode_id_t::store_imm_u32, opcode_meta_t::imm2, cycles_const_t{m}, decode_const_t{1}, {.alu=1, .store=1}},
                {opcode_id_t::store_imm_u64, opcode_meta_t::imm2, cycles_const_t{m}, decode_const_t{1}, {.alu=1, .store=1}},

                {opcode_id_t::store_u8,  opcode_meta_t::reg1_imm1_s32, cycles_const_t{m}, decode_const_t{1}, {.alu=1, .store=1}},
                {opcode_id_t::store_u16, opcode_meta_t::reg1_imm1_s32, cycles_const_t{m}, decode_const_t{1}, {.alu=1, .store=1}},
                {opcode_id_t::store_u32, opcode_meta_t::reg1_imm1_s32, cycles_const_t{m}, decode_const_t{1}, {.alu=1, .store=1}},
                {opcode_id_t::store_u64, opcode_meta_t::reg1_imm1_s32, cycles_const_t{m}, decode_const_t{1}, {.alu=1, .store=1}},

                {opcode_id_t::branch_eq,   opcode_meta_t::reg2_off1, cycles_branch_t{}, decode_const_t{1}, {.alu=1}},
                {opcode_id_t::branch_ne,   opcode_meta_t::reg2_off1, cycles_branch_t{}, decode_const_t{1}, {.alu=1}},
                {opcode_id_t::branch_lt_u, opcode_meta_t::reg2_off1, cycles_branch_t{}, decode_const_t{1}, {.alu=1}},
                {opcode_id_t::branch_lt_s, opcode_meta_t::reg2_off1, cycles_branch_t{}, decode_const_t{1}, {.alu=1}},
                {opcode_id_t::branch_ge_u, opcode_meta_t::reg2_off1, cycles_branch_t{}, decode_const_t{1}, {.alu=1}},
                {opcode_id_t::branch_ge_s, opcode_meta_t::reg2_off1, cycles_branch_t{}, decode_const_t{1}, {.alu=1}},

                {opcode_id_t::branch_eq_imm,   opcode_meta_t::reg1_imm1_off1, cycles_branch_t{}, decode_const_t{1}, {.alu=1}},
                {opcode_id_t::branch_ne_imm,   opcode_meta_t::reg1_imm1_off1, cycles_branch_t{}, decode_const_t{1}, {.alu=1}},
                {opcode_id_t::branch_lt_u_imm, opcode_meta_t::reg1_imm1_off1, cycles_branch_t{}, decode_const_t{1}, {.alu=1}},
                {opcode_id_t::branch_le_u_imm, opcode_meta_t::reg1_imm1_off1, cycles_branch_t{}, decode_const_t{1}, {.alu=1}},
                {opcode_id_t::branch_ge_u_imm, opcode_meta_t::reg1_imm1_off1, cycles_branch_t{}, decode_const_t{1}, {.alu=1}},
                {opcode_id_t::branch_gt_u_imm, opcode_meta_t::reg1_imm1_off1, cycles_branch_t{}, decode_const_t{1}, {.alu=1}},
                {opcode_id_t::branch_lt_s_imm, opcode_meta_t::reg1_imm1_off1, cycles_branch_t{}, decode_const_t{1}, {.alu=1}},
                {opcode_id_t::branch_le_s_imm, opcode_meta_t::reg1_imm1_off1, cycles_branch_t{}, decode_const_t{1}, {.alu=1}},
                {opcode_id_t::branch_ge_s_imm, opcode_meta_t::reg1_imm1_off1, cycles_branch_t{}, decode_const_t{1}, {.alu=1}},
                {opcode_id_t::branch_gt_s_imm, opcode_meta_t::reg1_imm1_off1, cycles_branch_t{}, decode_const_t{1}, {.alu=1}},

                {opcode_id_t::div_u_32, opcode_meta_t::reg3, cycles_const_t{60}, decode_const_t{4}, {.alu=1, .div=1}, {2}},
                {opcode_id_t::div_s_32, opcode_meta_t::reg3, cycles_const_t{60}, decode_const_t{4}, {.alu=1, .div=1}, {2}},
                {opcode_id_t::rem_u_32, opcode_meta_t::reg3, cycles_const_t{60}, decode_const_t{4}, {.alu=1, .div=1}, {2}},
                {opcode_id_t::rem_s_32, opcode_meta_t::reg3, cycles_const_t{60}, decode_const_t{4}, {.alu=1, .div=1}, {2}},
                {opcode_id_t::div_u_64, opcode_meta_t::reg3, cycles_const_t{60}, decode_const_t{4}, {.alu=1, .div=1}, {2}},
                {opcode_id_t::div_s_64, opcode_meta_t::reg3, cycles_const_t{60}, decode_const_t{4}, {.alu=1, .div=1}, {2}},
                {opcode_id_t::rem_u_64, opcode_meta_t::reg3, cycles_const_t{60}, decode_const_t{4}, {.alu=1, .div=1}, {2}},
                {opcode_id_t::rem_s_64, opcode_meta_t::reg3, cycles_const_t{60}, decode_const_t{4}, {.alu=1, .div=1}, {2}},

                {opcode_id_t::and_inv, opcode_meta_t::reg3, cycles_const_t{2}, decode_const_t{3}, {.alu=1}, {2}},
                {opcode_id_t::or_inv,  opcode_meta_t::reg3, cycles_const_t{2}, decode_const_t{3}, {.alu=1}, {2}},

                {opcode_id_t::xnor, opcode_meta_t::reg3, cycles_const_t{2}, decode_regs_t{2, 3}, {.alu=1}, {2}},

                {opcode_id_t::neg_add_imm_64, opcode_meta_t::reg2_imm1, cycles_const_t{2}, decode_const_t{3}, {.alu=1}, {0}},
                {opcode_id_t::neg_add_imm_32, opcode_meta_t::reg2_imm1, cycles_const_t{3}, decode_const_t{4}, {.alu=1}, {0}},

                {opcode_id_t::load_imm,    opcode_meta_t::reg1_imm1_s32, cycles_const_t{1}, decode_const_t{1}, {}, {0}},
                {opcode_id_t::load_imm_64, opcode_meta_t::reg1_imm1_s64, cycles_const_t{1}, decode_const_t{2}, {}, {0}},

                {opcode_id_t::mul_64,     opcode_meta_t::reg3, cycles_const_t{3}, decode_regs_t{1, 2}, {.alu=1, .mul=1}, {2}},
                {opcode_id_t::mul_32,     opcode_meta_t::reg3, cycles_const_t{4}, decode_regs_t{2, 3}, {.alu=1, .mul=1}, {2}},
                {opcode_id_t::mul_imm_64, opcode_meta_t::reg2_imm1, cycles_const_t{3}, decode_regs_t{1, 2}, {.alu=1, .mul=1}, {0}},
                {opcode_id_t::mul_imm_32, opcode_meta_t::reg2_imm1, cycles_const_t{4}, decode_regs_t{2, 3}, {.alu=1, .mul=1}, {0}},

                {opcode_id_t::mul_upper_s_s, opcode_meta_t::reg3, cycles_const_t{4}, decode_const_t{4}, {.alu=1, .mul=1}, {2}},
                {opcode_id_t::mul_upper_u_u, opcode_meta_t::reg3, cycles_const_t{4}, decode_const_t{4}, {.alu=1, .mul=1}, {2}},
                {opcode_id_t::mul_upper_s_u, opcode_meta_t::reg3, cycles_const_t{6}, decode_const_t{4}, {.alu=1, .mul=1}, {2}},

                {opcode_id_t::trap,              opcode_meta_t::none, cycles_const_t{2}, decode_const_t{1}, {}},
                {opcode_id_t::fallthrough,       opcode_meta_t::none, cycles_const_t{2}, decode_const_t{1}, {}},
                {opcode_id_t::unlikely,          opcode_meta_t::none, cycles_const_t{40}, decode_const_t{1}, {}},
                {opcode_id_t::jump,              opcode_meta_t::off1, cycles_const_t{15}, decode_const_t{1}, {}},
                {opcode_id_t::load_imm_jump,     opcode_meta_t::reg1_imm1_off1, cycles_const_t{15}, decode_const_t{1}, {}, {0}},
                {opcode_id_t::jump_ind,          opcode_meta_t::reg1_imm1_s32, cycles_const_t{22}, decode_const_t{1}, {}},
                {opcode_id_t::load_imm_jump_ind, opcode_meta_t::reg2_imm2, cycles_const_t{22}, decode_const_t{1}, {}, {0}},

                {opcode_id_t::ecalli, opcode_meta_t::imm1, cycles_const_t{100}, decode_const_t{4}, {.alu=1}}
            });
            std::array<opcode_meta_t, 0x100> res{};
            for (const auto &op: opcodes) {
                res[static_cast<uint8_t>(op.id)] = opcode_meta_t{op.args_typ, op.cycles_cost, op.decode_cost, op.exec_units, op.dst_reg_idx, op.dst_is_src};
            }
            return res;
        };

        static constexpr auto opcode_table = make_cost_table();
        return opcode_table;
    }
}
