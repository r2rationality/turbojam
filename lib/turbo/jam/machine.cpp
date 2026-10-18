/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025-2026 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#if defined(_MSC_VER)
#   include <intrin.h>
#endif
#include <cstring>
#include <type_traits>
#include <boost/container/static_vector.hpp>
#include "machine.hpp"
#include "state.hpp"
#include "turbo/common/pool-allocator.hpp"
#include "turbo/common/scope-exit.hpp"

namespace turbo::jam::machine {

#if defined(__GNUC__) || defined(__clang__)
#   pragma GCC diagnostic push
#   pragma GCC diagnostic ignored "-Wpedantic"
    using int128_t = __int128;
    using uint128_t = unsigned __int128;
#   pragma GCC diagnostic pop
#endif

    struct machine_t::impl {
        static bool is_opcode(const uint8_t op) {
            return _opcode_table()[op].defined();
        }

        explicit impl(code_t &&code, const state_t &init, const pages_t &page_map):
            _pc{init.pc},
            _gas{init.gas},
            _regs{init.regs},
            _code{std::move(code)}
        {
            static constexpr auto stack_end = (1ULL << 32U) - 2 * config_prod::ZZ_pvm_init_zone_size - config_prod::ZI_pvm_input_size;
            _stack_begin = stack_end;
            for (const auto &page: page_map) {
                const auto page_id = page.address / config_prod::ZP_pvm_page_size;
                const auto cnt = page.length / config_prod::ZP_pvm_page_size;
                const auto segment_end = page.address + page.length;
                // Stack is the only writable entry that can reach stack_end. Everything else is considered heap
                if (page.is_writable) {
                    if (segment_end < stack_end) {
                        if (_heap_end < segment_end)
                            _heap_end = segment_end;
                    } else {
                        _stack_begin = page.address;
                    }
                }
                _add_pages(page_id, page_id + cnt, page.is_writable);
            }
            for (const auto &mc: init.memory)
                mem_write<false>(mc.address, mc.contents);
            if (_stack_begin < config_prod::ZZ_pvm_init_zone_size) [[unlikely]]
                throw exit_panic_t{};
            // Keep one guard zone below the stack without rounding away valid heap pages.
            _stack_begin -= config_prod::ZZ_pvm_init_zone_size;
        }

        impl(impl &&) = delete;

        // (A.1) this must be re-entrant as it can be called again after a host call
        result_t run()
        {
            auto res = _run();
            // GP 0.7.2 requires the PC after halt or panic to be zero.
            if (std::holds_alternative<exit_halt_t>(res) || std::holds_alternative<exit_panic_t>(res)) {
                _pc = 0;
            }
            return res;
        }

        void skip_op()
        {
            _pc += _code.bitmasks.skip_len(_pc) + 1;
        }

        bool consume_gas(const gas_remaining_t gas)
        {
            static_assert(std::is_same_v<std::remove_cv_t<decltype(gas)>, decltype(_gas)>);
            if (gas > _gas) [[unlikely]] {
                _gas = 0;
                return false;
            }
            _gas -= gas;
            return true;
        }

        void set_gas(const gas_t gas)
        {
            _gas = gas;
        }

        void set_regs(const registers_t &regs)
        {
            _regs = regs;
        }

        void set_reg(const size_t id, const register_val_t val)
        {
            if (id >= _regs.size()) [[unlikely]]
                throw exit_panic_t{};
            _set_reg(id, val);
        }

        bool set_pages(const address_val_t p, const address_val_t sz, const page_init_method_t i)
        {
            const bool writable = i.access == page_init_method_t::write;
            const auto end_page_id = p + sz;
            if (end_page_id < p) [[unlikely]]
                return false;
            if (end_page_id > std::numeric_limits<address_val_t>::max() / config_prod::ZP_pvm_page_size) [[unlikely]]
                return false;
            for (address_val_t page_id = p; page_id < p + sz; ++page_id) {
                auto *page = _page_dir.lookup_mut(page_id);
                page_info_t next{};
                if (i.data == page_init_method_t::existing) {
                    if (!page) [[unlikely]]
                        return false;
                    next = page_info_t::rebind(*page, writable);
                } else if (i.access != page_init_method_t::none) {
                    next = page_info_t::lazy_zero(writable);
                }
                _upsert_page(page_id, page, next);
            }
            return true;
        }

        [[nodiscard]] heap_bounds_t heap_bounds() const
        {
            return {
                _heap_end / config_prod::ZP_pvm_page_size,
                _stack_begin / config_prod::ZP_pvm_page_size
            };
        }

        bool grow_heap(const register_val_t end_page)
        {
            const auto bounds = heap_bounds();
            if (end_page <= bounds.current || end_page > bounds.maximum)
                return false;
            _add_pages(static_cast<address_val_t>(bounds.current), static_cast<address_val_t>(end_page), true);
            _heap_end = static_cast<address_val_t>(end_page * config_prod::ZP_pvm_page_size);
            return true;
        }

        [[nodiscard]] const code_t &code() const
        {
            return _code;
        }

        [[nodiscard]] gas_remaining_t gas() const
        {
            return _gas;
        }

        [[nodiscard]] uint32_t pc() const
        {
            return _pc;
        }

        [[nodiscard]] const registers_t &regs() const
        {
            return _regs;
        }

        [[nodiscard]] std::optional<exit_page_fault_t> mem_writable(const address_val_t offset, const address_val_t sz) const {
            return _mem_accessible(offset, sz, true);
        }

        [[nodiscard]] std::optional<exit_page_fault_t> mem_readable(const address_val_t offset, const address_val_t sz) const {
            return _mem_accessible(offset, sz, false);
        }

        void mem_copy(const machine_t &src, const address_val_t dst_offset, const address_val_t src_offset, const address_val_t sz) {
            size_t copied = 0;
            src._impl->_mem_read_pages(src_offset, sz, [&](const uint8_t *src_ptr, const size_t chunk) {
                _mem_write_pages(dst_offset + copied, chunk, [&](uint8_t *dst_ptr, const size_t dst_chunk) {
                    if (src_ptr) {
                        std::memcpy(dst_ptr, src_ptr, dst_chunk);
                        src_ptr += dst_chunk;
                    } else {
                        std::memset(dst_ptr, 0, dst_chunk);
                    }
                });
                copied += chunk;
            });
        }

        void mem_read(std::span<uint8_t> res, const address_val_t offset) const
        {
            size_t i = 0;
            _mem_read_pages(offset, res.size(), [&](const uint8_t *src, const size_t chunk) {
                if (src) {
                    std::memcpy(res.data() + i, src, chunk);
                } else {
                    std::memset(res.data() + i, 0, chunk);
                }
                i += chunk;
            });
        }

        uint8_vector mem_read(const address_val_t offset, const address_val_t sz) const
        {
            uint8_vector res;
            res.reserve(sz);
            _mem_read_pages(offset, sz, [&](const uint8_t *src, const size_t chunk) {
                if (src) {
                    res.insert(res.end(), src, src + chunk);
                } else {
                    res.insert(res.end(), chunk, uint8_t{0});
                }
            });
            return res;
        }

        template<bool respect_writable = true>
        void mem_write(const address_val_t offset, const buffer data)
        {
            size_t i = 0;
            _mem_write_pages<respect_writable>(offset, data.size(), [&](uint8_t *dst_ptr, const size_t chunk) {
                std::memcpy(dst_ptr, data.data() + i, chunk);
                i += chunk;
            });
        }

        state_t state() const
        {
            memory_chunks_t mem{};
            memory_chunk_t chunk{};
            const auto flush_chunk = [&chunk, &mem](const register_val_t page_base, const size_t off) {
                if (!chunk.contents.empty()) {
                    chunk.address = numeric_cast<uint32_t>(page_base + off - chunk.contents.size());
                    mem.emplace_back(std::move(chunk));
                    chunk.contents.clear();
                }
            };
            for (size_t l1_idx = 0; l1_idx < page_dir_t::l1_size; ++l1_idx) {
                const auto &l2 = _page_dir.l1[l1_idx];
                if (!l2) continue;
                for (size_t l2_idx = 0; l2_idx < page_dir_t::l2_size; ++l2_idx) {
                    const auto &info = (*l2)[l2_idx];
                    if (!info.exists() || !info.is_materialized()) continue;
                    const register_val_t page_id = (l1_idx << page_dir_t::l2_bits) | l2_idx;
                    const register_val_t page_base = page_id * config_prod::ZP_pvm_page_size;
                    for (size_t off = 0; off < config_prod::ZP_pvm_page_size; ++off) {
                        const auto b = info.data()[off];
                        if (b) {
                            chunk.contents.emplace_back(b);
                        } else {
                            flush_chunk(page_base, off);
                        }
                    }
                    flush_chunk(page_base, config_prod::ZP_pvm_page_size);
                }
            }
            return {
                _regs,
                _pc,
                _gas,
                std::move(mem)
            };
        }
    private:
        using vm_page_t = std::array<uint8_t, config_prod::ZP_pvm_page_size>;

        struct page_info_t {
            static constexpr uintptr_t flag_present = 0x1;
            static constexpr uintptr_t flag_writable = 0x2;
            static constexpr uintptr_t flag_materialized = 0x4;
            static constexpr uintptr_t flag_mask = flag_present | flag_writable | flag_materialized;

            uintptr_t _tagged = 0;

            page_info_t() = default;
            page_info_t(vm_page_t *ptr, const bool writable) noexcept:
                _tagged{reinterpret_cast<uintptr_t>(ptr) | flag_present | flag_materialized | (writable ? flag_writable : 0)}
            {}

            static page_info_t lazy_zero(const bool writable) noexcept
            {
                page_info_t info{};
                info._tagged = flag_present | (writable ? flag_writable : 0);
                return info;
            }

            static page_info_t rebind(const page_info_t info, const bool writable) noexcept
            {
                if (!info.exists())
                    return {};
                if (!info.is_materialized())
                    return lazy_zero(writable);
                return {info.page(), writable};
            }

            bool exists() const noexcept { return _tagged & flag_present; }
            vm_page_t *page() const noexcept { return reinterpret_cast<vm_page_t *>(_tagged & ~flag_mask); }
            uint8_t *data() const noexcept { return page()->data(); }
            bool is_writable() const noexcept { return _tagged & flag_writable; }
            bool is_materialized() const noexcept { return _tagged & flag_materialized; }
        };

        using page_pool_t = turbo::pool_allocator_t<vm_page_t, 0x20>;

        struct page_dir_t {
            static constexpr size_t l2_bits = 10;
            static constexpr size_t l1_size = 1 << l2_bits;  // 1024
            static constexpr size_t l2_size = 1 << l2_bits;  // 1024
            static constexpr size_t page_size = config_prod::ZP_pvm_page_size;
            static_assert(std::numeric_limits<address_val_t>::max() == l1_size * l2_size * page_size - 1U);
            using l2_table_t = std::array<page_info_t, l2_size>;

            std::array<std::unique_ptr<l2_table_t>, l1_size> l1{};

            [[nodiscard]] const page_info_t *lookup(const address_val_t page_id) const noexcept
            {
                if (page_id > std::numeric_limits<address_val_t>::max() / page_size) [[unlikely]]
                    return nullptr;
                const auto &l2 = l1[page_id >> l2_bits];
                if (!l2) [[unlikely]]
                    return nullptr;
                const auto &info = (*l2)[page_id & (l2_size - 1)];
                if (!info.exists())
                    return nullptr;
                return &info;
            }

            page_info_t *lookup_mut(const address_val_t page_id) noexcept
            {
                if (page_id > std::numeric_limits<address_val_t>::max() / page_size) [[unlikely]]
                    return nullptr;
                auto &l2 = l1[page_id >> l2_bits];
                if (!l2) [[unlikely]]
                    return nullptr;
                auto &info = (*l2)[page_id & (l2_size - 1)];
                if (!info.exists())
                    return nullptr;
                return &info;
            }

            void insert(const uint32_t page_id, const page_info_t info)
            {
                if (page_id > std::numeric_limits<address_val_t>::max() / page_size) [[unlikely]]
                    throw exit_panic_t{};
                auto &l2 = l1[page_id >> l2_bits];
                if (!l2)
                    l2 = std::make_unique<l2_table_t>();
                (*l2)[page_id & (l2_size - 1)] = info;
            }
        };

        struct tlb_entry_t {
            address_val_t page_id = ~address_val_t{0};
            const page_info_t *info = nullptr;

            void reset() noexcept {
                page_id = ~address_val_t{0};
                info = nullptr;
            }

            void set(const address_val_t new_page_id, const page_info_t *new_info) noexcept {
                page_id = new_page_id;
                info = new_info;
            }
        };
        static constexpr size_t tlb_size = 8;

        // Hot fields - accessed on every instruction (first ~3 cache lines)
        address_val_t _pc{};
        bool _gas_charged = false;
        gas_remaining_t _gas = 0;
        registers_t _regs{};
        // Warm fields - accessed on memory operations / page faults
        mutable tlb_entry_t _last_page{};
        mutable std::array<tlb_entry_t, tlb_size> _tlb{};
        page_dir_t _page_dir{};
        page_pool_t _page_pool{};
        address_val_t _stack_begin = 0; // After construction: maximum exclusive heap end, below the stack guard zone.
        address_val_t _heap_end = 0;
        // Cold fields - rarely accessed after construction
        code_t _code;

        using op_res_t = std::variant<std::monostate, register_val_t, result_t>;
        using op_exec_t = op_res_t(*)(impl &, const code_t::opcode_t &);
        static_assert(sizeof(op_exec_t) == sizeof(uintptr_t), "opcode dispatch pointer must fit in exactly one uintptr_t");

        struct opcode_t
        {
            constexpr opcode_t() noexcept = default;

            opcode_t(const op_exec_t e):
                _packed{_exec_bits_checked(e)}
            {
            }

            [[nodiscard]] op_exec_t exec_fn() const noexcept
            {
                return _exec_from_bits(_packed);
            }

            [[nodiscard]] bool defined() const noexcept {
                return _packed != 0;
            }

            bool operator==(const opcode_t &) const = default;
        private:
            uintptr_t _packed = 0;

            [[nodiscard]] static uintptr_t _exec_bits_checked(const op_exec_t exec)
            {
                uintptr_t raw = 0;
                std::memcpy(&raw, &exec, sizeof(raw));
                return raw;
            }

            [[nodiscard]] static op_exec_t _exec_from_bits(const uintptr_t raw) noexcept
            {
                op_exec_t exec {};
                std::memcpy(&exec, &raw, sizeof(exec));
                return exec;
            }
        };

        static const std::array<opcode_t, 0x100> &_opcode_table()
        {
            static const auto ops = [] {
                struct opcode_spec_t {
                    uint8_t opcode;
                    op_exec_t exec;
                };
                constexpr auto specs = std::to_array<opcode_spec_t>({
                    {0, &impl::trap},
                    {1, &impl::fallthrough},
                    {2, &impl::unlikely},
                    {10, &impl::ecalli},
                    {20, &impl::load_imm_64},
                    {30, &impl::store_imm_u8},
                    {31, &impl::store_imm_u16},
                    {32, &impl::store_imm_u32},
                    {33, &impl::store_imm_u64},
                    {40, &impl::jump},
                    {50, &impl::jump_ind},
                    {51, &impl::load_imm},
                    {52, &impl::load_u8},
                    {53, &impl::load_i8},
                    {54, &impl::load_u16},
                    {55, &impl::load_i16},
                    {56, &impl::load_u32},
                    {57, &impl::load_i32},
                    {58, &impl::load_u64},
                    {59, &impl::store_u8},
                    {60, &impl::store_u16},
                    {61, &impl::store_u32},
                    {62, &impl::store_u64},
                    {70, &impl::store_imm_ind_u8},
                    {71, &impl::store_imm_ind_u16},
                    {72, &impl::store_imm_ind_u32},
                    {73, &impl::store_imm_ind_u64},
                    {80, &impl::load_imm_jump},
                    {81, &impl::branch_eq_imm},
                    {82, &impl::branch_ne_imm},
                    {83, &impl::branch_lt_u_imm},
                    {84, &impl::branch_le_u_imm},
                    {85, &impl::branch_ge_u_imm},
                    {86, &impl::branch_gt_u_imm},
                    {87, &impl::branch_lt_s_imm},
                    {88, &impl::branch_le_s_imm},
                    {89, &impl::branch_ge_s_imm},
                    {90, &impl::branch_gt_s_imm},
                    {100, &impl::move_reg},
                    {101, &impl::count_set_bits_64},
                    {102, &impl::count_set_bits_32},
                    {103, &impl::leading_zero_bits_64},
                    {104, &impl::leading_zero_bits_32},
                    {105, &impl::trailing_zero_bits_64},
                    {106, &impl::trailing_zero_bits_32},
                    {107, &impl::sign_extend_8},
                    {108, &impl::sign_extend_16},
                    {109, &impl::zero_extend_16},
                    {110, &impl::reverse_bytes},
                    {120, &impl::store_ind_u8},
                    {121, &impl::store_ind_u16},
                    {122, &impl::store_ind_u32},
                    {123, &impl::store_ind_u64},
                    {124, &impl::load_ind_u8},
                    {125, &impl::load_ind_i8},
                    {126, &impl::load_ind_u16},
                    {127, &impl::load_ind_i16},
                    {128, &impl::load_ind_u32},
                    {129, &impl::load_ind_i32},
                    {130, &impl::load_ind_u64},
                    {131, &impl::add_imm_32},
                    {132, &impl::and_imm},
                    {133, &impl::xor_imm},
                    {134, &impl::or_imm},
                    {135, &impl::mul_imm_32},
                    {136, &impl::set_lt_u_imm},
                    {137, &impl::set_lt_s_imm},
                    {138, &impl::shlo_l_imm_32},
                    {139, &impl::shlo_r_imm_32},
                    {140, &impl::shar_r_imm_32},
                    {141, &impl::neg_add_imm_32},
                    {142, &impl::set_gt_u_imm},
                    {143, &impl::set_gt_s_imm},
                    {144, &impl::shlo_l_imm_alt_32},
                    {145, &impl::shlo_r_imm_alt_32},
                    {146, &impl::shar_r_imm_alt_32},
                    {147, &impl::cmov_iz_imm},
                    {148, &impl::cmov_nz_imm},
                    {149, &impl::add_imm_64},
                    {150, &impl::mul_imm_64},
                    {151, &impl::shlo_l_imm_64},
                    {152, &impl::shlo_r_imm_64},
                    {153, &impl::shar_r_imm_64},
                    {154, &impl::neg_add_imm_64},
                    {155, &impl::shlo_l_imm_alt_64},
                    {156, &impl::shlo_r_imm_alt_64},
                    {157, &impl::shar_r_imm_alt_64},
                    {158, &impl::rot_r_64_imm},
                    {159, &impl::rot_r_64_imm_alt},
                    {160, &impl::rot_r_32_imm},
                    {161, &impl::rot_r_32_imm_alt},
                    {170, &impl::branch_eq},
                    {171, &impl::branch_ne},
                    {172, &impl::branch_lt_u},
                    {173, &impl::branch_lt_s},
                    {174, &impl::branch_ge_u},
                    {175, &impl::branch_ge_s},
                    {180, &impl::load_imm_jump_ind},
                    {190, &impl::add_32},
                    {191, &impl::sub_32},
                    {192, &impl::mul_32},
                    {193, &impl::div_u_32},
                    {194, &impl::div_s_32},
                    {195, &impl::rem_u_32},
                    {196, &impl::rem_s_32},
                    {197, &impl::shlo_l_32},
                    {198, &impl::shlo_r_32},
                    {199, &impl::shar_r_32},
                    {200, &impl::add_64},
                    {201, &impl::sub_64},
                    {202, &impl::mul_64},
                    {203, &impl::div_u_64},
                    {204, &impl::div_s_64},
                    {205, &impl::rem_u_64},
                    {206, &impl::rem_s_64},
                    {207, &impl::shlo_l_64},
                    {208, &impl::shlo_r_64},
                    {209, &impl::shar_r_64},
                    {210, &impl::and_},
                    {211, &impl::xor_},
                    {212, &impl::or_},
                    {213, &impl::mul_upper_s_s},
                    {214, &impl::mul_upper_u_u},
                    {215, &impl::mul_upper_s_u},
                    {216, &impl::set_lt_u},
                    {217, &impl::set_lt_s},
                    {218, &impl::cmov_iz},
                    {219, &impl::cmov_nz},
                    {220, &impl::rot_l_64},
                    {221, &impl::rot_l_32},
                    {222, &impl::rot_r_64},
                    {223, &impl::rot_r_32},
                    {224, &impl::and_inv},
                    {225, &impl::or_inv},
                    {226, &impl::xnor},
                    {227, &impl::max},
                    {228, &impl::max_u},
                    {229, &impl::min},
                    {230, &impl::min_u}
                });
                static_assert([](const auto &definitions) {
                    int previous_opcode = -1;
                    for (const auto &spec: definitions) {
                        if (spec.opcode <= previous_opcode || !spec.exec)
                            return false;
                        previous_opcode = spec.opcode;
                    }
                    return true;
                }(specs), "opcode definitions must be sorted and unique, with non-null handlers and supported operand lengths");
                static_assert([](const auto &definitions) {
                    std::array<bool, 0x100> defined{};
                    for (const auto &spec: definitions)
                        defined[spec.opcode] = true;
                    for (size_t opcode = 0; opcode < defined.size(); ++opcode) {
                        if (code_t::is_block_end_opcode(static_cast<uint8_t>(opcode)) && !defined[opcode])
                            return false;
                    }
                    return true;
                }(specs), "every block-end opcode must have a handler");

                std::array<opcode_t, 0x100> res{};
                for (const auto &spec: specs) {
                    res[spec.opcode] = opcode_t{spec.exec};
                }
                return res;
            }();
            return ops;
        }

        template<typename F>
        void _mem_read_pages(const address_val_t offset, const address_val_t sz, F &&consume) const
        {
            const auto ex = _mem_walk_pages(
                offset, sz,
                [&](const address_val_t, const address_val_t, const address_val_t page_off, const address_val_t chunk, const page_info_t &page) -> std::optional<exit_page_fault_t> {
                    consume(page.is_materialized() ? page.data() + page_off : nullptr, chunk);
                    return {};
                }
            );
            if (ex) [[unlikely]]
                throw *ex;
        }

        template<bool respect_writable = true, typename F>
        void _mem_write_pages(const address_val_t offset, const address_val_t sz, F &&consume)
        {
            const auto ex = _mem_walk_pages(
                offset, sz,
                [&](const address_val_t p, const address_val_t, const address_val_t page_off, const address_val_t chunk, const page_info_t &page) -> std::optional<exit_page_fault_t> {
                    auto &mut_page = const_cast<page_info_t &>(page);
                    if constexpr (respect_writable) {
                        if (!mut_page.is_writable()) [[unlikely]]
                            return exit_page_fault_t{p - page_off};
                    }
                    _materialize_page(mut_page);
                    consume(mut_page.data() + page_off, chunk);
                    return {};
                }
            );
            if (ex) [[unlikely]]
                throw *ex;
        }

        result_t _run()
        {
            try {
                const auto &ops = _opcode_table();
                const auto &blks = _code.blocks();
                for (;;) {
                    auto blk_it = blks.upper_bound(_pc);
                    if (blk_it == blks.begin())
                        throw exit_panic_t{};
                    --blk_it;
                    const auto &blk_ops = blk_it->second.opcodes;
                    const auto num_ops = blk_ops.size();
                    size_t next_op = 0;

                    // allow continuation of a block after an out-of-gas, page-fault or host call
                    if (!_gas_charged) {
                        if (!consume_gas(blk_it->second.cost)) [[unlikely]]
                            return exit_out_of_gas_t{};
                        _gas_charged = true;
                    } else if (_pc != blk_it->first) [[unlikely]] {
                        auto next_pc = blk_it->first;
                        while (next_op < num_ops && next_pc < _pc) {
                            next_pc += 1U + blk_ops[next_op].skip_len;
                            ++next_op;
                        }
                        if (next_op == blk_ops.size() || next_pc != _pc)
                            throw exit_panic_t{};
                    }

                    // guaranteed to be >= 1 by construction
                    for (size_t i = next_op; i < num_ops - 1U; ++i) {
                        const auto op = blk_ops[i];
                        const auto res = ops[op.id].exec_fn()(*this, op);
                        if (std::holds_alternative<result_t>(res)) [[unlikely]]
                            return std::get<result_t>(res);
                        _pc += op.skip_len + 1U;
                    }
                    const auto &last_op = blk_ops.back();
                    const auto last_exec = ops[last_op.id].exec_fn();
                    // (A.6) - psi_1
                    switch (auto res = last_exec(*this, last_op); res.index()) {
                        case 0:
                            _pc += last_op.skip_len + 1U;
                            _gas_charged = false;
                            break;
                        case 1:
                            _pc = std::get<1>(res);
                            _gas_charged = false;
                            break;
                        case 2: return std::get<2>(std::move(res));
                        [[unlikely]] default: throw error(fmt::format("unsupported op_res_t index: {}", res.index()));
                    }
                }
            } catch (exit_page_fault_t &ex) {
                return {std::move(ex)};
            } catch (exit_out_of_gas_t &ex) {
                return {std::move(ex)};
            } catch (...) { // exit_panic_t or an internal error
                return {exit_panic_t{}};
            }
        }

        // opcode helper functions

        void _set_reg(const register_idx_t idx, const register_val_t val)
        {
            _regs[idx] = val;
        }

        static std::tuple<register_idx_t, register_idx_t, register_val_t> _args_reg2_imm1(const buffer data)
        {
            const auto *ptr = data.data();
            const auto b0 = ptr[0];
            const register_idx_t r_a = std::min(12ULL, b0 & 0xFULL);
            const register_idx_t r_b = std::min(12ULL, b0 / 16ULL);
            const auto nu_x = [&]() noexcept -> register_val_t {
                switch (data.size()) {
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
            return std::make_tuple(r_a, r_b, nu_x);
        }

        static op_res_t djump(const code_t &code, const register_val_t addr)
        {
            if (addr == (1ULL << 32ULL) - (1ULL << 16ULL)) [[unlikely]]
                return exit_halt_t{};
            if (addr == 0) [[unlikely]]
                return exit_panic_t{};
            if (addr > code.jump_table.size() * config_prod::ZA_pvm_address_alignment_factor) [[unlikely]]
                return exit_panic_t{};
            if (addr % config_prod::ZA_pvm_address_alignment_factor != 0) [[unlikely]]
                return exit_panic_t{};
            const auto ji = addr / config_prod::ZA_pvm_address_alignment_factor;
            const auto new_pc = code.jump_table.at(ji - 1);
            return {new_pc};
        }

        static op_res_t sjump(const register_val_t new_pc)
        {
            return {new_pc};
        }

        static op_res_t branch_base(const register_val_t new_pc, const bool cond, const code_t::blocks_t &blocks)
        {
            if (cond)
                return sjump(new_pc);
            // even though the branch is not take we need still to check that it refererred to the start of a basic block
            // we check only on the negative branch because an sjump will do that anyway as part of the transition
            if (const auto blk_it = blocks.find(new_pc); blk_it == blocks.end()) [[unlikely]]
                return exit_panic_t{};
            return {};
        }

        void _add_pages(const address_val_t start_page, const address_val_t end_page, const bool is_writable)
        {
            if (end_page < start_page) [[unlikely]]
                throw exit_panic_t{};
            const auto next = page_info_t::lazy_zero(is_writable);
            for (address_val_t page_id = start_page; page_id < end_page; ++page_id) {
                _insert_page(page_id, next);
            }
        }

        void _invalidate_page_cache(const address_val_t page_id) const noexcept
        {
            if (_last_page.page_id == page_id)
                _last_page.reset();
            if (auto &slot = _tlb[page_id & (tlb_size - 1)]; slot.page_id == page_id)
                slot.reset();
        }

        const page_info_t *_page_lookup(const address_val_t page_id) const noexcept
        {
            if (page_id != _last_page.page_id) {
                auto &tlb_slot = _tlb[page_id & (tlb_size - 1)];
                if (tlb_slot.page_id != page_id) {
                    const auto *info = _page_dir.lookup(page_id);
                    if (!info) [[unlikely]]
                        return nullptr;
                    tlb_slot.set(page_id, info);
                }
                _last_page.set(page_id, tlb_slot.info);
            }
            return _last_page.info;
        }

        void _materialize_page(page_info_t &page)
        {
            if (!page.is_materialized()) {
                auto *mem_page = _page_pool.allocate();
                std::memset(mem_page, 0, sizeof(*mem_page));
                page = page_info_t{mem_page, page.is_writable()};
            }
        }

        void _insert_page(const address_val_t page_id, const page_info_t next)
        {
            _page_dir.insert(page_id, next);
            _invalidate_page_cache(page_id);
        }

        void _replace_page(const address_val_t page_id, page_info_t &page, const page_info_t next)
        {
            if (page.is_materialized()) {
                const auto old_page = page.page();
                if (!next.is_materialized() || next.page() != old_page)
                    _page_pool.deallocate(old_page);
            }
            page = next;
            _invalidate_page_cache(page_id);
        }

        void _upsert_page(const address_val_t page_id, page_info_t *page, const page_info_t next)
        {
            if (page) {
                _replace_page(page_id, *page, next);
            } else if (next.exists()) {
                _insert_page(page_id, next);
            }
        }

        template<typename F>
        std::optional<exit_page_fault_t> _mem_walk_pages(const address_val_t offset, const address_val_t sz, F &&consume) const
        {
            static address_val_t page_size = config_prod::ZP_pvm_page_size;
            address_val_t p = offset, remaining = sz;
            while (remaining > 0) {
                const auto page_id = p / page_size;
                const auto page_off = p % page_size;
                const auto *page = _page_lookup(page_id);
                if (!page) [[unlikely]]
                    return exit_page_fault_t{page_id * page_size};
                const auto chunk = std::min(remaining, page_size - page_off);
                if (const auto ex = consume(p, page_id, page_off, chunk, *page); ex) [[unlikely]]
                    return ex;
                p += chunk;
                remaining -= chunk;
            }
            return {};
        }

        [[nodiscard]] std::optional<exit_page_fault_t> _mem_accessible(const address_val_t offset, const address_val_t sz, const bool require_writable) const
        {
            return _mem_walk_pages(offset, sz, [&](const address_val_t p, const address_val_t, const address_val_t page_off, const address_val_t, const page_info_t &page) -> std::optional<exit_page_fault_t> {
                if (require_writable && !page.is_writable()) [[unlikely]]
                    return exit_page_fault_t{p - page_off};
                return {};
            });
        }

        // (A.8)
        template<size_t SZ>
        std::pair<address_val_t, const page_info_t *> _addr_check(const address_val_t addr) const
        {
            static constexpr address_val_t page_size  = config_prod::ZP_pvm_page_size;
            static constexpr address_val_t page_mask  = page_size - 1;
            static constexpr unsigned page_shift = std::countr_zero(page_size);
            static_assert((page_size & page_mask) == 0, "page size must be power of two");
            if (addr < config_prod::ZZ_pvm_init_zone_size) [[unlikely]]
                throw exit_panic_t{};
            const auto page_off = addr & page_mask;
            const auto page_id  = addr >> page_shift;
            if (page_off > page_mask - (SZ - 1)) [[unlikely]]
                throw exit_page_fault_t{(addr & ~page_mask) + page_size};
            const auto *page = _page_lookup(page_id);
            if (!page) [[unlikely]]
                throw exit_page_fault_t{page_id * page_size};
            return {page_off, page};
        }

        template<size_t SZ>
        std::pair<address_val_t, page_info_t *> _addr_check_mut(const address_val_t addr) const {
            const auto [page_off, page] = _addr_check<SZ>(addr);
            return {page_off, const_cast<page_info_t *>(page)};
        }

        template<size_t SZ>
        register_val_t _load_unsigned(const address_val_t addr) const
        {
            const auto [page_off, page_it] = _addr_check<SZ>(addr);
            if (!page_it->is_materialized())
                return 0;
            if constexpr (SZ == 1) {
                return page_it->data()[page_off];
            } else if constexpr (SZ == 2) {
                uint16_t res;
                std::memcpy(&res, page_it->data() + page_off, sizeof(res));
                return res;
            } else if constexpr (SZ == 4) {
                uint32_t res;
                std::memcpy(&res, page_it->data() + page_off, sizeof(res));
                return res;
            } else if constexpr (SZ == 8) {
                uint64_t res;
                std::memcpy(&res, page_it->data() + page_off, sizeof(res));
                return res;
            } else {
                throw exit_panic_t{};
            }
        }

        template<size_t SZ>
        register_val_t _load_signed(const address_val_t addr)
        {
            return code_t::sign_extend(SZ, _load_unsigned<SZ>(addr));
        }

        template<typename T>
        void _store_unsigned(const address_val_t addr, const T val)
        {
            auto [page_off, page] = _addr_check_mut<sizeof(T)>(addr);
            if (!page->is_writable()) [[unlikely]]
                throw exit_page_fault_t{addr - page_off};
            _materialize_page(*page);
            std::memcpy(page->data() + page_off, &val, sizeof(val));
        }

        template<typename Pred>
        static op_res_t _branch_reg2_off1(const registers_t &regs, const code_t::opcode_t &op, Pred &&pred, const code_t::blocks_t &blocks)
        {
            return branch_base(op.imm_1, pred(regs[op.reg_1], regs[op.reg_2]), blocks);
        }

        template<typename Pred>
        static op_res_t _branch_reg1_imm1_off1(const registers_t &regs, const code_t::opcode_t &op, Pred &&pred, const code_t::blocks_t &blocks)
        {
            return branch_base(op.imm_2, pred(regs[op.reg_1], op.imm_1), blocks);
        }

        template<size_t SZ, bool Signed>
        static op_res_t _load_direct(impl &self, registers_t &regs, const code_t::opcode_t &op)
        {
            if constexpr (Signed)
                regs[op.reg_1] = self._load_signed<SZ>(op.imm_1);
            else
                regs[op.reg_1] = self._load_unsigned<SZ>(op.imm_1);
            return {};
        }

        template<typename T>
        static op_res_t _store_direct(impl &self, const registers_t &regs, const code_t::opcode_t &op)
        {
            self._store_unsigned(op.imm_1, static_cast<T>(regs[op.reg_1]));
            return {};
        }

        template<typename T>
        static op_res_t _store_imm_indirect(impl &self, const registers_t &regs, const code_t::opcode_t &op)
        {
            self._store_unsigned(regs[op.reg_1] + op.imm_1, static_cast<T>(op.imm_2));
            return {};
        }

        template<typename T>
        static op_res_t _store_indirect(impl &self, const registers_t &regs, const code_t::opcode_t &op)
        {
            self._store_unsigned(regs[op.reg_2] + op.imm_1, static_cast<T>(regs[op.reg_1]));
            return {};
        }

        template<size_t SZ, bool Signed>
        static op_res_t _load_indirect(impl &self, registers_t &regs, const code_t::opcode_t &op)
        {
            const auto addr = regs[op.reg_2] + op.imm_1;
            if constexpr (Signed)
                regs[op.reg_1] = self._load_signed<SZ>(addr);
            else
                regs[op.reg_1] = self._load_unsigned<SZ>(addr);
            return {};
        }

        template<typename Op>
        static op_res_t _reg3_apply(registers_t &regs, const code_t::opcode_t &op, Op &&fn)
        {
            regs[op.reg_3] = fn(regs[op.reg_1], regs[op.reg_2]);
            return {};
        }

        // opcode implementations

        static op_res_t trap(impl &, const code_t::opcode_t &)
        {
            return exit_panic_t{};
        }

        static op_res_t fallthrough(impl &self, const code_t::opcode_t &op)
        {
            return register_val_t{self._pc + 1U + op.skip_len};
        }

        static op_res_t unlikely(impl &, const code_t::opcode_t &op)
        {
            return {};
        }

        static op_res_t ecalli(impl &self, const code_t::opcode_t &op)
        {
            return exit_host_call_t{op.imm_1};
        }

        static op_res_t store_imm_u8(impl &self, const code_t::opcode_t &op)
        {
            self._store_unsigned(op.imm_1, static_cast<uint8_t>(op.imm_2));
            return {};
        }

        static op_res_t store_imm_u16(impl &self, const code_t::opcode_t &op)
        {
            self._store_unsigned(op.imm_1, static_cast<uint16_t>(op.imm_2));
            return {};
        }

        static op_res_t store_imm_u32(impl &self, const code_t::opcode_t &op)
        {
            self._store_unsigned(op.imm_1, static_cast<uint32_t>(op.imm_2));
            return {};
        }

        static op_res_t store_imm_u64(impl &self, const code_t::opcode_t &op)
        {
            self._store_unsigned(op.imm_1, op.imm_2);
            return {};
        }

        static op_res_t load_imm(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_1, op.imm_1);
            return {};
        }

        static op_res_t load_imm_64(impl &self, const code_t::opcode_t &op)
        {
            // Todo: check that one register byte and eight immediate bytes, independent of the current skip (can read from the extra padded 0s)
            self._set_reg(op.reg_1, op.imm_1);
            return {};
        }

        static op_res_t move_reg(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_1, self._regs[op.reg_2]);
            return {};
        }

        static op_res_t count_set_bits_64(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_1, std::popcount(self._regs[op.reg_2]));
            return {};
        }

        static op_res_t count_set_bits_32(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_1, std::popcount(static_cast<uint32_t>(self._regs[op.reg_2])));
            return {};
        }

        static op_res_t leading_zero_bits_64(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_1, std::countl_zero(self._regs[op.reg_2]));
            return {};
        }

        static op_res_t leading_zero_bits_32(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_1, std::countl_zero(static_cast<uint32_t>(self._regs[op.reg_2])));
            return {};
        }

        static op_res_t trailing_zero_bits_64(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_1, std::countr_zero(self._regs[op.reg_2]));
            return {};
        }

        static op_res_t trailing_zero_bits_32(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_1, std::countr_zero(static_cast<uint32_t>(self._regs[op.reg_2])));
            return {};
        }

        static op_res_t sign_extend_8(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_1, code_t::sign_extend(1, self._regs[op.reg_2]));
            return {};
        }

        static op_res_t sign_extend_16(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_1, code_t::sign_extend(2, self._regs[op.reg_2]));
            return {};
        }

        static op_res_t zero_extend_16(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_1, self._regs[op.reg_2] & 0xFFFF);
            return {};
        }

        static op_res_t reverse_bytes(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_1, std::byteswap(self._regs[op.reg_2]));
            return {};
        }

        static op_res_t branch_eq(impl &self, const code_t::opcode_t &op)
        {
            return _branch_reg2_off1(self._regs, op, [](const register_val_t lhs, const register_val_t rhs) noexcept { return lhs == rhs; },
                self._code.blocks());
        }

        static op_res_t branch_ne(impl &self, const code_t::opcode_t &op)
        {
            return _branch_reg2_off1(self._regs, op, [](const register_val_t lhs, const register_val_t rhs) noexcept { return lhs != rhs; },
                self._code.blocks());
        }

        static op_res_t branch_lt_u(impl &self, const code_t::opcode_t &op)
        {
            return _branch_reg2_off1(self._regs, op, [](const register_val_t lhs, const register_val_t rhs) noexcept { return lhs < rhs; },
                self._code.blocks());
        }

        static op_res_t branch_lt_s(impl &self, const code_t::opcode_t &op)
        {
            return _branch_reg2_off1(self._regs, op,
                [](const register_val_t lhs, const register_val_t rhs) noexcept {
                    return static_cast<register_val_signed_t>(lhs) < static_cast<register_val_signed_t>(rhs);
                },
                self._code.blocks());
        }

        static op_res_t branch_ge_u(impl &self, const code_t::opcode_t &op)
        {
            return _branch_reg2_off1(self._regs, op, [](const register_val_t lhs, const register_val_t rhs) noexcept { return lhs >= rhs; },
                self._code.blocks());
        }

        static op_res_t branch_ge_s(impl &self, const code_t::opcode_t &op)
        {
            return _branch_reg2_off1(self._regs, op,
                [](const register_val_t lhs, const register_val_t rhs) noexcept {
                    return static_cast<register_val_signed_t>(lhs) >= static_cast<register_val_signed_t>(rhs);
                },
                self._code.blocks());
        }

        static op_res_t add_imm_32(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_1, code_t::sign_extend(4, static_cast<uint32_t>(self._regs[op.reg_2] + op.imm_1)));
            return {};
        }

        static op_res_t and_imm(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_1, self._regs[op.reg_2] & op.imm_1);
            return {};
        }

        static op_res_t xor_imm(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_1, self._regs[op.reg_2] ^ op.imm_1);
            return {};
        }

        static op_res_t or_imm(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_1, self._regs[op.reg_2] | op.imm_1);
            return {};
        }

        static op_res_t mul_imm_32(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_1, code_t::sign_extend(4, self._regs[op.reg_2] * op.imm_1));
            return {};
        }

        static op_res_t set_lt_u_imm(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_1, self._regs[op.reg_2] < op.imm_1);
            return {};
        }

        static op_res_t set_lt_s_imm(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_1, static_cast<register_val_signed_t>(self._regs[op.reg_2]) < static_cast<register_val_signed_t>(op.imm_1));
            return {};
        }

        static op_res_t shlo_l_imm_32(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_1, code_t::sign_extend(4, static_cast<uint32_t>(self._regs[op.reg_2]) << (op.imm_1 % 32U)));
            return {};
        }

        static op_res_t shlo_r_imm_32(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_1, code_t::sign_extend(4, static_cast<uint32_t>(self._regs[op.reg_2]) >> (op.imm_1 % 32U)));
            return {};
        }

        static op_res_t shar_r_imm_32(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_1, static_cast<register_val_t>(static_cast<int32_t>(self._regs[op.reg_2]) >> (op.imm_1 % 32U)));
            return {};
        }

        static op_res_t neg_add_imm_32(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_1, code_t::sign_extend(4, static_cast<uint32_t>(op.imm_1 + (1ULL << 32ULL) - self._regs[op.reg_2])));
            return {};
        }

        static op_res_t set_gt_u_imm(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_1, self._regs[op.reg_2] > op.imm_1);
            return {};
        }

        static op_res_t set_gt_s_imm(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_1, static_cast<register_val_signed_t>(self._regs[op.reg_2]) > static_cast<register_val_signed_t>(op.imm_1));
            return {};
        }

        static op_res_t shlo_l_imm_alt_32(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_1, code_t::sign_extend(4, static_cast<uint32_t>(op.imm_1) << (self._regs[op.reg_2] % 32U)));
            return {};
        }

        static op_res_t shlo_r_imm_alt_32(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_1, code_t::sign_extend(4, static_cast<uint32_t>(op.imm_1) >> (self._regs[op.reg_2] % 32U)));
            return {};
        }

        static op_res_t shar_r_imm_alt_32(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_1, static_cast<register_val_t>(static_cast<int32_t>(op.imm_1) >> (self._regs[op.reg_2] % 32U)));
            return {};
        }

        static op_res_t cmov_iz_imm(impl &self, const code_t::opcode_t &op)
        {
            if (self._regs[op.reg_2] == 0)
                self._set_reg(op.reg_1, op.imm_1);
            return {};
        }

        static op_res_t cmov_nz_imm(impl &self, const code_t::opcode_t &op)
        {
            if (self._regs[op.reg_2] != 0)
                self._set_reg(op.reg_1, op.imm_1);
            return {};
        }

        static op_res_t add_imm_64(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_1, self._regs[op.reg_2] + op.imm_1);
            return {};
        }

        static op_res_t mul_imm_64(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_1, self._regs[op.reg_2] * op.imm_1);
            return {};
        }

        static op_res_t shlo_l_imm_64(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_1, self._regs[op.reg_2] << (op.imm_1 % 64U));
            return {};
        }

        static op_res_t shlo_r_imm_64(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_1, self._regs[op.reg_2] >> (op.imm_1 % 64U));
            return {};
        }

        static op_res_t shar_r_imm_64(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_1, static_cast<register_val_t>(static_cast<register_val_signed_t>(self._regs[op.reg_2]) >> (op.imm_1 % 64U)));
            return {};
        }

        static op_res_t neg_add_imm_64(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_1, op.imm_1 - self._regs[op.reg_2]);
            return {};
        }

        static op_res_t shlo_l_imm_alt_64(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_1, op.imm_1 << (self._regs[op.reg_2] % 64U));
            return {};
        }

        static op_res_t shlo_r_imm_alt_64(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_1, op.imm_1 >> (self._regs[op.reg_2] % 64U));
            return {};
        }

        static op_res_t shar_r_imm_alt_64(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_1, static_cast<register_val_t>(static_cast<register_val_signed_t>(op.imm_1) >> (self._regs[op.reg_2] % 64U)));
            return {};
        }

        static op_res_t rot_r_64_imm(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_1, std::rotr(self._regs[op.reg_2], op.imm_1));
            return {};
        }

        static op_res_t rot_r_64_imm_alt(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_1, std::rotr(op.imm_1, self._regs[op.reg_2]));
            return {};
        }

        static op_res_t rot_r_32_imm(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_1, code_t::sign_extend(4, std::rotr(static_cast<uint32_t>(self._regs[op.reg_2]), static_cast<uint32_t>(op.imm_1))));
            return {};
        }

        static op_res_t rot_r_32_imm_alt(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_1, code_t::sign_extend(4, std::rotr(static_cast<uint32_t>(op.imm_1), static_cast<uint32_t>(self._regs[op.reg_2]))));
            return {};
        }

        static op_res_t load_imm_jump(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_1, op.imm_1);
            return sjump(op.imm_2);
        }

        static op_res_t load_imm_jump_ind(impl &self, const code_t::opcode_t &op)
        {
            const auto jt_idx = (self._regs[op.reg_2] + op.imm_2) % (1ULL << 32ULL);
            self._set_reg(op.reg_1, op.imm_1);
            return djump(self._code, jt_idx);
        }

        static op_res_t branch_eq_imm(impl &self, const code_t::opcode_t &op)
        {
            return _branch_reg1_imm1_off1(self._regs, op, [](const register_val_t lhs, const register_val_t rhs) noexcept { return lhs == rhs; },
                self._code.blocks());
        }

        static op_res_t branch_ne_imm(impl &self, const code_t::opcode_t &op)
        {
            return _branch_reg1_imm1_off1(self._regs, op, [](const register_val_t lhs, const register_val_t rhs) noexcept { return lhs != rhs; },
                self._code.blocks());
        }

        static op_res_t branch_lt_u_imm(impl &self, const code_t::opcode_t &op)
        {
            return _branch_reg1_imm1_off1(self._regs, op, [](const register_val_t lhs, const register_val_t rhs) noexcept { return lhs < rhs; },
                self._code.blocks());
        }

        static op_res_t branch_le_u_imm(impl &self, const code_t::opcode_t &op)
        {
            return _branch_reg1_imm1_off1(self._regs, op, [](const register_val_t lhs, const register_val_t rhs) noexcept { return lhs <= rhs; },
                self._code.blocks());
        }

        static op_res_t branch_ge_u_imm(impl &self, const code_t::opcode_t &op)
        {
            return _branch_reg1_imm1_off1(self._regs, op, [](const register_val_t lhs, const register_val_t rhs) noexcept { return lhs >= rhs; },
                self._code.blocks());
        }

        static op_res_t branch_gt_u_imm(impl &self, const code_t::opcode_t &op)
        {
            return _branch_reg1_imm1_off1(self._regs, op, [](const register_val_t lhs, const register_val_t rhs) noexcept { return lhs > rhs; },
                self._code.blocks());
        }

        static op_res_t branch_lt_s_imm(impl &self, const code_t::opcode_t &op)
        {
            return _branch_reg1_imm1_off1(self._regs, op,
                [](const register_val_t lhs, const register_val_t rhs) noexcept {
                    return static_cast<register_val_signed_t>(lhs) < static_cast<register_val_signed_t>(rhs);
                },
                self._code.blocks());
        }

        static op_res_t branch_le_s_imm(impl &self, const code_t::opcode_t &op)
        {
            return _branch_reg1_imm1_off1(self._regs, op,
                [](const register_val_t lhs, const register_val_t rhs) noexcept {
                    return static_cast<register_val_signed_t>(lhs) <= static_cast<register_val_signed_t>(rhs);
                },
                self._code.blocks());
        }

        static op_res_t branch_ge_s_imm(impl &self, const code_t::opcode_t &op)
        {
            return _branch_reg1_imm1_off1(self._regs, op,
                [](const register_val_t lhs, const register_val_t rhs) noexcept {
                    return static_cast<register_val_signed_t>(lhs) >= static_cast<register_val_signed_t>(rhs);
                },
                self._code.blocks());
        }

        static op_res_t branch_gt_s_imm(impl &self, const code_t::opcode_t &op)
        {
            return _branch_reg1_imm1_off1(self._regs, op,
                [](const register_val_t lhs, const register_val_t rhs) noexcept {
                    return static_cast<register_val_signed_t>(lhs) > static_cast<register_val_signed_t>(rhs);
                },
                self._code.blocks());
        }

        static op_res_t jump(impl &, const code_t::opcode_t &op)
        {
            return sjump(op.imm_1);
        }

        static op_res_t jump_ind(impl &self, const code_t::opcode_t &op)
        {
            return djump(self._code, (self._regs[op.reg_1] + op.imm_1) % (1ULL << 32ULL));
        }

        static op_res_t load_u8(impl &self, const code_t::opcode_t &op)
        {
            return _load_direct<1, false>(self, self._regs, op);
        }

        static op_res_t load_u16(impl &self, const code_t::opcode_t &op)
        {
            return _load_direct<2, false>(self, self._regs, op);
        }

        static op_res_t load_u32(impl &self, const code_t::opcode_t &op)
        {
            return _load_direct<4, false>(self, self._regs, op);
        }

        static op_res_t load_u64(impl &self, const code_t::opcode_t &op)
        {
            return _load_direct<8, false>(self, self._regs, op);
        }

        static op_res_t load_i8(impl &self, const code_t::opcode_t &op)
        {
            return _load_direct<1, true>(self, self._regs, op);
        }

        static op_res_t load_i16(impl &self, const code_t::opcode_t &op)
        {
            return _load_direct<2, true>(self, self._regs, op);
        }

        static op_res_t load_i32(impl &self, const code_t::opcode_t &op)
        {
            return _load_direct<4, true>(self, self._regs, op);
        }

        static op_res_t store_u8(impl &self, const code_t::opcode_t &op)
        {
            return _store_direct<uint8_t>(self, self._regs, op);
        }

        static op_res_t store_u16(impl &self, const code_t::opcode_t &op)
        {
            return _store_direct<uint16_t>(self, self._regs, op);
        }

        static op_res_t store_u32(impl &self, const code_t::opcode_t &op)
        {
            return _store_direct<uint32_t>(self, self._regs, op);
        }

        static op_res_t store_u64(impl &self, const code_t::opcode_t &op)
        {
            return _store_direct<register_val_t>(self, self._regs, op);
        }

        static op_res_t store_imm_ind_u8(impl &self, const code_t::opcode_t &op)
        {
            return _store_imm_indirect<uint8_t>(self, self._regs, op);
        }

        static op_res_t store_imm_ind_u16(impl &self, const code_t::opcode_t &op)
        {
            return _store_imm_indirect<uint16_t>(self, self._regs, op);
        }

        static op_res_t store_imm_ind_u32(impl &self, const code_t::opcode_t &op)
        {
            return _store_imm_indirect<uint32_t>(self, self._regs, op);
        }

        static op_res_t store_imm_ind_u64(impl &self, const code_t::opcode_t &op)
        {
            return _store_imm_indirect<register_val_t>(self, self._regs, op);
        }

        static op_res_t store_ind_u8(impl &self, const code_t::opcode_t &op)
        {
            return _store_indirect<uint8_t>(self, self._regs, op);
        }

        static op_res_t store_ind_u16(impl &self, const code_t::opcode_t &op)
        {
            return _store_indirect<uint16_t>(self, self._regs, op);
        }

        static op_res_t store_ind_u32(impl &self, const code_t::opcode_t &op)
        {
            return _store_indirect<uint32_t>(self, self._regs, op);
        }

        static op_res_t store_ind_u64(impl &self, const code_t::opcode_t &op)
        {
            return _store_indirect<register_val_t>(self, self._regs, op);
        }

        static op_res_t load_ind_u8(impl &self, const code_t::opcode_t &op)
        {
            return _load_indirect<1, false>(self, self._regs, op);
        }

        static op_res_t load_ind_u16(impl &self, const code_t::opcode_t &op)
        {
            return _load_indirect<2, false>(self, self._regs, op);
        }

        static op_res_t load_ind_u32(impl &self, const code_t::opcode_t &op)
        {
            return _load_indirect<4, false>(self, self._regs, op);
        }

        static op_res_t load_ind_u64(impl &self, const code_t::opcode_t &op)
        {
            return _load_indirect<8, false>(self, self._regs, op);
        }

        static op_res_t load_ind_i8(impl &self, const code_t::opcode_t &op)
        {
            return _load_indirect<1, true>(self, self._regs, op);
        }

        static op_res_t load_ind_i16(impl &self, const code_t::opcode_t &op)
        {
            return _load_indirect<2, true>(self, self._regs, op);
        }

        static op_res_t load_ind_i32(impl &self, const code_t::opcode_t &op)
        {
            return _load_indirect<4, true>(self, self._regs, op);
        }

        static op_res_t add_32(impl &self, const code_t::opcode_t &op)
        {
            return _reg3_apply(self._regs, op, [](const register_val_t lhs, const register_val_t rhs) noexcept {
                return code_t::sign_extend(4, static_cast<uint32_t>(lhs + rhs));
            });
        }

        static op_res_t sub_32(impl &self, const code_t::opcode_t &op)
        {
            return _reg3_apply(self._regs, op, [](const register_val_t lhs, const register_val_t rhs) noexcept {
                return code_t::sign_extend(4, static_cast<uint32_t>(lhs - rhs));
            });
        }

        static op_res_t mul_32(impl &self, const code_t::opcode_t &op)
        {
            return _reg3_apply(self._regs, op, [](const register_val_t lhs, const register_val_t rhs) noexcept {
                return code_t::sign_extend(4, static_cast<uint32_t>(lhs * rhs));
            });
        }

        static op_res_t div_u_32(impl &self, const code_t::opcode_t &op)
        {
            const auto reg_a_u32 = static_cast<uint32_t>(self._regs[op.reg_1]);
            const auto reg_b_u32 = static_cast<uint32_t>(self._regs[op.reg_2]);
            self._set_reg(op.reg_3, reg_b_u32 != 0 ? code_t::sign_extend(4, reg_a_u32 / reg_b_u32) : std::numeric_limits<uint64_t>::max());
            return {};
        }

        static op_res_t div_s_32(impl &self, const code_t::opcode_t &op)
        {
            const auto reg_a_s32 = static_cast<int32_t>(self._regs[op.reg_1]);
            const auto reg_b_s32 = static_cast<int32_t>(self._regs[op.reg_2]);
            if (reg_b_s32 != 0) {
                if (reg_a_s32 != std::numeric_limits<int32_t>::min() || reg_b_s32 != -1) {
                    self._set_reg(op.reg_3, static_cast<register_val_t>(reg_a_s32 / reg_b_s32));
                } else {
                    self._set_reg(op.reg_3, static_cast<register_val_t>(reg_a_s32));
                }
            } else {
                self._set_reg(op.reg_3, std::numeric_limits<uint64_t>::max());
            }
            return {};
        }

        static op_res_t rem_u_32(impl &self, const code_t::opcode_t &op)
        {
            const auto reg_a_u32 = static_cast<uint32_t>(self._regs[op.reg_1]);
            const auto reg_b_u32 = static_cast<uint32_t>(self._regs[op.reg_2]);
            self._set_reg(op.reg_3, code_t::sign_extend(4, reg_b_u32 != 0 ? reg_a_u32 % reg_b_u32 : reg_a_u32));
            return {};
        }

        static op_res_t rem_s_32(impl &self, const code_t::opcode_t &op)
        {
            const auto reg_a_s32 = static_cast<int32_t>(self._regs[op.reg_1]);
            const auto reg_b_s32 = static_cast<int32_t>(self._regs[op.reg_2]);
            if (reg_a_s32 != std::numeric_limits<int32_t>::min() || reg_b_s32 != -1)
                self._set_reg(op.reg_3, reg_b_s32 != 0 ? static_cast<register_val_t>(reg_a_s32 % reg_b_s32) : reg_a_s32);
            else {
                self._set_reg(op.reg_3, 0);
            }
            return {};
        }

        static op_res_t shlo_l_32(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_3, code_t::sign_extend(4, static_cast<uint32_t>(self._regs[op.reg_1]) << (self._regs[op.reg_2] % 32U)));
            return {};
        }

        static op_res_t shlo_r_32(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_3, code_t::sign_extend(4, static_cast<uint32_t>(self._regs[op.reg_1]) >> static_cast<uint32_t>(self._regs[op.reg_2] % 32U)));
            return {};
        }

        static op_res_t shar_r_32(impl &self, const code_t::opcode_t &op)
        {
            const auto reg_a_s32 = static_cast<int32_t>(self._regs[op.reg_1]);
            const auto reg_b_s32 = static_cast<int32_t>(self._regs[op.reg_2] % 32U);
            self._set_reg(op.reg_3, code_t::sign_extend(4, reg_a_s32 >> reg_b_s32));
            return {};
        }

        static op_res_t add_64(impl &self, const code_t::opcode_t &op)
        {
            return _reg3_apply(self._regs, op, [](const register_val_t lhs, const register_val_t rhs) noexcept { return lhs + rhs; });
        }

        static op_res_t sub_64(impl &self, const code_t::opcode_t &op)
        {
            return _reg3_apply(self._regs, op, [](const register_val_t lhs, const register_val_t rhs) noexcept { return lhs - rhs; });
        }

        static op_res_t mul_64(impl &self, const code_t::opcode_t &op)
        {
            return _reg3_apply(self._regs, op, [](const register_val_t lhs, const register_val_t rhs) noexcept { return lhs * rhs; });
        }

        static op_res_t div_u_64(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_3, self._regs[op.reg_2] != 0 ? self._regs[op.reg_1] / self._regs[op.reg_2] : std::numeric_limits<uint64_t>::max());
            return {};
        }

        static op_res_t div_s_64(impl &self, const code_t::opcode_t &op)
        {
            const auto reg_a_s64 = static_cast<register_val_signed_t>(self._regs[op.reg_1]);
            const auto reg_b_s64 = static_cast<register_val_signed_t>(self._regs[op.reg_2]);
            if (self._regs[op.reg_2] != 0) {
                if (reg_a_s64 != std::numeric_limits<register_val_signed_t>::min() || reg_b_s64 != -1) {
                    self._set_reg(op.reg_3, static_cast<register_val_t>(reg_a_s64 / reg_b_s64));
                } else {
                    self._set_reg(op.reg_3, self._regs[op.reg_1]);
                }
            } else {
                self._set_reg(op.reg_3, std::numeric_limits<uint64_t>::max());
            }
            return {};
        }

        static op_res_t rem_u_64(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_3, self._regs[op.reg_2] != 0 ? self._regs[op.reg_1] % self._regs[op.reg_2] : self._regs[op.reg_1]);
            return {};
        }

        static op_res_t rem_s_64(impl &self, const code_t::opcode_t &op)
        {
            const auto reg_a_s64 = static_cast<register_val_signed_t>(self._regs[op.reg_1]);
            const auto reg_b_s64 = static_cast<register_val_signed_t>(self._regs[op.reg_2]);
            if (reg_a_s64 != std::numeric_limits<register_val_signed_t>::min() || reg_b_s64 != -1)
                self._set_reg(op.reg_3, reg_b_s64 != 0 ? static_cast<register_val_t>(reg_a_s64 % reg_b_s64) : reg_a_s64);
            else {
                self._set_reg(op.reg_3, 0);
            }
            return {};
        }

        static op_res_t shlo_l_64(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_3, self._regs[op.reg_1] << (self._regs[op.reg_2] % 64U));
            return {};
        }

        static op_res_t shlo_r_64(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_3, self._regs[op.reg_1] >> (self._regs[op.reg_2] % 64U));
            return {};
        }

        static op_res_t shar_r_64(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_3, static_cast<register_val_t>(static_cast<register_val_signed_t>(self._regs[op.reg_1]) >> (static_cast<register_val_signed_t>(self._regs[op.reg_2] % 64U))));
            return {};
        }

        static op_res_t and_(impl &self, const code_t::opcode_t &op)
        {
            return _reg3_apply(self._regs, op, [](const register_val_t lhs, const register_val_t rhs) noexcept { return lhs & rhs; });
        }

        static op_res_t xor_(impl &self, const code_t::opcode_t &op)
        {
            return _reg3_apply(self._regs, op, [](const register_val_t lhs, const register_val_t rhs) noexcept { return lhs ^ rhs; });
        }

        static op_res_t or_(impl &self, const code_t::opcode_t &op)
        {
            return _reg3_apply(self._regs, op, [](const register_val_t lhs, const register_val_t rhs) noexcept { return lhs | rhs; });
        }

        static op_res_t mul_upper_s_s(impl &self, const code_t::opcode_t &op)
        {
#if defined(_MSC_VER)
            _mul128(static_cast<register_val_signed_t>(self._regs[op.reg_1]), static_cast<register_val_signed_t>(self._regs[op.reg_2]), reinterpret_cast<register_val_signed_t *>(&self._regs[op.reg_3]));
#elif defined(__GNUC__) || defined(__clang__)
            auto sign_extend_u64_to_i128 = [](uint64_t x) -> int128_t {
                return (x & (1ULL << 63)) ? static_cast<int128_t>(x) - (int128_t(1) << 64) : static_cast<int128_t>(x);
            };

            int128_t lhs = sign_extend_u64_to_i128(self._regs[op.reg_1]);
            int128_t rhs = sign_extend_u64_to_i128(self._regs[op.reg_2]);
            int128_t product = lhs * rhs;

            self._set_reg(op.reg_3, static_cast<register_val_t>(product >> 64));
#else
#   error "MULH operation implemented only for Visual C++, GCC, and Clang compilers"
#endif
            return {};
        }

        static op_res_t mul_upper_u_u(impl &self, const code_t::opcode_t &op)
        {
#if defined(_MSC_VER)
            _umul128(self._regs[op.reg_1], self._regs[op.reg_2], &self._regs[op.reg_3]);
#elif defined(__GNUC__) || defined(__clang__)
            self._set_reg(op.reg_3, static_cast<register_val_t>((static_cast<uint128_t>(self._regs[op.reg_1]) * static_cast<uint128_t>(self._regs[op.reg_2])) >> 64U));
#else
#   error "MULH operation implemented only for Visual C++, GCC, and Clang compilers"
#endif
            return {};
        }

        static op_res_t mul_upper_s_u(impl &self, const code_t::opcode_t &op)
        {
            const auto reg_a_s64 = static_cast<register_val_signed_t>(self._regs[op.reg_1]);
            const bool reg_a_neg = reg_a_s64 < 0;
            const uint64_t reg_a_u64 = static_cast<uint64_t>(reg_a_neg ? -reg_a_s64 : reg_a_s64);
#if defined(_MSC_VER)            
            const uint64_t lo = _umul128(reg_a_u64, self._regs[op.reg_2], &self._regs[op.reg_3]);
#elif defined(__GNUC__) || defined(__clang__)
            const auto res = static_cast<int128_t>(reg_a_u64) * static_cast<uint128_t>(self._regs[op.reg_2]);
            const auto lo = static_cast<uint64_t>(res);
            self._set_reg(op.reg_3, res >> 64U);
#else
#   error "MULH operation implemented only for Visual C++, GCC, and Clang compilers"
#endif
            if (reg_a_neg) {
                self._set_reg(op.reg_3, ~self._regs[op.reg_3]);
                if (lo == 0) {
                    self._regs[op.reg_3] += 1;
                }
            }
            return {};
        }

        static op_res_t set_lt_u(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_3, self._regs[op.reg_1] < self._regs[op.reg_2]);
            return {};
        }

        static op_res_t set_lt_s(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_3, static_cast<register_val_signed_t>(self._regs[op.reg_1]) < static_cast<register_val_signed_t>(self._regs[op.reg_2]));
            return {};
        }

        static op_res_t cmov_iz(impl &self, const code_t::opcode_t &op)
        {
            if (self._regs[op.reg_2] == 0)
                self._set_reg(op.reg_3, self._regs[op.reg_1]);
            return {};
        }

        static op_res_t cmov_nz(impl &self, const code_t::opcode_t &op)
        {
            if (self._regs[op.reg_2] != 0)
                self._set_reg(op.reg_3, self._regs[op.reg_1]);
            return {};
        }

        static op_res_t rot_l_64(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_3, std::rotl(self._regs[op.reg_1], self._regs[op.reg_2]));
            return {};
        }

        static op_res_t rot_l_32(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_3, code_t::sign_extend(4, std::rotl(static_cast<uint32_t>(self._regs[op.reg_1]), static_cast<uint32_t>(self._regs[op.reg_2]))));
            return {};
        }

        static op_res_t rot_r_64(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_3, std::rotr(self._regs[op.reg_1], self._regs[op.reg_2]));
            return {};
        }

        static op_res_t rot_r_32(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_3, code_t::sign_extend(4, std::rotr(static_cast<uint32_t>(self._regs[op.reg_1]), static_cast<uint32_t>(self._regs[op.reg_2]))));
            return {};
        }

        static op_res_t and_inv(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_3, self._regs[op.reg_1] & (~self._regs[op.reg_2]));
            return {};
        }

        static op_res_t or_inv(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_3, self._regs[op.reg_1] | (~self._regs[op.reg_2]));
            return {};
        }

        static op_res_t xnor(impl &self, const code_t::opcode_t &op)
        {
            self._set_reg(op.reg_3, ~(self._regs[op.reg_1] ^ self._regs[op.reg_2]));
            return {};
        }

        static op_res_t max(impl &self, const code_t::opcode_t &op)
        {
            return _reg3_apply(self._regs, op, [](const register_val_t lhs, const register_val_t rhs) noexcept {
                return static_cast<register_val_t>(std::max(static_cast<register_val_signed_t>(lhs), static_cast<register_val_signed_t>(rhs)));
            });
        }

        static op_res_t max_u(impl &self, const code_t::opcode_t &op)
        {
            return _reg3_apply(self._regs, op, [](const register_val_t lhs, const register_val_t rhs) noexcept { return std::max(lhs, rhs); });
        }

        static op_res_t min(impl &self, const code_t::opcode_t &op)
        {
            return _reg3_apply(self._regs, op, [](const register_val_t lhs, const register_val_t rhs) noexcept {
                return static_cast<register_val_t>(std::min(static_cast<register_val_signed_t>(lhs), static_cast<register_val_signed_t>(rhs)));
            });
        }

        static op_res_t min_u(impl &self, const code_t::opcode_t &op)
        {
            return _reg3_apply(self._regs, op, [](const register_val_t lhs, const register_val_t rhs) noexcept { return std::min(lhs, rhs); });
        }
    };

    bool machine_t::is_opcode(const uint8_t op) {
        return impl::is_opcode(op);
    }

    machine_t::machine_t(code_t &&code, const state_t &init, const pages_t &page_map):
        _impl{std::make_unique<impl>(std::move(code), init, page_map)}
    {
    }

    machine_t::machine_t(machine_t &&o):
        _impl{std::move(o._impl)}
    {
    }

    machine_t::~machine_t()
    {
    }

    result_t machine_t::run()
    {
        return _impl->run();
    }

    void machine_t::consume_gas(const gas_t gas)
    {
        if (!_impl->consume_gas(gas)) [[unlikely]]
            throw exit_out_of_gas_t{};
    }

    void machine_t::set_gas(const gas_t gas)
    {
        _impl->set_gas(gas);
    }

    void machine_t::set_reg(const size_t id, const register_val_t val)
    {
        return _impl->set_reg(id, val);
    }

    void machine_t::set_regs(const registers_t &regs)
    {
        return _impl->set_regs(regs);
    }

    static std::optional<exit_page_fault_t> mem_range_ok(const register_val_t offset, const register_val_t sz) {
        if (sz > 0) {
            static constexpr register_val_t addr_max = std::numeric_limits<address_val_t>::max();
            const int offset_too_big = offset > addr_max;
            const int size_too_big = sz > addr_max;
            const auto end_offset = offset + sz;
            const int end_offset_overflow = end_offset < offset;
            const int end_offset_too_big = static_cast<int>(sz > 0) & static_cast<int>(end_offset - 1U > addr_max);
            if (offset_too_big | size_too_big | end_offset_overflow | end_offset_too_big) [[unlikely]]
                return exit_page_fault_t{addr_max};
        }
        return {};
    }

    bool machine_t::set_pages(const register_val_t p, const register_val_t sz, const page_init_method_t i) {
        static constexpr register_val_t addr_max = std::numeric_limits<address_val_t>::max();
        static constexpr address_val_t page_size = config_prod::ZP_pvm_page_size;
        if (p > addr_max / page_size) [[unlikely]]
            return false;
        if (sz > addr_max / page_size) [[unlikely]]
            return false;
        return _impl->set_pages(numeric_cast<address_val_t>(p), numeric_cast<address_val_t>(sz), i);
    }

    heap_bounds_t machine_t::heap_bounds() const
    {
        return _impl->heap_bounds();
    }

    bool machine_t::grow_heap(const register_val_t end_page)
    {
        return _impl->grow_heap(end_page);
    }

    void machine_t::skip_op()
    {
        return _impl->skip_op();
    }

    gas_remaining_t machine_t::gas() const
    {
        return const_cast<machine_t *>(this)->_impl->gas();
    }

    address_val_t machine_t::pc() const
    {
        return const_cast<machine_t *>(this)->_impl->pc();
    }

    const registers_t &machine_t::regs() const
    {
        return const_cast<machine_t *>(this)->_impl->regs();
    }

    std::optional<exit_page_fault_t> machine_t::mem_writable(const register_val_t offset, const register_val_t sz) const {
        if (auto err = mem_range_ok(offset, sz); err) [[unlikely]]
            return err;
        return const_cast<machine_t *>(this)->_impl->mem_writable(offset, sz);
    }

    std::optional<exit_page_fault_t> machine_t::mem_readable(const register_val_t offset, const register_val_t sz) const {
        if (auto err = mem_range_ok(offset, sz); err) [[unlikely]]
            return err;
        return const_cast<machine_t *>(this)->_impl->mem_readable(offset, sz);
    }

    void machine_t::mem_copy(const machine_t &src, const register_val_t dst_offset, const register_val_t src_offset, const register_val_t sz) {
        if (auto err = mem_range_ok(src_offset, sz); err) [[unlikely]]
            throw std::move(*err);
        if (auto err = mem_range_ok(dst_offset, sz); err) [[unlikely]]
            throw std::move(*err);
        return _impl->mem_copy(src, dst_offset, src_offset, sz);
    }

    void machine_t::mem_write(const register_val_t offset, const buffer data)
    {
        if (auto err = mem_range_ok(offset, data.size()); err) [[unlikely]]
            throw std::move(*err);
        _impl->mem_write(offset, data);
    }

    void machine_t::mem_initialize(const register_val_t offset, const buffer data)
    {
        if (auto err = mem_range_ok(offset, data.size()); err) [[unlikely]]
            throw std::move(*err);
        _impl->mem_write<false>(offset, data);
    }

    void machine_t::mem_read(const std::span<uint8_t> out, const register_val_t offset) const
    {
        if (auto err = mem_range_ok(offset, out.size()); err) [[unlikely]]
            throw std::move(*err);
        const_cast<machine_t *>(this)->_impl->mem_read(out, offset);
    }

    uint8_vector machine_t::mem_read(const register_val_t offset, const register_val_t sz) const
    {
        if (auto err = mem_range_ok(offset, sz); err) [[unlikely]]
            throw std::move(*err);
        return const_cast<machine_t *>(this)->_impl->mem_read(offset, sz);
    }

    std::optional<uint8_vector> machine_t::try_mem_read(const register_val_t offset, const register_val_t sz) const noexcept
    {
        if (auto err = mem_range_ok(offset, sz); err) [[unlikely]]
            return {};
        try {
            return mem_read(offset, sz);
        } catch (...) {
            return {};
        }
    }

    state_t machine_t::state() const
    {
        return const_cast<machine_t *>(this)->_impl->state();
    }

    const code_t &machine_t::code() const
    {
        return _impl->code();
    }

    std::optional<machine_t> configure(const buffer blob, const address_val_t pc, const gas_t gas, const buffer args, const size_t max_code_size)
    try {
        decoder dec{blob};
        // (9.4)
        const auto meta_size = dec.uint_varlen<size_t>();
        if (meta_size > blob.size() - dec.consumed()) [[unlikely]]
            return {};
        (void)dec.next_bytes(meta_size);
        if (blob.size() - dec.consumed() > max_code_size) [[unlikely]]
            return {};

        // (A.38)
        const auto o_sz = dec.uint_fixed<size_t>(3);
        const auto w_sz = dec.uint_fixed<size_t>(3);
        const auto z_sz = dec.uint_fixed<size_t>(2);
        const auto s_sz = dec.uint_fixed<size_t>(3);

        const auto o_bytes = dec.next_bytes(o_sz);
        const auto w_bytes = dec.next_bytes(w_sz);

        const auto c_sz = dec.uint_fixed<size_t>(4);
        const auto code = dec.next_bytes(c_sz);
        if (!dec.empty()) [[unlikely]]
            return {};
        auto prg = code_t::from_bytes(code);

        // JAM (A.41)
        const auto total_sz = 5 * config_prod::ZZ_pvm_init_zone_size
            + config_prod::pvm_z_size(o_sz) + config_prod::pvm_z_size(w_sz + z_sz * config_prod::ZP_pvm_page_size)
            + config_prod::pvm_z_size(s_sz) + config_prod::ZI_pvm_input_size;
        if (total_sz > 1ULL << 32U) [[unlikely]]
            return {};

        state_t state{
            .pc = pc,
            .gas = numeric_cast<gas_remaining_t>(gas)
        };
        pages_t page_map{};

        // JAM (A.42)
        struct area_def_t {
            size_t address;
            size_t size;
            bool is_writable = false;
            std::optional<buffer> data{};
        };

        for (const auto &def: std::initializer_list<area_def_t>{
            // read only data
            { config_prod::ZZ_pvm_init_zone_size, o_bytes.size(), false, o_bytes },
            // writable data
            { config_prod::ZZ_pvm_init_zone_size * 2 + config_prod::pvm_z_size(o_bytes.size()), w_bytes.size() + z_sz * config_prod::ZP_pvm_page_size, true, w_bytes },
            // stack
            { (1ULL << 32U) - 2 * config_prod::ZZ_pvm_init_zone_size - config_prod::ZI_pvm_input_size - config_prod::pvm_p_size(s_sz), s_sz, true },
            // arguments
            { (1ULL << 32U) - config_prod::ZZ_pvm_init_zone_size - config_prod::ZI_pvm_input_size, args.size(), false, args },
        }) {
            page_map.emplace_back(page_t{
                .address=numeric_cast<uint32_t>(def.address),
                .length=numeric_cast<uint32_t>(config_prod::pvm_p_size(def.size)),
                .is_writable=def.is_writable
            });
            if (def.data) {
                state.memory.emplace_back(memory_chunk_t{
                    .address=numeric_cast<uint32_t>(def.address),
                    .contents=*def.data
                });
            }
        }

        // JAM (A.43)
        state.regs[0] = (1ULL << 32U) - (1ULL << 16U);
        state.regs[1] = (1ULL << 32U) - 2U * config_prod::ZZ_pvm_init_zone_size - config_prod::ZI_pvm_input_size;
        state.regs[7] = (1ULL << 32U) - config_prod::ZZ_pvm_init_zone_size - config_prod::ZI_pvm_input_size;
        state.regs[8] = args.size();

        std::optional<machine_t> m {};
        m.emplace(std::move(prg), state, page_map);
        return m;
    } catch (const std::exception &) {
        return {};
    }
}
