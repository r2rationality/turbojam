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
        explicit impl(program_t &&program, const state_t &init, const pages_t &page_map):
            _pc{init.pc},
            _gas{init.gas},
            _regs{init.regs},
            _program{std::move(program)}
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
            for (const auto &mc: init.memory) {
                size_t i = 0;
                _mem_write_pages<false>(mc.address, mc.contents.size(), [&](uint8_t *dst_ptr, const size_t chunk) {
                    std::memcpy(dst_ptr, mc.contents.data() + i, chunk);
                    i += chunk;
                });
            }
            if (_stack_begin < config_prod::ZZ_pvm_init_zone_size) [[unlikely]]
                throw exit_panic_t{};
            _stack_begin = ((_stack_begin - config_prod::ZZ_pvm_init_zone_size) / config_prod::ZZ_pvm_init_zone_size) * config_prod::ZZ_pvm_init_zone_size;
        }

        impl(impl &&) = delete;

        // this must be re-entrant as it can be called again after a host call
        result_t run()
        {
            try {
                const auto &ops = _opcode_table();
                const buffer code_view = _program.code;
                for (;;) {
                    const uint8_t opcode = _pc < code_view.size() ? code_view[_pc] : 0x00U;
                    const auto len = _skip_len(_pc, _program.bitmasks);
                    const auto &op = ops[opcode];
                    if (!consume_gas(1U)) [[unlikely]]
                        return exit_out_of_gas_t{};
                    if (len < op.min_len()) [[unlikely]]
                        throw exit_panic_t{};
                    const auto data = _pc < code_view.size() ? buffer{code_view.data() + _pc + 1U, len} : buffer{};
                    const auto exec = op.exec();
                    const auto next_pc = _pc + len + 1;
                    if (!op.block_end()) [[likely]] {
                        exec(*this, data);
                        _pc = next_pc;
                        continue;
                    }
                    auto res = exec(*this, data);
                    switch (res.index()) {
                        case 0:
                            _pc = next_pc;
                            break;
                        case 1:
                            _pc = std::get<1>(res);
                            break;
                        case 2: {
                            return std::get<2>(std::move(res));
                        }
                        [[unlikely]] default:
                            throw error(fmt::format("unsupported op_res_t index: {}", res.index()));
                    }
                }
            } catch (exit_halt_t &ex) {
                //_pc = 0; GP 0.7.2 seem to require that but breaks the existing PVM test cases
                return {std::move(ex)};
            } catch (exit_page_fault_t &ex) {
                return {std::move(ex)};
            } catch (exit_out_of_gas_t &ex) {
                return {std::move(ex)};
            } catch (exit_host_call_t &ex) {
                return {std::move(ex)};
            } catch (...) { // exit_panic_t or anything else
                //_pc = 0; GP 0.7.2 seem to require that but breaks the existing PVM test cases
                return {exit_panic_t{}};
            }
        }

        void skip_op()
        {
            _pc += _skip_len(_pc, _program.bitmasks) + 1;
        }

        bool consume_gas(const gas_t gas)
        {
            if (gas > static_cast<gas_t::base_type>(_gas)) [[unlikely]] {
                _gas = 0;
                return false;
            }
            _gas -= static_cast<gas_t::base_type>(gas);
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

        [[nodiscard]] std::optional<exit_page_fault_t> mem_writable(const size_t offset, const size_t sz) const {
            return _mem_accessible(offset, sz, true);
        }

        [[nodiscard]] std::optional<exit_page_fault_t> mem_readable(const size_t offset, const size_t sz) const {
            return _mem_accessible(offset, sz, false);
        }

        void mem_copy(const machine_t &src, const size_t dst_offset, const size_t src_offset, const size_t sz) {
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

        void mem_read(std::span<uint8_t> res, const size_t offset) const
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

        uint8_vector mem_read(const size_t offset, const size_t sz) const
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

        void mem_write(const size_t offset, const buffer data)
        {
            size_t i = 0;
            _mem_write_pages(offset, data.size(), [&](uint8_t *dst_ptr, const size_t chunk) {
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

        typedef uint8_t register_idx_t;

        struct page_dir_t {
            static constexpr size_t l2_bits = 10;
            static constexpr size_t l1_size = 1 << l2_bits;  // 1024
            static constexpr size_t l2_size = 1 << l2_bits;  // 1024
            using l2_table_t = std::array<page_info_t, l2_size>;

            std::array<std::unique_ptr<l2_table_t>, l1_size> l1{};

            [[nodiscard]] const page_info_t *lookup(const uint32_t page_id) const noexcept
            {
                const auto &l2 = l1[page_id >> l2_bits];
                if (!l2) [[unlikely]]
                    return nullptr;
                const auto &info = (*l2)[page_id & (l2_size - 1)];
                if (!info.exists())
                    return nullptr;
                return &info;
            }

            page_info_t *lookup_mut(const uint32_t page_id) noexcept
            {
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
        uint32_t _pc{};
        address_val_t _heap_end = 0;
        gas_remaining_t _gas = 0;
        registers_t _regs{};
        mutable tlb_entry_t _last_page{};
        mutable std::array<tlb_entry_t, tlb_size> _tlb{};
        // Warm fields - accessed on memory operations / page faults
        page_dir_t _page_dir{};
        page_pool_t _page_pool{};
        address_val_t _stack_begin = 0;
        // Cold fields - rarely accessed after construction
        program_t _program;

        using op_res_t = std::variant<std::monostate, register_val_t, result_t>;
        using op_exec_t = op_res_t(*)(impl &, buffer);
        static_assert(sizeof(op_exec_t) == sizeof(uintptr_t), "opcode dispatch pointer must fit in exactly one uintptr_t");

        struct opcode_t
        {
            static constexpr uintptr_t packed_bits = sizeof(uintptr_t) * 8U;
            static constexpr uintptr_t block_end_shift = packed_bits - 1U;
            static constexpr uintptr_t min_len_shift = packed_bits - 3U;
            static constexpr uintptr_t block_end_mask = uintptr_t{1} << block_end_shift;
            static constexpr uint8_t max_min_len = 2U;
            static constexpr uintptr_t min_len_value_mask = 0x3U;
            static constexpr uintptr_t min_len_mask = min_len_value_mask << min_len_shift;
            static constexpr uintptr_t flags_mask = block_end_mask | min_len_mask;

            uintptr_t packed = 0;

            constexpr opcode_t() noexcept = default;

            opcode_t(const op_exec_t e, const bool block_end_ = false, const uint8_t min_len_ = 0U):
                packed(_pack_checked(e, min_len_, block_end_))
            {
            }

            [[nodiscard]] static constexpr uintptr_t _pack_raw(const uintptr_t exec_bits, const uint8_t min_len, const bool block_end) noexcept
            {
                return exec_bits
                    | (static_cast<uintptr_t>(min_len) << min_len_shift)
                    | (block_end ? block_end_mask : 0U);
            }

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

            [[nodiscard]] static uintptr_t _pack_checked(const op_exec_t exec, const uint8_t min_len, const bool block_end)
            {
                const auto raw = _exec_bits_checked(exec);
                if ((raw & flags_mask) != 0U) [[unlikely]]
                    throw error(fmt::format("opcode exec pointer {:x} overlaps packed flag bits {:x}", raw, flags_mask));
                if (min_len > max_min_len) [[unlikely]]
                    throw error(fmt::format("opcode min_len {} exceeds packed max {}", min_len, max_min_len));
                return _pack_raw(raw, min_len, block_end);
            }

            [[nodiscard]] op_exec_t exec() const noexcept
            {
                return _exec_from_bits(packed & ~flags_mask);
            }

            [[nodiscard]] constexpr uint8_t min_len() const noexcept
            {
                return static_cast<uint8_t>((packed & min_len_mask) >> min_len_shift);
            }

            [[nodiscard]] constexpr bool block_end() const noexcept
            {
                return (packed & block_end_mask) != 0;
            }
        };

        static size_t _skip_len(const register_val_t opcode_pc, const bit_vector_t &bitmasks)
        {
            return bitmasks.count_zeros(static_cast<size_t>(opcode_pc) + 1U, 24U);
        }

        static const std::array<opcode_t, 0x100> &_opcode_table()
        {
            static const auto ops = [] {
                const opcode_t undef{&impl::trap};
                std::array<opcode_t, 0x100> res {
                    // 0x00
                    opcode_t{&impl::trap, true},
                    opcode_t{&impl::fallthrough, true},
                    undef, undef,
                    undef, undef, undef, undef,
                    // 0x08
                    undef, undef,
                    opcode_t{&impl::ecalli, true},
                    undef,
                    undef, undef, undef, undef,
                    // 0x10
                    undef, undef, undef, undef,
                    opcode_t{&impl::load_imm_64, false, 1U},
                    undef, undef, undef,
                    // 0x18
                    undef, undef, undef, undef,
                    undef, undef,
                    opcode_t{&impl::store_imm_u8, false, 1U},
                    opcode_t{&impl::store_imm_u16, false, 1U},
                    // 0x20
                    opcode_t{&impl::store_imm_u32, false, 1U},
                    opcode_t{&impl::store_imm_u64, false, 1U},
                    undef, undef,
                    undef, undef, undef, undef,
                    // 0x28
                    opcode_t{&impl::jump, true},
                    undef, undef, undef,
                    undef, undef, undef, undef,
                    // 0x30
                    undef, undef,
                    opcode_t{&impl::jump_ind, true, 1U},
                    opcode_t{&impl::load_imm, false, 1U},
                    opcode_t{&impl::load_u8, false, 1U},
                    opcode_t{&impl::load_i8, false, 1U},
                    opcode_t{&impl::load_u16, false, 1U},
                    opcode_t{&impl::load_i16, false, 1U},
                    // 0x38
                    opcode_t{&impl::load_u32, false, 1U},
                    opcode_t{&impl::load_i32, false, 1U},
                    opcode_t{&impl::load_u64, false, 1U},
                    opcode_t{&impl::store_u8, false, 1U},
                    opcode_t{&impl::store_u16, false, 1U},
                    opcode_t{&impl::store_u32, false, 1U},
                    opcode_t{&impl::store_u64, false, 1U},
                    undef,
                    // 0x40
                    undef, undef, undef, undef,
                    undef, undef,
                    opcode_t{&impl::store_imm_ind_u8, false, 1U},
                    opcode_t{&impl::store_imm_ind_u16, false, 1U},
                    // 0x48
                    opcode_t{&impl::store_imm_ind_u32, false, 1U},
                    opcode_t{&impl::store_imm_ind_u64, false, 1U},
                    undef, undef,
                    undef, undef, undef, undef,
                    // 0x50
                    opcode_t{&impl::load_imm_jump, true, 1U},
                    opcode_t{&impl::branch_eq_imm, true, 1U},
                    opcode_t{&impl::branch_ne_imm, true, 1U},
                    opcode_t{&impl::branch_lt_u_imm, true, 1U},
                    opcode_t{&impl::branch_le_u_imm, true, 1U},
                    opcode_t{&impl::branch_ge_u_imm, true, 1U},
                    opcode_t{&impl::branch_gt_u_imm, true, 1U},
                    opcode_t{&impl::branch_lt_s_imm, true, 1U},
                    //0x58
                    opcode_t{&impl::branch_le_s_imm, true, 1U},
                    opcode_t{&impl::branch_ge_s_imm, true, 1U},
                    opcode_t{&impl::branch_gt_s_imm, true, 1U},
                    undef,
                    undef, undef, undef, undef,
                    // 0x60
                    undef, undef, undef, undef,
                    opcode_t{&impl::move_reg, false, 1U},
                    opcode_t{&impl::sbrk, false, 1U},
                    opcode_t{&impl::count_set_bits_64, false, 1U},
                    opcode_t{&impl::count_set_bits_32, false, 1U},
                    // 0x68
                    opcode_t{&impl::leading_zero_bits_64, false, 1U},
                    opcode_t{&impl::leading_zero_bits_32, false, 1U},
                    opcode_t{&impl::trailing_zero_bits_64, false, 1U},
                    opcode_t{&impl::trailing_zero_bits_32, false, 1U},
                    opcode_t{&impl::sign_extend_8, false, 1U},
                    opcode_t{&impl::sign_extend_16, false, 1U},
                    opcode_t{&impl::zero_extend_16, false, 1U},
                    opcode_t{&impl::reverse_bytes, false, 1U},
                    // 0x70
                    undef, undef, undef, undef,
                    undef, undef, undef, undef,
                    // 0x78
                    opcode_t{&impl::store_ind_u8, false, 1U},
                    opcode_t{&impl::store_ind_u16, false, 1U},
                    opcode_t{&impl::store_ind_u32, false, 1U},
                    opcode_t{&impl::store_ind_u64, false, 1U},
                    opcode_t{&impl::load_ind_u8, false, 1U},
                    opcode_t{&impl::load_ind_i8, false, 1U},
                    opcode_t{&impl::load_ind_u16, false, 1U},
                    opcode_t{&impl::load_ind_i16, false, 1U},
                    // 0x80
                    opcode_t{&impl::load_ind_u32, false, 1U},
                    opcode_t{&impl::load_ind_i32, false, 1U},
                    opcode_t{&impl::load_ind_u64, false, 1U},
                    opcode_t{&impl::add_imm_32, false, 1U},
                    opcode_t{&impl::and_imm, false, 1U},
                    opcode_t{&impl::xor_imm, false, 1U},
                    opcode_t{&impl::or_imm, false, 1U},
                    opcode_t{&impl::mul_imm_32, false, 1U},
                    // 0x88
                    opcode_t{&impl::set_lt_u_imm, false, 1U},
                    opcode_t{&impl::set_lt_s_imm, false, 1U},
                    opcode_t{&impl::shlo_l_imm_32, false, 1U},
                    opcode_t{&impl::shlo_r_imm_32, false, 1U},
                    opcode_t{&impl::shar_r_imm_32, false, 1U},
                    opcode_t{&impl::neg_add_imm_32, false, 1U},
                    opcode_t{&impl::set_gt_u_imm, false, 1U},
                    opcode_t{&impl::set_gt_s_imm, false, 1U},
                    // 0x90
                    opcode_t{&impl::shlo_l_imm_alt_32, false, 1U},
                    opcode_t{&impl::shlo_r_imm_alt_32, false, 1U},
                    opcode_t{&impl::shar_r_imm_alt_32, false, 1U},
                    opcode_t{&impl::cmov_iz_imm, false, 1U},
                    opcode_t{&impl::cmov_nz_imm, false, 1U},
                    opcode_t{&impl::add_imm_64, false, 1U},
                    opcode_t{&impl::mul_imm_64, false, 1U},
                    opcode_t{&impl::shlo_l_imm_64, false, 1U},
                    // 0x98
                    opcode_t{&impl::shlo_r_imm_64, false, 1U},
                    opcode_t{&impl::shar_r_imm_64, false, 1U},
                    opcode_t{&impl::neg_add_imm_64, false, 1U},
                    opcode_t{&impl::shlo_l_imm_alt_64, false, 1U},
                    opcode_t{&impl::shlo_r_imm_alt_64, false, 1U},
                    opcode_t{&impl::shar_r_imm_alt_64, false, 1U},
                    opcode_t{&impl::rot_r_64_imm, false, 1U},
                    opcode_t{&impl::rot_r_64_imm_alt, false, 1U},
                    // 0xA0
                    opcode_t{&impl::rot_r_32_imm, false, 1U},
                    opcode_t{&impl::rot_r_32_imm_alt, false, 1U},
                    undef, undef,
                    undef, undef, undef, undef,
                    // 0xA8
                    undef, undef,
                    opcode_t{&impl::branch_eq, true, 1U},
                    opcode_t{&impl::branch_ne, true, 1U},
                    opcode_t{&impl::branch_lt_u, true, 1U},
                    opcode_t{&impl::branch_lt_s, true, 1U},
                    opcode_t{&impl::branch_ge_u, true, 1U},
                    opcode_t{&impl::branch_ge_s, true, 1U},
                    // 0xB0
                    undef, undef, undef, undef,
                    opcode_t{&impl::load_imm_jump_ind, true, 2U},
                    undef, undef, undef,
                    // 0xB8
                    undef, undef, undef, undef,
                    undef, undef,
                    opcode_t{&impl::add_32, false, 2U},
                    opcode_t{&impl::sub_32, false, 2U},
                    // 0xC0
                    opcode_t{&impl::mul_32, false, 2U},
                    opcode_t{&impl::div_u_32, false, 2U},
                    opcode_t{&impl::div_s_32, false, 2U},
                    opcode_t{&impl::rem_u_32, false, 2U},
                    opcode_t{&impl::rem_s_32, false, 2U},
                    opcode_t{&impl::shlo_l_32, false, 2U},
                    opcode_t{&impl::shlo_r_32, false, 2U},
                    opcode_t{&impl::shar_r_32, false, 2U},
                    // 0xC8
                    opcode_t{&impl::add_64, false, 2U},
                    opcode_t{&impl::sub_64, false, 2U},
                    opcode_t{&impl::mul_64, false, 2U},
                    opcode_t{&impl::div_u_64, false, 2U},
                    opcode_t{&impl::div_s_64, false, 2U},
                    opcode_t{&impl::rem_u_64, false, 2U},
                    opcode_t{&impl::rem_s_64, false, 2U},
                    opcode_t{&impl::shlo_l_64, false, 2U},
                    // 0xD0
                    opcode_t{&impl::shlo_r_64, false, 2U},
                    opcode_t{&impl::shar_r_64, false, 2U},
                    opcode_t{&impl::and_, false, 2U},
                    opcode_t{&impl::xor_, false, 2U},
                    opcode_t{&impl::or_, false, 2U},
                    opcode_t{&impl::mul_upper_s_s, false, 2U},
                    opcode_t{&impl::mul_upper_u_u, false, 2U},
                    opcode_t{&impl::mul_upper_s_u, false, 2U},
                    // 0xD8
                    opcode_t{&impl::set_lt_u, false, 2U},
                    opcode_t{&impl::set_lt_s, false, 2U},
                    opcode_t{&impl::cmov_iz, false, 2U},
                    opcode_t{&impl::cmov_nz, false, 2U},
                    opcode_t{&impl::rot_l_64, false, 2U},
                    opcode_t{&impl::rot_l_32, false, 2U},
                    opcode_t{&impl::rot_r_64, false, 2U},
                    opcode_t{&impl::rot_r_32, false, 2U},
                    // 0xE0
                    opcode_t{&impl::and_inv, false, 2U},
                    opcode_t{&impl::or_inv, false, 2U},
                    opcode_t{&impl::xnor, false, 2U},
                    opcode_t{&impl::max, false, 2U},
                    opcode_t{&impl::max_u, false, 2U},
                    opcode_t{&impl::min, false, 2U},
                    opcode_t{&impl::min_u, false, 2U},
                    undef,
                    // 0xE8
                    undef, undef, undef, undef,
                    undef, undef, undef, undef,
                    // 0xF0
                    undef, undef, undef, undef,
                    undef, undef, undef, undef,
                    // 0xF8
                    undef, undef, undef, undef,
                    undef, undef, undef, undef,
                };
                return res;
            }();
            return ops;
        }

        //
        template<typename F>
        void _mem_read_pages(const size_t offset, const size_t sz, F &&consume) const
        {
            const auto ex = _mem_walk_pages(
                offset, sz,
                [&](const size_t, const size_t, const size_t page_off, const size_t chunk, const page_info_t &page) -> std::optional<exit_page_fault_t> {
                    consume(page.is_materialized() ? page.data() + page_off : nullptr, chunk);
                    return {};
                }
            );
            if (ex) [[unlikely]]
                throw *ex;
        }

        template<bool respect_writable = true, typename F>
        void _mem_write_pages(const size_t offset, const size_t sz, F &&consume)
        {
            const auto ex = _mem_walk_pages(
                offset, sz,
                [&](const size_t p, const size_t page_id, const size_t page_off, const size_t chunk, const page_info_t &page) -> std::optional<exit_page_fault_t> {
                    auto &mut_page = const_cast<page_info_t &>(page);
                    if constexpr (respect_writable) {
                        if (!mut_page.is_writable()) [[unlikely]]
                            return exit_page_fault_t{p};
                    }
                    _materialize_page(page_id, mut_page);
                    consume(mut_page.data() + page_off, chunk);
                    return {};
                }
            );
            if (ex) [[unlikely]]
                throw *ex;
        }

        // opcode helper functions

        void _set_reg(const register_idx_t idx, const register_val_t val)
        {
            _regs[idx] = val;
        }

        static void _ensure_readable(const buffer data, const size_t off, const size_t num_bytes)
        {
            if (num_bytes == 0)
                return;
            if (off > data.size() || num_bytes > data.size() - off) [[unlikely]]
                throw error(fmt::format("requested offset: {} and size: {} end over the end of buffer's size: {}!", off, num_bytes, data.size()));
        }

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

        static std::tuple<register_idx_t, register_idx_t> _args_reg2(const buffer data)
        {
            const auto *ptr = data.data();
            const auto b0 = ptr[0];
            const register_idx_t r_d = std::min(12ULL, b0 & 0xFULL);
            const register_idx_t r_a = std::min(12ULL, b0 / 16ULL);
            return std::make_tuple(r_d, r_a);
        }

        static std::tuple<register_idx_t, register_idx_t, register_idx_t> _args_reg3(const buffer data)
        {
            const auto *ptr = data.data();
            const auto b0 = ptr[0];
            const auto b1 = ptr[1];
            const register_idx_t r_a = std::min(12ULL, b0 & 0xFULL);
            const register_idx_t r_b = std::min(12ULL, b0 / 16ULL);
            const register_idx_t r_d = std::min(12ULL, b1 & 0xFULL);
            return std::make_tuple(r_a, r_b, r_d);
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

        static std::tuple<register_idx_t, register_idx_t, register_val_t, register_val_t> _args_reg2_imm2(const buffer data)
        {
            const auto *ptr = data.data();
            const auto b0 = ptr[0];
            const auto b1 = ptr[1];
            const register_idx_t r_a = std::min(12ULL, b0 & 0xFULL);
            const register_idx_t r_b = std::min(12ULL, b0 / 16ULL);
            const size_t l_x = std::min(4ULL, b1 % 8ULL);
            _ensure_readable(data, 2U, l_x);
            const size_t base_y = 2U + l_x;
            const size_t l_y = data.size() > base_y ? std::min(size_t{4}, data.size() - base_y) : 0U;
            const auto nu_x = _read_signed_imm32_unchecked(ptr + 2U, l_x);
            const auto nu_y = _read_signed_imm32_unchecked(ptr + base_y, l_y);
            return std::make_tuple(r_a, r_b, nu_x, nu_y);
        }

        static std::tuple<register_idx_t, register_idx_t, register_val_t> _args_reg2_off1(const register_val_t pc, const buffer data)
        {
            const auto [r_a, r_b, nu_x] = _args_reg2_imm1(data);
            const auto new_pc = static_cast<register_val_t>(static_cast<register_val_signed_t>(pc) + static_cast<register_val_signed_t>(nu_x));
            return std::make_tuple(r_a, r_b, new_pc);
        }

        static std::tuple<register_idx_t, register_val_t> _args_reg1_imm1(const buffer data, const size_t max_size)
        {
            const auto *ptr = data.data();
            const auto b0 = ptr[0];
            const register_idx_t r_a = std::min(12ULL, b0 & 0xFULL);
            const size_t l_x = std::min(max_size, data.size() - 1U);
            const auto nu_x = max_size <= 4U
                ? _read_signed_imm32_unchecked(ptr + 1U, l_x)
                : sign_extend(l_x, _read_uint_le_unchecked(ptr + 1U, l_x));
            return std::make_tuple(r_a, nu_x);
        }

        static std::tuple<register_idx_t, register_val_t> _args_reg1_imm1_unsigned(const buffer data, const size_t max_size)
        {
            const auto *ptr = data.data();
            const auto b0 = ptr[0];
            const register_idx_t r_a = std::min(12ULL, b0 & 0xFULL);
            const size_t l_x = std::min(max_size, data.size() - 1U);
            const auto nu_x = max_size <= 4U
                ? _read_uint32_le_unchecked(ptr + 1U, l_x)
                : _read_uint_le_unchecked(ptr + 1U, l_x);
            return std::make_tuple(r_a, nu_x);
        }

        static std::tuple<register_idx_t, register_val_t> _args_reg1_imm1_s32(const buffer data)
        {
            return _args_reg1_imm1(data, 4ULL);
        }

        static std::tuple<register_idx_t, register_val_t> _args_reg1_imm1_s64(const buffer data)
        {
            return _args_reg1_imm1(data, 8ULL);
        }

        static std::tuple<register_idx_t, register_val_t> _args_reg1_imm1_u64(const buffer data)
        {
            return _args_reg1_imm1_unsigned(data, 8ULL);
        }

        static std::tuple<register_idx_t, register_val_t, register_val_t> _args_reg1_imm2(const buffer data)
        {
            const auto *ptr = data.data();
            const auto b0 = ptr[0];
            const register_idx_t r_a = std::min(12ULL, b0 & 0xFULL);
            const size_t l_x = std::min(4ULL, (b0 / 16ULL) % 8ULL);
            _ensure_readable(data, 1U, l_x);
            const size_t base_y = 1U + l_x;
            const size_t l_y = data.size() > base_y ? std::min(size_t{4}, data.size() - base_y) : 0U;
            const auto nu_x = _read_signed_imm32_unchecked(ptr + 1U, l_x);
            const auto nu_y = _read_signed_imm32_unchecked(ptr + base_y, l_y);
            return std::make_tuple(r_a, nu_x, nu_y);
        }

        static std::tuple<register_idx_t, register_val_t, register_val_t> _args_reg1_imm1_off1(const register_val_t pc, const buffer data)
        {
            const auto *ptr = data.data();
            const auto b0 = ptr[0];
            const register_idx_t r_a = std::min(12ULL, b0 & 0xFULL);
            const size_t l_x = std::min(4ULL, (b0 / 16ULL) % 8ULL);
            _ensure_readable(data, 1U, l_x);
            const size_t base_y = 1U + l_x;
            const size_t l_y = data.size() > base_y ? std::min(size_t{4}, data.size() - base_y) : 0U;
            const auto nu_x = _read_signed_imm32_unchecked(ptr + 1U, l_x);
            const auto nu_y_pre = _read_signed_imm32_unchecked(ptr + base_y, l_y);
            const auto nu_y = static_cast<register_val_t>(static_cast<register_val_signed_t>(pc) + static_cast<register_val_signed_t>(nu_y_pre));
            return std::make_tuple(r_a, nu_x, nu_y);
        }

        static std::tuple<register_val_t> _args_imm1(const buffer data)
        {
            const size_t l_x = std::min(size_t{4}, data.size());
            return _read_signed_imm32_unchecked(data.data(), l_x);
        }

        static std::tuple<register_val_t, register_val_t> _args_imm2(const buffer data)
        {
            const auto *ptr = data.data();
            const size_t l_x = std::min(4ULL, ptr[0] % 8ULL);
            _ensure_readable(data, 1U, l_x);
            const size_t base_y = 1U + l_x;
            const size_t l_y = data.size() > base_y ? std::min(size_t{4}, data.size() - base_y) : 0U;
            const auto nu_x = _read_signed_imm32_unchecked(ptr + 1U, l_x);
            const auto nu_y = _read_signed_imm32_unchecked(ptr + base_y, l_y);
            return std::make_tuple(nu_x, nu_y);
        }

        static std::tuple<register_val_t> _args_off1(const register_val_t pc, const buffer data)
        {
            const size_t l_x = std::min(size_t{4}, data.size());
            const auto nu_x_pre = _read_signed_imm32_unchecked(data.data(), l_x);
            const auto nu_x = static_cast<register_val_t>(static_cast<register_val_signed_t>(pc) + static_cast<register_val_signed_t>(nu_x_pre));
            return std::make_tuple(nu_x);
        }

        static std::tuple<> _args_none(const buffer)
        {
            return {};
        }

        static op_res_t djump(const program_t &program, const register_val_t addr)
        {
            if (addr == (1ULL << 32ULL) - (1ULL << 16ULL)) [[unlikely]]
                return exit_halt_t{};
            if (addr == 0) [[unlikely]]
                return exit_panic_t{};
            if (addr > program.jump_table.size() * config_prod::ZA_pvm_address_alignment_factor) [[unlikely]]
                return exit_panic_t{};
            if (addr % config_prod::ZA_pvm_address_alignment_factor != 0) [[unlikely]]
                return exit_panic_t{};
            const auto ji = addr / config_prod::ZA_pvm_address_alignment_factor;
            const auto new_pc = program.jump_table.at(ji - 1);
            if (!program.bitmasks.test(new_pc)) [[unlikely]]
                return exit_panic_t{};
                return {new_pc};
        }

        static op_res_t branch_base(const program_t &program, const register_val_t new_pc, const bool cond)
        {
            if (cond) {
                if (new_pc >= program.code.size()) [[unlikely]]
                    return exit_panic_t{};
                if (!program.bitmasks.test_unchecked(new_pc)) [[unlikely]]
                    return exit_panic_t{};
                return {new_pc};
            }
            return {};
        }

        void _add_pages(const size_t start_page, const size_t end_page, const bool is_writable)
        {
            const auto next = page_info_t::lazy_zero(is_writable);
            for (size_t page_id = start_page; page_id < end_page; ++page_id) {
                _insert_page(static_cast<address_val_t>(page_id), next);
            }
        }

        void _invalidate_page_cache(const address_val_t page_id) const noexcept
        {
            if (_last_page.page_id == page_id)
                _last_page.reset();
            if (auto &slot = _tlb[page_id & (tlb_size - 1)]; slot.page_id == page_id)
                slot.reset();
        }

        const page_info_t *_page_lookup(const register_val_t page_id) const noexcept
        {
            if (page_id != _last_page.page_id) {
                auto &tlb_slot = _tlb[page_id & (tlb_size - 1)];
                if (tlb_slot.page_id != page_id) {
                    const auto *info = _page_dir.lookup(static_cast<uint32_t>(page_id));
                    if (!info) [[unlikely]]
                        return nullptr;
                    tlb_slot.set(page_id, info);
                }
                _last_page.set(page_id, tlb_slot.info);
            }
            return _last_page.info;
        }

        page_info_t *_page_lookup_mut(const register_val_t page_id) noexcept
        {
            return const_cast<page_info_t *>(_page_lookup(page_id));
        }

        void _materialize_page(const register_val_t, page_info_t &page)
        {
            if (page.is_materialized())
                return;
            auto *mem_page = _page_pool.allocate();
            std::memset(mem_page, 0, sizeof(*mem_page));
            page = page_info_t{mem_page, page.is_writable()};
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
        std::optional<exit_page_fault_t> _mem_walk_pages(const size_t offset, const size_t sz, F &&consume) const
        {
            size_t p = offset, remaining = sz;
            while (remaining > 0) {
                const auto page_id = p / config_prod::ZP_pvm_page_size;
                const auto page_off = p % config_prod::ZP_pvm_page_size;
                const auto *page = _page_lookup(page_id);
                if (!page) [[unlikely]]
                    return exit_page_fault_t{p};
                const auto chunk = std::min(remaining, config_prod::ZP_pvm_page_size - page_off);
                if (const auto ex = consume(p, page_id, page_off, chunk, *page); ex) [[unlikely]]
                    return ex;
                p += chunk;
                remaining -= chunk;
            }
            return {};
        }

        [[nodiscard]] std::optional<exit_page_fault_t> _mem_accessible(const size_t offset, const size_t sz, const bool require_writable) const
        {
            return _mem_walk_pages(offset, sz, [&](const size_t p, const size_t, const size_t, const size_t, const page_info_t &page) -> std::optional<exit_page_fault_t> {
                if (require_writable && !page.is_writable()) [[unlikely]]
                    return exit_page_fault_t{p};
                return {};
            });
        }

        template<size_t SZ>
        std::pair<size_t, const page_info_t *> _addr_check(const register_val_t addr) const
        {
            static constexpr register_val_t page_size  = config_prod::ZP_pvm_page_size;
            static constexpr register_val_t page_mask  = page_size - 1;
            static constexpr unsigned page_shift = std::countr_zero(page_size);
            static_assert((page_size & page_mask) == 0, "page size must be power of two");
            /* GP 0.7.2 seems to require that but not yet supported by the current PVM test cases
            const auto addr = static_cast<address_val_t>(addr_raw);
            if (addr < config_prod::ZZ_pvm_init_zone_size) [[unlikely]]
                throw exit_panic_t{};*/
            const auto page_off = addr & page_mask;
            const auto page_id  = addr >> page_shift;
            if (page_off > page_mask - (SZ - 1)) [[unlikely]]
                throw exit_page_fault_t{(addr & ~page_mask) + page_size};
            const auto *page = _page_lookup(page_id);
            if (!page) [[unlikely]]
                throw exit_page_fault_t{page_id * config_prod::ZP_pvm_page_size};
            return {page_off, page};
        }

        template<size_t SZ>
        register_val_t _load_unsigned(const register_val_t addr) const
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
        register_val_t _load_signed(const register_val_t addr)
        {
            return sign_extend(SZ, _load_unsigned<SZ>(addr));
        }

        template<typename T>
        void _store_unsigned(const register_val_t addr, const T val)
        {
            static constexpr register_val_t page_size  = config_prod::ZP_pvm_page_size;
            static constexpr register_val_t page_mask  = page_size - 1;
            static constexpr unsigned page_shift = std::countr_zero(page_size);
            const auto page_off = addr & page_mask;
            const auto page_id  = addr >> page_shift;
            if (page_off > page_mask - (sizeof(T) - 1)) [[unlikely]]
                throw exit_page_fault_t{(addr & ~page_mask) + page_size};
            auto *page = _page_lookup_mut(page_id);
            if (!page) [[unlikely]]
                throw exit_page_fault_t{page_id * config_prod::ZP_pvm_page_size};
            if (!page->is_writable()) [[unlikely]]
                throw exit_page_fault_t{addr};
            _materialize_page(page_id, *page);
            *reinterpret_cast<T*>(page->data() + page_off) = val;
        }

        template<typename Pred>
        static op_res_t _branch_reg2_off1(const program_t &program, const register_val_t pc, const registers_t &regs, const buffer data, Pred &&pred)
        {
            const auto [r_a, r_b, new_pc] = _args_reg2_off1(pc, data);
            return branch_base(program, new_pc, pred(regs[r_a], regs[r_b]));
        }

        template<typename Pred>
        static op_res_t _branch_reg1_imm1_off1(const program_t &program, const register_val_t pc, const registers_t &regs, const buffer data, Pred &&pred)
        {
            const auto [r_a, nu_x, new_pc] = _args_reg1_imm1_off1(pc, data);
            return branch_base(program, new_pc, pred(regs[r_a], nu_x));
        }

        template<size_t SZ, bool Signed>
        static op_res_t _load_direct(impl &self, registers_t &regs, const buffer data)
        {
            const auto [r_a, addr] = _args_reg1_imm1_s32(data);
            if constexpr (Signed)
                regs[r_a] = self._load_signed<SZ>(addr);
            else
                regs[r_a] = self._load_unsigned<SZ>(addr);
            return {};
        }

        template<typename T>
        static op_res_t _store_direct(impl &self, const registers_t &regs, const buffer data)
        {
            const auto [r_a, addr] = _args_reg1_imm1_s32(data);
            self._store_unsigned(addr, static_cast<T>(regs[r_a]));
            return {};
        }

        template<typename T>
        static op_res_t _store_imm_indirect(impl &self, const registers_t &regs, const buffer data)
        {
            const auto [r_a, nu_x, nu_y] = _args_reg1_imm2(data);
            self._store_unsigned(regs[r_a] + nu_x, static_cast<T>(nu_y));
            return {};
        }

        template<typename T>
        static op_res_t _store_indirect(impl &self, const registers_t &regs, const buffer data)
        {
            const auto [r_a, r_b, nu_x] = _args_reg2_imm1(data);
            self._store_unsigned(regs[r_b] + nu_x, static_cast<T>(regs[r_a]));
            return {};
        }

        template<size_t SZ, bool Signed>
        static op_res_t _load_indirect(impl &self, registers_t &regs, const buffer data)
        {
            const auto [r_a, r_b, nu_x] = _args_reg2_imm1(data);
            const auto addr = regs[r_b] + nu_x;
            if constexpr (Signed)
                regs[r_a] = self._load_signed<SZ>(addr);
            else
                regs[r_a] = self._load_unsigned<SZ>(addr);
            return {};
        }

        template<typename Op>
        static op_res_t _reg3_apply(registers_t &regs, const buffer data, Op &&op)
        {
            const auto [r_a, r_b, r_d] = _args_reg3(data);
            regs[r_d] = op(regs[r_a], regs[r_b]);
            return {};
        }

        // opcode implementations

        static op_res_t trap(impl &, const buffer)
        {
            return exit_panic_t{};
        }

        static op_res_t fallthrough(impl &, const buffer)
        {
            // do nothing
            return {};
        }

        static op_res_t ecalli(impl &self, const buffer data)
        {
            const auto [nu_x] = self._args_imm1(data);
            return exit_host_call_t{nu_x};
        }

        static op_res_t store_imm_u8(impl &self, const buffer data)
        {
            const auto [nu_x, nu_y] = self._args_imm2(data);
            self._store_unsigned(nu_x, static_cast<uint8_t>(nu_y));
            return {};
        }

        static op_res_t store_imm_u16(impl &self, const buffer data)
        {
            const auto [nu_x, nu_y] = self._args_imm2(data);
            self._store_unsigned(nu_x, static_cast<uint16_t>(nu_y));
            return {};
        }

        static op_res_t store_imm_u32(impl &self, const buffer data)
        {
            const auto [nu_x, nu_y] = self._args_imm2(data);
            self._store_unsigned(nu_x, static_cast<uint32_t>(nu_y));
            return {};
        }

        static op_res_t store_imm_u64(impl &self, const buffer data)
        {
            const auto [nu_x, nu_y] = self._args_imm2(data);
            self._store_unsigned(nu_x, nu_y);
            return {};
        }

        static op_res_t load_imm(impl &self, const buffer data)
        {
            if (data.size() > 5) [[unlikely]]
                throw exit_panic_t{};
            const auto [r_a, nu_x] = self._args_reg1_imm1_s64(data);
            self._set_reg(r_a, nu_x);
            return {};
        }

        static op_res_t load_imm_64(impl &self, const buffer data)
        {
            if (data.size() != 9) [[unlikely]]
                throw exit_panic_t{};
            const auto [r_a, nu_x] = self._args_reg1_imm1_u64(data);
            self._set_reg(r_a, nu_x);
            return {};
        }

        static op_res_t move_reg(impl &self, const buffer data)
        {
            const auto [r_d, r_a] = self._args_reg2(data);
            self._set_reg(r_d, self._regs[r_a]);
            return {};
        }

        static op_res_t sbrk(impl &self, const buffer data)
        {
            const auto [r_d, r_a] = self._args_reg2(data);
            const auto size = self._regs[r_a];
            if (size > 0) {
                const auto new_heap_end = self._heap_end + size;
                // check for an arithmetic overflow and getting into the stack area
                if (new_heap_end < self._heap_end || new_heap_end >= self._stack_begin) [[unlikely]] {
                    self._set_reg(r_d, 0);
                    return {};
                }
                const auto begin_page_id = (self._heap_end + config_prod::ZP_pvm_page_size - 1) / config_prod::ZP_pvm_page_size;
                const auto end_page_id = (new_heap_end + config_prod::ZP_pvm_page_size - 1) / config_prod::ZP_pvm_page_size;
                if (begin_page_id < end_page_id)
                    self._add_pages(begin_page_id, end_page_id, true);
                self._heap_end = new_heap_end;
            }
            self._set_reg(r_d, self._heap_end);
            return {};
        }

        static op_res_t count_set_bits_64(impl &self, const buffer data)
        {
            const auto [r_d, r_a] = self._args_reg2(data);
            self._set_reg(r_d, std::popcount(self._regs[r_a]));
            return {};
        }

        static op_res_t count_set_bits_32(impl &self, const buffer data)
        {
            const auto [r_d, r_a] = self._args_reg2(data);
            self._set_reg(r_d, std::popcount(static_cast<uint32_t>(self._regs[r_a])));
            return {};
        }

        static op_res_t leading_zero_bits_64(impl &self, const buffer data)
        {
            const auto [r_d, r_a] = self._args_reg2(data);
            self._set_reg(r_d, std::countl_zero(self._regs[r_a]));
            return {};
        }

        static op_res_t leading_zero_bits_32(impl &self, const buffer data)
        {
            const auto [r_d, r_a] = self._args_reg2(data);
            self._set_reg(r_d, std::countl_zero(static_cast<uint32_t>(self._regs[r_a])));
            return {};
        }

        static op_res_t trailing_zero_bits_64(impl &self, const buffer data)
        {
            const auto [r_d, r_a] = self._args_reg2(data);
            self._set_reg(r_d, std::countr_zero(self._regs[r_a]));
            return {};
        }

        static op_res_t trailing_zero_bits_32(impl &self, const buffer data)
        {
            const auto [r_d, r_a] = self._args_reg2(data);
            self._set_reg(r_d, std::countr_zero(static_cast<uint32_t>(self._regs[r_a])));
            return {};
        }

        static op_res_t sign_extend_8(impl &self, const buffer data)
        {
            const auto [r_d, r_a] = self._args_reg2(data);
            self._set_reg(r_d, sign_extend(1, self._regs[r_a]));
            return {};
        }

        static op_res_t sign_extend_16(impl &self, const buffer data)
        {
            const auto [r_d, r_a] = self._args_reg2(data);
            self._set_reg(r_d, sign_extend(2, self._regs[r_a]));
            return {};
        }

        static op_res_t zero_extend_16(impl &self, const buffer data)
        {
            const auto [r_d, r_a] = self._args_reg2(data);
            self._set_reg(r_d, self._regs[r_a] & 0xFFFF);
            return {};
        }

        static op_res_t reverse_bytes(impl &self, const buffer data)
        {
            const auto [r_d, r_a] = self._args_reg2(data);
            self._set_reg(r_d, std::byteswap(self._regs[r_a]));
            return {};
        }

        static op_res_t branch_eq(impl &self, const buffer data)
        {
            return _branch_reg2_off1(self._program, self._pc, self._regs, data, [](const register_val_t lhs, const register_val_t rhs) noexcept { return lhs == rhs; });
        }

        static op_res_t branch_ne(impl &self, const buffer data)
        {
            return _branch_reg2_off1(self._program, self._pc, self._regs, data, [](const register_val_t lhs, const register_val_t rhs) noexcept { return lhs != rhs; });
        }

        static op_res_t branch_lt_u(impl &self, const buffer data)
        {
            return _branch_reg2_off1(self._program, self._pc, self._regs, data, [](const register_val_t lhs, const register_val_t rhs) noexcept { return lhs < rhs; });
        }

        static op_res_t branch_lt_s(impl &self, const buffer data)
        {
            return _branch_reg2_off1(self._program, self._pc, self._regs, data, [](const register_val_t lhs, const register_val_t rhs) noexcept {
                return static_cast<register_val_signed_t>(lhs) < static_cast<register_val_signed_t>(rhs);
            });
        }

        static op_res_t branch_ge_u(impl &self, const buffer data)
        {
            return _branch_reg2_off1(self._program, self._pc, self._regs, data, [](const register_val_t lhs, const register_val_t rhs) noexcept { return lhs >= rhs; });
        }

        static op_res_t branch_ge_s(impl &self, const buffer data)
        {
            return _branch_reg2_off1(self._program, self._pc, self._regs, data, [](const register_val_t lhs, const register_val_t rhs) noexcept {
                return static_cast<register_val_signed_t>(lhs) >= static_cast<register_val_signed_t>(rhs);
            });
        }

        static op_res_t add_imm_32(impl &self, const buffer data)
        {
            const auto [r_a, r_b, nu_x] = self._args_reg2_imm1(data);
            self._set_reg(r_a, sign_extend(4, static_cast<uint32_t>(self._regs[r_b] + nu_x)));
            return {};
        }

        static op_res_t and_imm(impl &self, const buffer data)
        {
            const auto [r_a, r_b, nu_x] = self._args_reg2_imm1(data);
            self._set_reg(r_a, self._regs[r_b] & nu_x);
            return {};
        }

        static op_res_t xor_imm(impl &self, const buffer data)
        {
            const auto [r_a, r_b, nu_x] = self._args_reg2_imm1(data);
            self._set_reg(r_a, self._regs[r_b] ^ nu_x);
            return {};
        }

        static op_res_t or_imm(impl &self, const buffer data)
        {
            const auto [r_a, r_b, nu_x] = self._args_reg2_imm1(data);
            self._set_reg(r_a, self._regs[r_b] | nu_x);
            return {};
        }

        static op_res_t mul_imm_32(impl &self, const buffer data)
        {
            const auto [r_a, r_b, nu_x] = self._args_reg2_imm1(data);
            self._set_reg(r_a, sign_extend(4, self._regs[r_b] * nu_x));
            return {};
        }

        static op_res_t set_lt_u_imm(impl &self, const buffer data)
        {
            const auto [r_a, r_b, nu_x] = self._args_reg2_imm1(data);
            self._set_reg(r_a, self._regs[r_b] < nu_x);
            return {};
        }

        static op_res_t set_lt_s_imm(impl &self, const buffer data)
        {
            const auto [r_a, r_b, nu_x] = self._args_reg2_imm1(data);
            self._set_reg(r_a, static_cast<register_val_signed_t>(self._regs[r_b]) < static_cast<register_val_signed_t>(nu_x));
            return {};
        }

        static op_res_t shlo_l_imm_32(impl &self, const buffer data)
        {
            const auto [r_a, r_b, nu_x] = self._args_reg2_imm1(data);
            self._set_reg(r_a, sign_extend(4, static_cast<uint32_t>(self._regs[r_b]) << static_cast<uint32_t>(nu_x)));
            return {};
        }

        static op_res_t shlo_r_imm_32(impl &self, const buffer data)
        {
            const auto [r_a, r_b, nu_x] = self._args_reg2_imm1(data);
            self._set_reg(r_a, sign_extend(4, static_cast<uint32_t>(self._regs[r_b]) >> static_cast<uint32_t>(nu_x)));
            return {};
        }

        static op_res_t shar_r_imm_32(impl &self, const buffer data)
        {
            const auto [r_a, r_b, nu_x] = self._args_reg2_imm1(data);
            self._set_reg(r_a, static_cast<register_val_t>(static_cast<int32_t>(self._regs[r_b]) >> static_cast<uint32_t>(nu_x)));
            return {};
        }

        static op_res_t neg_add_imm_32(impl &self, const buffer data)
        {
            const auto [r_a, r_b, nu_x] = self._args_reg2_imm1(data);
            self._set_reg(r_a, sign_extend(4, static_cast<uint32_t>(nu_x + (1ULL << 32ULL) - self._regs[r_b])));
            return {};
        }

        static op_res_t set_gt_u_imm(impl &self, const buffer data)
        {
            const auto [r_a, r_b, nu_x] = self._args_reg2_imm1(data);
            self._set_reg(r_a, self._regs[r_b] > nu_x);
            return {};
        }

        static op_res_t set_gt_s_imm(impl &self, const buffer data)
        {
            const auto [r_a, r_b, nu_x] = self._args_reg2_imm1(data);
            self._set_reg(r_a, static_cast<register_val_signed_t>(self._regs[r_b]) > static_cast<register_val_signed_t>(nu_x));
            return {};
        }

        static op_res_t shlo_l_imm_alt_32(impl &self, const buffer data)
        {
            const auto [r_a, r_b, nu_x] = self._args_reg2_imm1(data);
            self._set_reg(r_a, sign_extend(4, static_cast<uint32_t>(nu_x) << static_cast<uint32_t>(self._regs[r_b])));
            return {};
        }

        static op_res_t shlo_r_imm_alt_32(impl &self, const buffer data)
        {
            const auto [r_a, r_b, nu_x] = self._args_reg2_imm1(data);
            self._set_reg(r_a, sign_extend(4, static_cast<uint32_t>(nu_x) >> static_cast<uint32_t>(self._regs[r_b])));
            return {};
        }

        static op_res_t shar_r_imm_alt_32(impl &self, const buffer data)
        {
            const auto [r_a, r_b, nu_x] = self._args_reg2_imm1(data);
            self._set_reg(r_a, static_cast<register_val_t>(static_cast<int32_t>(nu_x) >> static_cast<uint32_t>(self._regs[r_b])));
            return {};
        }

        static op_res_t cmov_iz_imm(impl &self, const buffer data)
        {
            const auto [r_a, r_b, nu_x] = self._args_reg2_imm1(data);
            self._set_reg(r_a, self._regs[r_b] == 0 ?  nu_x : self._regs[r_a]);
            return {};
        }

        static op_res_t cmov_nz_imm(impl &self, const buffer data)
        {
            const auto [r_a, r_b, nu_x] = self._args_reg2_imm1(data);
            self._set_reg(r_a, self._regs[r_b] != 0 ?  nu_x : self._regs[r_a]);
            return {};
        }

        static op_res_t add_imm_64(impl &self, const buffer data)
        {
            const auto [r_a, r_b, nu_x] = self._args_reg2_imm1(data);
            self._set_reg(r_a, self._regs[r_b] + nu_x);
            return {};
        }

        static op_res_t mul_imm_64(impl &self, const buffer data)
        {
            const auto [r_a, r_b, nu_x] = self._args_reg2_imm1(data);
            self._set_reg(r_a, self._regs[r_b] * nu_x);
            return {};
        }

        static op_res_t shlo_l_imm_64(impl &self, const buffer data)
        {
            const auto [r_a, r_b, nu_x] = self._args_reg2_imm1(data);
            self._set_reg(r_a, self._regs[r_b] << nu_x);
            return {};
        }

        static op_res_t shlo_r_imm_64(impl &self, const buffer data)
        {
            const auto [r_a, r_b, nu_x] = self._args_reg2_imm1(data);
            self._set_reg(r_a, self._regs[r_b] >> nu_x);
            return {};
        }

        static op_res_t shar_r_imm_64(impl &self, const buffer data)
        {
            const auto [r_a, r_b, nu_x] = self._args_reg2_imm1(data);
            self._set_reg(r_a, static_cast<register_val_t>(static_cast<register_val_signed_t>(self._regs[r_b]) >> static_cast<register_val_signed_t>(nu_x)));
            return {};
        }

        static op_res_t neg_add_imm_64(impl &self, const buffer data)
        {
            const auto [r_a, r_b, nu_x] = self._args_reg2_imm1(data);
            self._set_reg(r_a, nu_x - self._regs[r_b]);
            return {};
        }

        static op_res_t shlo_l_imm_alt_64(impl &self, const buffer data)
        {
            const auto [r_a, r_b, nu_x] = self._args_reg2_imm1(data);
            self._set_reg(r_a, nu_x << self._regs[r_b]);
            return {};
        }

        static op_res_t shlo_r_imm_alt_64(impl &self, const buffer data)
        {
            const auto [r_a, r_b, nu_x] = self._args_reg2_imm1(data);
            self._set_reg(r_a, nu_x >> self._regs[r_b]);
            return {};
        }

        static op_res_t shar_r_imm_alt_64(impl &self, const buffer data)
        {
            const auto [r_a, r_b, nu_x] = self._args_reg2_imm1(data);
            self._set_reg(r_a, static_cast<register_val_t>(static_cast<register_val_signed_t>(nu_x) >> static_cast<register_val_signed_t>(self._regs[r_b])));
            return {};
        }

        static op_res_t rot_r_64_imm(impl &self, const buffer data)
        {
            const auto [r_a, r_b, nu_x] = self._args_reg2_imm1(data);
            self._set_reg(r_a, std::rotr(self._regs[r_b], nu_x));
            return {};
        }

        static op_res_t rot_r_64_imm_alt(impl &self, const buffer data)
        {
            const auto [r_a, r_b, nu_x] = self._args_reg2_imm1(data);
            self._set_reg(r_a, std::rotr(nu_x, self._regs[r_b]));
            return {};
        }

        static op_res_t rot_r_32_imm(impl &self, const buffer data)
        {
            const auto [r_a, r_b, nu_x] = self._args_reg2_imm1(data);
            self._set_reg(r_a, sign_extend(4, std::rotr(static_cast<uint32_t>(self._regs[r_b]), static_cast<uint32_t>(nu_x))));
            return {};
        }

        static op_res_t rot_r_32_imm_alt(impl &self, const buffer data)
        {
            const auto [r_a, r_b, nu_x] = self._args_reg2_imm1(data);
            self._set_reg(r_a, sign_extend(4, std::rotr(static_cast<uint32_t>(nu_x), static_cast<uint32_t>(self._regs[r_b]))));
            return {};
        }

        static op_res_t load_imm_jump(impl &self, const buffer data)
        {
            const auto [r_a, nu_x, nu_y] = _args_reg1_imm1_off1(self._pc, data);
            self._set_reg(r_a, nu_x);
            return branch_base(self._program, nu_y, true);
        }

        static op_res_t load_imm_jump_ind(impl &self, const buffer data)
        {
            const auto [r_a, r_b, nu_x, nu_y] = self._args_reg2_imm2(data);
            const auto jt_idx = (self._regs[r_b] + nu_y) % (1ULL << 32ULL);
            self._set_reg(r_a, nu_x);
            return djump(self._program, jt_idx);
        }

        static op_res_t branch_eq_imm(impl &self, const buffer data)
        {
            return _branch_reg1_imm1_off1(self._program, self._pc, self._regs, data, [](const register_val_t lhs, const register_val_t rhs) noexcept { return lhs == rhs; });
        }

        static op_res_t branch_ne_imm(impl &self, const buffer data)
        {
            return _branch_reg1_imm1_off1(self._program, self._pc, self._regs, data, [](const register_val_t lhs, const register_val_t rhs) noexcept { return lhs != rhs; });
        }

        static op_res_t branch_lt_u_imm(impl &self, const buffer data)
        {
            return _branch_reg1_imm1_off1(self._program, self._pc, self._regs, data, [](const register_val_t lhs, const register_val_t rhs) noexcept { return lhs < rhs; });
        }

        static op_res_t branch_le_u_imm(impl &self, const buffer data)
        {
            return _branch_reg1_imm1_off1(self._program, self._pc, self._regs, data, [](const register_val_t lhs, const register_val_t rhs) noexcept { return lhs <= rhs; });
        }

        static op_res_t branch_ge_u_imm(impl &self, const buffer data)
        {
            return _branch_reg1_imm1_off1(self._program, self._pc, self._regs, data, [](const register_val_t lhs, const register_val_t rhs) noexcept { return lhs >= rhs; });
        }

        static op_res_t branch_gt_u_imm(impl &self, const buffer data)
        {
            return _branch_reg1_imm1_off1(self._program, self._pc, self._regs, data, [](const register_val_t lhs, const register_val_t rhs) noexcept { return lhs > rhs; });
        }

        static op_res_t branch_lt_s_imm(impl &self, const buffer data)
        {
            return _branch_reg1_imm1_off1(self._program, self._pc, self._regs, data, [](const register_val_t lhs, const register_val_t rhs) noexcept {
                return static_cast<register_val_signed_t>(lhs) < static_cast<register_val_signed_t>(rhs);
            });
        }

        static op_res_t branch_le_s_imm(impl &self, const buffer data)
        {
            return _branch_reg1_imm1_off1(self._program, self._pc, self._regs, data, [](const register_val_t lhs, const register_val_t rhs) noexcept {
                return static_cast<register_val_signed_t>(lhs) <= static_cast<register_val_signed_t>(rhs);
            });
        }

        static op_res_t branch_ge_s_imm(impl &self, const buffer data)
        {
            return _branch_reg1_imm1_off1(self._program, self._pc, self._regs, data, [](const register_val_t lhs, const register_val_t rhs) noexcept {
                return static_cast<register_val_signed_t>(lhs) >= static_cast<register_val_signed_t>(rhs);
            });
        }

        static op_res_t branch_gt_s_imm(impl &self, const buffer data)
        {
            return _branch_reg1_imm1_off1(self._program, self._pc, self._regs, data, [](const register_val_t lhs, const register_val_t rhs) noexcept {
                return static_cast<register_val_signed_t>(lhs) > static_cast<register_val_signed_t>(rhs);
            });
        }

        static op_res_t jump(impl &self, const buffer data)
        {
            const auto [nu_x] = _args_off1(self._pc, data);
            return branch_base(self._program, nu_x, true);
        }

        static op_res_t jump_ind(impl &self, const buffer data)
        {
            const auto [r_a, nu_x] = self._args_reg1_imm1_s32(data);
            return djump(self._program, (self._regs[r_a] + nu_x) % (1ULL << 32ULL));
        }

        static op_res_t load_u8(impl &self, const buffer data)
        {
            return _load_direct<1, false>(self, self._regs, data);
        }

        static op_res_t load_u16(impl &self, const buffer data)
        {
            return _load_direct<2, false>(self, self._regs, data);
        }

        static op_res_t load_u32(impl &self, const buffer data)
        {
            return _load_direct<4, false>(self, self._regs, data);
        }

        static op_res_t load_u64(impl &self, const buffer data)
        {
            return _load_direct<8, false>(self, self._regs, data);
        }

        static op_res_t load_i8(impl &self, const buffer data)
        {
            return _load_direct<1, true>(self, self._regs, data);
        }

        static op_res_t load_i16(impl &self, const buffer data)
        {
            return _load_direct<2, true>(self, self._regs, data);
        }

        static op_res_t load_i32(impl &self, const buffer data)
        {
            return _load_direct<4, true>(self, self._regs, data);
        }

        static op_res_t store_u8(impl &self, const buffer data)
        {
            return _store_direct<uint8_t>(self, self._regs, data);
        }

        static op_res_t store_u16(impl &self, const buffer data)
        {
            return _store_direct<uint16_t>(self, self._regs, data);
        }

        static op_res_t store_u32(impl &self, const buffer data)
        {
            return _store_direct<uint32_t>(self, self._regs, data);
        }

        static op_res_t store_u64(impl &self, const buffer data)
        {
            return _store_direct<register_val_t>(self, self._regs, data);
        }

        static op_res_t store_imm_ind_u8(impl &self, const buffer data)
        {
            return _store_imm_indirect<uint8_t>(self, self._regs, data);
        }

        static op_res_t store_imm_ind_u16(impl &self, const buffer data)
        {
            return _store_imm_indirect<uint16_t>(self, self._regs, data);
        }

        static op_res_t store_imm_ind_u32(impl &self, const buffer data)
        {
            return _store_imm_indirect<uint32_t>(self, self._regs, data);
        }

        static op_res_t store_imm_ind_u64(impl &self, const buffer data)
        {
            return _store_imm_indirect<register_val_t>(self, self._regs, data);
        }

        static op_res_t store_ind_u8(impl &self, const buffer data)
        {
            return _store_indirect<uint8_t>(self, self._regs, data);
        }

        static op_res_t store_ind_u16(impl &self, const buffer data)
        {
            return _store_indirect<uint16_t>(self, self._regs, data);
        }

        static op_res_t store_ind_u32(impl &self, const buffer data)
        {
            return _store_indirect<uint32_t>(self, self._regs, data);
        }

        static op_res_t store_ind_u64(impl &self, const buffer data)
        {
            return _store_indirect<register_val_t>(self, self._regs, data);
        }

        static op_res_t load_ind_u8(impl &self, const buffer data)
        {
            return _load_indirect<1, false>(self, self._regs, data);
        }

        static op_res_t load_ind_u16(impl &self, const buffer data)
        {
            return _load_indirect<2, false>(self, self._regs, data);
        }

        static op_res_t load_ind_u32(impl &self, const buffer data)
        {
            return _load_indirect<4, false>(self, self._regs, data);
        }

        static op_res_t load_ind_u64(impl &self, const buffer data)
        {
            return _load_indirect<8, false>(self, self._regs, data);
        }

        static op_res_t load_ind_i8(impl &self, const buffer data)
        {
            return _load_indirect<1, true>(self, self._regs, data);
        }

        static op_res_t load_ind_i16(impl &self, const buffer data)
        {
            return _load_indirect<2, true>(self, self._regs, data);
        }

        static op_res_t load_ind_i32(impl &self, const buffer data)
        {
            return _load_indirect<4, true>(self, self._regs, data);
        }

        static op_res_t add_32(impl &self, const buffer data)
        {
            return _reg3_apply(self._regs, data, [](const register_val_t lhs, const register_val_t rhs) noexcept {
                return sign_extend(4, static_cast<uint32_t>(lhs + rhs));
            });
        }

        static op_res_t sub_32(impl &self, const buffer data)
        {
            return _reg3_apply(self._regs, data, [](const register_val_t lhs, const register_val_t rhs) noexcept {
                return sign_extend(4, static_cast<uint32_t>(lhs - rhs));
            });
        }

        static op_res_t mul_32(impl &self, const buffer data)
        {
            return _reg3_apply(self._regs, data, [](const register_val_t lhs, const register_val_t rhs) noexcept {
                return sign_extend(4, static_cast<uint32_t>(lhs * rhs));
            });
        }

        static op_res_t div_u_32(impl &self, const buffer data)
        {
            const auto [r_a, r_b, r_d] = self._args_reg3(data);
            self._set_reg(r_d, self._regs[r_b] != 0 ? sign_extend(4, static_cast<uint32_t>(self._regs[r_a] / self._regs[r_b])) : std::numeric_limits<uint64_t>::max());
            return {};
        }

        static op_res_t div_s_32(impl &self, const buffer data)
        {
            const auto [r_a, r_b, r_d] = self._args_reg3(data);
            const auto reg_a_s32 = static_cast<int32_t>(self._regs[r_a]);
            const auto reg_b_s32 = static_cast<int32_t>(self._regs[r_b]);
            if (self._regs[r_b] != 0) {
                if (reg_a_s32 != std::numeric_limits<int32_t>::min() || reg_b_s32 != -1) {
                    self._set_reg(r_d, static_cast<register_val_t>(reg_a_s32 / reg_b_s32));
                } else {
                    self._set_reg(r_d, static_cast<register_val_t>(reg_a_s32));
                }
            } else {
                self._set_reg(r_d, std::numeric_limits<uint64_t>::max());
            }
            return {};
        }

        static op_res_t rem_u_32(impl &self, const buffer data)
        {
            const auto [r_a, r_b, r_d] = self._args_reg3(data);
            const auto reg_a_u32 = static_cast<uint32_t>(self._regs[r_a]);
            const auto reg_b_u32 = static_cast<uint32_t>(self._regs[r_b]);
            self._set_reg(r_d, sign_extend(4, reg_b_u32 != 0 ? reg_a_u32 % reg_b_u32 : reg_a_u32));
            return {};
        }

        static op_res_t rem_s_32(impl &self, const buffer data)
        {
            const auto [r_a, r_b, r_d] = self._args_reg3(data);
            const auto reg_a_s32 = static_cast<int32_t>(self._regs[r_a]);
            const auto reg_b_s32 = static_cast<int32_t>(self._regs[r_b]);
            if (reg_a_s32 != std::numeric_limits<int32_t>::min() || reg_b_s32 != -1)
                self._set_reg(r_d, reg_b_s32 != 0 ? static_cast<register_val_t>(reg_a_s32 % reg_b_s32) : reg_a_s32);
            else {
                self._set_reg(r_d, 0);
            }
            return {};
        }

        static op_res_t shlo_l_32(impl &self, const buffer data)
        {
            const auto [r_a, r_b, r_d] = self._args_reg3(data);
            self._set_reg(r_d, sign_extend(4, static_cast<uint32_t>(self._regs[r_a]) << static_cast<uint32_t>(self._regs[r_b])));
            return {};
        }

        static op_res_t shlo_r_32(impl &self, const buffer data)
        {
            const auto [r_a, r_b, r_d] = self._args_reg3(data);
            self._set_reg(r_d, sign_extend(4, static_cast<uint32_t>(self._regs[r_a]) >> static_cast<uint32_t>(self._regs[r_b] % 32U)));
            return {};
        }

        static op_res_t shar_r_32(impl &self, const buffer data)
        {
            const auto [r_a, r_b, r_d] = self._args_reg3(data);
            const auto reg_a_s32 = static_cast<int32_t>(self._regs[r_a]);
            const auto reg_b_s32 = static_cast<int32_t>(self._regs[r_b] % 32U);
            self._set_reg(r_d, sign_extend(4, reg_a_s32 >> reg_b_s32));
            return {};
        }

        static op_res_t add_64(impl &self, const buffer data)
        {
            return _reg3_apply(self._regs, data, [](const register_val_t lhs, const register_val_t rhs) noexcept { return lhs + rhs; });
        }

        static op_res_t sub_64(impl &self, const buffer data)
        {
            return _reg3_apply(self._regs, data, [](const register_val_t lhs, const register_val_t rhs) noexcept { return lhs - rhs; });
        }

        static op_res_t mul_64(impl &self, const buffer data)
        {
            return _reg3_apply(self._regs, data, [](const register_val_t lhs, const register_val_t rhs) noexcept { return lhs * rhs; });
        }

        static op_res_t div_u_64(impl &self, const buffer data)
        {
            const auto [r_a, r_b, r_d] = self._args_reg3(data);
            self._set_reg(r_d, self._regs[r_b] != 0 ? self._regs[r_a] / self._regs[r_b] : std::numeric_limits<uint64_t>::max());
            return {};
        }

        static op_res_t div_s_64(impl &self, const buffer data)
        {
            const auto [r_a, r_b, r_d] = self._args_reg3(data);
            const auto reg_a_s64 = static_cast<register_val_signed_t>(self._regs[r_a]);
            const auto reg_b_s64 = static_cast<register_val_signed_t>(self._regs[r_b]);
            if (self._regs[r_b] != 0) {
                if (reg_a_s64 != std::numeric_limits<register_val_signed_t>::min() || reg_b_s64 != -1) {
                    self._set_reg(r_d, static_cast<register_val_t>(reg_a_s64 / reg_b_s64));
                } else {
                    self._set_reg(r_d, self._regs[r_a]);
                }
            } else {
                self._set_reg(r_d, std::numeric_limits<uint64_t>::max());
            }
            return {};
        }

        static op_res_t rem_u_64(impl &self, const buffer data)
        {
            const auto [r_a, r_b, r_d] = self._args_reg3(data);
            self._set_reg(r_d, self._regs[r_b] != 0 ? self._regs[r_a] % self._regs[r_b] : self._regs[r_a]);
            return {};
        }

        static op_res_t rem_s_64(impl &self, const buffer data)
        {
            const auto [r_a, r_b, r_d] = self._args_reg3(data);
            const auto reg_a_s64 = static_cast<register_val_signed_t>(self._regs[r_a]);
            const auto reg_b_s64 = static_cast<register_val_signed_t>(self._regs[r_b]);
            if (reg_a_s64 != std::numeric_limits<register_val_signed_t>::min() || reg_b_s64 != -1)
                self._set_reg(r_d, reg_b_s64 != 0 ? static_cast<register_val_t>(reg_a_s64 % reg_b_s64) : reg_a_s64);
            else {
                self._set_reg(r_d, 0);
            }
            return {};
        }

        static op_res_t shlo_l_64(impl &self, const buffer data)
        {
            const auto [r_a, r_b, r_d] = self._args_reg3(data);
            self._set_reg(r_d, self._regs[r_a] << (self._regs[r_b] % 64U));
            return {};
        }

        static op_res_t shlo_r_64(impl &self, const buffer data)
        {
            const auto [r_a, r_b, r_d] = self._args_reg3(data);
            self._set_reg(r_d, self._regs[r_a] >> (self._regs[r_b] % 64U));
            return {};
        }

        static op_res_t shar_r_64(impl &self, const buffer data)
        {
            const auto [r_a, r_b, r_d] = self._args_reg3(data);
            self._set_reg(r_d, static_cast<register_val_t>(static_cast<register_val_signed_t>(self._regs[r_a]) >> (static_cast<register_val_signed_t>(self._regs[r_b] % 64U))));
            return {};
        }

        static op_res_t and_(impl &self, const buffer data)
        {
            return _reg3_apply(self._regs, data, [](const register_val_t lhs, const register_val_t rhs) noexcept { return lhs & rhs; });
        }

        static op_res_t xor_(impl &self, const buffer data)
        {
            return _reg3_apply(self._regs, data, [](const register_val_t lhs, const register_val_t rhs) noexcept { return lhs ^ rhs; });
        }

        static op_res_t or_(impl &self, const buffer data)
        {
            return _reg3_apply(self._regs, data, [](const register_val_t lhs, const register_val_t rhs) noexcept { return lhs | rhs; });
        }

        static op_res_t mul_upper_s_s(impl &self, const buffer data)
        {
            const auto [r_a, r_b, r_d] = self._args_reg3(data);
#if defined(_MSC_VER)
            _mul128(static_cast<register_val_signed_t>(self._regs[r_a]), static_cast<register_val_signed_t>(self._regs[r_b]), reinterpret_cast<register_val_signed_t *>(&self._regs[r_d]));
#elif defined(__GNUC__) || defined(__clang__)
            auto sign_extend_u64_to_i128 = [](uint64_t x) -> int128_t {
                return (x & (1ULL << 63)) ? static_cast<int128_t>(x) - (int128_t(1) << 64) : static_cast<int128_t>(x);
            };

            int128_t lhs = sign_extend_u64_to_i128(self._regs[r_a]);
            int128_t rhs = sign_extend_u64_to_i128(self._regs[r_b]);
            int128_t product = lhs * rhs;

            self._set_reg(r_d, static_cast<register_val_t>(product >> 64));
            //self._set_reg(r_d, static_cast<register_val_t>((static_cast<int128_t>(self._regs[r_a]) * static_cast<int128_t>(self._regs[r_b])) >> 64U));
#else
#   error "MULH operation implemented only for Visual C++, GCC, and Clang compilers"
#endif
            return {};
        }

        static op_res_t mul_upper_u_u(impl &self, const buffer data)
        {
            const auto [r_a, r_b, r_d] = self._args_reg3(data);
#if defined(_MSC_VER)
            _umul128(self._regs[r_a], self._regs[r_b], &self._regs[r_d]);
#elif defined(__GNUC__) || defined(__clang__)
            self._set_reg(r_d, static_cast<register_val_t>((static_cast<uint128_t>(self._regs[r_a]) * static_cast<uint128_t>(self._regs[r_b])) >> 64U));
#else
#   error "MULH operation implemented only for Visual C++, GCC, and Clang compilers"
#endif
            return {};
        }

        static op_res_t mul_upper_s_u(impl &self, const buffer data)
        {
            const auto [r_a, r_b, r_d] = self._args_reg3(data);
            const auto reg_a_s64 = static_cast<register_val_signed_t>(self._regs[r_a]);
            const bool reg_a_neg = reg_a_s64 < 0;
            const uint64_t reg_a_u64 = static_cast<uint64_t>(reg_a_neg ? -reg_a_s64 : reg_a_s64);
#if defined(_MSC_VER)            
            const uint64_t lo = _umul128(reg_a_u64, self._regs[r_b], &self._regs[r_d]);
#elif defined(__GNUC__) || defined(__clang__)
            const auto res = static_cast<int128_t>(reg_a_u64) * static_cast<uint128_t>(self._regs[r_b]);
            const auto lo = static_cast<uint64_t>(res);
            self._set_reg(r_d, res >> 64U);
#else
#   error "MULH operation implemented only for Visual C++, GCC, and Clang compilers"
#endif
            if (reg_a_neg) {
                self._set_reg(r_d, ~self._regs[r_d]);
                if (lo == 0) {
                    self._regs[r_d] += 1;
                }
            }
            return {};
        }

        static op_res_t set_lt_u(impl &self, const buffer data)
        {
            const auto [r_a, r_b, r_d] = self._args_reg3(data);
            self._set_reg(r_d, self._regs[r_a] < self._regs[r_b]);
            return {};
        }

        static op_res_t set_lt_s(impl &self, const buffer data)
        {
            const auto [r_a, r_b, r_d] = self._args_reg3(data);
            self._set_reg(r_d, static_cast<register_val_signed_t>(self._regs[r_a]) < static_cast<register_val_signed_t>(self._regs[r_b]));
            return {};
        }

        static op_res_t cmov_iz(impl &self, const buffer data)
        {
            const auto [r_a, r_b, r_d] = self._args_reg3(data);
            self._set_reg(r_d, self._regs[r_b] == 0 ? self._regs[r_a] : self._regs[r_d]);
            return {};
        }

        static op_res_t cmov_nz(impl &self, const buffer data)
        {
            const auto [r_a, r_b, r_d] = self._args_reg3(data);
            self._set_reg(r_d, self._regs[r_b] != 0 ? self._regs[r_a] : self._regs[r_d]);
            return {};
        }

        static op_res_t rot_l_64(impl &self, const buffer data)
        {
            const auto [r_a, r_b, r_d] = self._args_reg3(data);
            self._set_reg(r_d, std::rotl(self._regs[r_a], self._regs[r_b]));
            return {};
        }

        static op_res_t rot_l_32(impl &self, const buffer data)
        {
            const auto [r_a, r_b, r_d] = self._args_reg3(data);
            self._set_reg(r_d, sign_extend(4, std::rotl(static_cast<uint32_t>(self._regs[r_a]), static_cast<uint32_t>(self._regs[r_b]))));
            return {};
        }

        static op_res_t rot_r_64(impl &self, const buffer data)
        {
            const auto [r_a, r_b, r_d] = self._args_reg3(data);
            self._set_reg(r_d, std::rotr(self._regs[r_a], self._regs[r_b]));
            return {};
        }

        static op_res_t rot_r_32(impl &self, const buffer data)
        {
            const auto [r_a, r_b, r_d] = self._args_reg3(data);
            self._set_reg(r_d, sign_extend(4, std::rotr(static_cast<uint32_t>(self._regs[r_a]), static_cast<uint32_t>(self._regs[r_b]))));
            return {};
        }

        static op_res_t and_inv(impl &self, const buffer data)
        {
            const auto [r_a, r_b, r_d] = self._args_reg3(data);
            self._set_reg(r_d, self._regs[r_a] & (~self._regs[r_b]));
            return {};
        }

        static op_res_t or_inv(impl &self, const buffer data)
        {
            const auto [r_a, r_b, r_d] = self._args_reg3(data);
            self._set_reg(r_d, self._regs[r_a] | (~self._regs[r_b]));
            return {};
        }

        static op_res_t xnor(impl &self, const buffer data)
        {
            const auto [r_a, r_b, r_d] = self._args_reg3(data);
            self._set_reg(r_d, ~(self._regs[r_a] ^ self._regs[r_b]));
            return {};
        }

        static op_res_t max(impl &self, const buffer data)
        {
            return _reg3_apply(self._regs, data, [](const register_val_t lhs, const register_val_t rhs) noexcept {
                return static_cast<register_val_t>(std::max(static_cast<register_val_signed_t>(lhs), static_cast<register_val_signed_t>(rhs)));
            });
        }

        static op_res_t max_u(impl &self, const buffer data)
        {
            return _reg3_apply(self._regs, data, [](const register_val_t lhs, const register_val_t rhs) noexcept { return std::max(lhs, rhs); });
        }

        static op_res_t min(impl &self, const buffer data)
        {
            return _reg3_apply(self._regs, data, [](const register_val_t lhs, const register_val_t rhs) noexcept {
                return static_cast<register_val_t>(std::min(static_cast<register_val_signed_t>(lhs), static_cast<register_val_signed_t>(rhs)));
            });
        }

        static op_res_t min_u(impl &self, const buffer data)
        {
            return _reg3_apply(self._regs, data, [](const register_val_t lhs, const register_val_t rhs) noexcept { return std::min(lhs, rhs); });
        }
    };

    machine_t::machine_t(program_t &&program, const state_t &init, const pages_t &page_map):
        _impl{std::make_unique<impl>(std::move(program), init, page_map)}
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

    bool machine_t::set_pages(const address_val_t p, const address_val_t sz, const page_init_method_t i) {
        return _impl->set_pages(p, sz, i);
    }

    void machine_t::skip_op()
    {
        return _impl->skip_op();
    }

    gas_remaining_t machine_t::gas() const
    {
        return const_cast<machine_t *>(this)->_impl->gas();
    }

    uint32_t machine_t::pc() const
    {
        return const_cast<machine_t *>(this)->_impl->pc();
    }

    const registers_t &machine_t::regs() const
    {
        return const_cast<machine_t *>(this)->_impl->regs();
    }

    std::optional<exit_page_fault_t> machine_t::mem_writable(const size_t offset, const size_t sz) const {
        return const_cast<machine_t *>(this)->_impl->mem_writable(offset, sz);
    }

    std::optional<exit_page_fault_t> machine_t::mem_readable(const size_t offset, const size_t sz) const {
        return const_cast<machine_t *>(this)->_impl->mem_readable(offset, sz);
    }

    void machine_t::mem_copy(const machine_t &src, const size_t dst_offset, const size_t src_offset, const size_t sz) {
        return _impl->mem_copy(src, dst_offset, src_offset, sz);
    }

    void machine_t::mem_write(const size_t offset, const buffer data)
    {
        _impl->mem_write(offset, data);
    }

    void machine_t::mem_read(const std::span<uint8_t> out, const size_t offset) const
    {
        const_cast<machine_t *>(this)->_impl->mem_read(out, offset);
    }

    uint8_vector machine_t::mem_read(const size_t offset, const size_t sz) const
    {
        return const_cast<machine_t *>(this)->_impl->mem_read(offset, sz);
    }

    std::optional<uint8_vector> machine_t::try_mem_read(const size_t offset, const size_t sz) const noexcept
    {
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

    std::optional<machine_t> configure(const buffer code, const uint32_t pc, const gas_t gas_init, const buffer a_bytes)
    {
        decoder dec{code};
        // JAM (9.4)
        const auto meta = codec::from<byte_sequence_t>(dec);

        // JAM (A.3)
        const auto o_sz = dec.uint_fixed<size_t>(3);
        const auto w_sz = dec.uint_fixed<size_t>(3);
        const auto z_sz = dec.uint_fixed<size_t>(2);
        const auto s_sz = dec.uint_fixed<size_t>(3);

        const auto o_bytes = dec.next_bytes(o_sz);
        const auto w_bytes = dec.next_bytes(w_sz);

        if (const auto c_sz = dec.uint_fixed<size_t>(4); c_sz != dec.size()) [[unlikely]]
            return {};
        auto prg = program_t::from_bytes(dec.next_bytes(dec.size()));

        // JAM (A.40)
        const auto total_sz = 5 * config_prod::ZZ_pvm_init_zone_size
            + config_prod::pvm_z_size(o_sz) + config_prod::pvm_z_size(w_sz + z_sz * config_prod::ZZ_pvm_init_zone_size)
            + config_prod::pvm_z_size(s_sz) + config_prod::ZI_pvm_input_size;
        if (total_sz > 1ULL << 32U) [[unlikely]]
            return {};

        state_t state{
            .pc = pc,
            .gas = numeric_cast<gas_remaining_t>(static_cast<gas_t::base_type>(gas_init))
        };
        pages_t page_map{};

        // JAM (A.41)
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
            { (1ULL << 32U) - config_prod::ZZ_pvm_init_zone_size - config_prod::ZI_pvm_input_size, a_bytes.size(), false, a_bytes },
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

        // JAM (A.42)
        state.regs[0] = (1ULL << 32U) - (1ULL << 16U);
        state.regs[1] = (1ULL << 32U) - 2 * config_prod::ZZ_pvm_init_zone_size - config_prod::ZI_pvm_input_size;
        state.regs[7] = (1ULL << 32U) - config_prod::ZZ_pvm_init_zone_size - config_prod::ZI_pvm_input_size;
        state.regs[8] = a_bytes.size();

        std::optional<machine_t> m {};
        m.emplace(std::move(prg), state, page_map);
        return m;
    }
}
