#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <algorithm>
#include <bit>
#include <cstdint>
#include <exception>
#include <type_traits>
#include <variant>
#include "types/common.hpp"
#include "types/constants.hpp"
#include "encoding.hpp"

namespace turbo::jam::machine {
    using register_val_t = uint64_t;
    using register_val_signed_t = int64_t;
    using address_val_t = uint32_t;
    // in contrast to GP gas_remaining is unsigned, with gas_consume implementing the set to 0 on overuse
    using gas_remaining_t = gas_t::base_type;

    struct memory_chunk_t {
        uint32_t address = 0;
        byte_sequence_t contents {};

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

    struct page_t {
        uint32_t address = 0;
        uint32_t length = 0;
        bool is_writable = false;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("address"sv, address);
            if (address % config_prod::ZP_pvm_page_size != 0) [[unlikely]]
                throw error(fmt::format("an invalid page address: {}", address));
            archive.process("length"sv, length);
            if (length % config_prod::ZP_pvm_page_size != 0) [[unlikely]]
                throw error(fmt::format("an invalid page length: {}", length));
            archive.process("is-writable"sv, is_writable);
        }
    };
    using pages_t = sequence_t<page_t>;

    using registers_t = fixed_sequence_t<register_val_t, 13>;

    struct state_t {
        registers_t regs {};
        uint32_t pc {};
        gas_remaining_t gas = 0;
        memory_chunks_t memory {};

        bool operator==(const state_t &o) const noexcept
        {
            if (regs != o.regs)
                return false;
            if (pc != o.pc)
                return false;
            if (memory != o.memory)
                return false;
            /*if (gas != o.gas)
                return false;*/
            return true;
        }
    };

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
            _num_bits { o._num_bits },
            _bytes { std::move(o._bytes) }
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

        [[nodiscard]] size_t count_zeros(const size_t pos, const size_t max_len) const noexcept
        {
            if (pos >= _num_bits || max_len == 0U) [[unlikely]]
                return 0U;

            auto current = pos;
            auto remaining = std::min(max_len, _num_bits - pos);
            size_t zeroes = 0U;

            while (remaining != 0U) {
                const auto byte_pos = current >> 3U;
                const auto bit_pos = current & 7U;
                const auto chunk_bits = std::min(remaining, size_t { 32 } - bit_pos);
                const auto *ptr = _bytes.data() + byte_pos;
                auto bits = static_cast<uint32_t>(ptr[0])
                    | (static_cast<uint32_t>(ptr[1]) << 8U)
                    | (static_cast<uint32_t>(ptr[2]) << 16U)
                    | (static_cast<uint32_t>(ptr[3]) << 24U);
                bits >>= bit_pos;
                const auto mask = chunk_bits == 32U
                    ? ~uint32_t { 0 }
                    : (uint32_t { 1 } << chunk_bits) - 1U;
                const auto chunk = bits & mask;
                if (chunk != 0U)
                    return zeroes + static_cast<size_t>(std::countr_zero(chunk));
                zeroes += chunk_bits;
                current += chunk_bits;
                remaining -= chunk_bits;
            }
            return zeroes;
        }
    private:
        size_t _num_bits;
        uint8_vector _bytes;
    };

    struct exit_halt_t final: error {
        exit_halt_t(): error { "exit_halt_t" } {}
        bool operator==(const exit_halt_t &) const
        {
            return true;
        }
    };
    struct exit_panic_t final: error {
        exit_panic_t(): error { "exit_panic_t" } {}
        bool operator==(const exit_panic_t &) const
        {
            return true;
        }
    };
    struct exit_out_of_gas_t final: error {
        exit_out_of_gas_t(): error { "exit_out_of_gas_t" } {}
        bool operator==(const exit_out_of_gas_t &) const
        {
            return true;
        }
    };
    struct exit_page_fault_t final: error {
        register_val_t addr;

        exit_page_fault_t(const register_val_t a=0):
            error { "exit_page_fault_t" },
            addr { a }
        {}

        bool operator==(const exit_page_fault_t &o) const
        {
            if (addr != o.addr)
                return false;
            return true;
        }
    };
    struct exit_host_call_t final: error {
        register_val_t id;

        exit_host_call_t(const register_val_t id):
            error { "exit_host_call_t" },
            id { id }
        {}

        bool operator==(const exit_host_call_t &o) const
        {
            if (id != o.id)
                return false;
            return true;
        }
    };

    using result_base_t = std::variant<exit_halt_t, exit_panic_t, exit_page_fault_t, exit_host_call_t, exit_out_of_gas_t>;
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
        using offset_list_t = std::vector<uint32_t>;

        bit_vector_t bitmasks;
        uint8_vector code;
        offset_list_t jump_table;

        program_t() =delete;
        program_t(const program_t &o) =delete;

        program_t(bit_vector_t &&b, uint8_vector &&c, offset_list_t &&jt):
            bitmasks{std::move(b)},
            code{std::move(c)},
            jump_table{std::move(jt)}
        {
        }

        program_t(program_t &&o):
            bitmasks{std::move(o.bitmasks)},
            code{std::move(o.code)},
            jump_table{std::move(o.jump_table)}
        {
        }

        static program_t from_bytes(uint8_vector bytes)
        {
            decoder dec{bytes};
            const auto jt_sz = dec.uint_varlen();
            const auto jt_offset_sz = dec.uint_fixed<uint8_t>(1);
            const auto code_sz = dec.uint_varlen();
            offset_list_t jt{};
            jt.reserve(jt_sz);
            while (jt.size() < jt_sz) {
                jt.emplace_back(dec.uint_fixed<uint32_t>(jt_offset_sz));
            }
            const auto code_offset = numeric_cast<size_t>(dec.skip_bytes(code_sz) - bytes.data());
            bit_vector_t bitmasks{dec.next_bytes((code_sz + 7) / 8), code_sz};
            if (!dec.empty()) [[unlikely]]
                throw error("failed to decode all bytes of the program blob");
            // reuse the pre-allocated buffer for better performance
            bytes.erase(bytes.begin(), bytes.begin() + code_offset);
            bytes.resize(code_sz);
            return {
                std::move(bitmasks),
                std::move(bytes),
                std::move(jt)
            };
        }
    private:
        uint8_vector _raw;
    };

    inline register_val_t sign_extend(const size_t num_bytes, const register_val_t value)
    {
        if (num_bytes > 8) [[unlikely]]
            throw exit_panic_t{};
        if (num_bytes == 0) [[unlikely]]
            return 0;
        const size_t bit_count = num_bytes << 3U;
        const size_t extend_bits = 64U - bit_count;
        return static_cast<register_val_t>(static_cast<register_val_signed_t>(value << extend_bits) >> extend_bits);
    }

    struct machine_t {
        machine_t() =delete;
        machine_t(const machine_t &o) =delete;
        machine_t(machine_t &&o);
        machine_t(program_t &&program, const state_t &init, const pages_t &page_map);
        ~machine_t();
        result_t run();
        void consume_gas(gas_t gas);
        void set_reg(size_t id, register_val_t val);
        [[nodiscard]] std::optional<exit_page_fault_t> mem_writable(size_t offset, size_t sz) const;
        [[nodiscard]] std::optional<exit_page_fault_t> mem_readable(size_t offset, size_t sz) const;
        void mem_copy(const machine_t &src, size_t dst_offset, size_t src_offset, size_t sz);
        void mem_write(size_t offset, buffer data);
        void mem_read(std::span<uint8_t> out, size_t offset) const;
        [[nodiscard]] uint8_vector mem_read(size_t offset, size_t sz) const;
        void skip_op();
        [[nodiscard]] const registers_t &regs() const;
        [[nodiscard]] uint32_t pc() const;
        [[nodiscard]] gas_remaining_t gas() const;
        [[nodiscard]] std::optional<uint8_vector> try_mem_read(size_t offset, size_t sz) const noexcept;
        [[nodiscard]] state_t state() const;

        template <std::size_t... Is>
        constexpr auto pick_regs() {
            const auto &r = regs();
            static_assert(((Is < registers_t::fixed_size) && ...), "invalid register index");
            return std::tuple{r[Is]...};
        }
    private:
        struct impl;
        std::unique_ptr<impl> _impl;
    };

    using invocation_result_base_t = std::variant<uint8_vector, exit_panic_t, exit_out_of_gas_t>;
    struct invocation_result_t: invocation_result_base_t {
        using base_type = invocation_result_base_t;
        using base_type::base_type;
    };

    using host_call_res_base_t = std::variant<std::monostate, exit_panic_t, exit_out_of_gas_t>;
    struct host_call_res_t: host_call_res_base_t {
        using base_type = host_call_res_base_t;
        using base_type::base_type;

        // an item does not exist
        static constexpr register_val_t none = std::numeric_limits<register_val_t>::max();
        // name unknown
        static constexpr register_val_t what = std::numeric_limits<register_val_t>::max() - 1;
        // memory not accessible
        static constexpr register_val_t oob  = std::numeric_limits<register_val_t>::max() - 2;
        // index unknown
        static constexpr register_val_t who  = std::numeric_limits<register_val_t>::max() - 3;
        // storage full
        static constexpr register_val_t full = std::numeric_limits<register_val_t>::max() - 4;
        // core index unknown
        static constexpr register_val_t core = std::numeric_limits<register_val_t>::max() - 5;
        // insufficient funds
        static constexpr register_val_t cash = std::numeric_limits<register_val_t>::max() - 6;
        // gas limit too low
        static constexpr register_val_t low  = std::numeric_limits<register_val_t>::max() - 7;
        // already solicited or cannot be forgotten
        static constexpr register_val_t huh  = std::numeric_limits<register_val_t>::max() - 8;
        static constexpr register_val_t ok   = 0;
    };

    struct invocation_t {
        gas_t gas_used{};
        invocation_result_base_t result;
    };
    extern std::optional<machine_t> configure(buffer blob, uint32_t pc, gas_t gas, buffer args);
    template<typename HostInit, typename HostFn>
    invocation_t invoke(buffer blob, uint32_t pc, gas_t gas, buffer args,
        HostInit &&host_init, HostFn &&host_fn)
    {
        auto m = configure(blob, pc, gas, args);
        if (!m) [[unlikely]]
            return { 0, exit_panic_t {} };
        host_init(*m);
        const auto halt_status = [&]() -> uint8_vector {
            auto data = m->try_mem_read(m->regs().at(7), m->regs().at(8));
            return data ? std::move(*data) : uint8_vector {};
        };
        const auto gas_begin = m->gas();
        std::variant<std::monostate, invocation_result_base_t> status {};
        try {
            while (std::holds_alternative<std::monostate>(status)) {
                const auto m_res = m->run();
                std::visit([&](const auto &rv) {
                    using T = std::decay_t<decltype(rv)>;
                    if constexpr (std::is_same_v<T, exit_host_call_t>) {
                        auto h_res = host_fn(rv.id);
                        std::visit([&](auto &&hv) {
                            using HT = std::decay_t<decltype(hv)>;
                            if constexpr (std::is_same_v<HT, std::monostate>) {
                                m->skip_op();
                            } else if constexpr (std::is_same_v<HT, exit_halt_t>) {
                                status = halt_status();
                            } else if constexpr (std::is_same_v<HT, exit_out_of_gas_t>) {
                                status = std::move(hv);
                            } else {
                                status = exit_panic_t {};
                            }
                        }, std::move(h_res));
                    } else if constexpr (std::is_same_v<T, exit_out_of_gas_t>) {
                        status = exit_out_of_gas_t {};
                    } else if constexpr (std::is_same_v<T, exit_halt_t>) {
                        status = halt_status();
                    } else {
                        status = exit_panic_t {};
                    }
                }, m_res);
            }
        } catch (const std::exception &) {
            status = exit_panic_t {};
        }
        return {
            numeric_cast<gas_t::base_type>(gas_begin - m->gas()),
            std::get<invocation_result_base_t>(std::move(status))
        };
    }
}
