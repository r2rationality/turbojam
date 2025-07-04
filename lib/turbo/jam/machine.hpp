#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <cstdint>
#include <variant>
#include "types/common.hpp"
#include "types/constants.hpp"
#include "encoding.hpp"

namespace turbo::jam::machine {
    using register_val_t = uint64_t;
    using register_val_signed_t = int64_t;
    using address_val_t = register_val_t;
    using gas_remaining_t = register_val_signed_t;

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
            // JAM Paper 0.6.4 defines the gas consumed by each of code to be 0!
            // Thus, disabling the gas check until that is changed.
            /*if (gas != o.gas)
                return false;*/
            return true;
        }
    };

    struct bit_vector_t {
        bit_vector_t() =delete;
        bit_vector_t(const bit_vector_t &o) =delete;

        bit_vector_t(const buffer bytes, const size_t num_bits):
            _num_bits { num_bits },
            _bytes { bytes }
        {
            if (_num_bits > _bytes.size() * 8) [[unlikely]]
                throw error(fmt::format("to many bits for bit vector of {} bytes: {}", _bytes.size(), _num_bits));
        }

        bit_vector_t(bit_vector_t &&o):
            _num_bits { o._num_bits },
            _bytes { std::move(o._bytes) }
        {
        }

        [[nodiscard]] size_t size() const
        {
            return _num_bits;
        }

        [[nodiscard]] bool test(const size_t pos) const
        {
            if (pos >= _num_bits) [[unlikely]]
                return true;
            const auto byte_pos = pos >> 3;
            const auto bit_pos = pos & 7;
            return (_bytes)[byte_pos] & (1 << bit_pos);
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
        using offset_list_t = std::vector<uint32_t>;

        offset_list_t jump_table;
        uint8_vector code;
        bit_vector_t bitmasks;

        program_t() =delete;
        program_t(const program_t &o) =delete;

        program_t(offset_list_t &&jt, uint8_vector &&c, bit_vector_t &&b):
            jump_table { std::move(jt) },
            code { std::move(c) },
            bitmasks { std::move(b) }
        {
        }

        program_t(program_t &&o):
            jump_table { std::move(o.jump_table) },
            code { std::move(o.code) },
            bitmasks { std::move(o.bitmasks) }
        {
        }

        static program_t from_bytes(const buffer bytes)
        {
            decoder dec { bytes };
            const auto jt_sz = dec.uint_varlen();
            const auto jt_offset_sz = dec.uint_fixed<uint8_t>(1);
            const auto code_sz = dec.uint_varlen();
            offset_list_t jt {};
            jt.reserve(jt_sz);
            while (jt.size() < jt_sz) {
                jt.emplace_back(dec.uint_fixed<uint32_t>(jt_offset_sz));
            }
            const auto code = dec.next_bytes(code_sz);
            const auto bitmasks = dec.next_bytes((code_sz + 7) / 8);
            if (!dec.empty()) [[unlikely]]
                throw error("failed to decode all bytes of the program blob");
            return {
                std::move(jt),
                uint8_vector { code },
                bit_vector_t { bitmasks, code_sz }
            };
        }
    };

    struct machine_t {
        machine_t() =delete;
        machine_t(const machine_t &o) =delete;
        machine_t(machine_t &&o);
        machine_t(program_t &&program, const state_t &init, const pages_t &page_map);
        ~machine_t();
        result_t run();
        void consume_gas(gas_t gas);
        void set_reg(size_t id, register_val_t val);
        void mem_write(size_t offset, buffer data);
        [[nodiscard]] uint8_vector mem_read(size_t offset, size_t sz) const;
        void skip_op();
        [[nodiscard]] const registers_t &regs() const;
        [[nodiscard]] uint32_t pc() const;
        [[nodiscard]] gas_remaining_t gas() const;
        [[nodiscard]] std::optional<uint8_vector> try_mem_read(size_t offset, size_t sz) const noexcept;
        [[nodiscard]] state_t state() const;
    private:
        struct impl;
        byte_array<304> _impl_storage;

        impl *_impl_ptr();
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
        gas_t gas_used {};
        invocation_result_base_t result;
    };
    using host_call_func_t = std::function<host_call_res_t(register_val_t, machine_t &)>;

    extern std::optional<machine_t> configure(buffer blob, uint32_t pc, gas_t gas, buffer args);
    extern invocation_t invoke(buffer blob, uint32_t pc, gas_t gas, buffer args, const host_call_func_t &host_fn);
}
