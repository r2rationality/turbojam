#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <cstdint>
#include <variant>
#include "types/constants.hpp"
#include "encoding.hpp"
#include "types.hpp"

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
            if (address % config_prod::pvm_page_size != 0) [[unlikely]]
                throw error(fmt::format("an invalid page address: {}", address));
            archive.process("length"sv, length);
            if (length % config_prod::pvm_page_size != 0) [[unlikely]]
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

    struct bit_buffer_t: buffer {
        using base_type = buffer;

        bit_buffer_t(const buffer bytes, const size_t num_bits):
            buffer { bytes },
            _bit_size { num_bits }
        {
        }

        [[nodiscard]] size_t size() const
        {
            return _bit_size;
        }

        [[nodiscard]] bool test(const size_t pos) const
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
        register_val_t addr = 0;

        bool operator==(const exit_page_fault_t &o) const
        {
            if (addr != o.addr)
                return false;
            return true;
        }
    };
    struct exit_host_call_t final {
        register_val_t id = 0;

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
        using offset_list = std::vector<uint32_t>;

        offset_list jump_table;
        buffer code;
        bit_buffer_t bitmasks;

        static program_t from_bytes(decoder &dec)
        {
            const auto jt_sz = dec.uint_varlen();
            const auto jt_offset_sz = dec.uint_fixed<uint8_t>(1);
            const auto code_sz = dec.uint_varlen();
            offset_list jt {};
            jt.reserve(jt_sz);
            while (jt.size() < jt_sz) {
                jt.emplace_back(dec.uint_fixed<uint32_t>(jt_offset_sz));
            }
            const auto code = dec.next_bytes(code_sz);
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
        machine_t(const program_t &program, const state_t &init, const pages_t &page_map);
        ~machine_t();
        result_t run();
        [[nodiscard]] const registers_t &regs() const;
        [[nodiscard]] uint32_t pc() const;
        [[nodiscard]] gas_remaining_t gas() const;
        [[nodiscard]] std::optional<uint8_vector> mem(size_t offset, size_t sz) const;
        [[nodiscard]] state_t state() const;
    private:
        struct impl;
        byte_array<304> _impl_storage;

        impl *_impl_ptr();
    };

    using invocation_result_base_t = std::variant<uint8_vector, machine::exit_panic_t, machine::exit_out_of_gas_t>;
    struct invocation_result_t: invocation_result_base_t {
        using base_type = invocation_result_base_t;
        using base_type::base_type;
    };

    struct invocation_t {
        gas_t gas_used {};
        invocation_result_base_t result;
    };

    extern invocation_t invoke(buffer code, uint32_t pc, gas_t gas, buffer args);
}
