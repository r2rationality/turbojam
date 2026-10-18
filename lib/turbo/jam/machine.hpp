#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <algorithm>
#include <array>
#include <bit>
#include <cstdint>
#include <exception>
#include <optional>
#include <type_traits>
#include <variant>
#include <turbo/jam/types/constants.hpp>
#include <turbo/jam/encoding.hpp>
#include <turbo/jam/machine/common.hpp>
#include <turbo/jam/machine/program.hpp>

namespace turbo::jam::machine {
    struct memory_chunk_t {
        address_val_t address = 0;
        byte_sequence_t contents{};

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

    struct page_init_method_t {
        enum access_t {none, read, write};
        enum data_t {zero, existing};

        const access_t access = none;
        const data_t data = zero;

        static page_init_method_t from_code(const register_val_t r) {
            switch (r) {
            case 0: return {none, zero};
            case 1: return {read, zero};
            case 2: return {write, zero};
            case 3: return {read, existing};
            case 4: return {write, existing};
            default: [[unlikely]]
                throw error(fmt::format("invalid page init code: {}", r));
            }
        }

        page_init_method_t() = delete;

        page_init_method_t(const access_t a, const data_t d):
            access{a},
            data{d}
        {}
    };

    struct page_t {
        address_val_t address = 0;
        address_val_t length = 0;
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
        address_val_t pc {};
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
            if (gas != o.gas)
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
                return {exit_panic_t{}};
            if (val == "halt"sv)
                return {exit_halt_t{}};
            if (val == "page-fault"sv)
                return {exit_page_fault_t{}};
            if (val == "out-of-gas"sv)
                return {exit_out_of_gas_t{}};
            if (val == "ecalli"sv)
                return {exit_host_call_t{}};
            throw error(fmt::format("unsupported machine_status_t value '{}'", val));
        }

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            static constexpr codec::variant_names_t<base_type> names{
                "halt"sv, "panic"sv, "out-of-gas"sv, "page-fault"sv, "ecalli"sv
            };
            archive.process(codec::as_variant_t<base_type>{*this, names});
        }
    };

    struct machine_t {
        [[nodiscard]] static bool is_opcode(uint8_t);

        machine_t() =delete;
        machine_t(const machine_t &o) =delete;
        machine_t(machine_t &&o);
        machine_t(code_t &&code, const state_t &init, const pages_t &page_map);
        ~machine_t();
        result_t run();
        void consume_gas(gas_t gas);
        void set_gas(gas_t gas);
        void set_reg(size_t id, register_val_t val);
        void set_regs(const registers_t &regs);
        bool set_pages(register_val_t p, register_val_t sz, page_init_method_t i);
        [[nodiscard]] std::optional<exit_page_fault_t> mem_writable(register_val_t offset, register_val_t sz) const;
        [[nodiscard]] std::optional<exit_page_fault_t> mem_readable(register_val_t offset, register_val_t sz) const;
        void mem_copy(const machine_t &src, register_val_t dst_offset, register_val_t src_offset, register_val_t sz);
        void mem_write(register_val_t offset, buffer data);
        // Populate mapped memory without changing its page permissions.
        void mem_initialize(register_val_t offset, buffer data);
        void mem_read(std::span<uint8_t> out, register_val_t offset) const;
        [[nodiscard]] uint8_vector mem_read(register_val_t offset, register_val_t sz) const;
        void skip_op();
        [[nodiscard]] const registers_t &regs() const;
        [[nodiscard]] const code_t &code() const;
        [[nodiscard]] address_val_t pc() const;
        [[nodiscard]] gas_remaining_t gas() const;
        [[nodiscard]] std::optional<uint8_vector> try_mem_read(register_val_t offset, register_val_t sz) const noexcept;
        [[nodiscard]] state_t state() const;

        template <std::size_t... Is>
        constexpr auto regs(std::index_sequence<Is...>) {
            static_assert(((Is < registers_t::fixed_size) && ...), "invalid register index");
            const auto &r = regs();
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

    struct inner_pvm_res_t {
        static constexpr register_val_t halt = 0;
        static constexpr register_val_t panic = 1;
        static constexpr register_val_t fault = 2;
        static constexpr register_val_t host = 3;
        static constexpr register_val_t oog = 4;
    };

    struct invocation_t {
        gas_t gas_used{};
        invocation_result_base_t result;
    };

    extern std::optional<machine_t> configure(buffer blob, address_val_t pc, gas_t gas, buffer args,
        size_t max_code_size=std::numeric_limits<size_t>::max());

    // (A.44) - Psi_M
    template<typename HostInit, typename HostFn>
    invocation_t invoke(const buffer blob, const address_val_t pc, const gas_t gas, const buffer args, HostInit &&host_init, HostFn &&host_fn, const size_t max_code_size)
    {
        auto m = configure(blob, pc, gas, args, max_code_size);
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
            numeric_cast<gas_t>(gas_begin - m->gas()),
            std::get<invocation_result_base_t>(std::move(status))
        };
    }

    inline bool code_t::is_opcode(uint8_t opcode) {
        return machine_t::is_opcode(opcode);
    }
} // namespace turbo::jam::machine
