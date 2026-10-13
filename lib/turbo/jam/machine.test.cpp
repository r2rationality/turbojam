/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/test.hpp>
#include <turbo/codec/json.hpp>
#include "machine.hpp"

namespace {
    using namespace std::string_view_literals;
    using namespace turbo;
    using namespace turbo::codec;
    using namespace turbo::jam;

    struct block_gas_cost_t {
        machine::address_val_t pc;
        gas_t cost;

        void serialize(auto &archive) {
            archive.process("pc"sv, pc);
            archive.process("cost"sv, cost);
        }
    };

    struct run_step_t {
        void serialize(auto &archive) {
        }
    };

    struct assert_step_t {
        machine::result_t status;
        std::optional<machine::registers_t> regs;
        std::optional<machine::address_val_t> pc;
        std::optional<machine::memory_chunks_t> memory;
        std::optional<machine::gas_remaining_t> gas;

        void serialize(auto &archive) {
            archive.process("status"sv, status);
            archive.process("regs"sv, regs);
            archive.process("pc"sv, pc);
            archive.process("memory"sv, memory);
            archive.process("gas"sv, gas);
            {
                std::optional<machine::address_val_t> page_fault_address{};
                archive.process("page-fault-address"sv, page_fault_address);
                if (page_fault_address) {
                    if (!std::holds_alternative<machine::exit_page_fault_t>(status)) [[unlikely]]
                        throw error{"page-fault-address must be set only for page-fault status but have: {}", status};
                    std::get<machine::exit_page_fault_t>(status).addr = *page_fault_address;
                }
            }
            {
                std::optional<uint32_t> host_call;
                archive.process("hostcall"sv, host_call);
                if (host_call) {
                    if (!std::holds_alternative<machine::exit_host_call_t>(status)) [[unlikely]]
                        throw error{"hostcall must be set only for host-call status but have: {}", status};
                    std::get<machine::exit_host_call_t>(status).id = *host_call;
                }
            }
        }
    };

    struct set_reg_step_t {
        machine::register_idx_t reg;
        machine::register_val_t value;

        void serialize(auto &archive) {
            archive.process("reg"sv, reg);
            archive.process("value"sv, value);
        }
    };

    using map_step_t = machine::page_t;
    using write_step_t = machine::memory_chunk_t;

    using step_base_t = std::variant<run_step_t, assert_step_t, map_step_t, write_step_t, set_reg_step_t>;
    struct step_t: step_base_t {
        using base_type = step_base_t;
        using base_type::base_type;

        void serialize(auto &archive) {
            static constexpr codec::variant_names_t<base_type> names{
                "run"sv,
                "assert"sv,
                "map"sv,
                "write"sv,
                "set-reg"sv
            };
            archive.process(codec::as_variant<base_type>(*this, names));
        }
    };

    using block_gas_costs_t = sequence_t<block_gas_cost_t>;

    struct test_case_t {
        std::string name;
        machine::address_val_t initial_pc;
        machine::gas_remaining_t initial_gas;
        sequence_t<uint8_t> program;
        block_gas_costs_t block_gas_costs;
        sequence_t<step_t> steps;

        void serialize(auto &archive)
        {
            archive.process("name"sv, name);
            archive.process("initial-pc"sv, initial_pc);
            archive.process("initial-gas"sv, initial_gas);
            archive.process("program"sv, program);
            archive.process("block-gas-costs"sv, block_gas_costs);
            archive.process("steps"sv, steps);
        }
    };

    template<typename CFG=config_prod>
    void test_program(const std::string &path)
    {
        try {
            const auto tc = json::load_obj<test_case_t>(path);
            const machine::state_t init_state{.pc=tc.initial_pc, .gas = tc.initial_gas};
            const machine::pages_t init_pages{};
            machine::machine_t m{machine::code_t::from_bytes(buffer{tc.program.data(), tc.program.size()}), init_state, init_pages};
            std::optional<machine::result_t> run_res{};
            for (const auto &step: tc.steps) {
                std::visit([&](const auto &s) {
                    using T = std::decay_t<decltype(s)>;
                    if constexpr (std::is_same_v<run_step_t, T>) {
                        run_res.emplace(m.run());
                    } else if constexpr (std::is_same_v<assert_step_t, T>) {
                        if (expect(run_res.has_value())) {
                            expect_equal(s.status, *run_res, path);
                        }
                    } else if constexpr (std::is_same_v<assert_step_t, T>) {
                        if (expect(run_res.has_value())) {
                            expect_equal(s.status, *run_res, path);
                        }
                    } else if constexpr (std::is_same_v<map_step_t, T>) {
                        if (s.address % CFG::ZP_pvm_page_size) [[unlikely]]
                            throw error{"map addresses must be at page boundary but got: {}", s.address};
                        if (s.length % CFG::ZP_pvm_page_size) [[unlikely]]
                            throw error{"map lengths must be in increments of page size but got: {}", s.length};
                        m.set_pages(s.address / CFG::ZP_pvm_page_size, s.length / CFG::ZP_pvm_page_size, machine::page_init_method_t::from_code(s.is_writable ? 2 : 1));
                    } else if constexpr (std::is_same_v<write_step_t, T>) {
                        m.mem_write(s.address, s.contents);
                    } else if constexpr (std::is_same_v<set_reg_step_t, T>) {
                        m.set_reg(s.reg, s.value);
                    } else {
                        throw error{"unsupported type: {}", typeid(T).name()};
                    }
                }, step);
            }
        } catch (const std::exception &ex) {
            expect(false) << path << ": exception: " << ex.what();
        }
    }
}

suite turbo_jam_machine_suite = [] {
    "turbo::jam::machine"_test = [] {
        //test_program(file::install_path("test/pvm-test-vectors/pvm/programs/multistep_ecalli_at_the_start_of_block.json"));
        "sign_extend"_test = [] {
            static constexpr machine::register_val_t neg1 = -1LL;
            for (size_t num_bytes: { 1, 2, 3, 4, 5, 6, 7, 8 }) {
                expect_equal(0x00ULL, machine::sign_extend(num_bytes, 0x00ULL));
                expect_equal(0x01ULL, machine::sign_extend(num_bytes, 0x01ULL));
                expect_equal(0xFFFFFFFFFFFFFFFFULL, machine::sign_extend(num_bytes, neg1 >> ((8U - num_bytes) << 3U)));
            }
            expect_equal(0xFFFFFFFFFF800000ULL, machine::sign_extend(3, 0x800000ULL));
        };
        "configure"_test = [] {
            const auto blob = file::read(file::install_path("test/pvm-my/jam-cardano.jam"));
            const auto m = machine::configure(blob, 0U, 1000U, buffer{});
        };
        "conformance tests"_test = [] {
            for (const auto &path: file::files_with_ext(file::install_path("test/pvm-test-vectors/pvm/programs"), ".json")) {
                test_program(path);
            }
        };
    };
};
