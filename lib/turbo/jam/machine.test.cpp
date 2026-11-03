/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <future>
#include <initializer_list>
#include <latch>
#include <turbo/crypto/blake2b.hpp>
#include <turbo/common/cli.hpp>
#include <turbo/common/test.hpp>
#include <turbo/codec/json.hpp>
#include "machine.hpp"
#include "machine/program-builder.hpp"

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
    using steps_t = sequence_t<step_t>;

    using block_gas_map_base_t = boost::container::flat_map<machine::address_val_t, gas_t>;
    struct block_gas_map_t: block_gas_map_base_t {
        using base_type = block_gas_map_base_t;
        using base_type::base_type;

        static block_gas_map_t from_json(const boost::json::value &j)
        {
            block_gas_map_t res{};
            const auto &m = j.as_object();
            res.reserve(m.size());
            for (const auto &[k, v] : m) {
                res.emplace_hint(res.end(), turbo::cli::from_str<machine::address_val_t>(k), numeric_cast<gas_t>(v.as_int64()));
            }
            return res;
        }
    };

    struct test_case_t {
        std::string name;
        machine::address_val_t initial_pc;
        machine::gas_remaining_t initial_gas;
        sequence_t<uint8_t> program;
        block_gas_map_t block_gas_costs;
        steps_t steps;

        void serialize(auto &archive)
        {
            archive.process("name"sv, name);
            archive.process("initial-pc"sv, initial_pc);
            archive.process("initial-gas"sv, initial_gas);
            archive.process("program"sv, program);
            {
                block_gas_costs_t costs{};
                archive.process("block-gas-costs"sv, costs);
                block_gas_costs.clear();
                block_gas_costs.reserve(costs.size());
                for (const auto &[pc, gas]: costs) {
                    block_gas_costs.emplace_hint(block_gas_costs.end(), pc, gas);
                }
            }
            archive.process("steps"sv, steps);
        }
    };

    struct test_case_gas_t {
        std::string name;
        sequence_t<uint8_t> program;
        block_gas_map_t block_gas_costs;

        void serialize(auto &archive)
        {
            archive.process("name"sv, name);
            archive.process("program"sv, program);
            archive.process("block-gas-costs"sv, block_gas_costs);
        }
    };

    template<typename CFG=config_prod>
    void test_case(const std::string &path, const test_case_t &tc)
    {
        const machine::state_t init_state{.pc=tc.initial_pc, .gas = tc.initial_gas};
        const machine::pages_t init_pages{};
        auto code = machine::code_t::from_bytes(buffer{tc.program.data(), tc.program.size()});
        {
            const auto &blocks = code.blocks();
            if (blocks.size() != tc.block_gas_costs.size()) [[unlikely]]
                throw error{"expected block counts differ from the simulated ones: {} != {}", tc.block_gas_costs.size(), blocks.size()};
            for (const auto &[i, exp_blk]: tc.block_gas_costs | std::views::enumerate) {
                const auto &sim_blk = *blocks.nth(i);
                if (sim_blk.first != exp_blk.first)
                    throw error{"block #{} does not match address: {} != {}", i, sim_blk.first, exp_blk.first};
                if (sim_blk.second.cost != exp_blk.second)
                    throw error{"block #{} does not match gas: {} != {}", i, sim_blk.second.cost, exp_blk.second};
            }
        }
        machine::machine_t m{std::move(code), init_state, init_pages};
        std::optional<machine::result_t> run_res{};
        for (const auto &step: tc.steps) {
            std::visit([&](const auto &s) {
                using T = std::decay_t<decltype(s)>;
                if constexpr (std::is_same_v<run_step_t, T>) {
                    if (run_res && std::holds_alternative<machine::exit_host_call_t>(*run_res)) {
                        // Resume after the suspended ecalli.
                        m.skip_op();
                    }
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
                    m.mem_initialize(s.address, s.contents);
                } else if constexpr (std::is_same_v<set_reg_step_t, T>) {
                    m.set_reg(s.reg, s.value);
                } else {
                    throw error{"unsupported type: {}", typeid(T).name()};
                }
            }, step);
        }
    }

    void test_program(const std::string &path)
    {
        try {
            const auto tc = json::load_obj<test_case_t>(path);
            test_case(path, tc);
        } catch (const std::exception &ex) {
            expect(false) << path << ": exception: " << ex.what();
        }
    }

    void test_gas(const std::string &path)
    {
        try {
            const auto t = json::load_obj<test_case_gas_t>(path);
            test_case(path, test_case_t{
                .name = std::move(t.name),
                .initial_pc = 0U,
                .initial_gas = 0U,
                .program = std::move(t.program),
                .block_gas_costs = std::move(t.block_gas_costs),
                .steps = steps_t{run_step_t{}}
            });
        } catch (const std::exception &ex) {
            expect(false) << path << ": exception: " << ex.what();
        }
    }

    machine::code_t control_flow_code(uint8_vector instrs, const std::initializer_list<size_t> starts,
        machine::code_t::offset_list_t jump_table = {})
    {
        uint8_vector bits((instrs.size() + 7U) / 8U, 0);
        for (const auto pc: starts)
            bits.at(pc / 8U) |= uint8_t{1} << (pc % 8U);
        machine::bit_vector_t bitmask{buffer{bits.data(), bits.size()}, instrs.size()};
        return {std::move(bitmask), std::move(instrs), std::move(jump_table)};
    }
}

suite turbo_jam_machine_suite = [] {
    "turbo::jam::machine"_test = [] {
        "cached configuration shares code but preserves invocation state and validation"_test = [] {
            machine::program_builder_t program{};
            program.load(7, 42);
            program.ecalli(0);
            const auto blob = program.program_bytes();
            const auto hash = crypto::blake2b::digest<opaque_hash_t>(blob);
            auto first = machine::configure(blob, 0, 1000, {}, blob.size(), hash);
            auto second = machine::configure(blob, 0, 2000, {}, blob.size(), hash);
            auto uncached = machine::configure(blob, 0, 1000, {}, blob.size());
            expect(first.has_value() && second.has_value() && uncached.has_value()) << fatal;
            expect(&first->code() == &second->code());
            const auto second_registers = second->regs();
            const auto result = first->run();
            expect(std::holds_alternative<machine::exit_host_call_t>(result));
            expect_equal(machine::register_val_t{42}, first->regs()[7]);
            expect(second_registers == second->regs());
            expect_equal(machine::gas_remaining_t{2000}, second->gas());
            expect(result == uncached->run());
            expect(first->state() == uncached->state());
            expect(!machine::configure(blob, 0, 1000, {}, 0, hash));

            auto invalid_code = program.code_bytes();
            auto invalid_blob = blob;
            invalid_code.back() = 0; // Missing delimiter boundary.
            invalid_blob.back() = 0;
            const auto invalid_hash = crypto::blake2b::digest<opaque_hash_t>(invalid_blob);
            expect(throws<error>([&] { (void)machine::code_t::from_bytes_cached(invalid_code, invalid_hash); }));
            expect(!machine::configure(invalid_blob, 0, 1000, {}, invalid_blob.size(), invalid_hash));
            expect(throws<error>([] { (void)machine::machine_t{std::shared_ptr<const machine::code_t>{}, {}, {}}; }));
        };
        "decoded program cache evicts the least recently used program without invalidating machines"_test = [] {
            const auto load = [](const size_t value) {
                machine::program_builder_t program{};
                program.load(7, value);
                const auto hash = crypto::blake2b::digest<opaque_hash_t>(program.program_bytes());
                return machine::code_t::from_bytes_cached(program.code_bytes(), hash);
            };
            constexpr size_t base = 1000000;
            const auto oldest = load(base);
            const std::weak_ptr<const machine::code_t> next_oldest = load(base + 1);
            for (size_t i = 2; i < machine::code_t::cache_capacity; ++i)
                (void)load(base + i);
            expect(oldest == load(base)); // A hit makes the oldest entry most recently used.
            {
                auto retained_code = next_oldest.lock();
                expect(static_cast<bool>(retained_code)) << fatal;
                machine::machine_t retained{std::move(retained_code), {.gas=1000}, {}};
                (void)load(base + machine::code_t::cache_capacity);
                // The machine, rather than the cache, now owns this decoded program.
                const auto reloaded = load(base + 1);
                expect(&retained.code() != reloaded.get());
                expect(oldest == load(base));
                expect(std::holds_alternative<machine::exit_panic_t>(retained.run()));
                expect_equal(machine::register_val_t{base + 1}, retained.regs()[7]);
            }
            expect(next_oldest.expired());
        };
        "decoded program cache concurrent reuse smoke test"_test = [] {
            machine::program_builder_t program{};
            program.load(7, 2000000);
            const auto bytes = program.code_bytes();
            const auto hash = crypto::blake2b::digest<opaque_hash_t>(program.program_bytes());
            // Concurrent callers do not guarantee overlapping cache misses.
            std::array<std::future<std::shared_ptr<const machine::code_t>>, 2> results;
            std::latch start{numeric_cast<ptrdiff_t>(results.size())};
            for (auto &result: results) {
                result = std::async(std::launch::async, [&] {
                    start.count_down();
                    start.wait();
                    return machine::code_t::from_bytes_cached(bytes, hash);
                });
            }
            const auto first = results[0].get();
            expect(first == results[1].get());
            expect(first == machine::code_t::from_bytes_cached(bytes, hash));
        };
        "shared opcode ranges survive program moves and execute all blocks"_test = [] {
            for (const size_t count: {0U, 1U, 33U, 96U}) {
                machine::program_builder_t program{};
                for (size_t i = 0; i < count; ++i) {
                    program.load(7, i + 1);
                    for (size_t j = 0; j < i % 3; ++j)
                        program.move(8, 7);
                    program.emit({1}); // fallthrough to the next block
                }
                auto code = [&] {
                    auto original = program.build_code();
                    return machine::code_t{std::move(original)};
                }(); // The original owner is destroyed before any opcode view is read.
                expect_equal(count + 1, code.blocks().size()); // includes the delimiter trap

                size_t block_index = 0;
                size_t opcode_offset = 0;
                gas_t total_cost = 0;
                const machine::code_t::opcode_t *next_opcode = nullptr;
                for (const auto &entry: code.blocks()) {
                    const auto &block = entry.second;
                    const auto ops = code.block_opcodes(block);
                    expect(!ops.empty()) << fatal;
                    expect_equal(opcode_offset, block.opcode_offset);
                    if (next_opcode)
                        expect(ops.data() == next_opcode);
                    if (block_index < count) {
                        expect_equal(block_index % 3 + 2, ops.size());
                        expect(ops.front().id == 51); // load_imm
                        expect_equal(block_index + 1, ops.front().imm_1);
                        for (size_t i = 1; i + 1 < ops.size(); ++i)
                            expect(ops[i].id == 100); // move_reg
                        expect(ops.back().id == 1); // fallthrough
                    } else {
                        expect_equal(size_t{1}, ops.size());
                        expect(ops.front().id == 0); // trap
                    }
                    next_opcode = ops.data() + ops.size();
                    opcode_offset += ops.size();
                    total_cost += block.cost;
                    ++block_index;
                }

                constexpr gas_t initial_gas = 100000;
                machine::machine_t m{std::move(code), {.gas=initial_gas}, {}};
                expect(std::holds_alternative<machine::exit_panic_t>(m.run()));
                expect_equal(count, m.regs()[7]);
                expect_equal(initial_gas - total_cost, m.gas());
            }
        };
        "gas model stalled cycles release execution units at the earliest completion"_test = [] {
            for (const size_t count: {1U, 2U, 4U, 5U, 9U, 33U}) {
                machine::program_builder_t program{};
                for (size_t i = 0; i < count; ++i)
                    program.ecalli(0);
                const auto code = program.build_code();
                expect_equal(size_t{1}, code.blocks().size());
                const auto &block = code.blocks().at(0);
                // Each host call occupies one of four ALUs for 100 cycles. Decoding
                // staggers their starts by one tick, and a fifth call waits for an ALU.
                expect_equal(gas_t{100} * ((count + 3) / 4) + (count - 1) % 4, block.cost);
                expect_equal(count + 1, code.block_opcodes(block).size());
            }
        };
        "gas model stalled cycles wake dependent instructions before longer executions finish"_test = [] {
            machine::program_builder_t program{};
            program.ecalli(0); // runs independently for 100 cycles
            program.emit({202, 0x21, 0}); // mul_64 r1, r2 -> r0
            program.emit({200, 0x10, 3}); // add_64 r0, r1 -> r3
            program.emit({203, 0x23, 4}); // div_u_64 r3, r2 -> r4
            program.emit({203, 0x24, 5}); // div_u_64 r4, r2 -> r5
            const auto code = program.build_code();
            expect_equal(size_t{1}, code.blocks().size());
            const auto &block = code.blocks().at(0);
            // The multiply starts at cycle 2. Its dependent chain takes 3+1+60+60
            // cycles, completing at 126; FIN and retirement take two further ticks.
            expect_equal(gas_t{125}, block.cost);
            expect_equal(size_t{6}, code.block_opcodes(block).size());
        };
        "gas model stalled cycles preserve decode budget refills"_test = [] {
            for (const size_t moves: {0U, 1U, 4U, 156U, 157U, 160U, 161U}) {
                machine::program_builder_t program{};
                program.ecalli(0);
                for (size_t i = 0; i < moves; ++i)
                    program.move(2, 1);
                program.emit({203, 0x21, 3}); // div_u_64 r1, r2 -> r3
                const auto code = program.build_code();
                expect_equal(size_t{1}, code.blocks().size());
                const auto &block = code.blocks().at(0);
                // Moves consume decode slots without adding reorder entries. The divider
                // starts at cycle 2 + ceil(moves/4), even while the host call is running.
                expect_equal(std::max(gas_t{100}, gas_t{61} + (moves + 3) / 4), block.cost);
                expect_equal(moves + 3, code.block_opcodes(block).size());
            }
        };
        "gas model reorder buffer wraparound"_test = [] {
            for (const size_t count: {1U, 31U, 32U, 33U, 64U, 97U}) {
                machine::program_builder_t program{};
                for (size_t i = 0; i < count; ++i)
                    program.emit({203, 0x10, 0}); // div_u_64 r0, r1 -> r0
                const auto code = program.build_code();
                expect_equal(size_t{1}, code.blocks().size());
                const auto &block = code.blocks().at(0);
                // Each dependent division takes 60 cycles. The independent delimiter
                // trap finishes while the divisions fill and drain the reorder buffer.
                expect_equal(gas_t{60} * count, block.cost);
                expect_equal(count + 1, code.block_opcodes(block).size());
            }
        };
        "gas model retired dependencies and move aliases"_test = [] {
            for (const size_t count: {1U, 31U, 32U, 33U, 64U, 97U}) {
                machine::program_builder_t program{};
                for (size_t i = 0; i < count; ++i) {
                    program.load(0, 7);
                    program.emit({203, 0x21, 3}); // div_u_64 r1, r2 -> r3
                    program.move(5, 0);
                    program.move(6, 3);
                    program.emit({200, 0x65, 4}); // add_64 r5, r6 -> r4
                }
                const auto code = program.build_code();
                expect_equal(size_t{1}, code.blocks().size());
                const auto &block = code.blocks().at(0);
                // Each add depends on a load that retires before its division finishes.
                // One divider serializes the 60-cycle divisions; the initial load
                // delays the first division by one tick, and the final add takes one.
                expect_equal(gas_t{60} * count + 2, block.cost);
                expect_equal(5 * count + 1, code.block_opcodes(block).size());
            }
        };
        "gas model reused slots do not revive satisfied dependencies"_test = [] {
            machine::program_builder_t program{};
            program.emit({202, 0x21, 0}); // mul_64 r1, r2 -> r0 (slot 0)
            program.emit({203, 0x21, 3}); // div_u_64 r1, r2 -> r3 (slot 1)
            program.emit({200, 0x30, 4}); // add_64 r0, r3 -> r4 (depends on both)
            for (size_t i = 0; i < 29; ++i)
                program.load(7, 0);
            program.emit({203, 0x21, 5}); // reuses slot 0 after the multiply retires

            const auto code = program.build_code();
            expect_equal(size_t{1}, code.blocks().size());
            const auto &block = code.blocks().at(0);
            // The add can start alongside the second division, without waiting for it.
            // Two serialized 60-cycle divisions plus one initial decode stall cost 121.
            expect_equal(gas_t{121}, block.cost);
            expect_equal(size_t{34}, code.block_opcodes(block).size());
        };
        "gas model moves with an empty reorder buffer"_test = [] {
            for (const size_t count: {0U, 31U, 32U, 33U, 64U, 97U}) {
                machine::program_builder_t program{};
                for (size_t i = 0; i < count; ++i)
                    program.move(1, 0);
                const auto code = program.build_code();
                expect_equal(size_t{1}, code.blocks().size());
                const auto &block = code.blocks().at(0);
                // Moves use only decode slots (four per cycle); the delimiter costs two.
                expect_equal(gas_t{count / 4 + 2}, block.cost);
                expect_equal(count + 1, code.block_opcodes(block).size());
            }
        };
        //test_gas(file::install_path("test/pvm-test-vectors/pvm/gas-tests/pinky.json"));
        //test_program(file::install_path("test/pvm-test-vectors/pvm/programs/riscv_rv64ua_amoadd_d.json"));
        "jump destinations"_test = [] {
            // jump; load_imm r0, 7; ecalli 0; trap. Only PCs 0 and 2 start blocks.
            for (const bool indirect: {false, true}) {
                for (const uint8_t target: {2, 3, 5, 8, 255}) {
                    auto code = indirect
                        ? control_flow_code({50, 0, 51, 0, 7, 10, 0, 0}, {0, 2, 5, 7}, {target})
                        : control_flow_code({40, target, 51, 0, 7, 10, 0, 0}, {0, 2, 5, 7});
                    const auto source_cost = code.blocks().at(0).cost;
                    const auto destination_cost = code.blocks().at(2).cost;
                    machine::state_t init{.gas=10000};
                    init.regs[0] = indirect ? 2 : 41;
                    machine::machine_t m{std::move(code), init, {}};
                    const auto res = m.run();
                    if (target == 2) {
                        expect(std::holds_alternative<machine::exit_host_call_t>(res));
                        expect_equal(machine::register_val_t{7}, m.regs()[0]);
                        expect_equal(init.gas - source_cost - destination_cost, m.gas());
                    } else {
                        expect(std::holds_alternative<machine::exit_panic_t>(res));
                        expect_equal(init.regs[0], m.regs()[0]);
                        expect_equal(init.gas - source_cost, m.gas());
                    }
                }
            }
        };
        "conditional destinations"_test = [] {
            for (const bool taken: {false, true}) {
                for (const uint8_t target: {3, 4, 6, 9, 255}) {
                    // branch_eq_imm r0, 0, target; load_imm r1, 7; ecalli 0; trap.
                    auto code = control_flow_code({81, 0, target, 51, 1, 7, 10, 0, 0}, {0, 3, 6, 8});
                    const auto source_cost = code.blocks().at(0).cost;
                    machine::state_t init{.gas=10000};
                    init.regs[0] = taken ? 0 : 1;
                    init.regs[1] = 41;
                    machine::machine_t m{std::move(code), init, {}};
                    const auto res = m.run();
                    if (target == 3) {
                        expect(std::holds_alternative<machine::exit_host_call_t>(res));
                        expect_equal(machine::register_val_t{7}, m.regs()[1]);
                    } else {
                        expect(std::holds_alternative<machine::exit_panic_t>(res));
                        expect_equal(init.regs[1], m.regs()[1]);
                        expect_equal(init.gas - source_cost, m.gas());
                    }
                }
                for (const bool immediate: {false, true}) {
                    // The target is valid PC 0, but fallthrough is past the end of code.
                    auto code = immediate
                        ? control_flow_code({81, 0, 0}, {0})
                        : control_flow_code({170, 0x10, 0}, {0});
                    const auto cost = code.blocks().at(0).cost;
                    machine::state_t init{.gas=10000};
                    init.regs[0] = taken ? 0 : 1;
                    machine::machine_t m{std::move(code), init, {}};
                    expect(std::holds_alternative<machine::exit_panic_t>(m.run()));
                    expect_equal(init.gas - cost, m.gas());
                }
            }
        };
        "interior entry and resumption"_test = [] {
            for (const bool initially_out_of_gas: {false, true}) {
                // Start at ecalli, skipping load_imm, while paying for the whole block.
                auto code = control_flow_code({51, 0, 7, 10, 0, 0}, {0, 3, 5});
                const auto cost = code.blocks().at(0).cost;
                machine::state_t init{.pc=3, .gas=initially_out_of_gas ? 0ULL : 10000ULL};
                init.regs[0] = 41;
                machine::machine_t m{std::move(code), init, {}};
                if (initially_out_of_gas) {
                    expect(std::holds_alternative<machine::exit_out_of_gas_t>(m.run()));
                    expect_equal(machine::address_val_t{3}, m.pc());
                    expect_equal(machine::gas_remaining_t{0}, m.gas());
                    m.set_gas(10000);
                }
                expect(std::holds_alternative<machine::exit_host_call_t>(m.run()));
                expect_equal(init.regs[0], m.regs()[0]);
                expect_equal(10000 - cost, m.gas());
                m.skip_op();
                expect(std::holds_alternative<machine::exit_panic_t>(m.run()));
                expect_equal(10000 - cost, m.gas());
            }
            for (const machine::address_val_t pc: {1, 6}) {
                auto code = control_flow_code({51, 0, 7, 10, 0, 0}, {0, 3, 5});
                machine::machine_t m{std::move(code), {.pc=pc, .gas=10000}, {}};
                expect(std::holds_alternative<machine::exit_panic_t>(m.run()));
                expect_equal(machine::gas_remaining_t{10000}, m.gas());
            }
        };
        "fallthrough transition"_test = [] {
            auto code = control_flow_code({1, 10, 0, 0}, {0, 1, 3});
            const auto cost = code.blocks().at(0).cost + code.blocks().at(1).cost;
            machine::machine_t m{std::move(code), {.gas=10000}, {}};
            expect(std::holds_alternative<machine::exit_host_call_t>(m.run()));
            expect_equal(10000 - cost, m.gas());
        };
        "sign_extend"_test = [] {
            static constexpr machine::register_val_t neg1 = -1LL;
            for (size_t num_bytes: { 1, 2, 3, 4, 5, 6, 7, 8 }) {
                expect_equal(0x00ULL, machine::code_t::sign_extend(num_bytes, 0x00ULL));
                expect_equal(0x01ULL, machine::code_t::sign_extend(num_bytes, 0x01ULL));
                expect_equal(0xFFFFFFFFFFFFFFFFULL, machine::code_t::sign_extend(num_bytes, neg1 >> ((8U - num_bytes) << 3U)));
            }
            expect_equal(0xFFFFFFFFFF800000ULL, machine::code_t::sign_extend(3, 0x800000ULL));
        };
        "configure"_test = [] {
            const auto blob = file::read(file::install_path("test/pvm-my/jam-cardano.jam"));
            const auto m = machine::configure(blob, 0U, 1000U, buffer{});
        };
        "conformance program tests"_test = [] {
            for (const auto &path: file::files_with_ext(file::install_path("test/pvm-test-vectors/pvm/programs"), ".json")) {
                test_program(path);
            }
        };
        "conformance gas tests"_test = [] {
            for (const auto &path: file::files_with_ext(file::install_path("test/pvm-test-vectors/pvm/gas-tests"), ".json")) {
                test_gas(path);
            }
        };
    };
};
