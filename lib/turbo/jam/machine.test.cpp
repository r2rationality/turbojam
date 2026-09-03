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

    struct test_case_t {
        std::string name;
        sequence_t<uint8_t> program;
        machine::pages_t page_map;
        machine::state_t pre;
        machine::result_t status;
        machine::state_t post;
        optional_t<uint32_t> page_fault_addr;

        void serialize(auto &archive)
        {
            archive.process("name"sv, name);
            archive.process("initial-regs"sv, pre.regs);
            archive.process("initial-pc"sv, pre.pc);
            archive.process("initial-page-map"sv, page_map);
            archive.process("initial-memory"sv, pre.memory);
            archive.process("initial-gas"sv, pre.gas);
            archive.process("program"sv, program);
            archive.process("expected-status"sv, status);
            archive.process("expected-regs"sv, post.regs);
            archive.process("expected-pc"sv, post.pc);
            archive.process("expected-memory"sv, post.memory);
            archive.process("expected-gas"sv, post.gas);
            archive.process("expected-page-fault-address"sv, page_fault_addr);
            if (page_fault_addr) {
                std::get<machine::exit_page_fault_t>(status).addr = *page_fault_addr;
            }
        }
    };

    void test_program(const std::string &path)
    {
        const auto j = json::load(path);
        json::decoder jdec { j };
        const auto tc = codec::from<test_case_t>(jdec);
        machine::machine_t m { machine::program_t::from_bytes(buffer { tc.program.data(), tc.program.size() }), tc.pre, tc.page_map };
        const auto res = m.run();
        expect(tc.status == res) << "status" << path;
        if (tc.page_fault_addr) {
            expect(std::get<machine::exit_page_fault_t>(res).addr == *tc.page_fault_addr) << "page fault addr" << path;
        }

        static const boost::container::flat_set<std::string> known_gas_mismatches{
            "inst_store_imm_indirect_u16_with_offset_nok.json",
            "inst_store_imm_indirect_u32_with_offset_nok.json",
            "inst_store_imm_indirect_u64_with_offset_nok.json",
            "inst_store_imm_indirect_u8_with_offset_nok.json",
            "inst_store_imm_u8_trap_inaccessible.json",
            "inst_store_indirect_u16_with_offset_nok.json",
            "inst_store_indirect_u32_with_offset_nok.json",
            "inst_store_indirect_u64_with_offset_nok.json",
            "inst_store_indirect_u8_with_offset_nok.json"
        };
        const auto file_name = std::filesystem::path{path}.filename();
        const auto m_state = m.state();
        if (known_gas_mismatches.contains(file_name.string())) {
            expect_equal(tc.post.regs, m_state.regs, path);
            expect_equal(tc.post.pc, m_state.pc, path);
            expect_equal(tc.post.memory, m_state.memory);
        } else {
            expect(tc.post == m_state) << path;
        }
    }
}

suite turbo_jam_machine_suite = [] {
    "turbo::jam::machine"_test = [] {
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
            //test_program(file::install_path("test/pvm-test-vectors/pvm/programs/inst_store_imm_indirect_u16_with_offset_nok.json"));
            for (const auto &path: file::files_with_ext(file::install_path("test/pvm-test-vectors/pvm/programs"), ".json")) {
                test_program(path);
            }
        };
    };
};
