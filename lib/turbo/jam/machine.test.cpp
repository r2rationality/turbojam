/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/test.hpp>
#include <turbo/codec/json.hpp>
#include "machine.hpp"
#include "types.hpp"

namespace {
    using namespace std::string_view_literals;
    using namespace turbo;
    using namespace turbo::codec;
    using namespace turbo::jam;

    struct test_case_t: codec::serializable_t<test_case_t> {
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
        const auto tc = test_case_t::from(jdec);
        decoder dec { buffer { tc.program.data(), tc.program.size() } };
        const auto prg = machine::program_t::from_bytes(dec);
        machine::machine_t m { prg, tc.pre, tc.page_map };
        const auto res = m.run();
        expect(tc.status == res) << "status" << path;
        if (tc.page_fault_addr) {
            expect(std::get<machine::exit_page_fault_t>(res).addr == *tc.page_fault_addr) << "page fault addr" << path;
        }
        expect(tc.post == m.state()) << "state" << path;
    }
}

suite turbo_jam_machine_suite = [] {
    "turbo::jam::machine"_test = [] {
        test_program(file::install_path("test/pvm-test-vectors/pvm/programs/inst_store_imm_indirect_u16_with_offset_nok.json"));
        for (const auto &path: file::files_with_ext(file::install_path("test/pvm-test-vectors/pvm/programs"), ".json")) {
            test_program(path);
        }
    };
};
