/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <cstdint>
#include <turbo/common/test.hpp>
#include <turbo/codec/json.hpp>
#include "machine.hpp"
#include "types.hpp"

namespace {
    using namespace std::string_view_literals;
    using namespace turbo;
    using namespace turbo::codec;
    using namespace turbo::jam;

    struct memory_chunk_t: codec::serializable_t<memory_chunk_t> {
        uint32_t address;
        sequence_t<uint8_t> contents;

        void serialize(auto &archive)
        {
            archive.process("address"sv, address);
            archive.process("contents"sv, contents);
        }
    };
    using memory_chunks_t = sequence_t<memory_chunk_t>;

    struct page_t: codec::serializable_t<page_t> {
        uint32_t address;
        uint32_t length;
        bool is_writable;

        void serialize(auto &archive)
        {
            archive.process("address"sv, address);
            archive.process("length"sv, length);
            archive.process("is-writable"sv, is_writable);
        }
    };
    using pages_t = sequence_t<page_t>;

    using status_base_t = std::variant<machine::exit_panic_t, machine::exit_halt_t, machine::exit_page_fault_t>;
    struct machine_status_t: status_base_t {
        using base_type = status_base_t;
        using base_type::base_type;

        static machine_status_t from_json(const json::value &j)
        {
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

    struct machine_state_t {
        fixed_sequence_t<uint64_t, 13> regs;
        uint32_t pc;
        memory_chunks_t memory;
        int64_t gas;
    };

    struct test_case_t: codec::serializable_t<test_case_t> {
        std::string name;
        sequence_t<uint8_t> program;
        pages_t page_map;
        machine_state_t pre;
        machine_status_t status;
        machine_state_t post;
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
        }
    };

    void test_program(const std::string &path)
    {
        const auto j = json::load(path);
        json::decoder jdec { j };
        const auto tc = test_case_t::from(jdec);
        expect(false) << path;
    }
}

suite turbo_jam_machine_suite = [] {
    "turbo::jam::machine"_test = [] {
        for (const auto &path: file::files_with_ext(file::install_path("test/pvm-test-vectors/pvm/programs"), ".json")) {
            test_program(path);
        }
    };
};
