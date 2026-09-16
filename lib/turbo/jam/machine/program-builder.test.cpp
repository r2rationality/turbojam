/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/test.hpp>
#include "program-builder.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jam;
}

suite turbo_jam_machine_program_builder_suite = [] {
    "turbo::jam::machine::program_builder"_test = [] {
        "program encoding remains valid across bitmask byte and varint length boundaries"_test = [] {
            for (const machine::address_val_t size: {0U, 7U, 8U, 126U, 127U, 128U, 16382U, 16383U, 16384U}) {
                machine::program_builder_t program{};
                program.pad_code(size);
                const uint8_vector metadata(size, 0xaa);
                program.set_metadata(metadata);
                const size_t image_size = 2 * size + 128;
                program.pad_image(image_size);

                const auto decoded = program.build_code();
                expect_equal(size_t{size} + 1, decoded.instrs.size());
                expect_equal(decoded.instrs.size(), decoded.bitmasks.size());
                expect(decoded.bitmasks.test(size)); // final delimiter is an instruction
                const auto image = program.data_bytes();
                expect_equal(image_size, image.size());
                const auto blob = program.program_bytes();
                jam::decoder dec{blob};
                expect_equal(metadata.size(), dec.uint_varlen<size_t>());
                expect(dec.next_bytes(metadata.size()) == static_cast<buffer>(metadata));
                expect(dec.next_bytes(image.size()) == static_cast<buffer>(image));
                expect(dec.empty());
                expect(machine::configure(blob, 0, gas_t{100}, buffer{}).has_value());
            }
        };

        "loads and moves preserve all 64 bits"_test = [] {
            for (const machine::register_val_t value: {
                0ULL, 0x7fffffffULL, 0x80000000ULL, 0xffffffffULL,
                0xffffffff80000000ULL, 0xffffffffffffffffULL, 0x123456789abcdef0ULL
            }) {
                machine::program_builder_t program{};
                program.load(12, value);
                program.move(11, 12);
                machine::machine_t m{program.build_code(), machine::state_t{.gas=100}, {}};
                expect(std::holds_alternative<machine::exit_panic_t>(m.run())); // final delimiter trap
                expect_equal(value, m.regs()[12]);
                expect_equal(value, m.regs()[11]);
            }
        };

        "entry points and writable output"_test = [] {
            for (const machine::address_val_t pc: {0U, 5U}) {
                machine::program_builder_t blob{};
                // Cross a zone boundary so the writable base cannot be a fixed test constant.
                const uint8_vector read_only(config_prod::ZZ_pvm_init_zone_size + 1, 0x5a);
                const auto read_address = blob.append_readonly(read_only);
                const uint8_vector output{0, 1, 2, 3, 0xff};
                const uint8_vector prefix{9, 8, 7};
                const auto prefix_address = blob.append_writeable(prefix);
                const auto write_address = blob.append_writeable(uint8_vector(output.size(), 0));
                expect_equal(prefix_address + prefix.size(), write_address);
                blob.pad_code(pc);
                blob.return_bytes(write_address, numeric_cast<uint32_t>(output.size()));

                const auto bytes = blob.program_bytes();
                const auto result = machine::invoke(bytes, pc, gas_t{100}, buffer{},
                    [&](machine::machine_t &m) {
                        expect(m.mem_read(read_address, read_only.size()) == read_only);
                        expect(m.mem_read(prefix_address, prefix.size()) == prefix);
                        expect(m.mem_read(write_address, output.size()) == uint8_vector(output.size(), 0));
                        m.mem_write(write_address, output);
                    },
                    [](machine::register_val_t) -> machine::host_call_res_t { return {}; },
                    config_tiny::WC_max_service_code_size);
                expect(std::holds_alternative<uint8_vector>(result.result)) << fatal;
                expect(std::get<uint8_vector>(result.result) == output);
            }
        };

        "ecalli sign extends its immediate"_test = [] {
            for (const int32_t id: {std::numeric_limits<int32_t>::min(), int32_t{-1}, int32_t{0}, std::numeric_limits<int32_t>::max()}) {
                machine::program_builder_t program{};
                program.ecalli(id);
                machine::machine_t m{program.build_code(), machine::state_t{.gas=10}, {}};
                const auto result = m.run();
                expect(std::holds_alternative<machine::exit_host_call_t>(result)) << fatal;
                expect_equal(static_cast<machine::register_val_t>(id), std::get<machine::exit_host_call_t>(result).id);
            }
        };

        "host arguments and previous results"_test = [] {
            machine::program_builder_t program{};
            constexpr machine::register_val_t large = 0x123456789abcdef0ULL;
            program.host_call(host_call_t::fetch, {large, 2, 3, 4, 5, 6});
            program.host_call(host_call_t::gas); // preserve the previous result in r7

            machine::machine_t m{program.build_code(), machine::state_t{.gas=100}, {}};
            for (const auto id: {host_call_t::fetch, host_call_t::gas}) {
                const auto result = m.run();
                expect(std::holds_alternative<machine::exit_host_call_t>(result)) << fatal;
                expect_equal(std::to_underlying(id), std::get<machine::exit_host_call_t>(result).id);
                expect_equal(id == host_call_t::fetch ? large : machine::host_call_res_t::who, m.regs()[7]);
                for (size_t reg = 8; reg <= 12; ++reg)
                    expect_equal(reg - 6, m.regs()[reg]);
                m.set_reg(7, machine::host_call_res_t::who);
                m.skip_op();
            }
        };

        "invalid builder arguments"_test = [] {
            machine::program_builder_t blob{};
            expect(throws([&] { blob.load(13, 0); }));
            expect(throws([&] { blob.load(256, 0); }));
            expect(throws([&] { blob.move(0, 13); }));
            expect(throws([&] { blob.host_call(host_call_t::fetch, {1, 2, 3, 4, 5, 6, 7}); }));
            expect(blob.code_bytes() == machine::program_builder_t{}.code_bytes());

            blob.trap();
            expect(throws([&] { blob.pad_code(0); }));
            (void)blob.append_writeable(uint8_vector{0});
            expect(throws([&] { (void)blob.append_readonly(uint8_vector{1}); }));
            expect(throws([&] { blob.pad_image(256); }));
        };
    };
};
