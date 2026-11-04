/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <initializer_list>
#include <turbo/common/test.hpp>
#include <turbo/storage/memory.hpp>
#include "host-service.hpp"
#include "machine/program-builder.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jam;

    struct host_fixture_t {
        using cfg = config_tiny;
        static constexpr service_id_t actor = 100;
        static constexpr machine::address_val_t data_address = cfg::ZZ_pvm_init_zone_size;

        accounts_t<cfg> accounts{std::make_shared<storage::memory::db_t>()};
        time_slot_t<cfg> slot{cfg::D_preimage_expunge_delay + 2};
        machine::machine_t m{
            machine::program_builder_t{}.build_code(), machine::state_t{.gas=1'000'000},
            {{.address=data_address, .length=cfg::ZP_pvm_page_size, .is_writable=true}}
        };

        machine::host_call_res_t call_host(auto &host, const host_call_t id,
            const std::initializer_list<machine::register_val_t> args)
        {
            expect(args.size() <= machine::registers_t::fixed_size - 7) << fatal;
            size_t reg = 7;
            for (const auto arg: args)
                m.set_reg(reg++, arg);
            return host.call(std::to_underlying(id));
        }
    };

    struct accumulate_host_fixture_t: host_fixture_t {
        accumulate_context_t<cfg> ok{actor, entropy_t{}, slot, mutable_state_t<cfg>{accounts, {}}};
        accumulate_context_t<cfg> err{ok};
        host_service_accumulate_t<cfg> host{
            {.m=m, .services=ok.state.services, .service_id=actor, .slot=slot, .fetch={}},
            ok, err
        };

        machine::host_call_res_t call(const host_call_t id,
            const std::initializer_list<machine::register_val_t> args)
        {
            return call_host(host, id, args);
        }
    };

    struct refine_host_fixture_t: host_fixture_t {
        account_updates_t<cfg> services{accounts};
        host_service_refine_t<cfg> host;

        explicit refine_host_fixture_t(const uint16_t export_offset=0):
            host{{.m=m, .services=services, .service_id=actor, .slot=slot, .fetch={}}, export_offset}
        {
        }

        machine::host_call_res_t call(const host_call_t id,
            const std::initializer_list<machine::register_val_t> args)
        {
            return call_host(host, id, args);
        }

        machine::register_val_t add_machine()
        {
            const auto code = machine::program_builder_t{}.code_bytes();
            m.mem_write(data_address, code);
            expect(std::holds_alternative<std::monostate>(call(host_call_t::machine, {data_address, code.size(), 0}))) << fatal;
            const auto [id] = m.regs(std::index_sequence<7>{});
            expect(id < 63U) << fatal;
            return id;
        }

        void invocation_args(const gas_t gas)
        {
            encoder enc{};
            enc.uint_fixed(8, gas);
            enc.process(machine::registers_t{});
            m.mem_write(data_address, enc.bytes());
        }
    };
}

suite turbo_jam_host_service_suite = [] {
    "turbo::jam::host_service"_test = [] {
        "accumulate"_test = [] {
            "eject validates memory before an oversized target"_test = [] {
                accumulate_host_fixture_t f{};
                const auto target = std::numeric_limits<machine::register_val_t>::max();
                expect(std::holds_alternative<machine::exit_panic_t>(f.call(host_call_t::eject, {target, 0})));
                expect_equal(target, f.m.regs()[7]);
                expect_equal(gas_t{1'000'000 - 458}, f.m.gas());
                expect(std::holds_alternative<std::monostate>(f.call(host_call_t::eject, {target, f.data_address})));
                expect_equal(machine::host_call_res_t::who, f.m.regs()[7]);
            };

            "memory faults precede service and privilege errors"_test = [] {
                const auto absent = std::numeric_limits<machine::register_val_t>::max() - 1;
                const auto check = [&](const host_call_t id, const std::initializer_list<machine::register_val_t> args) {
                    accumulate_host_fixture_t f{};
                    expect(std::holds_alternative<machine::exit_panic_t>(f.call(id, args)));
                    expect_equal(*args.begin(), f.m.regs()[7]);
                };
                check(host_call_t::lookup, {absent, 0, 0, 0, 1});
                check(host_call_t::read, {absent, 0, 1, 0, 0, 1});
                check(host_call_t::assign, {absent, 0, absent});
                check(host_call_t::designate, {0, 1});
                check(host_call_t::bless, {absent, 0, absent, absent, 0, 0});
                check(host_call_t::new_, {0, 0, 0, 0, 1, 0});
                check(host_call_t::transfer, {absent, 0, 0, 0});
                check(host_call_t::provide, {absent, 0, 1});
            };

            "invalid blob lengths precede pointer faults"_test = [] {
                const auto length = uint64_t{1} << 32U;
                for (const auto id: {host_call_t::query, host_call_t::solicit, host_call_t::forget, host_call_t::provide}) {
                    accumulate_host_fixture_t f{};
                    f.m.set_gas(100'000'000'000ULL);
                    const auto res = id == host_call_t::provide
                        ? f.call(id, {f.actor, 0, length}) : f.call(id, {0, length});
                    expect(std::holds_alternative<std::monostate>(res));
                    expect_equal(machine::host_call_res_t::huh, f.m.regs()[7]);
                }
            };

            "designate rejects an overflowing memory size before its count"_test = [] {
                accumulate_host_fixture_t f{};
                f.m.set_gas(std::numeric_limits<gas_t>::max());
                const auto count = std::numeric_limits<uint64_t>::max() / sizeof(validator_data_t) + 1;
                expect(std::holds_alternative<machine::exit_panic_t>(f.call(host_call_t::designate, {f.data_address, count})));
            };

            "failed yield preserves the previous commitment"_test = [] {
                accumulate_host_fixture_t f{};
                opaque_hash_t hash{};
                hash[0] = 1;
                f.ok.result = hash;
                // Half the next hash is readable; the rest crosses into an unmapped page.
                const auto bad_address = f.data_address + accumulate_host_fixture_t::cfg::ZP_pvm_page_size - 16;
                expect(std::holds_alternative<machine::exit_panic_t>(f.call(host_call_t::yield, {bad_address})));
                expect_equal(f.ok.result.value(), hash);
            };

            "eject rejects an oversized footprint without narrowing it"_test = [] {
                accumulate_host_fixture_t f{};
                encoder owner{};
                owner.uint_fixed(32, f.actor);
                service_info_t<accumulate_host_fixture_t::cfg> info{};
                info.code_hash = static_cast<buffer>(owner.bytes());
                info.items = 2;
                info.bytes = (uint64_t{1} << 32U) + 81;
                f.ok.state.services.info_set(200, info);
                // Narrowing the footprint to zero would otherwise allow ejection.
                f.ok.state.services.info_set(f.actor, {});
                f.ok.state.services.lookup_set(200, {opaque_hash_t{}, 0}, {0, 1});
                expect(std::holds_alternative<std::monostate>(f.call(host_call_t::eject, {200, f.data_address})));
                expect_equal(machine::host_call_res_t::huh, f.m.regs()[7]);
                expect(f.ok.state.services.info_get(200) == info);
            };

            "bless remains permissive for non-managers"_test = [] {
                accumulate_host_fixture_t f{};
                expect(f.ok.state.chi.get().bless != f.actor) << fatal;
                expect(std::holds_alternative<std::monostate>(f.call(host_call_t::bless, {1, f.data_address, 2, 3, 0, 0})));
                expect_equal(machine::host_call_res_t::ok, f.m.regs()[7]);
                expect_equal(service_id_t{1}, f.ok.state.chi.get().bless);
            };

            "grow_heap drains insufficient gas even without growth"_test = [] {
                accumulate_host_fixture_t f{};
                f.m.set_gas(274);
                expect(std::holds_alternative<machine::exit_out_of_gas_t>(f.call(host_call_t::grow_heap, {0})));
                expect_equal(gas_t{0}, f.m.gas());
            };

            "eject cannot remove the executing service"_test = [] {
                using fixture = accumulate_host_fixture_t;
                fixture f{};
                auto &services = f.ok.state.services;
                encoder owner{};
                owner.uint_fixed(32, fixture::actor);
                service_info_t<fixture::cfg> info{};
                info.code_hash = static_cast<buffer>(owner.bytes());
                info.balance = 10'000;
                info.items = 2;
                info.bytes = 81;
                services.info_set(fixture::actor, info);

                const uint8_vector preimage{};
                const lookup_meta_map_key_t key{crypto::blake2b::digest<opaque_hash_t>(preimage), 0};
                const lookup_meta_map_val_t<fixture::cfg> history{0, 1};
                services.preimage_set(fixture::actor, key.hash, preimage);
                services.lookup_set(fixture::actor, key, history);
                f.m.mem_write(fixture::data_address, key.hash);

                // All ownership, footprint, and age conditions pass; only d == s forbids ejection.
                const auto result = f.call(host_call_t::eject, {fixture::actor, fixture::data_address});
                expect(std::holds_alternative<std::monostate>(result)) << fatal;
                expect_equal(machine::host_call_res_t::who, f.m.regs()[7]);
                expect(f.ok.new_ids.empty());
                expect(f.ok.ejected_ids.empty());
                expect(services.info_get(fixture::actor) == info);
                expect(services.lookup_get(fixture::actor, key) == history);
                const auto retained = services.preimage_get(fixture::actor, key.hash);
                if (expect(retained.has_value()))
                    expect(retained->empty());
            };
        };

        "refine"_test = [] {
            "historical lookup validates the hash even for an absent service"_test = [] {
                refine_host_fixture_t f{};
                expect(std::holds_alternative<machine::exit_panic_t>(f.call(host_call_t::historical_lookup, {200, 0, 0, 0, 1})));
                expect(std::holds_alternative<std::monostate>(f.call(host_call_t::historical_lookup, {200, f.data_address, 0, 0, 1})));
                expect_equal(machine::host_call_res_t::none, f.m.regs()[7]);
            };

            "machine capacity precedes pointer and code validation"_test = [] {
                refine_host_fixture_t f{};
                for (size_t i = 0; i < 63; ++i)
                    static_cast<void>(f.add_machine());
                expect(std::holds_alternative<std::monostate>(f.call(host_call_t::machine, {0, 1, 0})));
                expect_equal(machine::host_call_res_t::full, f.m.regs()[7]);
                // An empty blob is readable but is not valid machine code.
                expect(std::holds_alternative<std::monostate>(f.call(host_call_t::machine, {f.data_address, 0, 0})));
                expect_equal(machine::host_call_res_t::full, f.m.regs()[7]);
            };

            "pages prioritizes missing machines and preserves pages on failure"_test = [] {
                refine_host_fixture_t f{};
                const auto id = f.add_machine();
                expect(std::holds_alternative<std::monostate>(f.call(host_call_t::pages, {99, 0, 1, 5})));
                expect_equal(machine::host_call_res_t::who, f.m.regs()[7]);
                expect(std::holds_alternative<std::monostate>(f.call(host_call_t::pages, {id, 16, 1, 5})));
                expect_equal(machine::host_call_res_t::huh, f.m.regs()[7]);
                expect(std::holds_alternative<std::monostate>(f.call(host_call_t::pages, {id, 0, 1, 2})));
                expect_equal(machine::host_call_res_t::huh, f.m.regs()[7]);
                expect(std::holds_alternative<std::monostate>(f.call(host_call_t::pages, {id, 16, 1, 2})));
                expect_equal(machine::host_call_res_t::ok, f.m.regs()[7]);
                // Page 16 exists, page 17 does not: changing both to read-only must change neither.
                expect(std::holds_alternative<std::monostate>(f.call(host_call_t::pages, {id, 16, 2, 3})));
                expect_equal(machine::host_call_res_t::huh, f.m.regs()[7]);
                expect(std::holds_alternative<std::monostate>(f.call(host_call_t::poke, {id, f.data_address, 16 * refine_host_fixture_t::cfg::ZP_pvm_page_size, 1})));
                expect_equal(machine::host_call_res_t::ok, f.m.regs()[7]);
            };

            "invoke charges its full budget before checking the machine"_test = [] {
                refine_host_fixture_t f{};
                f.invocation_args(100);
                f.m.set_gas(1'067);
                expect(std::holds_alternative<machine::exit_out_of_gas_t>(f.call(host_call_t::invoke, {99, f.data_address})));
                expect_equal(machine::register_val_t{99}, f.m.regs()[7]);
                f.m.set_gas(1'068);
                expect(std::holds_alternative<std::monostate>(f.call(host_call_t::invoke, {99, f.data_address})));
                expect_equal(machine::host_call_res_t::who, f.m.regs()[7]);
                expect_equal(gas_t{0}, f.m.gas());
            };

            "invoke refunds unused inner gas"_test = [] {
                refine_host_fixture_t f{};
                const auto id = f.add_machine();
                f.invocation_args(100);
                f.m.set_gas(2'000);
                expect(std::holds_alternative<std::monostate>(f.call(host_call_t::invoke, {id, f.data_address})));
                expect_equal(machine::inner_pvm_res_t::panic, f.m.regs()[7]);
                const auto output = f.m.mem_read(f.data_address, 112);
                decoder dec{output};
                const auto remaining = dec.uint_fixed<gas_t>(8);
                expect(remaining > 0 && remaining < 100);
                expect_equal(gas_t{2'000 - 968 - 100} + remaining, f.m.gas());
            };

            "export counts segments and validates memory before capacity"_test = [] {
                refine_host_fixture_t f{refine_host_fixture_t::cfg::WX_max_package_exports - 2};
                const auto first = refine_host_fixture_t::cfg::WX_max_package_exports - 2;
                for (size_t i = 0; i < 2; ++i) {
                    expect(std::holds_alternative<std::monostate>(f.call(host_call_t::export_, {f.data_address, 1})));
                    expect_equal(first + i, f.m.regs()[7]);
                }
                expect(std::holds_alternative<machine::exit_panic_t>(f.call(host_call_t::export_, {0, 1})));
                expect(std::holds_alternative<std::monostate>(f.call(host_call_t::export_, {f.data_address, 1})));
                expect_equal(machine::host_call_res_t::full, f.m.regs()[7]);
            };

            "fetch faults without partially writing the destination"_test = [] {
                refine_host_fixture_t f{};
                const auto output = f.data_address + refine_host_fixture_t::cfg::ZP_pvm_page_size - 1;
                const uint8_vector marker{0xab};
                f.m.mem_write(output, marker);
                expect(std::holds_alternative<machine::exit_panic_t>(f.call(host_call_t::fetch, {output, 0, 2, 0, 0, 0})));
                expect_equal(machine::register_val_t{output}, f.m.regs()[7]);
                expect(f.m.mem_read(output, marker.size()) == marker);
            };

            "fetch returns raw work-item payload bytes"_test = [] {
                refine_host_fixture_t f{};
                work_package_t<refine_host_fixture_t::cfg> package{};
                package.items.emplace_back();
                const byte_sequence_t payload{0xab};
                package.items.back().payload = payload;
                host_service_refine_t<refine_host_fixture_t::cfg> host{
                    {.m=f.m, .services=f.services, .service_id=f.actor, .slot=f.slot, .fetch={.package=&package}}, 0
                };
                expect(std::holds_alternative<std::monostate>(f.call_host(host, host_call_t::fetch, {f.data_address, 0, payload.size(), 13, 0, 0})));
                expect_equal(payload.size(), f.m.regs()[7]);
                expect(f.m.mem_read(f.data_address, payload.size()) == payload);
            };
        };
    };
};
