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

    struct accumulate_host_fixture_t {
        using cfg = config_tiny;
        static constexpr service_id_t actor = 100;
        static constexpr machine::address_val_t data_address = cfg::ZZ_pvm_init_zone_size;

        accounts_t<cfg> accounts{std::make_shared<storage::memory::db_t>()};
        time_slot_t<cfg> slot{cfg::D_preimage_expunge_delay + 2};
        machine::machine_t m{
            machine::program_builder_t{}.build_code(), machine::state_t{.gas=1'000},
            {{.address=data_address, .length=cfg::ZP_pvm_page_size, .is_writable=true}}
        };
        accumulate_context_t<cfg> ok{actor, entropy_t{}, slot, mutable_state_t<cfg>{accounts, {}}};
        accumulate_context_t<cfg> err{ok};
        host_service_accumulate_t<cfg> host{
            {.m=m, .services=ok.state.services, .service_id=actor, .slot=slot, .fetch={}},
            ok, err
        };

        machine::host_call_res_t call(const host_call_t id,
            const std::initializer_list<machine::register_val_t> args)
        {
            expect(args.size() <= machine::registers_t::fixed_size - 7) << fatal;
            size_t reg = 7;
            for (const auto arg: args)
                m.set_reg(reg++, arg);
            return host.call(std::to_underlying(id));
        }
    };
}

suite turbo_jam_host_service_suite = [] {
    "turbo::jam::host_service"_test = [] {
        "accumulate"_test = [] {
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
    };
};
