/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/storage/memory.hpp>
#include "state.hpp"
#include "machine/program-builder.hpp"
#include "test-vectors.hpp"

namespace turbo::jam {
    struct accumulate_test_access_t {
        static constexpr auto one = &state_t<config_tiny>::accumulate_delta_one;
        static constexpr auto star = &state_t<config_tiny>::accumulate_delta_star;
    };
}

namespace turbo_jam_accumulate_test {
    using namespace turbo;
    using namespace turbo::jam;
    using namespace std::string_view_literals;

    struct accumulate_program_t: machine::program_builder_t {
        const machine::address_val_t zero_hash = append_readonly(opaque_hash_t{});

        accumulate_program_t() {
            pad_code(5);
        }

        void halt() {
            return_bytes(zero_hash, sizeof(opaque_hash_t)); // A zero-hash commitment proves normal completion.
        }

        void fail(const bool out_of_gas) {
            if (out_of_gas)
                loop_forever();
            else
                trap();
        }
    };

    struct accumulation_fixture_t {
        using cfg = config_tiny;
        static constexpr service_id_t actor = 100;
        static constexpr service_id_t target = 200;
        static constexpr balance_t initial_balance = 10'000;
        static constexpr gas_t::base_type gas_budget = 1'000;

        accounts_t<cfg> accounts{std::make_shared<storage::memory::db_t>()};
        privileges_t<cfg> chi{};
        entropy_t entropy{};
        time_slot_t<cfg> slot{cfg::D_preimage_expunge_delay + 2};
        free_services_t free_services{{actor, gas_budget}};

        explicit accumulation_fixture_t(const machine::program_builder_t &program)
            : accumulation_fixture_t{program.program_bytes()}
        {
        }

        explicit accumulation_fixture_t(const uint8_vector &code)
        {
            service_info_t<cfg> info{};
            info.balance = initial_balance;
            info.code_hash = crypto::blake2b::digest<opaque_hash_t>(code);
            info.items = 2U;
            info.bytes = 81U + code.size();
            accounts.info_set(actor, info);
            accounts.preimage_set(actor, info.code_hash, code);
            accounts.lookup_set(actor, {info.code_hash, numeric_cast<uint32_t>(code.size())}, {0});
            chi.registrar = actor;
        }

        void add_ejectable_target(const service_id_t id=target)
        {
            service_info_t<cfg> info{};
            encoder::uint_fixed(info.code_hash, 32U, actor);
            info.balance = initial_balance;
            info.items = 2U;
            info.bytes = 81U;
            accounts.info_set(id, info);
            accounts.lookup_set(id, {opaque_hash_t{}, 0U}, {0U, 1U});
        }

        accumulate_result_t<cfg> one(const deferred_transfers_t<cfg> &transfers={})
        {
            return accumulate_test_access_t::one({accounts, chi}, slot, entropy, actor, {}, transfers, &free_services);
        }

        delta_star_result_t<cfg> star(const deferred_transfers_t<cfg> &transfers={})
        {
            return accumulate_test_access_t::star({accounts, chi}, slot, entropy, {}, transfers, &free_services);
        }
    };

    struct stored_items_config_t {
        std::string key_name = "key";
        std::string val_name = "value";
    };
    using stored_items_t = map_t<byte_sequence_t, byte_sequence_t, stored_items_config_t>;

    struct preimage_blobs_config_t {
        std::string key_name = "hash";
        std::string val_name = "blob";
    };
    using preimage_blobs_t = map_t<opaque_hash_t, byte_sequence_t, preimage_blobs_config_t>;

    struct preimage_requests_config_t {
        std::string key_name = "key";
        std::string val_name = "value";
    };
    template<typename CFG>
    using preimage_requests_t = map_t<lookup_meta_map_key_t, lookup_meta_map_val_t<CFG>, preimage_requests_config_t>;

    template<typename CFG>
    struct test_account_t {
        service_info_t<CFG> service;
        stored_items_t storage;
        preimage_blobs_t preimage_blobs;
        preimage_requests_t<CFG> preimage_requests;

        void serialize(auto &archive)
        {
            archive.process("service"sv, service);
            archive.process("storage"sv, storage);
            archive.process("preimage_blobs"sv, preimage_blobs);
            archive.process("preimage_requests"sv, preimage_requests);
        }

        bool operator==(const test_account_t &) const = default;
    };

    template<typename CFG>
    struct test_accounts_t: accounts_t<CFG> {
        test_accounts_t(storage::db_ptr_t db=std::make_shared<storage::memory::db_t>()):
            accounts_t<CFG>::accounts_t{std::move(db)}
        {
        }

        void serialize(auto &archive)
        {
            map_t<service_id_t, test_account_t<CFG>, accounts_config_t> taccs;
            archive.process(taccs);
            for (auto &&[id, tacc]: taccs) {
                this->info_set(id, std::move(tacc.service));
                for (auto &&[k, v]: tacc.storage) {
                    this->storage_set_raw(id, k, static_cast<buffer>(v));
                }
                for (auto &&[k, v]: tacc.preimage_blobs) {
                    this->preimage_set(id, k, uint8_vector{v});
                }
                for (auto &&[k, v]: tacc.preimage_requests) {
                    this->lookup_set(id, k, std::move(v));
                }
            }
        }
    };

    template<typename CFG>
    struct test_input_t {
        time_slot_t<CFG> slot;
        work_reports_t<CFG> reports;

        void serialize(auto &archive)
        {
            archive.process("slot"sv, slot);
            archive.process("reports"sv, reports);
        }

        bool operator==(const test_input_t &o) const = default;
    };

    struct err_code_t {
        void serialize(auto &)
        {
        }

        bool operator==(const err_code_t &) const
        {
            return true;
        }
    };

    using test_output_base_t = std::variant<accumulate_root_t, err_code_t>;
    struct test_output_t: test_output_base_t {
        using base_type = test_output_base_t;
        using base_type::base_type;

        void serialize(auto &archive)
        {
            static constexpr codec::variant_names_t<base_type> names {
                "ok"sv,
                "err"sv
            };
            archive.process(codec::as_variant<base_type>(*this, names));
        }
    };

    template<typename CFG>
    struct test_state_t {
        time_slot_t<CFG> tau;
        entropy_t eta0;
        ready_queue_t<CFG> omega;
        accumulated_queue_t<CFG> ksi;
        privileges_t<CFG> chi;
        services_statistics_t pi_services;
        test_accounts_t<CFG> accounts;

        void serialize(auto &archive)
        {
            archive.process("slot"sv, tau);
            archive.process("entropy"sv, eta0);
            archive.process("ready_queue"sv, omega);
            archive.process("accumulated"sv, ksi);
            archive.process("privileges"sv, chi);
            archive.process("statistics"sv, pi_services);
            archive.process("accounts"sv, accounts);
        }

        bool operator==(const test_state_t &o) const {
            if (tau != o.tau)
                return false;
            if (eta0 != o.eta0)
                return false;
            if (omega != o.omega)
                return false;
            if (ksi != o.ksi)
                return false;
            if (chi != o.chi)
                return false;
            if (pi_services != o.pi_services)
                return false;
            if (accounts != o.accounts)
                return false;
            return true;
        }
    };

    template<typename CFG>
    struct test_case_t {
        test_input_t<CFG> in;
        test_state_t<CFG> pre;
        test_output_t out;
        test_state_t<CFG> post;

        void serialize(auto &archive)
        {
            archive.process("input"sv, in);
            archive.process("pre_state"sv, pre);
            archive.process("output"sv, out);
            archive.process("post_state"sv, post);
        }

        bool operator==(const test_case_t &o) const = default;
    };

    template<typename CFG>
    void test_file(const std::string &path)
    {
        const auto tc = jam::load_obj<test_case_t<CFG>>(path + ".bin");
        {
            const auto j_tc = codec::json::load_obj<test_case_t<CFG>>(path + ".json");
            expect(tc == j_tc) << "the json test case does not match the binary one" << path;
        }
        std::optional<test_output_t> out{};
        auto new_st = tc.pre;
        try {
            new_st.pi_services.clear();
            auto res = state_t<CFG>::accumulate(
                new_st.pi_services, new_st.omega, new_st.ksi,
                new_st.eta0, tc.pre.accounts,
                tc.pre.tau, tc.pre.chi,
                tc.in.slot, tc.in.reports
            );
            expect(new_st.accounts == tc.pre.accounts) << "accumulate must leave its input accounts unchanged" << path;
            // accumulate updates da_load statistics
            out.emplace(res.theta.root());
            if (res.chi)
                new_st.chi = *res.chi;
            new_st.accounts.consume_from(std::move(res.delta));
            state_t<CFG>::tau_prime(new_st.tau, tc.in.slot);
        } catch (const error &) {
            out.emplace(err_code_t {});
            new_st = tc.pre;
        } catch (const std::exception &ex) {
            expect(false) << ex.what() << path;
        } catch (...) {
            expect(false) << "An unknown error occurred" << path;
        }
        if (out.has_value()) {
            expect(out == tc.out) << path;
            const auto state_matches = new_st == tc.post;
            expect(state_matches) << path;
            if (!state_matches)
                logger::warn("{} accounts diff: {}", path, tc.post.accounts.diff(new_st.accounts));
        } else {
            expect(false) << path;
        }
    }
}

namespace {
    using namespace turbo_jam_accumulate_test;
}

suite turbo_jam_accumulate_suite = [] {
    "turbo::jam::accumulate"_test = [] {
        "test vectors"_test = [] {
            static const auto test_prefix = test_vector_dir("stf/accumulate/");
            static std::optional<std::string> override_test{};
            //override_test.emplace("tiny/work_for_ejected_service-3");
            if (!override_test) {
                for (const auto &path: file::files_with_ext(test_prefix + "tiny", ".bin")) {
                    test_file<config_tiny>(path.substr(0, path.size() - 4));
                }
                for (const auto &path: file::files_with_ext(test_prefix + "full", ".bin")) {
                    test_file<config_prod>(path.substr(0, path.size() - 4));
                }
            } else {
                test_file<config_tiny>(test_prefix + *override_test);
            }
        };

        "regressions"_test = [] {
            using fixture_t = accumulation_fixture_t;
            using cfg = fixture_t::cfg;

            "check uses initial account membership"_test = [] {
                constexpr service_id_t occupied = cfg::S_min_public_service_index;
                constexpr service_id_t available = occupied + 1;
                accounts_t<cfg> accounts{std::make_shared<storage::memory::db_t>()};
                accounts.info_set(occupied, {});
                accumulate_context_t<cfg> ctx{fixture_t::actor, entropy_t{}, time_slot_t<cfg>{0}, mutable_state_t<cfg>{accounts, {}}};
                ctx.state.services.info_erase(occupied);
                ctx.state.services.info_set(available, {});
                expect_equal(available, ctx.check(occupied));
            };

            "malformed code keeps transfer credit without using gas"_test = [] {
                const deferred_transfers_t<cfg> transfers{
                    {.source=300, .destination=fixture_t::actor, .amount=50, .metadata={}, .gas_limit=0}
                };
                for (const auto &code: {
                    uint8_vector{}, // Missing metadata
                    uint8_vector{0}, // truncated memory header
                    uint8_vector(16, 0) // an empty inner program
                }) {
                    const auto result = fixture_t{code}.one(transfers);
                    expect_equal(gas_t{0}, result.gas);
                    expect_equal(fixture_t::initial_balance + 50, result.state.services.info_get_or_throw(fixture_t::actor).balance);
                }
            };

            "recreated existing account is excluded from merge"_test = [] {
                accumulate_program_t program{};
                program.host_call(host_call_t::eject, {fixture_t::target, program.zero_hash});
                program.host_call(host_call_t::new_, {program.zero_hash, 0, 0, 0, 0, fixture_t::target});
                program.halt();
                fixture_t f{program};
                f.add_ejectable_target();
                const auto original = f.accounts.info_get_or_throw(fixture_t::target);
                const auto original_lookup = f.accounts.lookup_get(fixture_t::target, {opaque_hash_t{}, 0});

                const auto local = f.one();
                // Establish that the local replacement differs from the account the merge must preserve.
                expect(local.state.services.info_get_or_throw(fixture_t::target).code_hash == opaque_hash_t{}) << fatal;

                for (const auto amount: {balance_t{0}, balance_t{50}}) {
                    deferred_transfers_t<cfg> transfers{};
                    if (amount)
                        transfers.push_back({.source=300, .destination=fixture_t::target, .amount=amount, .metadata={}, .gas_limit=0});
                    auto expected = original;
                    expected.balance += amount;

                    // (12.19): the registrar contributes neither n nor m for the recreated account.
                    // With a transfer, the recipient contributes its own credited account to n.
                    const auto result = f.star(transfers);
                    expect(result.state.services.info_get(fixture_t::target) == expected) << "transfer amount=" << amount;
                    expect(result.state.services.lookup_get(fixture_t::target, {opaque_hash_t{}, 0}) == original_lookup);
                }
            };

            "checkpoint selects recreation contributions"_test = [] {
                for (const bool checkpoint_after_new: {false, true}) {
                    for (const bool out_of_gas: {false, true}) {
                        accumulate_program_t program{};
                        program.host_call(host_call_t::eject, {fixture_t::target, program.zero_hash});
                        if (!checkpoint_after_new)
                            program.host_call(host_call_t::checkpoint);
                        program.host_call(host_call_t::new_, {program.zero_hash, 0, 0, 0, 0, fixture_t::target});
                        if (checkpoint_after_new)
                            program.host_call(host_call_t::checkpoint);
                        program.fail(out_of_gas);
                        fixture_t f{program};
                        f.add_ejectable_target();
                        const auto original = f.accounts.info_get(fixture_t::target);
                        const auto original_lookup = f.accounts.lookup_get(fixture_t::target, {opaque_hash_t{}, 0});

                        const auto local = f.one();
                        expect(local.ejected_ids.contains(fixture_t::target) == !checkpoint_after_new);
                        expect_equal(checkpoint_after_new ? set_t<service_id_t>{fixture_t::target} : set_t<service_id_t>{},
                            local.updated_foreign_ids);

                        const auto result = f.star();
                        if (checkpoint_after_new) {
                            expect(result.state.services.info_get(fixture_t::target) == original);
                            expect(result.state.services.lookup_get(fixture_t::target, {opaque_hash_t{}, 0}) == original_lookup);
                        } else {
                            expect(!result.state.services.info_get(fixture_t::target).has_value());
                            expect(!result.state.services.lookup_get(fixture_t::target, {opaque_hash_t{}, 0}).has_value());
                        }
                    }
                }
            };

            "filtered merge preserves other account contributions"_test = [] {
                constexpr service_id_t added = 201;
                constexpr service_id_t removed = 202;
                constexpr service_id_t recreated = 203;
                accumulate_program_t program{};
                program.host_call(host_call_t::eject, {fixture_t::target, program.zero_hash});
                program.host_call(host_call_t::new_, {program.zero_hash, 0, 0, 0, 0, fixture_t::target});
                program.host_call(host_call_t::new_, {program.zero_hash, 0, 0, 0, 0, added});
                program.host_call(host_call_t::eject, {removed, program.zero_hash});
                program.host_call(host_call_t::eject, {recreated, program.zero_hash});
                program.host_call(host_call_t::new_, {program.zero_hash, 0, 0, 0, 0, recreated});
                program.halt();
                fixture_t f{program};
                f.add_ejectable_target();
                f.add_ejectable_target(removed);
                f.add_ejectable_target(recreated);

                const auto local = f.one();
                expect_equal(set_t<service_id_t>{added}, local.new_ids);
                expect_equal(set_t<service_id_t>{removed}, local.ejected_ids);
                expect_equal(set_t<service_id_t>{fixture_t::target, recreated}, local.updated_foreign_ids);

                const auto result = f.star();
                expect(result.state.services.info_get(fixture_t::actor) == local.state.services.info_get(fixture_t::actor));
                expect(result.state.services.info_get(added) == local.state.services.info_get(added));
                expect(result.state.services.lookup_get(added, {opaque_hash_t{}, 0}).has_value());
                expect(!result.state.services.contains(removed));
                expect(!result.state.services.lookup_get(removed, {opaque_hash_t{}, 0}).has_value());
                for (const auto id: {fixture_t::target, recreated}) {
                    expect(result.state.services.info_get(id) == f.accounts.info_get(id));
                    expect(result.state.services.lookup_get(id, {opaque_hash_t{}, 0}) == f.accounts.lookup_get(id, {opaque_hash_t{}, 0}));
                }
            };

            "initial membership includes previous accumulation rounds"_test = [] {
                accumulate_program_t program{};
                program.host_call(host_call_t::eject, {fixture_t::target, program.zero_hash});
                program.host_call(host_call_t::new_, {program.zero_hash, 0, 0, 0, 0, fixture_t::target});
                program.halt();
                fixture_t f{program};
                f.add_ejectable_target();
                const auto original = f.accounts.info_get_or_throw(fixture_t::target);
                const lookup_meta_map_key_t key{opaque_hash_t{}, 0};
                const auto history = f.accounts.lookup_get(fixture_t::target, key);
                expect(history.has_value()) << fatal;
                f.accounts.info_erase(fixture_t::target);
                f.accounts.lookup_erase(fixture_t::target, key);

                // The account exists in the incoming overlay, but not in its backing database.
                mutable_state_t<cfg> initial{f.accounts, f.chi};
                initial.services.info_set(fixture_t::target, original);
                initial.services.lookup_set(fixture_t::target, key, *history);
                const auto result = accumulate_test_access_t::star(std::move(initial), f.slot, f.entropy, {}, {}, &f.free_services);
                expect(result.state.services.info_get(fixture_t::target) == original);
                expect(result.state.services.lookup_get(fixture_t::target, key) == history);
            };

            "code size limit excludes metadata"_test = [] {
                static constexpr size_t limit = cfg::WC_max_service_code_size;
                for (const auto code_size: {limit, limit + 1}) {
                    accumulate_program_t program{};
                    program.halt();
                    program.pad_image(code_size);
                    const auto result = fixture_t{program}.one();
                    const bool executable = code_size <= limit;
                    expect(result.commitment.has_value() == executable) << "code_size=" << code_size;
                    if (!executable)
                        expect_equal(gas_t{0}, result.gas);
                }
            };

            "recipient keeps transfer credit"_test = [] {
                const deferred_transfers_t<cfg> transfers{
                    {.source=300, .destination=fixture_t::actor, .amount=50, .metadata={}, .gas_limit=0}
                };
                for (const auto outcome: {0, 1, 2}) {
                    accumulate_program_t program{};
                    switch (outcome) {
                        case 0: program.halt(); break;
                        case 1: program.fail(false); break;
                        case 2: program.fail(true); break;
                    }
                    const auto result = fixture_t{program}.star(transfers);
                    expect(result.state.services.info_get_or_throw(fixture_t::actor).balance == fixture_t::initial_balance + 50) << outcome;
                }
            };

            "checkpointed creation preserves account contributions"_test = [] {
                for (const bool out_of_gas: {false, true}) {
                    accumulate_program_t program{};
                    program.host_call(host_call_t::new_, {program.zero_hash, 0, 0, 0, 0, fixture_t::target});
                    program.host_call(host_call_t::checkpoint);
                    program.fail(out_of_gas);
                    fixture_t f{program};
                    const auto result = f.one();
                    expect_equal(set_t<service_id_t>{fixture_t::target}, result.new_ids);
                    const auto merged = f.star();
                    expect(merged.state.services.info_get(fixture_t::target) == result.state.services.info_get_or_throw(fixture_t::target));
                    expect(merged.state.services.lookup_get(fixture_t::target, {opaque_hash_t{}, 0}).has_value());
                }
            };

            "checkpointed ejection preserves account contributions"_test = [] {
                for (const bool out_of_gas: {false, true}) {
                    accumulate_program_t program{};
                    program.host_call(host_call_t::eject, {fixture_t::target, program.zero_hash});
                    program.host_call(host_call_t::checkpoint);
                    program.fail(out_of_gas);
                    fixture_t f{program};
                    f.add_ejectable_target();
                    const auto result = f.one();
                    expect(!result.state.services.contains(fixture_t::target));
                    expect_equal(set_t<service_id_t>{fixture_t::target}, result.ejected_ids);
                }
            };

            "ejection conflicting with recipient account is rejected"_test = [] {
                accumulate_program_t program{};
                program.host_call(host_call_t::eject, {fixture_t::target, program.zero_hash});
                program.halt();
                fixture_t f{program};
                f.add_ejectable_target();

                for (const auto amount: {balance_t{0}, balance_t{50}}) {
                    const deferred_transfers_t<cfg> transfers{{
                        .source=300, .destination=fixture_t::target, .amount=amount, .metadata={}, .gas_limit=0
                    }};
                    // (12.19): the recipient contributes its own account even with no code and zero credit,
                    // when it stages no writes. That contribution conflicts with the registrar's ejection.
                    bool conflict = false;
                    try {
                        (void)f.star(transfers);
                    } catch (const err_accumulate_conflict_t &) {
                        conflict = true;
                    }
                    expect(conflict) << "transfer amount=" << amount;
                }
            };
        };
    };
};
