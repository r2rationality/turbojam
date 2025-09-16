/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/storage/memory.hpp>
#include "state.hpp"
#include "test-vectors.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jam;
    using namespace std::string_view_literals;

    struct stored_items_config_t {
        std::string key_name = "key";
        std::string val_name = "value";
    };
    using stored_items_t = map_t<byte_sequence_t, byte_sequence_t, stored_items_config_t>;

    struct preimage_items_config_t {
        std::string key_name = "hash";
        std::string val_name = "blob";
    };
    using preimage_items_t = map_t<opaque_hash_t, byte_sequence_t, preimage_items_config_t>;

    template<typename CFG>
    struct test_account_t {
        service_info_t<CFG> service;
        stored_items_t storage;
        preimage_items_t preimages;

        void serialize(auto &archive)
        {
            archive.process("service"sv, service);
            archive.process("storage"sv, storage);
            archive.process("preimages"sv, preimages);
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
                for (auto &&[k, v]: tacc.preimages) {
                    this->preimage_set(id, k, uint8_vector{v});
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
            static codec::variant_names_t<base_type> names {
                "ok"sv,
                "err"sv
            };
            archive.template process_variant<base_type>(*this, names);
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
            account_updates_t<CFG> new_delta{new_st.accounts};
            auto res = state_t<CFG>::accumulate(
                new_delta, new_st.pi_services,
                new_st.omega, new_st.ksi,
                new_st.eta0,
                new_st.tau, new_st.chi,
                tc.in.slot, tc.in.reports
            );
            // accumulate updates da_load statistics
            out.emplace(res.root);
            if (res.chi)
                new_st.chi = *res.chi;
            new_delta.commit();
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
                logger::warn("{} diff: {}", path, tc.post.accounts.diff(new_st.accounts));
        } else {
            expect(false) << path;
        }
    }
}

suite turbo_jam_accumulate_suite = [] {
    "turbo::jam::accumulate"_test = [] {
        static const auto test_prefix = test_vector_dir("stf/accumulate/");
        static std::optional<std::string> override_test{};
        //override_test.emplace("tiny/accumulate_ready_queued_reports-1");
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
};
