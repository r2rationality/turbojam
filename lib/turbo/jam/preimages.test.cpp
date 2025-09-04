/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/storage/memory.hpp>
#include "types/errors.hpp"
#include "state.hpp"
#include "test-vectors.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jam;

    template<typename CFG>
    struct test_account_t {
        preimage_items_t preimages;
        lookup_meta_items_t<CFG> lookup_metas;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("preimages"sv, preimages);
            archive.process("lookup_meta"sv, lookup_metas);
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
                for (auto &&[k, v]: tacc.preimages) {
                    this->preimage_set(id, k, static_cast<buffer>(v));
                }
                for (auto &&[k, v]: tacc.lookup_metas) {
                    this->lookup_set(id, k, std::move(v));
                }
                this->info_set(id, service_info_t<CFG>{});
            }
        }
    };

    template<typename CFG>
    struct test_input_t {
        preimages_extrinsic_t preimages;
        time_slot_t<CFG> slot;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("preimages"sv, preimages);
            archive.process("slot"sv, slot);
        }

        bool operator==(const test_input_t &o) const = default;
    };

    struct ok_t {
        void serialize(auto &)
        {
            // do nothing
        }

        bool operator==(const ok_t &) const
        {
            return true;
        }
    };

    using err_code_base_t = std::variant<
        err_preimage_unneeded_t,
        err_preimages_not_sorted_or_unique_t
    >;

    struct err_code_t: err_group_t<err_code_t, err_code_base_t> {
        using base_type = err_group_t;
        using base_type::base_type;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            static_assert(std::variant_size_v<err_code_base_t> > 0);
            static codec::variant_names_t<err_code_base_t> names {
                "preimage_unneeded"sv,
                "preimages_not_sorted_unique"sv
            };
            archive.template process_variant<err_code_base_t>(*this, names);
        }
    };

    struct output_t: std::variant<ok_t, err_code_t> {
        using base_type = std::variant<ok_t, err_code_t>;
        using base_type::base_type;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            static_assert(std::variant_size_v<base_type> > 0);
            static codec::variant_names_t<base_type> names {
                "ok"sv,
                "err"sv
            };
            archive.template process_variant<base_type>(*this, names);
        }
    };

    template<typename CFG>
    struct test_state_t {
        test_accounts_t<CFG> delta;
        services_statistics_t pi_services;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("accounts"sv, delta);
            archive.process("statistics"sv, pi_services);
        }

        bool operator==(const test_state_t &o) const = default;
    };

    template<typename CFG>
    struct test_case_t {
        test_input_t<CFG> in;
        test_state_t<CFG> pre;
        output_t out;
        test_state_t<CFG> post;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
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
            expect(tc == j_tc) << "json test case does not match the binary one" << path;
        }
        std::optional<output_t> out{};
        auto new_st = tc.pre;
        err_code_t::catch_into(
            [&] {
                account_updates_t<CFG> acc_updates{new_st.delta};
                state_t<CFG>::provide_preimages(acc_updates, new_st.pi_services, tc.in.slot, tc.in.preimages);
                acc_updates.commit();
                out.emplace(ok_t{});
            },
            [&](err_code_t err) {
                out.emplace(std::move(err));
                new_st = tc.pre;
            }
        );
        if (out.has_value()) {
            expect(out == tc.out) << path;
            expect(new_st == tc.post) << path;
        } else {
            expect(false) << path;
        }
    }
}

suite turbo_jam_preimages_suite = [] {
    "turbo::jam::preimages"_test = [] {
        static const auto test_prefix = test_vector_dir("stf/preimages/");
        static std::optional<std::string> override_test{};
        //override_test.emplace("tiny/preimage_needed-2");
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
