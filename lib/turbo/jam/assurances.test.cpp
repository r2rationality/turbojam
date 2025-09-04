/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include "types/errors.hpp"
#include "state.hpp"
#include "test-vectors.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jam;

    template<typename CFG>
    struct test_input_t {
        assurances_extrinsic_t<CFG> assurances;
        time_slot_t<CFG> slot;
        header_hash_t parent;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("assurances"sv, assurances);
            archive.process("slot"sv, slot);
            archive.process("parent"sv, parent);
        }

        bool operator==(const test_input_t &o) const = default;
    };

    template<typename CFG>
    struct test_output_data_t {
        work_reports_t<CFG> reported;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("reported"sv, reported);
        }

        bool operator==(const test_output_data_t &o) const = default;
    };

    using err_code_base_t = std::variant<
        err_bad_attestation_parent_t,
        err_bad_validator_index_t,
        err_core_not_engaged_t,
        err_bad_signature_t,
        err_not_sorted_or_unique_assurers
    >;

    struct err_code_t: err_group_t<err_code_t, err_code_base_t> {
        using base_type = err_group_t<err_code_t, err_code_base_t>;
        using base_type::base_type;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            static_assert(std::variant_size_v<err_code_base_t> > 0);
            static codec::variant_names_t<err_code_base_t> names {
                "bad_attestation_parent"sv,
                "bad_validator_index"sv,
                "core_not_engaged"sv,
                "bad_signature"sv,
                "not_sorted_or_unique_assurers"sv
            };
            archive.template process_variant<err_code_base_t>(*this, names);
        }
    };

    template<typename CFG>
    struct test_output_t: std::variant<test_output_data_t<CFG>, err_code_t> {
        using base_type = std::variant<test_output_data_t<CFG>, err_code_t>;

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
        availability_assignments_t<CFG> rho;
        validators_data_t<CFG> kappa;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("avail_assignments"sv, rho);
            archive.process("curr_validators"sv, kappa);
        }

        bool operator==(const test_state_t &o) const = default;
    };

    template<typename CFG>
    struct test_case_t {
        test_input_t<CFG> in;
        test_state_t<CFG> pre;
        test_output_t<CFG> out;
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
        std::optional<test_output_t<CFG>> out{};
        auto new_st = tc.pre;
        err_code_t::catch_into(
            [&] {
                test_output_data_t<CFG> res{};
                std::decay_t<typename decltype(state_t<CFG>::pi)::element_type> new_pi;
                // ignore the updated statistics as they are tested in a separate set of tests
                out.emplace(test_output_data_t{ state_t<CFG>::rho_dagger_2(new_st.rho, new_pi, tc.pre.kappa,
                    tc.in.slot, tc.in.parent, tc.in.assurances) });
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

suite turbo_jam_assurances_suite = [] {
    "turbo::jam::assurances"_test = [] {
        //test_file<config_tiny>(file::install_path("test/jam-test-vectors/stf/assurances/tiny/assurances_for_stale_report-1"));
        "tiny"_test = [] {
            for (const auto &path: file::files_with_ext(test_vector_dir("stf/assurances/tiny"), ".bin")) {
                test_file<config_tiny>(path.substr(0, path.size() - 4));
            }
        };
        "full"_test = [] {
            for (const auto &path: file::files_with_ext(test_vector_dir("stf/assurances/full"), ".bin")) {
                test_file<config_prod>(path.substr(0, path.size() - 4));
            }
        };
    };
};
