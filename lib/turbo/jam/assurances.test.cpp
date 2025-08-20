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

    template<typename CONSTANTS>
    struct input_t {
        assurances_extrinsic_t<CONSTANTS> assurances;
        time_slot_t<CONSTANTS> slot;
        header_hash_t parent;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("assurances"sv, assurances);
            archive.process("slot"sv, slot);
            archive.process("parent"sv, parent);
        }

        bool operator==(const input_t &o) const
        {
            if (assurances != o.assurances)
                return false;
            if (slot != o.slot)
                return false;
            if (parent != o.parent)
                return false;
            return true;
        }
    };

    template<typename CONSTANTS>
    struct output_data_t {
        work_reports_t<CONSTANTS> reported;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("reported"sv, reported);
        }

        bool operator==(const output_data_t &o) const
        {
            return reported == o.reported;
        }
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

    template<typename CONSTANTS>
    struct output_t: std::variant<output_data_t<CONSTANTS>, err_code_t> {
        using base_type = std::variant<output_data_t<CONSTANTS>, err_code_t>;

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

    template<typename CONSTANTS>
    struct test_case_t {
        file::tmp_directory tmp_dir_pre { fmt::format("test-jam-assurances-{}-pre", static_cast<void *>(this)) };
        file::tmp_directory tmp_dir_post { fmt::format("test-jam-assurances-{}-post", static_cast<void *>(this)) };
        input_t<CONSTANTS> in;
        state_t<CONSTANTS> pre { std::make_shared<triedb::db_t>(tmp_dir_pre.path()) };
        output_t<CONSTANTS> out;
        state_t<CONSTANTS> post { std::make_shared<triedb::db_t>(tmp_dir_post.path()) };

        static void serialize_state(auto &archive, const std::string_view &name, state_t<CONSTANTS> &st)
        {
            using namespace std::string_view_literals;
            archive.push(name);
            archive.process("avail_assignments"sv, st.rho);
            archive.process("curr_validators"sv, st.kappa);
            archive.pop();
        }

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("input"sv, in);
            serialize_state(archive, "pre_state"sv, pre);
            archive.process("output"sv, out);
            serialize_state(archive, "post_state"sv, post);
        }

        bool operator==(const test_case_t &o) const
        {
            if (in != o.in)
                return false;
            if (pre != o.pre)
                return false;
            if (out != o.out)
                return false;
            if (post != o.post)
                return false;
            return true;
        }
    };

    template<typename CFG>
    void test_file(const std::string &path)
    {
        const auto tc = jam::load_obj<test_case_t<CFG>>(path + ".bin");
        {
            const auto j_tc = codec::json::load_obj<test_case_t<CFG>>(path + ".json");
            expect(tc == j_tc) << "json test case does not match the binary one" << path;
        }
        std::optional<output_t<CFG>> out {};
        state_t<CFG> new_st = tc.pre.working_copy();
        err_code_t::catch_into(
            [&] {
                auto tmp_st = new_st.working_copy();
                output_data_t<CFG> res {};
                std::decay_t<typename decltype(tmp_st.pi)::element_type> tmp_pi;
                auto tmp_rho = tmp_st.rho.get();
                // ignore the updated statistics as they are tested in a separate set of tests
                out.emplace(output_data_t { state_t<CFG>::rho_dagger_2(tmp_rho, tmp_pi, tc.pre.kappa.get(),
                    tc.in.slot, tc.in.parent, tc.in.assurances) });
                tmp_st.rho.set(std::move(tmp_rho));
                new_st.commit(std::move(tmp_st));
            },
            [&](err_code_t err) {
                out.emplace(std::move(err));
            }
        );
        if (out.has_value()) {
            expect(out == tc.out) << path;
            const auto state_matches = new_st == tc.post;
            expect(state_matches) << path;
            if (!state_matches) {
                logger::info("pre_state == post_state: {}", tc.pre == tc.post ? "true" : "false");
                logger::info("pre_state == new_state: {}", tc.pre == new_st ? "true" : "false");
                const auto diff = new_st.snapshot().diff(tc.post.snapshot());
                logger::info("diff: {}", diff);
            }
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
