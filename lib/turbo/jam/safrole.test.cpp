/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include "types/errors.hpp"
#include "state.hpp"
#include "test-vectors.hpp"
#include "traces.hpp"

namespace {
    using namespace std::string_view_literals;
    using namespace turbo;
    using namespace turbo::jam;

    template<typename CFG>
    struct test_state_t {
        time_slot_t<CFG> tau;
        entropy_buffer_t eta;
        validators_data_t<CFG> lambda;
        validators_data_t<CFG> kappa;
        validators_data_t<CFG> iota;
        safrole_state_t<CFG> gamma;
        ed25519_keys_set_t post_offenders;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("tau"sv, tau);
            archive.process("eta"sv, eta);
            archive.process("lambda"sv, lambda);
            archive.process("kappa"sv, kappa);
            archive.process("gamma_k"sv, gamma.p);
            archive.process("iota"sv, iota);
            archive.process("gamma_a"sv, gamma.a);
            archive.process("gamma_s"sv, gamma.s);
            archive.process("gamma_z"sv, gamma.z);
            archive.process("post_offenders"sv, post_offenders);
        }

        bool operator==(const test_state_t &) const = default;
    };

    template<typename CFG>
    struct test_input_t {
        time_slot_t<CFG> slot;
        entropy_t entropy;
        tickets_extrinsic_t<CFG> extrinsic;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("slot"sv, slot);
            archive.process("entropy"sv, entropy);
            archive.process("extrinsic"sv, extrinsic);
        }

        bool operator==(const test_input_t &o) const = default;
    };

    using err_code_base_t = std::variant<
        err_bad_slot_t,
        err_unexpected_ticket_t,
        err_bad_ticket_order_t,
        err_bad_ticket_proof_t,
        err_bad_ticket_attempt_t,
        err_reserved_t,
        err_duplicate_ticket_t
    >;

    struct err_code_t: err_group_t<err_code_t, err_code_base_t> {
        using base_type = err_group_t<err_code_t, err_code_base_t>;
        using base_type::base_type;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            static_assert(std::variant_size_v<err_code_base_t> > 0);
            static codec::variant_names_t<err_code_base_t> names {
                "bad_slot"sv,
                "unexpected_ticket"sv,
                "bad_ticket_order"sv,
                "bad_ticket_proof"sv,
                "bad_ticket_attempt"sv,
                "reserved"sv,
                "duplicate_ticket"sv
            };
            archive.template process_variant<err_code_base_t>(*this, names);
        }
    };

    template<typename CFG>
    struct test_output_data_t {
        optional_t<epoch_mark_t<CFG>> epoch_mark {};
        optional_t<tickets_mark_t<CFG>> tickets_mark {};

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("epoch_mark"sv, epoch_mark);
            archive.process("tickets_mark"sv, tickets_mark);
        }

        bool operator==(const test_output_data_t &o) const = default;
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
    struct test_case_t {
        test_input_t<CFG> in;
        test_state_t<CFG> pre;
        test_output_t<CFG> out;
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
        std::optional<test_output_t<CFG>> out{};
        auto new_st = tc.pre;
        err_code_t::catch_into(
            [&] {
                state_t<CFG>::eta_prime(new_st.eta, new_st.tau, tc.in.slot, tc.in.entropy);
                auto res = state_t<CFG>::update_safrole(
                    new_st.gamma, new_st.kappa, new_st.lambda,
                    new_st.eta, new_st.post_offenders,
                    tc.pre.tau, tc.pre.iota,
                    tc.in.slot, tc.in.extrinsic
                );
                state_t<CFG>::tau_prime(new_st.tau, tc.in.slot);
                out.emplace(test_output_data_t<CFG>{std::move(res.epoch_mark), std::move(res.tickets_mark)});
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

suite turbo_jam_safrole_suite = [] {
    "turbo::jam::safrole"_test = [] {
        static const std::string test_prefix = "stf/safrole/";
        static std::optional<std::string> override_test{};
        //override_test.emplace("tiny/publish-tickets-no-mark-3");
        if (!override_test) {
            for (const auto &path: file::files_with_ext(test_vector_dir(test_prefix + "tiny"), ".bin")) {
                test_file<config_tiny>(path.substr(0, path.size() - 4));
            }
            for (const auto &path: file::files_with_ext(test_vector_dir(test_prefix + "full"), ".bin")) {
                test_file<config_prod>(path.substr(0, path.size() - 4));
            }
        } else {
            test_file<config_tiny>(test_vector_dir(test_prefix + *override_test));
        }
    };
};
