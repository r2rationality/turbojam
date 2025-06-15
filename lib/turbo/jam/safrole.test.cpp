/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/test.hpp>
#include "types/errors.hpp"
#include "state.hpp"

namespace {
    using namespace std::string_view_literals;
    using namespace turbo;
    using namespace turbo::jam;

    template<typename CONSTANTS>
    struct input_t {
        time_slot_t<CONSTANTS> slot;
        entropy_t entropy;
        tickets_extrinsic_t<CONSTANTS> extrinsic;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("slot"sv, slot);
            archive.process("entropy"sv, entropy);
            archive.process("extrinsic"sv, extrinsic);
        }

        bool operator==(const input_t &o) const
        {
            if (slot != o.slot)
                return false;
            if (entropy != o.entropy)
                return false;
            if (extrinsic != o.extrinsic)
                return false;
            return true;
        }
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

    template<typename CONSTANTS>
    struct output_t: std::variant<safrole_output_data_t<CONSTANTS>, err_code_t> {
        using base_type = std::variant<safrole_output_data_t<CONSTANTS>, err_code_t>;

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
        input_t<CONSTANTS> in;
        state_t<CONSTANTS> pre;
        output_t<CONSTANTS> out;
        state_t<CONSTANTS> post;

        static void serialize_state(auto &archive, const std::string_view &name, state_t<CONSTANTS> &self)
        {
            archive.push(name);
            archive.process("tau"sv, self.tau);
            archive.process("eta"sv, self.eta);
            archive.process("lambda"sv, self.lambda);
            archive.process("kappa"sv, self.kappa);
            archive.process("gamma_k"sv, self.gamma.k);
            archive.process("iota"sv, self.iota);
            archive.process("gamma_a"sv, self.gamma.a);
            archive.process("gamma_s"sv, self.gamma.s);
            archive.process("gamma_z"sv, self.gamma.z);
            archive.process("post_offenders"sv, self.psi.offenders);
            archive.pop();
        }

        void serialize(auto &archive)
        {
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
            expect(tc == j_tc) << "the json test case does not match the binary one" << path;
        }
        std::optional<output_t<CFG>> out {};
        state_t<CFG> res_st = tc.pre;
        err_code_t::catch_into(
            [&] {
                auto tmp_st = tc.pre;
                out.emplace(tmp_st.update_safrole(tc.pre.tau.get(), tc.in.slot, tc.in.entropy, tc.in.extrinsic));
                tmp_st.tau.set(state_t<CFG>::tau_prime(tc.pre.tau.get(), tc.in.slot));
                res_st = std::move(tmp_st);
            },
            [&](err_code_t err) {
                out.emplace(std::move(err));
            }
        );
        if (out.has_value()) {
            expect(out == tc.out) << path;
            expect(res_st == tc.post) << path;
        } else {
            expect(false) << path;
        }
    }
}

suite turbo_jam_safrole_suite = [] {
    "turbo::jam::safrole"_test = [] {
        "conformance test vectors"_test = [] {
            for (const auto &path: file::files_with_ext(file::install_path("test/jam-test-vectors/stf/safrole/tiny"), ".bin")) {
                test_file<config_tiny>(path.substr(0, path.size() - 4));
            }
            for (const auto &path: file::files_with_ext(file::install_path("test/jam-test-vectors/stf/safrole/full"), ".bin")) {
                test_file<config_prod>(path.substr(0, path.size() - 4));
            }
        };
    };
};
