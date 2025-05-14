/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/test.hpp>
#include "types/errors.hpp"
#include "types.hpp"

namespace {
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

        static state_t<CONSTANTS> decode_state(decoder &dec)
        {
            auto tau = dec.decode<decltype(pre.tau)>();
            auto eta = dec.decode<decltype(pre.eta)>();
            auto lambda = dec.decode<decltype(pre.lambda)>();
            auto kappa = dec.decode<decltype(pre.kappa)>();
            auto gamma_k = dec.decode<decltype(pre.gamma.k)>();
            auto iota = dec.decode<decltype(pre.iota)>();
            auto gamma_a = dec.decode<decltype(pre.gamma.a)>();
            auto gamma_s = dec.decode<decltype(pre.gamma.s)>();
            auto gamma_z = dec.decode<decltype(pre.gamma.z)>();
            auto psi_offenders = dec.decode<decltype(pre.psi.offenders)>();
            return {
                .gamma {
                    .a = std::move(gamma_a),
                    .k = std::move(gamma_k),
                    .s = std::move(gamma_s),
                    .z = std::move(gamma_z)
                },
                .eta = std::move(eta),
                .iota = std::move(iota),
                .kappa = std::move(kappa),
                .lambda = std::move(lambda),
                .tau = std::move(tau),
                .psi = {
                    .offenders = std::move(psi_offenders)
                }
            };
        }

        static test_case_t from_bytes(decoder &dec)
        {
            return {
                dec.decode<decltype(in)>(),
                decode_state(dec),
                dec.decode<decltype(out)>(),
                decode_state(dec)
            };
        }
    };

    template<typename CFG>
    void test_file(const std::string &path)
    {
        const auto tc = jam::load_obj<test_case_t<CFG>>(path);
        std::optional<output_t<CFG>> out {};
        state_t<CFG> res_st = tc.pre;
        err_code_t::catch_into(
            [&] {
                auto tmp_st = tc.pre;
                out.emplace(tmp_st.update_safrole(tc.in.slot, tc.in.entropy, tc.in.extrinsic));
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
            for (const auto &path: file::files_with_ext(file::install_path("test/jam-test-vectors/safrole/tiny"), ".bin")) {
                test_file<config_tiny>(path);
            }
            for (const auto &path: file::files_with_ext(file::install_path("test/jam-test-vectors/safrole/full"), ".bin")) {
                test_file<config_prod>(path);
            }
        };
    };
};
