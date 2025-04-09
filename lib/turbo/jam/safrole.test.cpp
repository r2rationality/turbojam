/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/test.hpp>
#include "errors.hpp"
#include "types.hpp"
#include "state.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jam;

    template<typename CONSTANTS>
    struct input_t {
        time_slot_t<CONSTANTS> slot;
        entropy_t entropy;
        tickets_extrinsic_t<CONSTANTS> extrinsic;

        static input_t from_bytes(codec::decoder &dec)
        {
            return {
                dec.decode<decltype(slot)>(),
                dec.decode<decltype(entropy)>(),
                dec.decode<decltype(extrinsic)>()
            };
        }
    };

    struct err_code_t: err_any_t {
        using base_type = err_any_t;
        using base_type::base_type;

        static err_code_t from_bytes(codec::decoder &dec)
        {
            switch (const auto typ = dec.decode<uint8_t>(); typ) {
                case 0: return { err_bad_slot_t {} };
                case 1: return { err_unexpected_ticket_t {} };
                case 2: return { err_bad_ticket_order_t {} };
                case 3: return { err_bad_ticket_proof_t {} };
                case 4: return { err_bad_ticket_attempt_t {} };
                case 5: return { err_reserved_t {} };
                case 6: return { err_duplicate_ticket_t {} };
                [[unlikely]] default: throw error(fmt::format("unsupported err_code_t type: {}", typ));
            }
        }
    };

    template<typename CONSTANTS>
    struct output_t: std::variant<safrole_output_data_t<CONSTANTS>, err_code_t> {
        using base_type = std::variant<safrole_output_data_t<CONSTANTS>, err_code_t>;

        static output_t from_bytes(codec::decoder &dec)
        {
            const auto typ = dec.decode<uint8_t>();
            switch (typ) {
                case 0: return { safrole_output_data_t<CONSTANTS>::from_bytes(dec) };
                case 1: return { err_code_t::from_bytes(dec) };
                    [[unlikely]] default: throw error(fmt::format("unsupported output_t type: {}", typ));
            }
        }
    };

    template<typename CONSTANTS>
    struct test_case_t {
        input_t<CONSTANTS> in;
        state_t<CONSTANTS> pre;
        output_t<CONSTANTS> out;
        state_t<CONSTANTS> post;

        static state_t<CONSTANTS> decode_state(codec::decoder &dec)
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
            auto psi_o_post = dec.decode<decltype(pre.psi_o_post)>();
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
                .psi_o_post = std::move(psi_o_post)
            };
        }

        static test_case_t from_bytes(codec::decoder &dec)
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
        const auto tc = codec::load<test_case_t<CFG>>(path);
        std::optional<output_t<CFG>> out {};
        state_t<CFG> res_st = tc.pre;
        err_any_t::catch_into(
            [&] {
                auto tmp_st = tc.pre;
                out.emplace(tmp_st.update_safrole(tc.in.slot, tc.in.entropy, tc.in.extrinsic));
                res_st = std::move(tmp_st);
            },
            [&](err_any_t err) {
                std::visit([&](auto &&e) {
                    out.emplace(std::move(e));
                }, std::move(err));
            }
        );
        expect(fatal(out.has_value())) << path;
        expect(out == tc.out) << path;
        expect(res_st == tc.post) << path;
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
