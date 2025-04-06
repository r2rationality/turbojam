/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/test.hpp>
#include "types.hpp"
#include "state.hpp"
#include "preimages.hpp"

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

    template<typename CONSTANTS>
    struct output_data_t {
        optional_t<epoch_mark_t<CONSTANTS>> epoch_mark;
        optional_t<tickets_mark_t<CONSTANTS>> tickets_mark;

        static output_data_t from_bytes(codec::decoder &dec)
        {
            return {
                dec.decode<decltype(epoch_mark)>(),
                dec.decode<decltype(tickets_mark)>()
            };
        }

        bool operator==(const output_data_t &o) const
        {
            if (epoch_mark != o.epoch_mark)
                return false;
            if (tickets_mark != o.tickets_mark)
                return false;
            return true;
        }
    };

    struct err_bad_slot_t {
        bool operator==(const err_bad_slot_t &) const {
            return true;
        }
    };
    struct err_unexpected_ticket_t {
        bool operator==(const err_unexpected_ticket_t &) const {
            return true;
        }
    };
    struct err_bad_ticket_order_t {
        bool operator==(const err_bad_ticket_order_t &) const {
            return true;
        }
    };
    struct err_bad_ticket_proof_t {
        bool operator==(const err_bad_ticket_proof_t &) const {
            return true;
        }
    };
    struct err_bad_ticket_attempt_t {
        bool operator==(const err_bad_ticket_attempt_t &) const {
            return true;
        }
    };
    struct err_reserved_t {
        bool operator==(const err_reserved_t &) const {
            return true;
        }
    };
    struct err_duplicate_ticket_t {
        bool operator==(const err_duplicate_ticket_t &) const {
            return true;
        }
    };

    struct err_code_t: std::variant<err_bad_slot_t, err_unexpected_ticket_t, err_bad_ticket_order_t, err_bad_ticket_proof_t, err_bad_ticket_attempt_t, err_reserved_t, err_duplicate_ticket_t> {
        using base_type = std::variant<err_bad_slot_t, err_unexpected_ticket_t, err_bad_ticket_order_t, err_bad_ticket_proof_t, err_bad_ticket_attempt_t, err_reserved_t, err_duplicate_ticket_t>;
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
    struct output_t: std::variant<output_data_t<CONSTANTS>, err_code_t> {
        using base_type = std::variant<output_data_t<CONSTANTS>, err_code_t>;

        static output_t from_bytes(codec::decoder &dec)
        {
            const auto typ = dec.decode<uint8_t>();
            switch (typ) {
                case 0: return { output_data_t<CONSTANTS>::from_bytes(dec) };
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
    void test_file(const std::string &path, const std::source_location &loc=std::source_location::current())
    {
        const auto tc = codec::load<test_case_t<CFG>>(path);
        auto new_st = tc.pre;
        std::optional<output_t<CFG>> out {};
        try {
            output_data_t<CFG> res {};
            new_st.update_safrole(tc.in.slot, tc.in.entropy, tc.in.extrinsic);
            out.emplace(std::move(res));
        } catch (jam::err_bad_slot_t &) {
            out.emplace(err_bad_slot_t {});
        } catch (jam::err_unexpected_ticket_t &) {
            out.emplace(err_unexpected_ticket_t {});
        } catch (jam::err_bad_ticket_order_t &) {
            out.emplace(err_bad_ticket_order_t {});
        } catch (jam::err_bad_ticket_proof_t &) {
            out.emplace(err_bad_ticket_proof_t {});
        } catch (jam::err_bad_ticket_attempt_t &) {
            out.emplace(err_bad_ticket_attempt_t {});
        } catch (jam::err_reserved_t &) {
            out.emplace(err_reserved_t {});
        } catch (jam::err_duplicate_ticket_t &) {
            out.emplace(err_duplicate_ticket_t {});
        }
        expect(fatal(out.has_value())) << path;
        expect(out == tc.out) << path;
        expect(new_st == tc.post) << path;
    }
}

suite turbo_jam_safrole_suite = [] {
    "turbo::jam::safrole"_test = [] {
        "conformance test vectors"_test = [] {
            test_file<config_tiny>(file::install_path("test/jam-test-vectors/safrole/tiny/enact-epoch-change-with-no-tickets-4.bin"));
            for (const auto &path: file::files_with_ext(file::install_path("test/jam-test-vectors/safrole/tiny"), ".bin")) {
                test_file<config_tiny>(path);
            }
            for (const auto &path: file::files_with_ext(file::install_path("test/jam-test-vectors/safrole/full"), ".bin")) {
                test_file<config_prod>(path);
            }
        };
    };
};
