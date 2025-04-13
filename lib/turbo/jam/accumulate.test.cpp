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

    struct tmp_account_t {
        service_info_t service;
        preimages_t preimages;

        static tmp_account_t from_bytes(decoder &dec)
        {
            return {
                dec.decode<decltype(service)>(),
                dec.decode<decltype(preimages)>()
            };
        }
    };

    using tmp_accounts_t = map_t<service_id_t, tmp_account_t>;

    template<typename CONSTANTS>
    struct input_t {
        time_slot_t<CONSTANTS> slot;
        work_reports_t<CONSTANTS> reports;

        static input_t from_bytes(decoder &dec)
        {
            return {
                dec.decode<decltype(slot)>(),
                dec.decode<decltype(reports)>()
            };
        }

        bool operator==(const input_t &o) const
        {
            if (slot != o.slot)
                return false;
            if (reports != o.reports)
                return false;
            return true;
        }
    };

    struct err_code_t {
        bool operator==(const err_code_t &) const
        {
            return true;
        }
    };

    using output_base_t = std::variant<accumulate_root_t, err_code_t>;
    struct output_t: output_base_t {
        using base_type = output_base_t;
        using base_type::base_type;

        static output_t from_bytes(decoder &dec)
        {
            const auto typ = dec.decode<uint8_t>();
            switch (typ) {
                case 0: return { accumulate_root_t::from_bytes(dec) };
                case 1: return { err_code_t {} };
                [[unlikely]] default: throw error(fmt::format("unsupported output_t type: {}", typ));
            }
        }
    };

    template<typename CONSTANTS>
    struct test_case_t {
        input_t<CONSTANTS> in;
        state_t<CONSTANTS> pre;
        output_t out;
        state_t<CONSTANTS> post;

        static accounts_t<CONSTANTS> decode_accounts(decoder &dec)
        {
            auto t_accs = dec.decode<tmp_accounts_t>();
            accounts_t<CONSTANTS> delta {};
            for (auto &&[id, t_acc]: t_accs) {
                delta.try_emplace(id, std::move(t_acc.preimages), lookup_metas_t<CONSTANTS> {}, std::move(t_acc.service));
            }
            return delta;
        }

        static state_t<CONSTANTS> decode_state(decoder &dec)
        {
            auto tau = dec.decode<decltype(pre.tau)>();
            auto eta0 = dec.decode<entropy_t>();
            auto nu = dec.decode<decltype(pre.nu)>();
            auto ksi = dec.decode<decltype(pre.ksi)>();
            auto chi = dec.decode<decltype(pre.chi)>();
            auto delta = decode_accounts(dec);

            return {
                .delta = std::move(delta),
                //.eta = std::move(eta),
                .nu = std::move(nu),
                .ksi = std::move(ksi),
                .tau = std::move(tau),
                .chi = std::move(chi)
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
        const auto tc = jam::load<test_case_t<CFG>>(path);
        std::optional<output_t> out {};
        state_t<CFG> res_st = tc.pre;
        try {
            auto tmp_st = tc.pre;
            //out.emplace(tmp_st.update_reports(tc.in.slot, tc.in.guarantees));
            res_st = std::move(tmp_st);
        } catch (const error &) {
            out.emplace(err_code_t {});
        }
        if (out.has_value()) {
            expect(out == tc.out) << path;
            expect(res_st == tc.post) << path;
        } else {
            expect(false) << path;
        }
    }
}

suite turbo_jam_accumulate_suite = [] {
    "turbo::jam::accumulate"_test = [] {
        "tiny test vectors"_test = [] {
            for (const auto &path: file::files_with_ext(file::install_path("test/jam-test-vectors/accumulate/tiny"), ".bin")) {
                test_file<config_tiny>(path);
            }
        };
        "full test vectors"_test = [] {
            for (const auto &path: file::files_with_ext(file::install_path("test/jam-test-vectors/accumulate/full"), ".bin")) {
                test_file<config_prod>(path);
            }
        };
    };
};
