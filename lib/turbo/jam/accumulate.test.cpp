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

    struct tmp_account_t: codec::serializable_t<tmp_account_t> {
        service_info_t service;
        preimages_t preimages;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("service"sv, service);
            archive.process("preimages"sv, preimages);
        }
    };

    using tmp_accounts_t = map_t<service_id_t, tmp_account_t, accounts_config_t>;

    template<typename CONSTANTS>
    struct input_t: codec::serializable_t<input_t<CONSTANTS>> {
        time_slot_t<CONSTANTS> slot;
        work_reports_t<CONSTANTS> reports;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("slot"sv, slot);
            archive.process("reports"sv, reports);
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
                case 0: return { accumulate_root_t::from(dec) };
                case 1: return { err_code_t {} };
                [[unlikely]] default: throw error(fmt::format("unsupported output_t type: {}", typ));
            }
        }
    };

    template<typename CONSTANTS>
    struct test_case_t: codec::serializable_t<test_case_t<CONSTANTS>> {
        input_t<CONSTANTS> in;
        state_t<CONSTANTS> pre;
        output_t out;
        state_t<CONSTANTS> post;

        static void serialize_accounts(auto &archive, const std::string_view name, accounts_t<CONSTANTS> &accs)
        {
            tmp_accounts_t taccs;
            archive.process(name, taccs);
            accs.clear();
            for (auto &&[id, tacc]: taccs) {
                account_t<CONSTANTS> acc {
                    .preimages=std::move(tacc.preimages),
                    .info=std::move(tacc.service)
                };
                const auto [it, created] = accs.try_emplace(std::move(id), std::move(acc));
                if (!created) [[unlikely]]
                    throw error(fmt::format("a duplicate account in the service map!"));
            }
        }

        static void serialize_state(auto &archive, const std::string_view, state_t<CONSTANTS> &st)
        {
            using namespace std::string_view_literals;
            archive.process("slot"sv, st.tau);
            archive.process("entropy"sv, st.eta[0]);
            archive.process("ready_queue"sv, st.nu);
            archive.process("accumulated"sv, st.ksi);
            archive.process("privileges"sv, st.chi);
            serialize_accounts(archive, "accounts"sv, st.delta);
        }

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("input"sv, in);
            serialize_state(archive, "pre_state"sv, pre);
            archive.process("output"sv, out);
            serialize_state(archive, "post_state"sv, post);
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
            out.emplace(tmp_st.accumulate(tc.in.slot, tc.in.reports));
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
        /*"tiny test vectors"_test = [] {
            for (const auto &path: file::files_with_ext(file::install_path("test/jam-test-vectors/accumulate/tiny"), ".bin")) {
                test_file<config_tiny>(path);
            }
        };
        "full test vectors"_test = [] {
            for (const auto &path: file::files_with_ext(file::install_path("test/jam-test-vectors/accumulate/full"), ".bin")) {
                test_file<config_prod>(path);
            }
        };*/
    };
};
