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
    struct tmp_account_t: codec::serializable_t<tmp_account_t<CONSTANTS>> {
        preimages_t preimages;
        lookup_metas_t<CONSTANTS> lookup_metas;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("preimages"sv, preimages);
            archive.process("lookup_meta"sv, lookup_metas);
        }
    };
    template<typename CONSTANTS>
    using tmp_accounts_t = map_t<service_id_t, tmp_account_t<CONSTANTS>, accounts_config_t>;

    template<typename CONSTANTS>
    struct input_t {
        preimages_extrinsic_t preimages;
        time_slot_t<CONSTANTS> slot;

        static input_t from_bytes(decoder &dec)
        {
            return {
                dec.decode<decltype(preimages)>(),
                dec.decode<decltype(slot)>()
            };
        }
    };

    struct ok_t {
        bool operator==(const ok_t &) const
        {
            return true;
        }
    };

    struct err_code_t: err_any_t {
        using base_type = err_any_t;
        using base_type::base_type;

        static err_code_t from_bytes(decoder &dec)
        {
            const auto typ = dec.decode<uint8_t>();
            switch (typ) {
                case 0: return { err_preimage_unneeded_t {} };
                case 1: return { err_preimages_not_sorted_or_unique_t {} };
                [[unlikely]] default: throw error(fmt::format("unsupported err_code_t type: {}", typ));
            }
        }
    };

    struct output_t: std::variant<ok_t, err_code_t> {
        using base_type = std::variant<ok_t, err_code_t>;
        using base_type::base_type;

        static output_t from_bytes(decoder &dec)
        {
            const auto typ = dec.decode<uint8_t>();
            switch (typ) {
                case 0: return { ok_t {} };
                case 1: return { err_code_t::from_bytes(dec) };
                [[unlikely]] default: throw error(fmt::format("unsupported output_t type: {}", typ));
            }
        }
    };

    template<typename CONSTANTS>
    struct test_case_t: codec::serializable_t<test_case_t<CONSTANTS>> {
        input_t<CONSTANTS> input;
        state_t<CONSTANTS> pre_state;
        output_t output;
        state_t<CONSTANTS> post_state;

        static void serialize_state(auto &archive, const std::string_view, state_t<CONSTANTS> &st)
        {
            using namespace std::string_view_literals;
            tmp_accounts_t<CONSTANTS> taccs;
            archive.process("accounts"sv, taccs);
            for (auto &&[id, tacc]: taccs) {
                st.delta.try_emplace(std::move(id), account_t<CONSTANTS> { .preimages=std::move(tacc.preimages), .lookup_metas=std::move(tacc.lookup_metas) });
            }
        }

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("input"sv, input);
            serialize_state(archive, "pre_state"sv, pre_state);
            archive.process("output"sv, output);
            serialize_state(archive, "post_state"sv, post_state);
        }
    };

    template<typename CFG>
    void test_file(const std::string &path)
    {
        const auto tc = jam::load<test_case_t<CFG>>(path);
        auto new_st = tc.pre_state;
        std::optional<output_t> out {};
        err_any_t::catch_into(
            [&] {
                new_st.delta = tc.pre_state.delta.apply(tc.input.slot, tc.input.preimages);
                out.emplace(ok_t {});
            },
            [&](err_any_t err) {
                std::visit([&](auto &&e) {
                    out.emplace(std::move(e));
                }, std::move(err));
            }
        );
        expect(fatal(out.has_value())) << path;
        expect(out == tc.output) << path;
        expect(new_st == tc.post_state) << path;
    }
}

suite turbo_jam_preimages_suite = [] {
    "turbo::jam::preimages"_test = [] {
        for (const auto &path: file::files_with_ext(file::install_path("test/jam-test-vectors/preimages/data"), ".bin")) {
            test_file<config_tiny>(path);
        }
    };
};
