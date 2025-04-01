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

    struct input_t {
        preimages_extrinsic_t preimages;
        time_slot_t slot;

        static input_t from_bytes(codec::decoder &dec)
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

    struct err_preimage_unneeded_t {
        bool operator==(const err_preimage_unneeded_t &o) const
        {
            return true;
        }
    };
    struct err_preimages_not_sorted_or_unique_t {
        bool operator==(const err_preimages_not_sorted_or_unique_t &o) const {
            return true;
        }
    };

    struct err_code_t: std::variant<err_preimage_unneeded_t, err_preimages_not_sorted_or_unique_t> {
        using base_type = std::variant<err_preimage_unneeded_t, err_preimages_not_sorted_or_unique_t>;
        using base_type::base_type;

        static err_code_t from_bytes(codec::decoder &dec)
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

        static output_t from_bytes(codec::decoder &dec)
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
    struct test_case_t {
        input_t input;
        state_t<CONSTANTS> pre_state;
        output_t output;
        state_t<CONSTANTS> post_state;

        static state_t<CONSTANTS> decode_state(codec::decoder &dec)
        {
            return {
                .delta=dec.decode<accounts_t>()
            };
        }

        static test_case_t from_bytes(codec::decoder &dec)
        {
            return {
                dec.decode<decltype(input)>(),
                decode_state(dec),
                dec.decode<decltype(output)>(),
                decode_state(dec)
            };
        }
    };

    template<typename CFG>
    void test_file(const std::string &path, const std::source_location &loc=std::source_location::current())
    {
        const auto tc = codec::load<test_case_t<CFG>>(path);
        auto new_st = tc.pre_state;
        std::optional<output_t> out {};
        try {
            new_st.delta = tc.pre_state.delta.apply(tc.input.slot, tc.input.preimages);
            out.emplace(ok_t {});
        } catch (jam::err_preimage_unneeded_t &) {
            out.emplace(err_preimage_unneeded_t {});
        } catch (jam::err_preimages_not_sorted_or_unique_t &) {
            out.emplace(err_preimages_not_sorted_or_unique_t {});
        }
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
