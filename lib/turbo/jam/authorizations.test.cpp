/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/test.hpp>
#include "types.hpp"
#include "state.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jam;

    struct input_t {
        time_slot_t slot;
        core_authorizers_t auths;

        static input_t from_bytes(codec::decoder &dec)
        {
            return {
                dec.decode<decltype(slot)>(),
                dec.decode<decltype(auths)>()
            };
        }
    };

    template<typename CONSTANTS=config_prod>
    struct test_case_t {
        input_t input;
        state_t<CONSTANTS> pre_state;
        state_t<CONSTANTS> post_state;

        static state_t<CONSTANTS> decode_state(codec::decoder &dec)
        {
            return {
                .alpha = dec.decode<decltype(pre_state.alpha)>(),
                .phi = dec.decode<decltype(pre_state.phi)>()
            };
        }

        static test_case_t from_bytes(codec::decoder &dec)
        {
            return {
                dec.decode<decltype(input)>(),
                decode_state(dec),
                decode_state(dec)
            };
        }
    };

    template<typename CFG>
    void test_file(const std::string &path, const std::source_location &loc=std::source_location::current())
    {
        const auto tc = codec::load<test_case_t<CFG>>(path);
        const auto new_alpha = tc.pre_state.alpha.apply(tc.input.slot, tc.input.auths, tc.pre_state.phi);
        expect(new_alpha == tc.post_state.alpha) << path;
    }
}

suite turbo_jam_authorizations_suite = [] {
    "turbo::jam::authorizations"_test = [] {
        "tiny"_test = [] {
            for (const auto &path: file::files_with_ext(file::install_path("test/jam-test-vectors/authorizations/tiny"), ".bin")) {
                test_file<config_tiny>(path);
            }
        };
        "full"_test = [] {
            for (const auto &path: file::files_with_ext(file::install_path("test/jam-test-vectors/authorizations/full"), ".bin")) {
                test_file<config_prod>(path);
            }
        };
    };
};
