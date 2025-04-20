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

    template<typename CONSTANTS>
    struct input_t {
        time_slot_t<CONSTANTS> slot;
        validator_index_t author_index;
        extrinsic_t<CONSTANTS> extrinsic;

        static input_t from_bytes(decoder &dec)
        {
            return {
                dec.decode<decltype(slot)>(),
                dec.decode<decltype(author_index)>(),
                dec.decode<decltype(extrinsic)>()
            };
        }
    };

    template<typename CONSTANTS>
    struct test_case_t: codec::serializable_t<test_case_t<CONSTANTS>> {
        input_t<CONSTANTS> in;
        state_t<CONSTANTS> pre;
        state_t<CONSTANTS> post;

        void serialize_state(auto &archive, const std::string_view /*name*/, state_t<CONSTANTS> &st)
        {
            using namespace std::string_view_literals;
            archive.process("statistics"sv, st.pi);
            archive.process("slot"sv, st.tau);
            archive.process("curr_validators"sv, st.kappa);
        }

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("input"sv, in);
            serialize_state(archive, "pre_state"sv, pre);
            serialize_state(archive, "post_state"sv, post);
        }
    };

    template<typename CFG>
    void test_file(const std::string &path, const std::source_location &loc=std::source_location::current())
    {
        const auto tc = jam::load<test_case_t<CFG>>(path);
        auto new_st = tc.pre;
        new_st.update_statistics(tc.in.slot, tc.in.author_index, tc.in.extrinsic);
        expect(new_st == tc.post, loc) << path;
    }
}

suite turbo_jam_statistics_suite = [] {
    "turbo::jam::statistics"_test = [] {
        for (const auto &path: file::files_with_ext(file::install_path("test/jam-test-vectors/statistics/tiny"), ".bin")) {
            test_file<config_tiny>(path);
        }
        for (const auto &path: file::files_with_ext(file::install_path("test/jam-test-vectors/statistics/full"), ".bin")) {
            test_file<config_prod>(path);
        }
    };
};
