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
        header_hash_t header_hash;
        state_root_t state_root;
        opaque_hash_t accumulate_root;
        reported_work_seq_t reported_work;

        static input_t from_bytes(decoder &dec)
        {
            return {
                dec.decode<decltype(header_hash)>(),
                dec.decode<decltype(state_root)>(),
                dec.decode<decltype(accumulate_root)>(),
                dec.decode<decltype(reported_work)>()
            };
        }
    };

    template<typename CONSTANTS=config_prod>
    struct test_case_t {
        input_t input;
        state_t<CONSTANTS> pre_state;
        state_t<CONSTANTS> post_state;

        static state_t<CONSTANTS> read_state(decoder &dec)
        {
            auto history = dec.decode<decltype(pre_state.beta)>();
            return { .beta=std::move(history) };
        }

        static test_case_t from_bytes(decoder &dec)
        {
            return {
                dec.decode<decltype(input)>(),
                read_state(dec),
                read_state(dec)
            };
        }
    };

    template<typename CFG>
    void test_file(const std::string &path, const std::source_location &loc=std::source_location::current())
    {
        const auto tc = jam::load<test_case_t<CFG>>(path);
        auto new_st = tc.pre_state;
        new_st.beta = new_st.beta.apply(tc.input.header_hash, tc.input.state_root, tc.input.accumulate_root, tc.input.reported_work);
        expect(fatal(new_st.beta.size() == tc.post_state.beta.size()));
        for (size_t i = 0; i < tc.post_state.beta.size(); ++i) {
            const auto &act_block = new_st.beta[i];
            const auto &exp_block = tc.post_state.beta[i];
            expect_equal(fmt::format("{}#{} header_hash", path, i), act_block.header_hash, exp_block.header_hash);
            expect_equal(fmt::format("{}#{} state_root", path, i), act_block.state_root, exp_block.state_root);
            expect(act_block.mmr == exp_block.mmr) << path << i;
            expect(act_block.reported == exp_block.reported) << path << i;
            expect(act_block == exp_block) << path << i;;
        }
        expect(new_st == tc.post_state, loc) << path;
    }
}

suite turbo_jam_history_suite = [] {
    "turbo::jam::history"_test = [] {
        for (const auto &path: file::files_with_ext(file::install_path("test/jam-test-vectors/history/data"), ".bin")) {
            test_file<config_tiny>(path);
        }
    };
};
