/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/test.hpp>
#include "types.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jam;

    struct raw_state_t {
        state_root_t state_root;
        state_dict_t keyvals;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("state_root"sv, state_root);
            archive.process("keyvals"sv, keyvals);
        }

        bool operator==(const raw_state_t &o) const
        {
            if (state_root != o.state_root)
                return false;
            if (keyvals != o.keyvals)
                return false;
            return true;
        }
    };

    struct test_case_t {
        raw_state_t pre;
        block_t<config_tiny> block;
        raw_state_t post;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("pre_state"sv, pre);
            archive.process("block"sv, block);
            archive.process("post_state"sv, post);
        }

        bool operator==(const test_case_t &o) const
        {
            if (pre != o.pre)
                return false;
            if (block != o.block)
                return false;
            if (post != o.post)
                return false;
            return true;
        }
    };

    void test_file(const std::string &path)
    {
        try {
            const auto tc = jam::load_obj<test_case_t>(path + ".bin");
            {
                const auto j_tc = codec::json::load_obj<test_case_t>(path + ".json");
                expect(tc == j_tc) << "the json test case does not match the binary one" << path;
            }
            state_t<config_tiny> st {};
            st = tc.pre.keyvals;
            st.apply(tc.block);
            const auto res = st.state_dict();
            expect_equal(path, res.root(), tc.post.state_root);
            expect(res != tc.post.keyvals) << path;
        } catch (const std::exception &ex) {
            expect(false) << path << ex.what();
        }
    }
}

suite turbo_jam_traces_suite = [] {
    "turbo::jam::traces"_test = [] {
        for (const auto &path: file::files_with_ext(file::install_path("test/jam-test-vectors/traces/fallback"), ".bin")) {
            test_file(path.substr(0, path.size() - 4));
        }
        for (const auto &path: file::files_with_ext(file::install_path("test/jam-test-vectors/traces/safrole"), ".bin")) {
            test_file(path.substr(0, path.size() - 4));
        }
        /*for (const auto &path: file::files_with_ext(file::install_path("test/jam-test-vectors/traces/reports-l0"), ".bin")) {
            test_file(path.substr(0, path.size() - 4));
        }*/
    };
};
