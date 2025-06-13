/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/test.hpp>
#include "types/state.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jam;

    struct input_t {
        header_hash_t header_hash;
        state_root_t parent_state_root;
        opaque_hash_t accumulate_root;
        reported_work_seq_t work_packages;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("header_hash"sv, header_hash);
            archive.process("parent_state_root"sv, parent_state_root);
            archive.process("accumulate_root"sv, accumulate_root);
            archive.process("work_packages"sv, work_packages);
        }

        bool operator==(const input_t &o) const
        {
            if (header_hash != o.header_hash)
                return false;
            if (parent_state_root != o.parent_state_root)
                return false;
            if (accumulate_root != o.accumulate_root)
                return false;
            if (work_packages != o.work_packages)
                return false;
            return true;
        }
    };

    template<typename CONSTANTS=config_prod>
    struct test_case_t {
        input_t in;
        state_t<CONSTANTS> pre;
        state_t<CONSTANTS> post;

        static void serialize_state(auto &archive, const std::string_view &name, state_t<CONSTANTS> &st)
        {
            using namespace std::string_view_literals;
            archive.push(name);
            archive.process("beta"sv, st.beta);
            archive.pop();
        }

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("input"sv, in);
            serialize_state(archive, "pre_state"sv, pre);
            serialize_state(archive, "post_state"sv, post);
        }

        bool operator==(const test_case_t &o) const
        {
            if (in != o.in)
                return false;
            if (pre != o.pre)
                return false;
            if (post != o.post)
                return false;
            return true;
        }
    };

    template<typename CFG>
    void test_file(const std::string &path)
    {
        const auto tc = jam::load_obj<test_case_t<CFG>>(path + ".bin");
        {
            const auto j_tc = codec::json::load_obj<test_case_t<CFG>>(path + ".json");
            expect(tc == j_tc) << "json test case does not match the binary one" << path;
        }
        state_t<CFG> new_st;
        new_st = tc.pre;
        new_st.update_history_1(tc.in.parent_state_root);
        new_st.update_history_2(tc.in.header_hash, tc.in.accumulate_root, tc.in.work_packages);
        expect(new_st == tc.post) << path;
    }
}

suite turbo_jam_history_suite = [] {
    "turbo::jam::history"_test = [] {
        for (const auto &path: file::files_with_ext(file::install_path("test/jam-test-vectors/stf/history/data"), ".bin")) {
            test_file<config_tiny>(path.substr(0, path.size() - 4));
        }
    };
};
