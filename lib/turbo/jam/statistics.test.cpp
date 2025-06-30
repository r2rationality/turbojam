/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/test.hpp>
#include "state.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jam;

    template<typename CONSTANTS>
    struct input_t {
        time_slot_t<CONSTANTS> slot;
        validator_index_t author_index;
        extrinsic_t<CONSTANTS> extrinsic;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("slot"sv, slot);
            archive.process("author_index"sv, author_index);
            archive.process("extrinsic"sv, extrinsic);
        }

        bool operator==(const input_t &o) const
        {
            if (slot != o.slot)
                return false;
            if (author_index != o.author_index)
                return false;
            if (extrinsic != o.extrinsic)
                return false;
            return true;
        }
    };

    template<typename CONSTANTS>
    struct test_case_t {
        file::tmp_directory tmp_dir_pre { fmt::format("test-jam-preimages-{}-pre", static_cast<void *>(this)) };
        file::tmp_directory tmp_dir_post { fmt::format("test-jam-preimages-{}-post", static_cast<void *>(this)) };
        input_t<CONSTANTS> in;
        state_t<CONSTANTS> pre { std::make_shared<triedb::client_t>(tmp_dir_pre.path()) };
        state_t<CONSTANTS> post { std::make_shared<triedb::client_t>(tmp_dir_post.path()) };

        void serialize_state(auto &archive, const std::string_view name, state_t<CONSTANTS> &st)
        {
            using namespace std::string_view_literals;
            archive.push(name);
            {
                auto new_pi = st.pi.get();
                archive.process("vals_curr_stats"sv, new_pi.current);
                archive.process("vals_last_stats"sv, new_pi.last);
                st.pi.set(std::move(new_pi));
            }
            archive.process("slot"sv, st.tau);
            archive.process("curr_validators"sv, st.kappa);
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
            expect(tc == j_tc) << "the json test case does not match the binary one" << path;
        }
        const file::tmp_directory state_dir { "test-jam-statistics" };
        state_t<CFG> new_st { tc.pre };
        new_st.pi.set(state_t<CFG>::pi_prime(statistics_t<CFG> { new_st.pi.get() }, tc.pre.tau.get(), tc.in.slot, tc.in.author_index, tc.in.extrinsic));
        new_st.tau.set(state_t<CFG>::tau_prime(tc.pre.tau.get(), tc.in.slot));
        expect(new_st.pi.get().current == tc.post.pi.get().current) << path;
        expect(new_st.pi.get().last == tc.post.pi.get().last) << path;
    }
}

suite turbo_jam_statistics_suite = [] {
    "turbo::jam::statistics"_test = [] {
        for (const auto &path: file::files_with_ext(file::install_path("test/jam-test-vectors/stf/statistics/tiny"), ".bin")) {
            test_file<config_tiny>(path.substr(0, path.size() - 4));
        }
        for (const auto &path: file::files_with_ext(file::install_path("test/jam-test-vectors/stf/statistics/full"), ".bin")) {
            test_file<config_prod>(path.substr(0, path.size() - 4));
        }
    };
};
