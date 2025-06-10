/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/test.hpp>
#include "types.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jam;

    template<typename CONSTANTS>
    struct input_t {
        time_slot_t<CONSTANTS> slot;
        core_authorizers_t auths;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("slot"sv, slot);
            archive.process("auths"sv, auths);
        }

        bool operator==(const input_t &o) const
        {
            if (slot != o.slot)
                return false;
            if (auths != o.auths)
                return false;
            return true;
        }
    };

    template<typename CONSTANTS=config_prod>
    struct test_case_t {
        input_t<CONSTANTS> in;
        state_t<CONSTANTS> pre;
        state_t<CONSTANTS> post;

        static void serialize_state(auto &archive, const std::string_view &name, state_t<CONSTANTS> &st)
        {
            using namespace std::string_view_literals;
            archive.push(name);
            archive.process("auth_pools"sv, st.alpha);
            archive.process("auth_queues"sv, st.phi);
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
        state_t<CFG> new_st = tc.pre;
        new_st.update_auth_pools(tc.in.slot, tc.in.auths);
        expect(new_st == tc.post) << path;
    }
}

suite turbo_jam_authorizations_suite = [] {
    "turbo::jam::authorizations"_test = [] {
        "tiny"_test = [] {
            for (const auto &path: file::files_with_ext(file::install_path("test/jam-test-vectors/stf/authorizations/tiny"), ".bin")) {
                test_file<config_tiny>(path.substr(0, path.size() - 4));
            }
        };
        "full"_test = [] {
            for (const auto &path: file::files_with_ext(file::install_path("test/jam-test-vectors/stf/authorizations/full"), ".bin")) {
                test_file<config_prod>(path.substr(0, path.size() - 4));
            }
        };
    };
};
