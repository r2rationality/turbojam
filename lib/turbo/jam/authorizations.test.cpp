/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/test.hpp>
#include "types.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jam;

    template<typename CONSTANTS=config_prod>
    struct test_state_t {
        auth_pools_t<CONSTANTS> auth_pools;
        auth_queues_t<CONSTANTS> auth_queues;

        static test_state_t from_bytes(codec::decoder &dec)
        {
            return {
                dec.decode<decltype(auth_pools)>(),
                dec.decode<decltype(auth_queues)>()
            };
        }
    };

    struct core_authorizer_t {
        core_index_t core;
        opaque_hash_t auth_hash;

        static core_authorizer_t from_bytes(codec::decoder &dec)
        {
            return {
                dec.decode<decltype(core)>(),
                dec.decode<decltype(auth_hash)>()
            };
        }
    };

    using core_authorizers_t = sequence_t<core_authorizer_t>;

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
        test_state_t<CONSTANTS> pre_state;
        test_state_t<CONSTANTS> post_state;

        static test_case_t from_bytes(codec::decoder &dec)
        {
            return {
                dec.decode<decltype(input)>(),
                dec.decode<decltype(pre_state)>(),
                dec.decode<decltype(post_state)>()
            };
        }
    };

    template<typename CFG>
    void test_file(const std::string &path, const std::source_location &loc=std::source_location::current())
    {
        const auto tc = codec::load<test_case_t<CFG>>(path);
        expect(false) << path;
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
