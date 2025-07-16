/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/test.hpp>
#include "erasure.hpp"
#include "erasure-coding/include/erasure-coding.hpp"

namespace {
    using namespace std::string_view_literals;
    using namespace turbo;
    using namespace turbo::jam;
    using namespace turbo::jam::erasure;

    template<typename CFG>
    struct test_case_t {
        byte_sequence_t data;
        sequence_t<byte_sequence_t, CFG::V_validator_count, CFG::V_validator_count> shards;

        void serialize(auto &archive)
        {
            archive.process("data"sv, data);
            archive.process("shards"sv, shards);
        }

        bool operator==(const test_case_t &) const = default;
    };

    template<typename CFG>
    void test_file(const std::string &path)
    {
        try {
            const auto tc = jam::load_obj<test_case_t<CFG>>(path + ".bin");
            {
                const auto j_tc = codec::json::load_obj<test_case_t<CFG>>(path + ".json");
                expect(tc == j_tc) << "the json test case does not match the binary one" << path;
            }
            const auto t_data = transpose(CFG::V_validator_count, tc.data);
            byte_array<6U * 2U> shards;
            if (const auto res = erasure_coding::construct_chunks(shards, CFG::V_validator_count, t_data); res != 0) [[unlikely]]
                throw error(fmt::format("erasure_coding::construct_chunks failed with error code {}", res));
            expect(false) << "not implemented";
        } catch (const std::exception &ex) {
            expect(false) << path << ex.what();
        }
    }
}

suite turbo_jam_erasure_suite = [] {
    "turbo::jam::erasure"_test = [] {
        "transpose"_test = [] {
            expect_equal(
                transpose(6, uint8_vector::from_hex("0102030405060708090a0b0c")),
                uint8_vector::from_hex("010207080304090a05060b0c")
            );
        };
        test_file<config_tiny>(file::install_path("test/jam-test-vectors/erasure/tiny/ec-32"));
        /*for (const auto &path: file::files_with_ext(file::install_path("test/jam-test-vectors/erasure/tiny"), ".bin")) {
            test_file<config_tiny>(path.substr(0, path.size() - 4));
        }
        for (const auto &path: file::files_with_ext(file::install_path("test/jam-test-vectors/erasure/full"), ".bin")) {
            test_file<config_prod>(path.substr(0, path.size() - 4));
        }*/
    };
};
