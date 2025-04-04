/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <boost/json.hpp>
#include <turbo/common/test.hpp>
#include <turbo/codec/json.hpp>
#include "types.hpp"
#include "shuffle.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::codec;
}

suite turbo_jam_shuffle_suite = [] {
    "turbo::jam::shuffle"_test = [] {
        "uint32_from_entropy"_test = [] {
            const auto entropy = jam::opaque_hash_t::from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
            expect_equal(0U, jam::shuffle::uint32_from_entropy(entropy, 0));
            expect_equal(0U, jam::shuffle::uint32_from_entropy(entropy, 1));
        };
        "test vectors"_test = [] {
            const auto test_vectors = json::load(file::install_path("test/jam-test-vectors/shuffle/shuffle_tests.json"));
            size_t case_no = 0;
            for (const auto &vector: test_vectors.as_array()) {
                const auto len = boost::json::value_to<size_t>(vector.at("input"));
                const auto entropy = jam::opaque_hash_t::from_hex(boost::json::value_to<std::string_view>(vector.at("entropy")));
                std::vector<size_t> in {};
                in.reserve(len);
                while (in.size() < len) {
                    in.emplace_back(in.size());
                }
                std::vector<size_t> exp {};
                exp.reserve(len);
                for (const auto &jv: vector.at("output").as_array()) {
                    exp.emplace_back(boost::json::value_to<size_t>(jv));
                }
                const auto act = jam::shuffle::with_entropy(in, entropy);
                expect_equal(fmt::format("#{}", case_no), exp, act);
                ++case_no;
            }
        };
    };
};
