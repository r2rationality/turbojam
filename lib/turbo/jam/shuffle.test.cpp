/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <boost/json.hpp>
#include <turbo/common/test.hpp>
#include <turbo/codec/json.hpp>
#include "types/state.hpp"
#include "shuffle.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::codec;
}

suite turbo_jam_shuffle_suite = [] {
    "turbo::jam::shuffle"_test = [] {
        "uint32_from_entropy"_test = [] {
            const auto entropy = jam::opaque_hash_t::from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
            expect_equal(3180133873U, jam::shuffle::uint32_from_entropy(entropy, 0));
            expect_equal(2874123541U, jam::shuffle::uint32_from_entropy(entropy, 1));
            expect_equal(1702679006U, jam::shuffle::uint32_from_entropy(entropy, 2));
            expect_equal(3779386820U, jam::shuffle::uint32_from_entropy(entropy, 3));
            expect_equal(313342713U, jam::shuffle::uint32_from_entropy(entropy, 4));
            expect_equal(1075366959U, jam::shuffle::uint32_from_entropy(entropy, 5));
            expect_equal(2867850673U, jam::shuffle::uint32_from_entropy(entropy, 6));
            expect_equal(573291173U, jam::shuffle::uint32_from_entropy(entropy, 7));
        };
        "shuffle empty"_test = [] {
            const auto entropy = jam::opaque_hash_t::from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
            const std::vector<size_t> seq {};
            const auto res = jam::shuffle::with_entropy(seq, entropy);
            expect_equal(seq, res);
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
                expect_equal(exp, act, fmt::format("#{}", case_no));
                ++case_no;
            }
        };
    };
};
