/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <boost/json.hpp>
#include <turbo/common/test.hpp>
#include <turbo/codec/json.hpp>
#include "merkle.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::codec;
    using namespace turbo::jam;
    using namespace turbo::jam::merkle;
}

suite turbo_jam_merkle_suite = [] {
    "turbo::jam::merkle"_test = [] {
        const auto test_vectors = json::load(file::install_path("test/jam-test-vectors/trie/trie.json"));
        size_t case_no = 0;
        for (const auto &vector: test_vectors.as_array()) {
            const auto &input = vector.at("input").as_object();
            const auto exp_out = hash_t::from_hex(json::value_to<std::string_view>(vector.at("output")));
            trie::input_map_t input_m {};
            for (const auto &[k, v]: input) {
                const auto tk = trie::key_t::from_hex(k.substr(0, 62));
                input_m.emplace(tk, uint8_vector::from_hex(json::value_to<std::string_view>(v)));
            }
            const auto act_out = trie::encode_blake2b(input_m);
            expect_equal(fmt::format("#{}", case_no), exp_out, act_out);
            ++case_no;
        }
    };
};
