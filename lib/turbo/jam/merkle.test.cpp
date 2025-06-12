/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <boost/json.hpp>
#include <turbo/common/test.hpp>
#include <turbo/codec/json.hpp>
#include <turbo/jam/types/state-dict.hpp>
#include "merkle.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::codec;
    using namespace turbo::jam;
    using namespace turbo::jam::merkle;
}

suite turbo_jam_merkle_suite = [] {
    "turbo::jam::merkle"_test = [] {
        const hash_func hf { static_cast<void(*)(const hash_span_t &, const buffer &)>(crypto::blake2b::digest) };
        "insert, update, erase"_test = [&] {
            trie_t trie { hf };
            expect(trie_t::opt_value_t {} == trie.get(trie_t::key_t {}));
            // insert
            static constexpr size_t num_nodes = 0x10;
            std::optional<hash_t> prev_root {};
            for (size_t i = 0; i < num_nodes; ++i) {
                const auto k = state_dict_t::make_key(i);
                const uint8_vector v { static_cast<std::string_view>(fmt::format("{:02X}", i)) };
                trie.set(k, trie_t::value_t { v, hf });
                expect(trie_t::value_t { v, hf } == trie.get(k)) << i;
                const auto new_root = trie.root();
                if (prev_root)
                    expect(prev_root != new_root) << i;
                prev_root = new_root;
            }
            // update
            prev_root.reset();
            for (size_t i = 0; i < num_nodes; ++i) {
                const auto k = state_dict_t::make_key(i);
                const uint8_vector v { static_cast<std::string_view>(fmt::format("{:02X}", i + 1)) };
                trie.set(k, trie_t::value_t { v, hf });
                expect(trie_t::value_t { v, hf } == trie.get(k)) << i;
                const auto new_root = trie.root();
                if (prev_root)
                    expect(prev_root != new_root) << i;
                prev_root = new_root;
            }
            // erase
            prev_root.reset();
            for (size_t i = 0; i < num_nodes; ++i) {
                const auto k = state_dict_t::make_key(i);
                trie.erase(k);
                expect(trie_t::opt_value_t {} == trie.get(k)) << i;
                const auto new_root = trie.root();
                if (prev_root)
                    expect(prev_root != new_root) << i;
                prev_root = new_root;
            }
        };
        "compressed vs naive"_test = [&] {
            trie::input_map_t input {};
            trie_t trie { hf };
            for (size_t i = 0; i < 0x200; ++i) {
                const auto k = state_dict_t::make_key(i, state_key_subhash_t {});
                const uint8_vector v { fmt::format("{}", i) };
                trie.set(k, { v, hf });
                input.emplace(k, v);
                expect(trie.root() == trie::encode_blake2b(input)) << i;
            }
        };
        const auto test_vectors = json::load(file::install_path("test/jam-test-vectors/trie/trie.json"));
        "compressed"_test = [&] {
            size_t case_no = 0;
            for (const auto &vector: test_vectors.as_array()) {
                const auto &input = vector.at("input").as_object();
                const auto exp_out = hash_t::from_hex(json::value_to<std::string_view>(vector.at("output")));
                trie_t trie { hf };
                for (const auto &[k, v]: input) {
                    const auto tk = trie::key_t::from_hex<trie::key_t>(k.substr(0, 62));
                    trie.set(tk, trie_t::value_t { uint8_vector::from_hex(json::value_to<std::string_view>(v)), hf });
                }
                expect_equal(exp_out, trie.root(), fmt::format("#{}", case_no));
                ++case_no;
            }
        };
        "naive"_test = [&] {
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
                expect_equal(exp_out, act_out, fmt::format("#{}", case_no));
                ++case_no;
            }
        };
    };
};
