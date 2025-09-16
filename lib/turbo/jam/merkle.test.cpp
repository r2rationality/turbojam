/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <boost/json.hpp>
#include <turbo/common/test.hpp>
#include <turbo/codec/json.hpp>
#include <turbo/jam/types/state-dict.hpp>
#include "merkle.hpp"
#include "state.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::codec;
    using namespace turbo::jam;
    using namespace turbo::jam::merkle;
}

suite turbo_jam_merkle_suite = [] {
    "turbo::jam::merkle"_test = [] {
        "merkle_balanced"_test = [] {
            static const service_commitments_t theta{
                service_commitments_t::value_type{306895876U, opaque_hash_t::from_hex("7079B9F32C7A6AD71072D367277C80D4473E9517D53595BC11B3F989ACC215FD")},
                service_commitments_t::value_type{3406277994U, opaque_hash_t::from_hex("6790891C04EE66AF8CCC61FE232EB374427810FDEB3A5F974BE76035D9A2F991")}
            };
            expect_equal(merkle::hash_t::from_hex("3DB8AECACB42DF7136B67EE7CF581EC55E718505F1285474A8B3138059E5B0FE"), theta.root());
        };
        "mmr"_test = [] {
            const hash_func hf { static_cast<void(*)(const hash_span_t &, const buffer &)>(crypto::blake2b::digest) };
            //const auto test_vectors = json::load(file::install_path("test/jam-test-vectors/trie/trie.json"));
            const auto test_vectors = json::load(file::install_path("test/overrides/trie.json"));
            "insert, update, erase"_test = [&] {
                trie_t trie { hf };
                expect(trie_t::opt_value_t {} == trie.get(merkle::key_t {}));
                // insert
                static constexpr size_t num_nodes = 0x10;
                std::optional<hash_t> prev_root {};
                for (size_t i = 0; i < num_nodes; ++i) {
                    const auto k = state_dict_t::make_key(i);
                    const uint8_vector v { static_cast<std::string_view>(fmt::format("{:02X}", i)) };
                    trie.set(k, v);
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
                    trie.set(k, v);
                    expect(trie_t::value_t { v, hf } == trie.get(k)) << i;
                    const auto new_root = trie.root();
                    if (prev_root)
                        expect(prev_root != new_root) << i;
                    prev_root = new_root;
                }
                size_t foreach_nodes = 0;
                trie.foreach([&](const auto &, const auto &) {
                    ++foreach_nodes;
                });
                expect_equal(num_nodes, trie.size());
                expect_equal(trie.size(), foreach_nodes);
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
            "compressed"_test = [&] {
                size_t case_no = 0;
                for (const auto &vector: test_vectors.as_array()) {
                    const auto &input = vector.at("input").as_object();
                    const auto exp_out = hash_t::from_hex(json::value_to<std::string_view>(vector.at("output")));
                    trie_t trie { hf };
                    for (const auto &[k, v]: input) {
                        const auto tk = trie::key_t::from_hex<trie::key_t>(k.substr(0, 62));
                        trie.set(tk, uint8_vector::from_hex(json::value_to<std::string_view>(v)));
                    }
                    expect_equal(exp_out, trie.root(), fmt::format("#{}", case_no));
                    ++case_no;
                }
            };
        };
    };
};
