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
                service_commitment_item_t{306895876U, opaque_hash_t::from_hex<opaque_hash_t>("7079B9F32C7A6AD71072D367277C80D4473E9517D53595BC11B3F989ACC215FD")},
                service_commitment_item_t{3406277994U, opaque_hash_t::from_hex<opaque_hash_t>("6790891C04EE66AF8CCC61FE232EB374427810FDEB3A5F974BE76035D9A2F991")}
            };
            expect_equal(merkle::hash_t::from_hex("3DB8AECACB42DF7136B67EE7CF581EC55E718505F1285474A8B3138059E5B0FE"), theta.root());
        };
        "merkle_unbalanced"_test = [] {
            static const service_commitments_t theta{
                service_commitment_item_t{1809557494U, opaque_hash_t::from_hex<opaque_hash_t>("38606724600532BF13CAED2D1AA6770225ED38BB213BF1B656689C68A1DF2D29")},
                service_commitment_item_t{2494454716U, opaque_hash_t::from_hex<opaque_hash_t>("5BB4353B428C0D4C422F2F7576EA5205091C08926ED7FC6A420CF172F40B1CB5")},
                service_commitment_item_t{3202820706U, opaque_hash_t::from_hex<opaque_hash_t>("0F60BAF1C25D5F6C212CDDBD58EF1BAD5FA167C4CC18D7BA1F9FFC89DF36E9DC")}
            };
            expect_equal(merkle::hash_t::from_hex("F06948493FA7EF5682770FC50E850F0B22F309E21AE6545EC9A688C32ED5C2C2"), theta.root());
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
