/* Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com) */

#include <algorithm>
#include <random>
#include <turbo/common/benchmark.hpp>
#include <turbo/codec/json.hpp>
#include <turbo/jam/types/state-dict.hpp>
#include "merkle.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jam::merkle;
}

suite turbo_jam_merkle_bench_suite = [] {
    "turbo::jam::merkle"_test = [] {
        const hash_func hf { static_cast<void(*)(const hash_span_t &, const buffer &)>(crypto::blake2b::digest) };
        {
            struct test_vector_t {
                trie::key_t key;
                uint8_vector value;
            };

            std::vector<test_vector_t> input {};
            for (size_t i = 0; i < 0x200; ++i) {
                input.emplace_back(
                    jam::state_dict_t::make_key(i, jam::state_key_subhash_t {}),
                    uint8_vector { fmt::format("{}", i) }
                );
            }
            std::random_device rd {};
            std::mt19937 g { rd() };
            std::shuffle(input.begin(), input.end(), g);

            ankerl::nanobench::Bench b {};
            b.title("turbo::jam::merkle")
                .output(&std::cerr)
                .unit("entries")
                .performanceCounters(true)
                .batch(input.size())
                .relative(true);
            b.run("naive unsorted - construct & compute root",[&] {
                trie::input_map_t input_m {};
                for (const auto &[k, v]: input) {;
                    input_m.emplace(k, v);
                }
                ankerl::nanobench::doNotOptimizeAway(trie::compute_root(input_m));
            });
            b.run("naive pre-sorted - construct & compute root",[&] {
                trie::node_map_t input_m {};
                for (const auto &[k, v]: input) {;
                    input_m.emplace_hint(input_m.end(), k, v, hf);
                }
                ankerl::nanobench::doNotOptimizeAway(trie::compute_root(input_m));
            });
            b.run("shared prefix - construct & compute root",[&] {
                trie_t trie { hf };
                for (const auto &[k, v]: input) {
                    trie.set(k, v);
                }
                ankerl::nanobench::doNotOptimizeAway(trie.root());
            });
            b.run("naive pre-sorted - construct & compute root for each element",[&] {
                trie::node_map_t input_m {};
                for (const auto &[k, v]: input) {;
                    input_m.emplace_hint(input_m.end(), k, v, hf);
                    ankerl::nanobench::doNotOptimizeAway(trie::compute_root(input_m));
                }
            });
            b.run("shared prefix - construct & compute root for each element",[&] {
                trie_t trie { hf };
                for (const auto &[k, v]: input) {
                    trie.set(k, v);
                    ankerl::nanobench::doNotOptimizeAway(trie.root());
                }
            });
            static constexpr size_t num_items = 250000;
            b.batch(num_items);
            b.run(fmt::format("shared prefix {} nodes", num_items),[&] {
                trie_t trie { hf };
                for (size_t i = 0; i < num_items; ++i) {
                    const auto v = buffer { reinterpret_cast<const uint8_t *>(&i), sizeof(i) };
                    const auto h = crypto::blake2b::digest(v);
                    key_t k = static_cast<buffer>(h).subbuf(1);
                    trie.set(k, v);
                }
                ankerl::nanobench::doNotOptimizeAway(trie.root());
            });
        }
    };
};