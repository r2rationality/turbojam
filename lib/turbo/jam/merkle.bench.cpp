/* Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com) */

#include <turbo/common/benchmark.hpp>
#include <turbo/codec/json.hpp>
#include "merkle.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jam::merkle;
}

suite turbo_jam_merkle_bench_suite = [] {
    "turbo::jam::merkle"_test = [] {
        const auto test_vector = codec::json::load(file::install_path("test/jam-test-vectors/trie/trie.json")).at(10);
        const auto &input = test_vector.at("input").as_object();
        ankerl::nanobench::Bench b {};
        b.title("turbo::jam::merkle")
            .output(&std::cerr)
            .unit("entries")
            .performanceCounters(true)
            .batch(input.size())
            .relative(true);
        {
            b.run("naive",[&] {
                trie::input_map_t input_m {};
                for (const auto &[k, v]: input) {
                    const auto tk = trie::key_t::from_hex(k.substr(0, 62));
                    input_m.emplace(tk, uint8_vector::from_hex(boost::json::value_to<std::string_view>(v)));
                }
                ankerl::nanobench::doNotOptimizeAway(trie::encode_blake2b(input_m));
            });
            const hash_func hf { static_cast<void(*)(const hash_span_t &, const buffer &)>(crypto::blake2b::digest) };
            b.run("shared prefix skipping",[&] {
                trie_t trie { hf };
                for (const auto &[k, v]: input) {
                    const auto tk = trie::key_t::from_hex<trie::key_t>(k.substr(0, 62));
                    trie.set(tk, trie_t::value_t { uint8_vector::from_hex(boost::json::value_to<std::string_view>(v)), hf });
                }
                ankerl::nanobench::doNotOptimizeAway(trie.root());
            });
        }
    };
};