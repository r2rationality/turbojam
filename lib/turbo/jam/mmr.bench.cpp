/* Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
* Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com) */

#include <turbo/common/benchmark.hpp>
#include "test-vectors.hpp"
#include "types/common.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jam;
}

suite turbo_jam_mmr_bench_suite = [] {
    "turbo::jam::mmr"_test = [] {
        ankerl::nanobench::Bench b{};
        b.title("turbo::jam::mmr")
            .output(&std::cerr)
            .unit("items")
            .performanceCounters(true);
        for (size_t num_items: {1U << 4U, 1U << 8U, 1U << 12U, 1U << 16U, 1U << 20U}) {
            const auto name = fmt::format("mmr with {} items", num_items);
            b.batch(num_items);
            b.run(name,[&] {
                mmr_t r{};
                opaque_hash_t hash{};
                for (size_t i = 0; i < num_items; ++i) {
                    encoder::uint_fixed(std::span{hash.data(), 4U}, 4U, i);
                    r.append(hash);
                }
                ankerl::nanobench::doNotOptimizeAway(r);
            });
        }
    };
};