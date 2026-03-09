/* Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2026 R2 Rationality OÜ (info at r2rationality dot com) */

#include <turbo/common/benchmark.hpp>
#include "test-vectors.hpp"
#include "traces.hpp"
#include "encoding.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jam;
}

const suite turbo_jam_encoding_bench_suite = [] {
    "turbo::jam::encoding"_test = [] {
        ankerl::nanobench::Bench b {};
        b.title("turbo::jam::encoding")
            .output(&std::cerr)
            .unit("bytes")
            .performanceCounters(true);
        const auto traces_prefix = test_vector_dir("traces/");
        const auto traces = file::files_with_ext(traces_prefix, ".bin")
            | std::views::filter([](const auto &p) { return !p.ends_with("genesis.bin"); })
            | std::ranges::to<std::vector>();
        const auto total_size = std::ranges::fold_left(
            traces | std::views::transform([](const auto &p){ return std::filesystem::file_size(p); }),
            size_t{0}, std::plus<size_t>{}
        );
        logger::info("# traces: {} total_size: {}", traces.size(), total_size);
        b.batch(total_size);
        b.run("decode",[&] {
            for (const auto &p: traces) {
                const auto res = jam::load_obj<traces::test_case_t>(p);
                ankerl::nanobench::doNotOptimizeAway(res);
            }
        });
    };
};