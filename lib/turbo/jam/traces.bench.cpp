/* Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
* Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com) */

#include <turbo/common/benchmark.hpp>
#include "test-vectors.hpp"
#include "traces.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jam;
}

suite turbo_jam_safrole_bench_suite = [] {
    "turbo::jam::safrole"_test = [] {
        ankerl::nanobench::Bench b {};
        b.title("turbo::jam::safrole")
            .output(&std::cerr)
            .unit("blocks")
            .performanceCounters(true)
            .relative(true);
        const auto traces_prefix = test_vector_dir("traces/");
        const auto genesis = jam::load_obj<traces::test_genesis_t<config_tiny>>(traces_prefix + "safrole/genesis.bin");
        b.run("fallback/00000072",[&] {
            const auto res = traces::test_file(test_vector_dir(traces_prefix + "fallback/00000072"), genesis.state.keyvals);
            ankerl::nanobench::doNotOptimizeAway(res);
        });
        b.run("safrole/00000048",[&] {
            const auto res = traces::test_file(test_vector_dir(traces_prefix + "safrole/00000048"), genesis.state.keyvals);
            ankerl::nanobench::doNotOptimizeAway(res);
        });
        b.run("preimages/00000072",[&] {
            const auto res = traces::test_file(test_vector_dir(traces_prefix + "preimages/00000072"), genesis.state.keyvals);
            ankerl::nanobench::doNotOptimizeAway(res);
        });
        b.run("storage/00000084",[&] {
            const auto res = traces::test_file(test_vector_dir(traces_prefix + "storage/00000084"), genesis.state.keyvals);
            ankerl::nanobench::doNotOptimizeAway(res);
        });
    };
};