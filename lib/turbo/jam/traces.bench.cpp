/* Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
* Copyright (c) 2024-2025 R2 Rationality OU (info at r2rationality dot com) */

#include <turbo/common/benchmark.hpp>
#include "test-vectors.hpp"
#include "fuzzer-runner.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jam;
    using namespace turbo::jam::fuzzer_runner;

    bool test_sample(const std::string &sample_dir) {
        const file::tmp_directory tmp_dir{"turbo-jam-fuzzer"};
        impl_vs_trace_client_t<config_tiny, local_processor_t> client{std::make_unique<local_processor_t<config_tiny>>("dev", tmp_dir.path())};
        return client.test_sample(sample_dir);
    }
}

suite turbo_jam_traces_bench_suite = [] {
    "turbo::jam::traces"_test = [] {
        ankerl::nanobench::Bench b {};
        b.title("turbo::jam::traces")
            .output(&std::cerr)
            .unit("blocks")
            .performanceCounters(true);
        const auto traces_prefix = test_vector_dir("traces/");
        b.run("fallback/00000072",[&] {
            const auto res = test_sample(traces_prefix + "fallback/00000072");
            ankerl::nanobench::doNotOptimizeAway(res);
        });
        b.run("safrole/00000048",[&] {
            const auto res = test_sample(traces_prefix + "safrole/00000048");
            ankerl::nanobench::doNotOptimizeAway(res);
        });
        b.run("preimages/00000072",[&] {
            const auto res = test_sample(traces_prefix + "preimages/00000072");
            ankerl::nanobench::doNotOptimizeAway(res);
        });
        b.run("storage/00000084",[&] {
            const auto res = test_sample(traces_prefix + "storage/00000084");
            ankerl::nanobench::doNotOptimizeAway(res);
        });
    };
};
