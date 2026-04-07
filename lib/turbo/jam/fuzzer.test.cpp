/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025-2026 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/file.hpp>
#include <turbo/jam/traces.hpp>
#include "test-vectors.hpp"
#include "fuzzer-runner.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jam::fuzzer_runner;
    using namespace turbo::jam::traces;
}

suite turbo_jam_fuzzer_suite = [] {
    "turbo::jam::fuzzer"_test = [] {
        "minifuzz forks"_test = [&] {
            file::tmp_directory tmp_dir{"turbo-jam-fuzzer"};
            minifuzz_client_t<config_tiny, local_processor_t> c{std::make_unique<local_processor_t<config_tiny>>("dev", tmp_dir.path())};
            c.test_dir(file::install_path("test/jam-conformance/fuzz-proto/examples/0.7.2/forks"));
        };
        "minifuzz no forks"_test = [&] {
            file::tmp_directory tmp_dir{"turbo-jam-fuzzer"};
            minifuzz_client_t<config_tiny, local_processor_t> c{std::make_unique<local_processor_t<config_tiny>>("dev", tmp_dir.path())};
            c.test_dir(file::install_path("test/jam-conformance/fuzz-proto/examples/0.7.2/no_forks"));
        };
        "jam-conformance fuzzer traces"_test = [&] {
            file::tmp_directory tmp_dir{"turbo-jam-fuzzer"};
            const auto data_dir = file::install_path("test/jam-conformance/fuzz-reports/0.7.2/traces/");
            impl_vs_trace_client_t<config_tiny, local_processor_t> client{std::make_unique<local_processor_t<config_tiny>>("dev", tmp_dir.path())};
            expect(client.test_dir(data_dir));
        };
    };
};
