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
        "shared genesis ancestry"_test = [] {
            const auto data_dir = file::install_path("test/jam-fuzzing/fuzz-reports/0.8.0/traces/");
            const auto genesis = load_obj<test_genesis_t<config_tiny>>(data_dir + "1792928756_4797/genesis.bin");
            const auto first = load_obj<test_case_t>(data_dir + "1792930791_3200/00000026.bin");
            const auto last = load_obj<test_case_t>(data_dir + "1792930791_3200/00000028.bin");
            const auto init = initialize_t<config_tiny>::from_snapshot(first.pre.keyvals, genesis.header);
            const auto &anchor = last.block.extrinsic.guarantees.front().report.context;
            expect_equal(anchor.lookup_anchor, genesis.header.hash());
            expect_equal(anchor.lookup_anchor_slot, init.ancestry.begin()->slot);
            expect_equal(anchor.lookup_anchor, init.ancestry.begin()->header_hash);
            expect(!init.ancestry.begin()->state_root) << "another trace's state root must not be reused";
            expect_equal(size_t{9}, init.ancestry.size()); // Genesis followed by beta slots 1..8.
            expect(init.ancestry.view().back().state_root == first.pre.state_root);

            const auto initial = initialize_t<config_tiny>::from_snapshot(genesis.state.keyvals, genesis.header);
            expect(size_t{1} == initial.ancestry.size()) << "genesis already present in beta must not be duplicated";
            expect(initial.ancestry.begin()->state_root == genesis.state.state_root);
        };
        "minifuzz forks"_test = [&] {
            file::tmp_directory tmp_dir{"turbo-jam-fuzzer"};
            minifuzz_client_t<config_tiny, local_processor_t> c{std::make_unique<local_processor_t<config_tiny>>("dev", tmp_dir.path())};
            const timer t{"minifuzz forks", logger::level::info};
            c.test_dir(file::install_path("test/jam-fuzzing/fuzz-proto/examples/0.8.0/forks"));
        };
        "minifuzz no forks"_test = [&] {
            file::tmp_directory tmp_dir{"turbo-jam-fuzzer"};
            minifuzz_client_t<config_tiny, local_processor_t> c{std::make_unique<local_processor_t<config_tiny>>("dev", tmp_dir.path())};
            const timer t{"minifuzz no forks", logger::level::info};
            c.test_dir(file::install_path("test/jam-fuzzing/fuzz-proto/examples/0.8.0/no_forks"));
        };
        "jam-fuzzing standalone trace"_test = [] {
            file::tmp_directory tmp_dir{"turbo-jam-fuzzer-standalone"};
            impl_vs_trace_client_t<config_tiny, local_processor_t> client{std::make_unique<local_processor_t<config_tiny>>("dev", tmp_dir.path())};
            expect(client.test_dir(file::install_path("test/jam-fuzzing/fuzz-reports/0.8.0/traces/1792930791_3200")));
        };
        "jam-fuzzing fuzzer traces"_test = [&] {
            file::tmp_directory tmp_dir{"turbo-jam-fuzzer"};
            const auto data_dir = file::install_path("test/jam-fuzzing/fuzz-reports/0.8.0/traces/");
            impl_vs_trace_client_t<config_tiny, local_processor_t> client{std::make_unique<local_processor_t<config_tiny>>("dev", tmp_dir.path())};
            const timer t{"fuzzer traces", logger::level::info};
            expect(client.test_dir(data_dir));
        };
    };
};
