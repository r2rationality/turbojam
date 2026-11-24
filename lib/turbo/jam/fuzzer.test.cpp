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

    template<typename CFG>
    struct initialize_capture_processor_t {
        std::optional<initialize_t<CFG>> &captured;
        state_root_t post_root;

        boost::asio::awaitable<message_t<CFG>> process(message_t<CFG> msg)
        {
            if (auto *init = std::get_if<initialize_t<CFG>>(&msg)) {
                captured = std::move(*init);
                co_return message_t<CFG>{state_root_t{captured->state.root()}};
            }
            co_return message_t<CFG>{post_root};
        }
    };
}

suite turbo_jam_fuzzer_suite = [] {
    "turbo::jam::fuzzer"_test = [] {
        const auto data_dir = file::install_path("test/jam-fuzzing/fuzz-reports/0.8.0/traces/");
        "snapshot initialization omits ancestry"_test = [&] {
            const auto tc = jam::load_obj<test_case_t>((std::filesystem::path{data_dir} / "1792930791_3200_full/00000026.bin").string());
            const auto init = initialize_t<config_tiny>::from_snapshot(tc.pre.keyvals);
            expect(init.state == tc.pre.keyvals);
            expect(init.ancestry.empty());
        };
        "trace client initialize ancestry"_test = [&] {
            const auto path = std::filesystem::path{data_dir} / "1792930791_3200_full";
            const auto tc = jam::load_obj<test_case_t>((path / "00000026.bin").string());
            const auto data = file::read((path / "00000026.bin").string());
            std::optional<initialize_t<config_tiny>> captured;
            auto proc = std::make_unique<initialize_capture_processor_t<config_tiny>>(captured, tc.post.state_root);
            impl_vs_trace_client_t<config_tiny, initialize_capture_processor_t> client{std::move(proc), io_worker_t::get()};
            expect(client.test_sample(data));
            expect(captured.has_value());
            if (captured) {
                expect(captured->state == tc.pre.keyvals);
                expect(captured->ancestry.empty());
            }
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
        "jam-fuzzing fuzzer traces"_test = [&] {
            file::tmp_directory tmp_dir{"turbo-jam-fuzzer"};
            impl_vs_trace_client_t<config_tiny, local_processor_t> client{std::make_unique<local_processor_t<config_tiny>>("dev", tmp_dir.path())};
            const timer t{"fuzzer traces", logger::level::info};
            expect(client.test_dir(data_dir));
        };
        "peer protocol version compatibility"_test = [] {
            const peer_info_t local{};
            expect(nothrow([&] { local.compatible_with(local); }));
            for (const uint8_t version: {0, 2}) {
                const peer_info_t peer{.fuzz_version = version};
                expect(throws<error>([&] { local.compatible_with(peer); }));
            }
        };
    };
};
