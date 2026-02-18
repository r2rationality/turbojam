/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <ranges>
#include <turbo/common/cli.hpp>
#include <turbo/common/file.hpp>
#include <turbo/common/variant.hpp>
#include <turbo/jam/traces.hpp>
// Must be included the last as it includes boost::asio and windows headers
#include "fuzzer.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::cli::fuzzer;
    using namespace turbo::jam::traces;
    using namespace std::string_view_literals;
}

namespace turbo::cli::fuzzer_client {
    struct cmd: command {
        void configure(config &cmd) const override
        {
            cmd.name = "fuzzer-client";
            cmd.desc = "Test a given Fuzzer API target listening at <unix-socket-path> using samples from <sample-dir>";
            cmd.opts.try_emplace("sock-path", "an optional path to the unix socket for an external fuzzer API");
            cmd.args.expect({"sample-dir"});
        }

        void run(const arguments &args, const options &opts) const override
        {
            const auto &data_dir = args.at(0);
            if (const auto it = opts.find("sock-path"); it != opts.end() && it->second) {
                _run_tests(impl_vs_trace_client_t<config_tiny, unix_socket_processor_t>{std::make_unique<unix_socket_processor_t<config_tiny>>(*it->second)}, data_dir);
            } else {
                _run_tests(impl_vs_trace_client_t<config_tiny, processor_t>{std::make_unique<processor_t<config_tiny>>("dev", file::tmp_directory{"turbo-jam-fuzzer"})}, data_dir);
            }
        }

    private:
        static void _run_tests(auto client, const std::string &path)
        {
            client.test_dir(path);
        }
    };
    static auto instance = command::reg(std::make_shared<cmd>());
}
