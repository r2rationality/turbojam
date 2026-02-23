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

namespace turbo::cli::fuzzer_convert {
    struct cmd: command {
        void configure(config &cmd) const override
        {
            cmd.name = "fuzzer-convert";
            cmd.desc = "Convert fuzzer traces in <source-dir> into an AFL fuzzer <states-dir> and <blocks-dir>";
            cmd.args.expect({"traces-dir", "states-dir", "blocks-dir"});
        }

        void run(const arguments &args) const override
        {
            const auto &traces_dir = args.at(0);
            const auto &states_dir = args.at(1);
            const auto &blocks_dir = args.at(2);
            for (const auto &e: std::filesystem::directory_iterator(traces_dir)) {
                if (e.is_directory() && !e.path().filename().string().starts_with(".")) {
                    _convert(e.path().string(), (std::filesystem::path(states_dir) / e.path().stem()).string(), (std::filesystem::path(blocks_dir) / e.path().stem()).string());
                }
            }
        }
    private:
        static void _convert(const std::string &sample_dir, const std::string &state_path, const std::string &out_prefix)
        {
            std::vector<test_case_t> test_cases{};
            {
                std::vector<std::string> paths{};
                for (const auto &e: std::filesystem::directory_iterator(sample_dir)) {
                    if (e.is_regular_file() && e.path().extension() == ".bin" && e.path().stem().string() != "genesis") {
                        paths.emplace_back(e.path().string());
                    }
                }
                std::sort(paths.begin(), paths.end());
                for (const auto &path: paths) {
                    test_cases.emplace_back(jam::load_obj<test_case_t>(path));
                }
            }
            if (!test_cases.empty()) {
                const auto &tc0 = test_cases[0];
                {
                    const jam::encoder enc{initialize_t<config_tiny>::from_snapshot(tc0.pre.keyvals)};
                    file::write(state_path, enc.bytes());
                }
                for (const auto &[i, tc]: test_cases | std::views::enumerate) {
                    const jam::encoder enc{tc.block};
                    file::write(fmt::format("{}-{}-{}-{}", out_prefix, i, tc.block.header.slot, tc.block.header.hash()), enc.bytes());
                }
                logger::info("converted {} test cases from {} into an AFL samples with prefix {}", test_cases.size(), sample_dir, out_prefix);
            } else {
                logger::info("no test cases found in {}, skipping conversion", sample_dir);
            }
        }
    };
    static auto instance = command::reg(std::make_shared<cmd>());
}
