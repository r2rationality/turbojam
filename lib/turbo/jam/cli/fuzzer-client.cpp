/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/cli.hpp>
#include <turbo/common/file.hpp>
#include "fuzzer.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::cli::fuzzer;
    using namespace std::string_view_literals;

    std::string_view read_line(std::string_view &buf)
    {
        size_t end = buf.find('\n');
        if (end == std::string_view::npos) [[unlikely]]
            end = buf.size();
        const size_t line_end = end && buf[end - 1] == '\r' ? end - 1 : end;
        const auto line = buf.substr(0, line_end);
        buf = buf.substr(line_end + 1);
        return line;
    }

    template<typename CFG>
    struct client_t {
        explicit client_t(std::string sock_path):
            _sock_path{std::move(sock_path)}
        {
        }

        void test_sample(const std::filesystem::path &data_dir)
        {
            const auto report = file::read(data_dir / "report.txt");
            auto buf = report.str();
            while (!buf.empty()) {
                if (const auto line = read_line(buf); line.starts_with("Reproduction Instruction")) {
                    const auto step = _extract_step(buf);
                    _test_step(data_dir, step);
                }
            }
        }

        void test_recursive(const std::string &data_dir)
        {
            for (const auto &e: std::filesystem::recursive_directory_iterator(data_dir)) {
                if (e.is_directory() && std::filesystem::exists(e.path() / "report.txt")) {
                    test_sample(e.path());
                }
            }
        }
    private:
        std::string _sock_path;
        boost::asio::io_context _ioc {};

        static size_t _extract_step(std::string_view buf)
        {
            static std::string_view match = "Step: "sv;
            while (!buf.empty()) {
                if (const auto line = read_line(buf); line.starts_with(match)) {
                    return cli::from_str<size_t>(line.substr(match.size()));
                }
            }
            throw error("Failed to extract the step number from report.txt");
        }

        void _test_step(const std::filesystem::path &data_dir, const size_t step)
        {
            const std::string block_path = (data_dir / fmt::format("{:08}.bin", step)).string();
            std::string base_path;
            switch (step) {
                [[unlikely]] case 0ULL:
                    throw error("step 0 is not supported!");
                case 1ULL:
                    base_path = (data_dir / "genesis.bin").string();
                    break;
                default:
                    base_path = (data_dir / fmt::format("{:08}.bin", step - 1)).string();
                    break;
            }
            logger::info("testing step {} from {}", step, data_dir);
            logger::info("base_path: {}", base_path);
            //const auto base = jam::load_obj<set_state_t<CFG>>(base_path);
            logger::info("block_path: {}", block_path);
            const auto block = jam::load_obj<import_block_t<CFG>>(block_path);
        }
    };
}

namespace turbo::cli::fuzzer_client {
    struct cmd: command {
        void configure(config &cmd) const override
        {
            cmd.name = "fuzzer-client";
            cmd.desc = "Test a given Fuzzer API target listening at <unix-socket-path> using samples from <data-dir>";
            cmd.args.expect({ "<unix-socket-path>", "data-dir" });
        }

        void run(const arguments &args) const override
        {
            const auto &sock_path = args.at(0);
            const auto &data_dir = args.at(1);
            client_t<config_tiny> c { sock_path };
            c.test_recursive(data_dir);
        }
    };
    static auto instance = command::reg(std::make_shared<cmd>());
}
