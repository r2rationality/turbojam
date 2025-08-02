/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <ranges>
#include <boost/asio/use_future.hpp>
#include <turbo/common/cli.hpp>
#include <turbo/common/file.hpp>
#include <turbo/jam/traces.hpp>
#include "fuzzer.hpp"
#include <boost/asio/experimental/awaitable_operators.hpp>

namespace {
    using namespace turbo;
    using namespace turbo::cli::fuzzer;
    using namespace turbo::jam::traces;
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

        void test_traces(const std::string &test_dir)
        {
            auto test_files_v = file::files_with_ext_path(test_dir, ".bin") | std::views::filter([](const auto &p) { return p.filename().stem() != "genesis"; });
            const auto test_files = std::vector<std::filesystem::path>(test_files_v.begin(), test_files_v.end());
            const auto genesis = jam::load_obj<test_genesis_t<config_tiny>>(fmt::format("{}/genesis.bin", test_dir));
            for (const auto &path: test_files) {
                const auto path_str = path.string();
                const auto tc = jam::load_obj<test_case_t>(path_str);
                auto check_fut = boost::asio::co_spawn(_ioc,
                    _check_case(
                        set_state_t<CFG>{genesis.header, genesis.state.keyvals},
                        import_block_t<CFG>{tc.block},
                        tc.post.state_root
                    ),
                    boost::asio::use_future
                );
                check_fut.wait();
                const auto ok = check_fut.get();
                if (ok)
                    logger::info("{}: passed", path_str);
                else
                    logger::error("{}: failed", path_str);
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

        boost::asio::awaitable<bool> _check_case(set_state_t<CFG> set_state, import_block_t<CFG> block, const state_root_t &exp_root)
        {
            const auto ex = co_await boost::asio::this_coro::executor;
            stream_protocol::socket conn{_ioc};
            const stream_protocol::endpoint ep{_sock_path};
            boost::asio::steady_timer timer(ex);
            timer.expires_after(std::chrono::milliseconds{500});
            using namespace boost::asio::experimental::awaitable_operators;
            auto res = co_await (conn.async_connect(ep, boost::asio::use_awaitable) || timer.async_wait(boost::asio::use_awaitable));
            const auto connected = std::visit([&](auto &&rv) -> bool {
                using T = std::decay_t<decltype(rv)>;
                if constexpr (std::is_same_v<T, void>) {
                    timer.cancel();
                    return true;
                } else {
                    logger::info("timed out while trying to connect to {}", _sock_path);
                    conn.shutdown(boost::asio::socket_base::shutdown_both);
                    return false;
                }
            }, std::move(res));
            if (connected) {
                co_await write_message(conn, message_t<CFG>{std::move(set_state)});
                const auto pre_root = std::get<state_root_t>(co_await read_message<CFG>(conn));
                co_await write_message(conn, message_t<CFG>{std::move(block)});
                const auto post_root = std::get<state_root_t>(co_await read_message<CFG>(conn));
                co_return post_root == exp_root;
            }
            co_return false;
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
            //c.test_recursive(data_dir);
            c.test_traces(data_dir);
        }
    };
    static auto instance = command::reg(std::make_shared<cmd>());
}
