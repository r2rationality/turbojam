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

    template<typename CFG>
    struct local_processor_t {
        explicit local_processor_t(std::string sock_path, io_worker_t &io_worker=io_worker_t::get()):
            _sock_path{std::move(sock_path)},
            _io_worker{io_worker}
        {
            _io_worker.sync_call(_connect());
            _io_worker.sync_call(_send_peer_info());
        }

        message_t<CFG> process(message_t<CFG> msg)
        {
            return _io_worker.sync_call(_process(std::move(msg)));
        }
    private:
        std::string _sock_path;
        io_worker_t &_io_worker;
        stream_protocol::socket _conn{_io_worker.io_context()};

        boost::asio::awaitable<void> _send_peer_info()
        {
            static const peer_info_t my_peer_info{"turbojam-fuzzer-client"};
            co_await write_message(_conn, message_t<CFG>{my_peer_info});
            const auto server_info = co_await read_message<CFG>(_conn);
            my_peer_info.compatible_with(variant::get_nice<peer_info_t>(server_info));
        }

        boost::asio::awaitable<void> _connect()
        {
            const auto ex = co_await boost::asio::this_coro::executor;
            const stream_protocol::endpoint ep{_sock_path};
            boost::asio::steady_timer timer{ex};
            timer.expires_after(std::chrono::milliseconds{500});
            using boost::asio::experimental::awaitable_operators::operator||;
            auto res = co_await (_conn.async_connect(ep, boost::asio::use_awaitable) || timer.async_wait(boost::asio::use_awaitable));
            if (res.index() == 0) [[likely]] {
                timer.cancel();
                logger::info("connected to {}", _sock_path);
            } else {
                boost::system::error_code ignored;
                _conn.cancel(ignored);
                _conn.close(ignored);
                throw error(fmt::format("timed out while trying to connect to {}", _sock_path));
            }
        }

        boost::asio::awaitable<message_t<CFG>> _process(message_t<CFG> msg)
        {
            co_await write_message(_conn, std::move(msg));
            co_return co_await read_message<CFG>(_conn);
        }
    };
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
                _run_tests(client_t<config_tiny, local_processor_t>{std::make_unique<local_processor_t<config_tiny>>(*it->second)}, data_dir);
            } else {
                _run_tests(client_t<config_tiny, processor_t>{std::make_unique<processor_t<config_tiny>>("dev", file::tmp_directory{"turbo-jam-fuzzer"})}, data_dir);
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
