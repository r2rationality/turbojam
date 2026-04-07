/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025-2026 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

// An implementation of the Fuzzer API defined here:
// https://github.com/davxy/jam-stuff/tree/main/fuzz-proto

#include <turbo/common/cli.hpp>
#include <turbo/common/variant.hpp>
#include <turbo/jam/chain.hpp>
#include <turbo/jam/fuzzer-runner.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/signal_set.hpp>

namespace {
    using namespace std::string_view_literals;
    using namespace boost::asio::experimental::awaitable_operators;
    using namespace boost::asio::local;
    using namespace turbo;
    using namespace turbo::jam;
    using namespace turbo::jam::fuzzer_runner;

    template<typename CFG>
    struct server_t {
        server_t(std::string chain_id, std::string sock_path):
            _chain_id{std::move(chain_id)},
            _sock_path{std::move(sock_path)}
        {
            boost::asio::co_spawn(_ioc, _listen(), boost::asio::detached);
        }

        ~server_t() noexcept
        {
            std::filesystem::remove(_sock_path);
        }

        void run()
        {
            boost::asio::signal_set signals{_ioc, SIGINT, SIGTERM};
            signals.async_wait([this](auto, auto){ _ioc.stop(); });
            _ioc.run();
        }
    private:
        std::string _chain_id;
        std::string _sock_path;
        boost::asio::io_context _ioc{};
        std::atomic<uint64_t> _next_client_id{};

        boost::asio::awaitable<void> _handle_client(stream_protocol::socket conn, const uint64_t client_id)
        {
            try {
                static const peer_info_t my_peer_info{};
                {
                    const auto handshake = co_await read_message<CFG>(conn);
                    const peer_info_t &peer_info = variant::get_nice<peer_info_t>(handshake);
                    co_await write_message<CFG>(conn, message_t<CFG>{my_peer_info});
                    my_peer_info.compatible_with(peer_info);
                }
                file::tmp_directory tmp_dir{fmt::format("turbo-jam-fuzzer-{}", client_id)};
                local_processor_t<CFG> processor{_chain_id, tmp_dir.path()};
                for (;;) {
                    auto msg_in = co_await read_message<CFG>(conn);
                    auto msg_out = co_await processor.process(std::move(msg_in));
                    co_await write_message(conn, std::move(msg_out));
                }
            } catch (const std::exception &ex) {
                logger::info("client disconnected: {}", ex.what());
            }
        }

        boost::asio::awaitable<void> _listen()
        try {
            auto ex = co_await boost::asio::this_coro::executor;
            logger::info("listening on {}", _sock_path);
            std::filesystem::remove(_sock_path);
            const stream_protocol::endpoint ep{_sock_path};
            stream_protocol::acceptor acceptor{ex, ep};
#if         defined(__unix__) || defined (__unix)
                ::chmod(_sock_path.c_str(), 0666);
#endif
            for (;;) {
                auto conn = co_await acceptor.async_accept(boost::asio::use_awaitable);
                logger::info("accepted a new connection");
                co_spawn(ex, _handle_client(std::move(conn), _next_client_id++), boost::asio::detached);
            }
        } catch (const std::exception &ex) {
            logger::error("listener failed: {}", ex.what());
        }
    };
}

namespace turbo::cli::fuzzer_api {
    struct cmd: command {
        void configure(config &cmd) const override
        {
            cmd.name = "fuzzer-api";
            cmd.desc = "Launch a local fuzzing API listening at <unix-socket-path>";
            cmd.args.expect({ "<unix-socket-path>" });
            cmd.opts.try_emplace(
                "cfg", "parameter set: either tiny or full", "tiny",
                [](const std::optional<std::string> &v)-> std::optional<std::string> {
                    if (!(v && (*v == "tiny" || *v == "full"))) {
                        return "cfg can be either tiny or full";
                    }
                    return {};
                }
            );
        }

        void run(const arguments &args, const options &opts) const override
        {
            const auto &sock_path = args.at(0);
            const auto cfg = opts.at("cfg").value();
            if (cfg == "tiny") {
                logger::info("starting a fuzzer API with tiny config");
                server_t<config_tiny> srv{"dev", sock_path};
                srv.run();
            } else {
                logger::info("starting a fuzzer API with full config");
                server_t<config_prod> srv{"dev", sock_path};
                srv.run();
            }
        }
    };
    static auto instance = command::reg(std::make_shared<cmd>());
}
