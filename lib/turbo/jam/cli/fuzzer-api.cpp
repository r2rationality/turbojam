/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025-2026 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

// An implementation of the Fuzzer API defined here:
// https://github.com/davxy/jam-stuff/tree/main/fuzz-proto

#include <turbo/common/cli.hpp>
#include <turbo/common/scope-exit.hpp>
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
        server_t(std::string chain_id, std::string data_path, std::string sock_path):
            _chain_id{std::move(chain_id)},
            _data_path{std::move(data_path)},
            _sock_path{std::move(sock_path)}
        {
            boost::asio::co_spawn(_ioc, _listen(), boost::asio::detached);
        }

        ~server_t() noexcept {
            std::filesystem::remove(_sock_path);
        }

        void run() {
            boost::asio::signal_set signals{_ioc, SIGINT, SIGTERM};
            signals.async_wait([this](auto, auto){ _ioc.stop(); });
            _ioc.run();
        }
    private:
        std::string _chain_id;
        std::string _data_path;
        std::string _sock_path;
        boost::asio::io_context _ioc{};
        std::atomic<uint64_t> _next_client_id{};

        boost::asio::awaitable<void> _handle_client(stream_protocol::socket conn, const uint64_t client_id)
        try {
            const auto client_data_path = fmt::format("{}/client-{}", _data_path, client_id);
            scope_exit{[&]{ std::filesystem::remove_all(client_data_path); }};
            static const peer_info_t my_peer_info{};
            uint8_vector read_buf{};
            {
                const auto handshake = co_await read_message<CFG>(conn, read_buf);
                const peer_info_t &peer_info = variant::get_nice<peer_info_t>(handshake);
                co_await write_message<CFG>(conn, message_t<CFG>{my_peer_info});
                my_peer_info.compatible_with(peer_info);
            }
            local_processor_t<CFG> processor{_chain_id, client_data_path};
            for (;;) {
                auto msg_in = co_await read_message<CFG>(conn, read_buf);
                auto msg_out = co_await processor.process(std::move(msg_in));
                co_await write_message(conn, std::move(msg_out));
            }
        } catch (const std::exception &ex) {
            logger::info("client disconnected: {}", ex.what());
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
        void configure(config &cmd) const override {
            cmd.name = "fuzzer-api";
            cmd.desc = "Launch a local fuzzing API listening";
            if (!_jam_fuzz_args()) {
                cmd.args.expect({ "<unix-socket-path>" });
                cmd.opts.try_emplace(
                    "spec", "parameter set: either tiny or full", "tiny",
                    [](const std::optional<std::string> &v)-> std::optional<std::string> {
                        if (!(v && (*v == "tiny" || *v == "full"))) {
                            return "can be either tiny or full";
                        }
                        return {};
                    }
                );
            }
        }

        void run(const arguments &args, const options &opts) const override {
            std::optional<file::tmp_directory> tmp_dir{};
            auto fuzz_args = _jam_fuzz_args();
            if (!fuzz_args) {
                tmp_dir.emplace("turbo-jam-fuzzer-api");
                fuzz_args.emplace(opts.at("spec").value(), tmp_dir->path(), args.at(0));
            }
            if (fuzz_args->spec == "tiny") {
                logger::info("starting a fuzzer API with tiny config");
                server_t<config_tiny> srv{"dev", fuzz_args->data_path, fuzz_args->sock_path};
                srv.run();
            } else if (fuzz_args->spec == "full") {
                logger::info("starting a fuzzer API with full config");
                server_t<config_prod> srv{"dev", fuzz_args->data_path, fuzz_args->sock_path};
                srv.run();
            } else {
                throw error(fmt::format("unsupported spec value: {}", fuzz_args->spec));
            }
        }
    private:
        struct jam_fuzz_args_t {
            std::string spec{};
            std::string data_path{};
            std::string sock_path{};

            static std::optional<jam_fuzz_args_t> from_env() {
                std::optional<jam_fuzz_args_t> res{};
                if (std::getenv("JAM_FUZZ")) {
                    const auto *spec = std::getenv("JAM_FUZZ_SPEC");
                    if (!spec) [[unlikely]]
                        throw error("JAM_FUZZ_SPEC environment variable must be set when JAM_FUZZ is set");
                    const auto *data_path = std::getenv("JAM_FUZZ_DATA_PATH");
                    if (!data_path) [[unlikely]]
                        throw error("JAM_FUZZ_DATA_PATH environment variable must be set when JAM_FUZZ is set");
                    const auto *sock_path = std::getenv("JAM_FUZZ_SOCK_PATH");
                    if (!sock_path) [[unlikely]]
                        throw error("JAM_FUZZ_SOCK_PATH environment variable must be set when JAM_FUZZ is set");
                    res.emplace(spec, data_path, sock_path);
                }
                return res;
            }
        };

        static const std::optional<jam_fuzz_args_t> &_jam_fuzz_args() {
            static const auto args = jam_fuzz_args_t::from_env();
            return args;
        }
    };
    static auto instance = command::reg(std::make_shared<cmd>());
}
