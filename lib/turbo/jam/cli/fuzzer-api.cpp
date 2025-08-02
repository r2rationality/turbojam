/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

// An implementation of the Fuzzer API defined here:
// https://github.com/davxy/jam-stuff/tree/main/fuzz-proto

#include <future>
#include <turbo/common/cli.hpp>
#include <turbo/common/mutex.hpp>
#include <turbo/jam/chain.hpp>
#include "fuzzer.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/use_future.hpp>

namespace {
    using namespace std::string_view_literals;
    using namespace boost::asio::experimental::awaitable_operators;
    using namespace boost::asio::local;
    using namespace turbo;
    using namespace turbo::cli::fuzzer;
    using namespace turbo::jam;

    template<typename CFG>
    struct server_t {
        server_t(std::string chain_id, std::string sock_path):
            _chain_id{std::move(chain_id)},
            _sock_path{std::move(sock_path)}
        {
            _futures.emplace_back(boost::asio::co_spawn(_ioc, _listen(), boost::asio::use_future));
        }

        void run()
        {
            for (;;) {
                {
                    std::scoped_lock lock { _futures_mutex };
                    for (auto it = _futures.begin(); it != _futures.end();) {
                        if (it->wait_for(std::chrono::milliseconds { 0 }) == std::future_status::ready) {
                            logger::info("one async operation has completed");
                            logger::run_log_errors([&] {
                                it->get();
                            });
                            it = _futures.erase(it);
                        } else {
                            ++it;
                        }
                    }
                    if (_futures.empty()) [[unlikely]]
                        break;
                }
                _ioc.run_for(std::chrono::milliseconds { 100 });
                if (_ioc.stopped())
                    _ioc.restart();
            }
        }
    private:
        std::string _chain_id;
        std::string _sock_path;
        file::tmp_directory _tmp_dir { "turbo-jam-fuzzer" };
        boost::asio::io_context _ioc {};
        std::mutex _futures_mutex alignas(mutex::alignment) {};
        std::vector<std::future<void>> _futures {};

        boost::asio::awaitable<void> _handle_client(stream_protocol::socket conn)
        {
            static const peer_info_t my_peer_info {
                "turbojam",
                { 0, 1, 0 },
                { 0, 6, 6 }
            };
            {
                const auto handshake = co_await read_message<CFG>(conn);
                const peer_info_t &peer_info = std::get<peer_info_t>(handshake);
                if (peer_info.jam_version != my_peer_info.jam_version) [[unlikely]]
                    throw error(fmt::format("jam version mismatch: {} != {}", peer_info.jam_version, my_peer_info.jam_version));
            }
            std::optional<chain_t<CFG>> chain {};
            for (;;) {
                auto msg = co_await read_message<CFG>(conn);
                auto resp = std::visit([&](auto &&m) -> message_t<CFG> {
                    using T = std::decay_t<decltype(m)>;
                    if constexpr (std::is_same_v<T, set_state_t<CFG>>) {
                        chain.emplace(_chain_id, _tmp_dir.path(), m.state, m.state);
                        if (chain->genesis_header() != m.header) [[unlikely]]
                            throw error("the provided header does not match the provided state and the genesis_header construction rules");
                        return chain->state_root();
                    } else if constexpr (std::is_same_v<T, import_block_t<CFG>>) {
                        if (!chain) [[unlikely]]
                            throw error("import_block is not allowed before set_state");
                        logger::run_log_errors([&] {
                            chain->apply(m);
                        });
                        return chain->state_root();
                    } else if constexpr (std::is_same_v<T, get_state_t>) {
                        if (!chain) [[unlikely]]
                            throw error("get_state is not allowed before set_state");
                        const auto &beta = chain->state().beta.get();
                        if (beta.empty() || beta.back().header_hash != m.header_hash) [[unlikely]]
                            throw error("get_state supports returning the state of only the latest block!");
                        return chain->state().snapshot();
                    } else {
                        throw error(fmt::format("unexpected message type: {}", typeid(T).name()));
                    }
                }, std::move(msg));
                co_await write_message(conn, std::move(resp));
            }
            co_return;
        }

        boost::asio::awaitable<void> _listen()
        {
            auto ex = co_await boost::asio::this_coro::executor;
            logger::info("listening on {}", _sock_path);
            std::filesystem::remove(_sock_path);
            const stream_protocol::endpoint ep{_sock_path};
            stream_protocol::acceptor acceptor{_ioc, ep};
            for (;;) {
                auto conn = co_await acceptor.async_accept(boost::asio::use_awaitable);
                std::scoped_lock lock { _futures_mutex };
                logger::info("accepted a new connection");
                _futures.emplace_back(co_spawn(ex, _handle_client(std::move(conn)), boost::asio::use_future));
            }
        }
    };
}

namespace turbo::cli::fuzzer_api {
    struct cmd: command {
        void configure(config &cmd) const override
        {
            cmd.name = "fuzzer-api";
            cmd.desc = "Launch a local local fuzzing API listening at <unix-socket-path>";
            cmd.args.expect({ "<unix-socket-path>" });
        }

        void run(const arguments &args) const override
        {
            const auto &sock_path = args.at(0);
            server_t<config_tiny> srv { "dev", sock_path };
            srv.run();
        }
    };
    static auto instance = command::reg(std::make_shared<cmd>());
}
