/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

// An implementation of the Fuzzer protocol defined here:
// https://github.com/davxy/jam-stuff/tree/main/fuzz-proto

#include <filesystem>
#include <future>
#include <turbo/common/bytes.hpp>
#include <turbo/common/cli.hpp>
#include <turbo/common/mutex.hpp>
#include <turbo/jam/chain.hpp>
#include <turbo/jam/types/header.hpp>
#include <turbo/jam/types/state-dict.hpp>

#ifdef _MSC_VER
#   include <SDKDDKVer.h>
#endif
#include <boost/asio/buffer.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/local/stream_protocol.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/use_future.hpp>
#include <boost/asio/write.hpp>

namespace {
    using namespace std::string_view_literals;
    using namespace boost::asio::experimental::awaitable_operators;
    using namespace boost::asio::local;
    using namespace turbo;
    using namespace turbo::jam;

    template<typename CFG>
    struct server {
        server(std::string chain_id, std::string sock_path):
            _chain_id{std::move(chain_id)},
            _sock_path{std::move(sock_path)}
        {
            _futures.emplace_back(boost::asio::co_spawn(_ioc, _listen(), boost::asio::use_future));
        }

        void run()
        {
            while (!_ioc.stopped() && !_destroy.load(std::memory_order_relaxed)) {
                _ioc.run_for(std::chrono::milliseconds { 100 });
            }
        }
    private:
        struct version_t {
            uint8_t major;
            uint8_t minor;
            uint8_t patch;

            void serialize(auto &archive)
            {
                archive.process("major"sv, major);
                archive.process("minor"sv, minor);
                archive.process("patch"sv, patch);
            }

            bool operator==(const version_t &) const = default;
        };

        struct peer_info_t {
            std::string name;
            version_t app_version;
            version_t jam_version;

            void serialize(auto &archive)
            {
                archive.process("name"sv, name);
                archive.process("app_version"sv, app_version);
                archive.process("jam_version"sv, jam_version);
            }
        };

        using import_block_t = block_t<CFG>;

        struct set_state_t {
            header_t<CFG> header;
            state_snapshot_t state;

            void serialize(auto &archive)
            {
                archive.process("header"sv, header);
                archive.process("state"sv, state);
            }
        };

        struct get_state_t {
            header_hash_t header_hash;

            void serialize(auto &archive)
            {
                archive.process("header_hash"sv, header_hash);
            }
        };

        using message_base_t = std::variant<
                peer_info_t,
                import_block_t,
                set_state_t,
                get_state_t,
                state_snapshot_t,
                state_root_t
            >;
        struct message_t: message_base_t {
            using base_type = message_base_t;
            using base_type::base_type;

            void serialize(auto &archive)
            {
                using namespace std::string_view_literals;
                static_assert(std::variant_size_v<base_type> > 0);
                static codec::variant_names_t<base_type> names {
                    "peer_info"sv,
                    "import_block"sv,
                    "set_state"sv,
                    "get_state"sv,
                    "state"sv,
                    "state_root"sv
                };
                archive.template process_variant<base_type>(*this, names);
            }
        };

        std::string _chain_id;
        std::string _sock_path;
        file::tmp_directory _tmp_dir { "turbo-jam-fuzzer" };
        boost::asio::io_context _ioc {};
        std::atomic<bool> _destroy { false };
        std::mutex _futures_mutex alignas(mutex::alignment) {};
        std::vector<std::future<void>> _futures {};

        static boost::asio::awaitable<message_t> _read_message(stream_protocol::socket &conn)
        {
            uint32_t msg_len = 0;
            uint8_vector msg_buf {};
            co_await boost::asio::async_read(conn, boost::asio::buffer(&msg_len, sizeof(msg_len)), boost::asio::use_awaitable);
            co_await boost::asio::async_read(conn, boost::asio::buffer(msg_buf.data(), msg_buf.size()), boost::asio::use_awaitable);
            decoder dec { msg_buf };
            co_return codec::from<message_t>(dec);
        }

        static boost::asio::awaitable<void> _write_message(stream_protocol::socket &conn, message_t msg)
        {
            const encoder enc { msg };
            const uint32_t msg_len = enc.bytes().size();
            co_await boost::asio::async_write(conn, boost::asio::buffer(&msg_len, sizeof(msg_len)), boost::asio::use_awaitable);
            co_await boost::asio::async_write(conn, boost::asio::buffer(enc.bytes()), boost::asio::use_awaitable);
        }

        boost::asio::awaitable<void> _handle_client(stream_protocol::socket conn)
        {
            static const peer_info_t my_peer_info {
                "turbojam",
                { 0, 1, 0 },
                { 0, 6, 6 }
            };
            {
                const auto handshake = co_await _read_message(conn);
                const peer_info_t &peer_info = std::get<peer_info_t>(handshake);
                if (peer_info.jam_version != my_peer_info.jam_version) [[unlikely]]
                    throw error(fmt::format("jam version mismatch: {} != {}", peer_info.jam_version, my_peer_info.jam_version));
            }
            std::optional<chain_t<CFG>> chain {};
            for (;;) {
                auto msg = co_await _read_message(conn);
                auto resp = std::visit([&](auto &&m) -> message_t {
                    using T = std::decay_t<decltype(m)>;
                    if constexpr (std::is_same_v<T, set_state_t>) {
                        chain.emplace(_chain_id, _tmp_dir.path(), m.state, m.state);
                        if (chain->genesis_header() != m.header) [[unlikely]]
                            throw error("the provided header does not match the provided state and the genesis_header construction rules");
                        return chain->state_root();
                    } else if constexpr (std::is_same_v<T, import_block_t>) {
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
                co_await _write_message(conn, std::move(resp));
            }
            co_return;
        }

        boost::asio::awaitable<void> _listen()
        {
            auto ex = co_await boost::asio::this_coro::executor;
            std::filesystem::remove(_sock_path);
            stream_protocol::acceptor acceptor { _ioc, stream_protocol::endpoint { _sock_path } };
            while (!_destroy.load(std::memory_order_relaxed)) {
                boost::asio::steady_timer timer(ex);
                timer.expires_after(std::chrono::milliseconds { 500 });
                auto res = co_await (acceptor.async_accept(boost::asio::use_awaitable) || timer.async_wait(boost::asio::use_awaitable));
                std::visit([&](auto &&rv) {
                    using T = std::decay_t<decltype(rv)>;
                    if constexpr (std::is_same_v<T, stream_protocol::socket>) {
                        timer.cancel();
                        std::scoped_lock lock { _futures_mutex };
                        logger::info("accepted a new connection");
                        _futures.emplace_back(co_spawn(ex, _handle_client(std::move(rv)), boost::asio::use_future));
                    } else {
                        logger::error("unexpected result from async_accept: {}", typeid(T).name());
                        acceptor.cancel();
                    }
                }, std::move(res));
            }
        }
    };
}

namespace turbo::cli::fuzzer_api {
    struct cmd: command {
        void configure(config &cmd) const override
        {
            cmd.name = "fuzzer-api";
            cmd.desc = "Launch a local server providing the local fuzzing API and listening a <unix-socket-path>";
            cmd.args.expect({ "<unix-socket-path>" });
        }

        void run(const arguments &args) const override
        {
            const auto &sock_path = args.at(0);
            server<config_tiny> srv { "dev", sock_path };
            srv.run();
        }
    };
    static auto instance = command::reg(std::make_shared<cmd>());
}
