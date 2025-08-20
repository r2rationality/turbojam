/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <ranges>
#include <turbo/common/cli.hpp>
#include <turbo/common/file.hpp>
#include <turbo/common/variant.hpp>
#include <turbo/jam/traces.hpp>
#include "fuzzer.hpp"
// Boost headers must be included after "fuzzer.hpp"
#include <boost/asio/use_future.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

namespace {
    using namespace turbo;
    using namespace turbo::cli::fuzzer;
    using namespace turbo::jam::traces;
    using namespace std::string_view_literals;
    
    [[nodiscard]] inline std::string_view read_line(std::string_view &buf) noexcept
    {
        const size_t nl  = buf.find('\n');
        const bool   has_nl = (nl != std::string_view::npos);
        const size_t pos = has_nl ? nl : buf.size();
        const auto *data = buf.data();
        const bool   has_cr = (pos > 0 && data[pos - 1] == '\r');
        const size_t line_end = pos - static_cast<size_t>(has_cr);
        std::string_view line{data, line_end};
        buf.remove_prefix(pos + static_cast<size_t>(has_nl));
        return line;
    }

    struct io_worker_t {
        static io_worker_t &get()
        {
            static io_worker_t worker{};
            return worker;
        }

        boost::asio::io_context &io_context()
        {
            return _ioc;
        }

        template<typename F>
        auto sync_call(F f)
        {
            auto fut = boost::asio::co_spawn(_ioc, std::move(f), boost::asio::use_future);
            if (_ioc.stopped())
                _ioc.restart();
            auto guard = boost::asio::make_work_guard(_ioc);
            using T = std::decay_t<decltype(fut.get())>;
            for (;;) {
                if (fut.wait_for(std::chrono::milliseconds{0}) == std::future_status::ready) [[unlikely]] {
                    if constexpr (std::is_void_v<T>) {
                        fut.get();
                        return;
                    } else {
                        return fut.get();
                    }
                }
                _ioc.run_for(std::chrono::milliseconds{100});
            }
        }
    private:
        boost::asio::io_context _ioc {};
    };

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
            static const peer_info_t my_peer_info {
                "turbojam-fuzzer-client",
                { 0, 1, 0 },
                { 0, 6, 6 }
            };
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

    template<typename CFG, template<typename ...> typename PROC>
    struct client_t {
        using my_processor_ptr_t = std::unique_ptr<PROC<CFG>>;

        explicit client_t(my_processor_ptr_t proc, io_worker_t &io_worker=io_worker_t::get()):
            _proc{std::move(proc)},
            _io_worker{io_worker}
        {
        }

        void test_sample(const std::string &path)
        {
            try {
                const auto tc = jam::load_obj<test_case_t>(path);
                auto ok = _io_worker.sync_call(_test_case(set_state_t<CFG>::from_snapshot(tc.pre.keyvals), import_block_t<CFG>{tc.block}, tc.post.state_root));
                ok &= _check_state_root(tc.block.header.hash(), tc.post.state_root, tc.post.keyvals);
                logger::info("sample {}: {}", path, ok ? "OK" : "FAILED");
            } catch (const std::exception &ex) {
                logger::error("sample {}: failed due to an uncaught exception: {}", path, ex.what());
            } catch (...) {
                logger::error("sample {}: failed due to an uncaught unknown exception", path);
            }
        }

        void test_dir(const std::filesystem::path &data_dir)
        {
            for (const auto &e: std::filesystem::recursive_directory_iterator(data_dir)) {
                if (e.is_regular_file() && e.path().extension() == ".bin" && e.path().stem() != "genesis")
                    test_sample(e.path().string());
            }
        }
    private:
        my_processor_ptr_t _proc;
        io_worker_t &_io_worker;

        boost::asio::awaitable<state_snapshot_t> _get_state(const header_hash_t &hh)
        {
            co_return variant::get_nice<state_snapshot_t>(_proc->process(message_t<CFG>{get_state_t{hh}}));
        }

        boost::asio::awaitable<bool> _test_case(set_state_t<CFG> set_state, import_block_t<CFG> block, const state_root_t &exp_root)
        {
            const auto pre_root = variant::get_nice<state_root_t>(_proc->process(message_t<CFG>{std::move(set_state)}));
            logger::trace("pre_root: {}", pre_root);
            const auto post_root = variant::get_nice<state_root_t>(_proc->process(message_t<CFG>{std::move(block)}));
            logger::trace("post_root: {}", post_root);
            co_return post_root == exp_root;
        }

        bool _check_state_root(const header_hash_t &hh, const state_root_t &exp_root, const state_snapshot_t &exp_state)
        {
            const auto snap = _io_worker.sync_call(_get_state(hh));
            const auto root = snap.root();
            const auto match = root == exp_root;
            if (!match) {
                logger::debug("state for block {} does not match expected root: {} actual: {}", hh, exp_root, root);
                logger::debug("state diff: {}", snap.diff(exp_state));
            }
            return match;
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
                client_t<config_tiny, local_processor_t> c{std::make_unique<local_processor_t<config_tiny>>(*it->second)};
                c.test_dir(data_dir);
            } else {
                client_t<config_tiny, processor_t> c{std::make_unique<processor_t<config_tiny>>("dev", file::tmp_directory{"turbo-jam-fuzzer"})};
                c.test_dir(data_dir);
            }

        }
    };
    static auto instance = command::reg(std::make_shared<cmd>());
}
