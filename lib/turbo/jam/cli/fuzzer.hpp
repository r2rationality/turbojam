#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/variant.hpp>
#include <turbo/jam/fuzzer.hpp>
#include <turbo/jam/traces.hpp>

#ifdef _MSC_VER
#   include <SDKDDKVer.h>
#endif
#include <boost/asio/buffer.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/local/stream_protocol.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/use_future.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#if !defined(BOOST_ASIO_HAS_LOCAL_SOCKETS)
#   error Local sockets not available on this platform.
#endif

namespace turbo::cli::fuzzer {
    using namespace turbo::jam;
    using namespace turbo::jam::fuzzer;
    using namespace turbo::jam::traces;
    using boost::asio::local::stream_protocol;
    
    template<typename CFG>
    static boost::asio::awaitable<message_t<CFG>> read_message(stream_protocol::socket &conn)
    {
        uint32_t msg_len = 0;
        co_await boost::asio::async_read(conn, boost::asio::buffer(&msg_len, sizeof(msg_len)), boost::asio::use_awaitable);
        uint8_vector msg_buf(msg_len);
        co_await boost::asio::async_read(conn, boost::asio::buffer(msg_buf.data(), msg_buf.size()), boost::asio::use_awaitable);
        decoder dec{msg_buf};
        co_return codec::from<message_t<CFG>>(dec);
    }

    template<typename CFG>
    static boost::asio::awaitable<void> write_message(stream_protocol::socket &conn, message_t<CFG> msg)
    {
        const encoder enc{msg};
        const uint32_t msg_len = enc.bytes().size();
        co_await boost::asio::async_write(conn, boost::asio::buffer(&msg_len, sizeof(msg_len)), boost::asio::use_awaitable);
        co_await boost::asio::async_write(conn, boost::asio::buffer(enc.bytes()), boost::asio::use_awaitable);
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
    struct unix_socket_processor_t {
        explicit unix_socket_processor_t(const std::string_view sock_path, io_worker_t &io_worker=io_worker_t::get()):
            _sock_path{sock_path},
            _io_worker{io_worker}
        {
            _io_worker.sync_call(_connect());
            _io_worker.sync_call(_send_peer_info());
        }

        boost::asio::awaitable<message_t<CFG>> process(message_t<CFG> msg)
        {
            co_await write_message(_conn, std::move(msg));
            co_return co_await read_message<CFG>(_conn);
            //return _io_worker.sync_call(_process(std::move(msg)));
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
    };

    template<typename CFG, template<typename ...> typename PROC>
    struct impl_vs_trace_client_t {
        using test_cases_t = std::vector<test_case_t>;
        using my_processor_ptr_t = std::unique_ptr<PROC<CFG>>;

        explicit impl_vs_trace_client_t(my_processor_ptr_t proc, io_worker_t &io_worker=io_worker_t::get()):
            _proc{std::move(proc)},
            _io_worker{io_worker}
        {
        }

        bool test_sample(const uint8_vector tc_data)
        {
            try {
                test_cases_t test_cases{};
                {
                    decoder dec{tc_data};
                    while (!dec.empty()) {
                        test_cases.emplace_back(codec::from<test_case_t>(dec));
                    }
                }
                return _io_worker.sync_call(_test_sample(std::move(test_cases)));
            } catch (const std::exception &ex) {
                logger::error("test_sample: failed due to an uncaught exception: {}", ex.what());
            } catch (...) {
                logger::error("test_sample: failed due to an uncaught unknown exception");
            }
            return false;
        }

        bool test_sample(const std::string &sample_dir)
        {
            try {
                const auto start_time = std::chrono::system_clock::now();
                std::vector<std::string> paths{};
                size_t total_size = 0;
                for (const auto &e: std::filesystem::directory_iterator(sample_dir)) {
                    if (e.is_regular_file() && e.path().extension() == ".bin" && e.path().stem().string() != "genesis") {
                        paths.emplace_back(e.path().string());
                        total_size += e.file_size();
                    }
                }
                std::sort(paths.begin(), paths.end());
                uint8_vector sample_data{};
                sample_data.reserve(total_size);
                for (const auto &path: paths) {
                    sample_data << file::read(path);
                }
                const auto ok = test_sample(std::move(sample_data));
                logger::info("sample {}({}): {} in {:0.3f} sec", sample_dir, paths.size(), ok ? "OK" : "FAILED",
                    std::chrono::duration<double>(std::chrono::system_clock::now() - start_time).count());
                return ok;
            } catch (const std::exception &ex) {
                logger::error("sample {}: failed due to an uncaught exception: {}", sample_dir, ex.what());
            } catch (...) {
                logger::error("sample {}: failed due to an uncaught unknown exception", sample_dir);
            }
            return false;
        }

        void test_dir(const std::filesystem::path &data_dir)
        {
            size_t ok = 0, err = 0;
            for (const auto &e: std::filesystem::directory_iterator(data_dir)) {
                if (e.is_directory() && !e.path().filename().string().starts_with('.')) {
                    auto &cnt = test_sample(e.path().string()) ? ok : err;
                    ++cnt;
                }
            }
            if (ok + err == 0U) {
                auto &cnt = test_sample(data_dir.string()) ? ok : err;
                ++cnt;
            }
            if (ok + err > 0U) {
                logger::info("{}: success rate: {:.3f}% ({} out of {})",
                    data_dir, static_cast<double>(ok) * 100 / static_cast<double>(ok + err), ok, ok + err);
            } else {
                logger::info("no actionable samples found in {}", data_dir);
            }
        }
    private:
        my_processor_ptr_t _proc;
        io_worker_t &_io_worker;

        boost::asio::awaitable<state_snapshot_t> _get_state(const header_hash_t &hh)
        {
            co_return ::turbo::variant::get_nice<state_snapshot_t>(_proc->process(message_t<CFG>{get_state_t{hh}}));
        }

        boost::asio::awaitable<bool> _test_sample(const test_cases_t test_cases)
        {
            if (test_cases.empty()) [[unlikely]]
                throw error("test_sample: no test cases provided!");
            const auto &tc0 = test_cases[0];
            auto pre_root = ::turbo::variant::get_nice<state_root_t>(co_await _proc->process(message_t<CFG>{initialize_t<CFG>::from_snapshot(tc0.pre.keyvals)}));
            logger::trace("pre_root: {}", pre_root);
            for (size_t i = 0; i < test_cases.size(); ++i) {
                const auto &tc = test_cases[i];
                logger::debug("sample {}: testing block {} {}", i, tc.block.header.slot, tc.block.header.hash());
                const auto resp = co_await _proc->process(message_t<CFG>{import_block_t<CFG>{tc.block}});
                const auto ok = std::visit([&](const auto &rv) -> bool {
                    using T = std::decay_t<decltype(rv)>;
                    if constexpr (std::is_same_v<T, turbo::jam::fuzzer::error_t>) {
                        logger::trace("sample {}: error: {}", i, rv);
                        return tc.pre.state_root == tc.post.state_root;
                    } else if constexpr (std::is_same_v<T, state_root_t>) {
                        logger::trace("sample {}: post_root: {}", i, rv);
                        return rv == tc.post.state_root;
                    } else {
                        throw error(fmt::format("sample {}: unexpected message type: {}", i, typeid(rv).name()));
                    }
                }, resp);
                logger::debug("sample {}: {}", i, ok ? "OK" : "FAILED");
                if (!ok)
                    co_return false;
            }
            co_return true;
        }

        void _print_state_diff(const header_hash_t &hh, const state_root_t &exp_root, const state_snapshot_t &exp_state)
        {
            const auto snap = _io_worker.sync_call(_get_state(hh));
            logger::debug("state for block {} does not match expected root: {} actual: {}", hh, exp_root, snap.root());
            logger::debug("state diff: {}", snap.diff(exp_state));
        }
    };

    template<typename CFG, template<typename ...> typename PROC>
    struct impl_vs_impl_client_t {
        using test_cases_t = std::vector<test_case_t>;
        using my_processor_ptr_t = std::unique_ptr<PROC<CFG>>;

        explicit impl_vs_impl_client_t(my_processor_ptr_t proc1, my_processor_ptr_t proc2, io_worker_t &io_worker=io_worker_t::get()):
            _proc1{std::move(proc1)},
            _proc2{std::move(proc2)},
            _io_worker{io_worker}
        {
        }

        bool test_sample(const uint8_vector tc_data)
        {
            try {
                initialize_t<CFG> init;
                std::vector<block_t<CFG>> blocks{};
                {
                    decoder dec{tc_data};
                    dec.process(init);
                    while (!dec.empty()) {
                        blocks.emplace_back(codec::from<block_t<CFG>>(dec));
                    }
                }
                return _io_worker.sync_call(_test_sample(std::move(init), std::move(blocks)));
            } catch (const std::exception &ex) {
                logger::error("test_sample: failed due to an uncaught exception: {}", ex.what());
            } catch (...) {
                logger::error("test_sample: failed due to an uncaught unknown exception");
            }
            return false;
        }
    private:
        my_processor_ptr_t _proc1;
        my_processor_ptr_t _proc2;
        io_worker_t &_io_worker;

        boost::asio::awaitable<bool> _test_sample(const initialize_t<CFG> &init, const std::vector<block_t<CFG>> &blocks)
        {
            using namespace boost::asio::experimental::awaitable_operators;
            if (blocks.empty()) [[unlikely]]
                throw error("test_sample: no test blocks provided!");
            {
                const auto[init1_res, init2_res] = co_await (_proc1->process(message_t<CFG>{init}) && _proc2->process(message_t<CFG>{init}));
                const auto pre_root1 = ::turbo::variant::get_nice<state_root_t>(init1_res);
                const auto pre_root2 = ::turbo::variant::get_nice<state_root_t>(init2_res);
                logger::trace("pre_root1: {} pre_root2: {}", pre_root1, pre_root2);
                if (pre_root1 != pre_root2) {
                    logger::error("initial state root mismatch: impl1: {} impl2: {}", pre_root1, pre_root2);
                    co_return false;
                }
            }
            for (size_t i = 0; i < blocks.size(); ++i) {
                const auto &block = blocks[i];
                logger::debug("sample {}: testing block {} {}", i, block.header.slot, block.header.hash());
                const auto [resp1, resp2] = co_await (_proc1->process(message_t<CFG>{import_block_t<CFG>{block}})
                    && _proc2->process(message_t<CFG>{import_block_t<CFG>{block}}));
                const auto ok = std::visit([&](const auto &rv1, const auto &rv2) -> bool {
                    using T1 = std::decay_t<decltype(rv1)>;
                    using T2 = std::decay_t<decltype(rv2)>;
                    if constexpr (std::is_same_v<T1, turbo::jam::fuzzer::error_t> && std::is_same_v<T2, turbo::jam::fuzzer::error_t>) {
                        logger::trace("sample {}: impl1 error: {} impl2 error: {}", i, rv1, rv2);
                        return true;
                    } else if constexpr (std::is_same_v<T1, state_root_t> && std::is_same_v<T2, state_root_t>) {
                        logger::trace("sample {}: post_root1: {} post_root2: {}", i, rv1, rv2);
                        return rv1 == rv2;
                    } else {
                        logger::trace("sample {}: impl1 response type: {} impl2 response type: {}", i, typeid(rv1).name(), typeid(rv2).name());
                        return false;
                    }
                }, resp1, resp2);
                logger::debug("sample {}: {}", i, ok ? "OK" : "FAILED");
                if (!ok)
                    co_return false;
            }
            co_return true;
        }
    };
}
