/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/file.hpp>
#include <turbo/common/variant.hpp>
#include <turbo/jam/traces.hpp>
#include <turbo/jam/cli/fuzzer.hpp>
#include "test-vectors.hpp"

// Boost headers must be included after "fuzzer.hpp"
#include <boost/asio/use_future.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

namespace {
    using namespace turbo;
    using namespace turbo::cli::fuzzer;
    using namespace turbo::jam::traces;
    using namespace std::string_view_literals;


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

    struct override_case_t {
        size_t case_no;
        std::string snap_path;
        std::optional<state_snapshot_t> snap{};
    };

    template<typename CFG, template<typename ...> typename PROC>
    struct client_t {
        using my_processor_ptr_t = std::unique_ptr<PROC<CFG>>;

        explicit client_t(my_processor_ptr_t proc, io_worker_t &io_worker=io_worker_t::get()):
            _proc{std::move(proc)},
            _io_worker{io_worker}
        {
        }

        bool test_sample(const std::string &in_path, const std::string &exp_path)
        {
            try {
                auto in = jam::load_obj<message_t<CFG>>(in_path);
                auto exp = jam::load_obj<message_t<CFG>>(exp_path);
                const auto start_time = std::chrono::system_clock::now();
                const auto ok = _io_worker.sync_call(_test_case(std::move(in), std::move(exp)));
                expect(ok) << in_path;
                return ok;
            } catch (const std::exception &ex) {
                logger::error("sample {}: failed due to an uncaught exception: {}", in_path, ex.what());
            } catch (...) {
                logger::error("sample {}: failed due to an uncaught unknown exception", in_path);
            }
            return false;
        }

        void test_dir(const std::filesystem::path &data_dir, std::optional<override_case_t> override={})
        {
            std::vector<std::string> fuzzer_files{};
            std::vector<std::string> target_files{};
            std::optional<initialize_t<CFG>> override_init{};
            for (const auto &path: file::files_with_ext(data_dir.string(), ".bin")) {
                if (path.contains("00000000_")) [[unlikely]]
                    continue;
                if (path.contains("_fuzzer_"))
                    fuzzer_files.emplace_back(path);
                if (path.contains("_target_"))
                    target_files.emplace_back(path);
                if (path.contains("fuzzer_initialize")) {
                    if (override_init) [[unlikely]]
                        throw error(fmt::format("an unexpected second initialize: {}", path));
                    override_init = load_obj<initialize_t<CFG>>(path);
                }
            }
            if (fuzzer_files.size() != target_files.size())
                throw error(fmt::format("the number of fuzzer files: {} != the number of target files: {}", fuzzer_files.size(), target_files.size()));
            //if (override && std::filesystem::exists(override->snap_path))
            //    override->snap = load_obj<state_snapshot_t>(override->snap_path);
            for (size_t i = 0; i < fuzzer_files.size(); ++i) {
                if (!override || (!override->snap && i < override->case_no)) [[unlikely]] {
                    test_sample(fuzzer_files[i], target_files[i]);
                }
                if (override && override->case_no == i) [[unlikely]] {
                    if (override->snap) {
                        override_init->state = std::move(*override->snap);
                        _io_worker.sync_call(_set_state(initialize_t<CFG>(std::move(*override_init))));
                    } else {
                        const auto snap = _io_worker.sync_call(_get_state({}));
                        const encoder enc{snap};
                        file::write(override->snap_path, enc.bytes());
                    }
                    test_sample(fuzzer_files[i], target_files[i]);
                    break;
                }
            }
        }
    private:
        my_processor_ptr_t _proc;
        io_worker_t &_io_worker;

        boost::asio::awaitable<state_root_t> _set_state(initialize_t<CFG> init)
        {
            co_return variant::get_nice<state_root_t>(_proc->process(message_t<CFG>{std::move(init)}));
        }

        boost::asio::awaitable<state_snapshot_t> _get_state(const header_hash_t &hh)
        {
            co_return variant::get_nice<state_snapshot_t>(_proc->process(message_t<CFG>{get_state_t{hh}}));
        }

        boost::asio::awaitable<bool> _test_case(message_t<CFG> in, message_t<CFG> exp)
        {
            const auto out = _proc->process(std::move(in));
            if (out.index() != exp.index()
                || (!std::holds_alternative<fuzzer::error_t>(out) && out != exp)) {
                logger::error("out: {}", out);
                logger::error("exp: {}", exp);
                co_return false;
            }
            co_return true;
        }
    };
}

suite turbo_jam_fuzzer_suite = [] {
    "turbo::jam::fuzzer"_test = [] {
        file::tmp_directory tmp_dir{"turbo-jam-fuzzer"};
        {
            client_t<config_tiny, processor_t> c{std::make_unique<processor_t<config_tiny>>("dev", tmp_dir)};
            c.test_dir(file::install_path("test/jam-conformance/fuzz-proto/examples/0.7.2/no_forks"));
        }
        {
            client_t<config_tiny, processor_t> c{std::make_unique<processor_t<config_tiny>>("dev", tmp_dir)};
            c.test_dir(file::install_path("test/jam-conformance/fuzz-proto/examples/0.7.2/forks")/*, override_case_t{
                45U,
                file::install_path("test/overrides/minifuzz-snap-45.bin")
            }*/);
        }
    };
};
