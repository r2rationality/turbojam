#include <turbo/common/logger.hpp>
#include <turbo/common/scheduler.hpp>
#include "client.hpp"
#include "internal/msquic.hpp"

namespace turbo::jamnp {
    using namespace quic;

    template<typename CFG>
    struct client_t<CFG>::impl_t {
        impl_t(address_t server_addr, std::string app_name, std::string alpn_id, const std::string &cert_prefix):
            _server_addr{std::move(server_addr)},
            _cfg{std::move(app_name), std::move(alpn_id), cert_prefix}
        {
        }

        [[nodiscard]] coro::task_t<block_list_t> fetch_blocks(const header_hash_t &hh, const uint32_t max_blocks, const direction_t direction)
        {
            logger::debug("fetch_blocks: started");
            std::shared_ptr<request_t> req {};
            co_await coro::get_handle_t{[&](auto h) {
                req = std::make_shared<request_t>([h] mutable {
                    logger::debug("notify_shutdown: started");
                    if (h && !h.done()) {
                        logger::debug("notify_shutdown: calling set_exception");
                        auto cast_h = std::coroutine_handle<typename coro::task_t<block_list_t>::promise_type>::from_address(h.address());
                        cast_h.promise().set_exception(
                            std::make_exception_ptr(error{fmt::format("connection has been shut down before request completion!")})
                        );
                        cast_h.resume();
                    }
                    logger::debug("notify_shutdown: completed");
                });
            }};
            _requests.emplace(req);
            auto cleanup = std::unique_ptr<void, std::function<void(void*)>> {nullptr, [&](void *) { _requests.erase(req); } };
            co_await _create_stream(req);
            logger::debug("fetch_blocks: created a stream");
            {
                const auto msg = _fetch_blocks_request(hh, max_blocks, direction);
                encoder enc {};
                enc.uint_fixed(1, 128U);
                enc.uint_fixed(4, msg.size());
                enc.next_bytes(msg);
                co_await req->send(enc.bytes());
            }
            logger::debug("fetch_blocks: sent a request");
            uint8_vector resp {};
            for (size_t i = 0; i < max_blocks; ++i) {
                const auto rcv_buf = co_await req->receive();
                resp << rcv_buf;
                decoder dec { resp };
                const auto msg_len = dec.uint_fixed<size_t>(4U);
                logger::debug("fetch_blocks: received a response chunk: new response size: {} msg_len: {}", resp.size(), msg_len);
                if (dec.size() >= msg_len) {
                    if (dec.size() > msg_len) [[unlikely]]
                        logger::error("fetch_blocks: received too much data: {} > {}!", dec.size(), msg_len);
                    block_list_t blocks {};
                    while (!dec.empty()) {
                        blocks.emplace_back(codec::from<block_t<CFG>>(dec));
                    }
                    logger::debug("fetch_blocks: returning blocks");
                    co_return blocks;
                }
            }
            throw error(fmt::format("fetch_blocks: received too little data: {}!", resp.size()));
        }

        [[nodiscard]] coro::task_t<state_resp_t> fetch_state(const header_hash_t &hh, const merkle::trie::key_t &key_start, const merkle::trie::key_t &key_end, const uint32_t max_size)
        {
            logger::debug("fetch_state: started");
            std::shared_ptr<request_t> req {};
            co_await coro::get_handle_t{[&](auto h) {
                req = std::make_shared<request_t>([h] mutable {
                    logger::debug("notify_shutdown: started");
                    if (h && !h.done()) {
                        logger::debug("notify_shutdown: calling set_exception");
                        auto cast_h = std::coroutine_handle<typename coro::task_t<block_list_t>::promise_type>::from_address(h.address());
                        cast_h.promise().set_exception(
                            std::make_exception_ptr(error{fmt::format("connection has been shut down before request completion!")})
                        );
                        cast_h.resume();
                    }
                    logger::debug("notify_shutdown: completed");
                });
            }};
            _requests.emplace(req);
            auto cleanup = std::unique_ptr<void, std::function<void(void*)>> {nullptr, [&](void *) { _requests.erase(req); } };
            co_await _create_stream(req);
            logger::debug("fetch_state: created a stream");
            {
                encoder enc {};
                enc.uint_fixed(1, 129U);
                enc.uint_fixed(4, 0); // will be updated later
                enc.next_bytes(hh);
                enc.next_bytes(key_start);
                enc.next_bytes(key_end);
                enc.uint_fixed(4, max_size);
                const auto msg_len = numeric_cast<uint32_t>(enc.bytes().size() - 5U);
                encoder::uint_fixed(std::span { enc.bytes().data() + 1, 4 }, 4, msg_len);
                logger::info("fetch-state: msg-len: {}", msg_len);
                logger::info("fetch-state: send: {}", enc.bytes());
                co_await req->send(enc.bytes());
            }
            logger::debug("fetch_state: sent a request");
            uint8_vector resp {};
            for (size_t i = 0; i < max_size; ++i) {
                const auto rcv_buf = co_await req->receive();
                resp << rcv_buf;
                decoder dec { resp };
                const auto msg_len = dec.uint_fixed<size_t>(4U);
                logger::debug("fetch_state: received a response chunk: new response size: {} msg_len: {}", resp.size(), msg_len);
                if (dec.size() >= msg_len) {
                    if (dec.size() > msg_len) [[unlikely]]
                        logger::error("fetch_state: received too much data: {} > {}!", dec.size(), msg_len);
                    state_resp_t result {};
                    dec.process(result);
                    logger::debug("fetch_state: returning state");
                    co_return result;
                }
                
            }
            throw error(fmt::format("fetch_state: received too little data: {}!", resp.size()));
        }
    private:
        address_t _server_addr;
        api_initializer_t _init {};
        config_client_t _cfg;
        std::mutex _mutex alignas(64U) {};
        MsQuicConnection *_conn = nullptr;
        std::coroutine_handle<> _connecting {};
        std::set<std::shared_ptr<request_t>> _requests {};

        static void _check_certificate(const X509 *)
        {
        }

        static uint8_vector _fetch_blocks_request(const header_hash_t &hh, const uint32_t max_blocks, const direction_t direction=direction_t::ascending)
        {
            logger::debug("making a block request: start hash: {} max_blocks: {} direction: {}", hh, max_blocks, static_cast<uint8_t>(direction));
            uint8_vector res {};
            res.reserve(sizeof(hh) + 1 + sizeof(max_blocks));
            res << hh;
            res << static_cast<uint8_t>(direction);
            res << buffer::from(max_blocks);
            return res;
        }

        static QUIC_STATUS QUIC_API _connection_callback(MsQuicConnection* conn, void *ctx, QUIC_CONNECTION_EVENT *event)
        {
            if (!ctx) [[unlikely]] {
                logger::error("jamsnp::connection_t: context cannot be nullptr!");
                return QUIC_STATUS_SUCCESS;
            }
            auto &self = *reinterpret_cast<impl_t *>(ctx);
            if (conn != self._conn) {
                logger::error("jamsnp::connection_t: context's connection does not match the parameter!");
                return QUIC_STATUS_SUCCESS;
            }
            switch (event->Type) {
                case QUIC_CONNECTION_EVENT_CONNECTED: {
                    logger::debug("jamsnp::connection: connected!");
                    std::coroutine_handle<> h {};
                    {
                        std::scoped_lock lk { self._mutex };
                        std::swap(self._connecting, h);
                    }
                    scheduler::get().submit("connection-connected", 100, [h] {
                        if (h && !h.done())
                            h.resume();
                        logger::debug("connection-complete processed");
                    });
                    break;
                }
	            case QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED: {
	                _check_certificate(reinterpret_cast<X509 *>(event->PEER_CERTIFICATE_RECEIVED.Certificate));
		            break;
	            }
                case QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE:
                    logger::debug("connection: streams available uni: {} bidi: {}!",
                        event->STREAMS_AVAILABLE.UnidirectionalCount, event->STREAMS_AVAILABLE.BidirectionalCount);
                    break;
                case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
                    //logger::debug("connection: resumption ticket received: {}!",
                    //    buffer { event->RESUMPTION_TICKET_RECEIVED.ResumptionTicket, event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength });
                    break;
                case QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED:
                    //logger::debug("connection: datagram state changed: SendEnabled: {} MaxSendLength: {}!\n",
                    //    event->DATAGRAM_STATE_CHANGED.SendEnabled, event->DATAGRAM_STATE_CHANGED.MaxSendLength);
                    break;
                case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT: {
                    logger::debug("connection: shut down by transport: ErrorCode: {:08X} Status: {}!",
                        event->SHUTDOWN_INITIATED_BY_TRANSPORT.ErrorCode, quic::status_name(event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status));
                    break;
                }
                case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
                    logger::debug("connection: shutdown by peer!");
                    break;
                case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE: {
                    logger::debug("connection: shutdown complete!");
                    decltype(self._requests) old_requests {};
                    {
                        std::scoped_lock lk { self._mutex };
                        if (self._conn) {
                            self._conn = nullptr;
                            std::swap(old_requests, self._requests);
                        }
                    }
                    scheduler::get().submit("connection-shutdown-complete", 100, [old_requests=std::move(old_requests)] {
                        logger::debug("connection-shutdown-complete processing started; pending requests: {}!", old_requests.size());
                        for (const auto &req: old_requests) {
                            req->notify_shutdown_func();
                        }
                        logger::debug("connection-shutdown-complete processed!");
                    });
                    break;
                }
                default:
                    logger::warn("jamsnp::connection: unexpected event: {}!", static_cast<int>(event->Type));
                    break;
            }
            return QUIC_STATUS_SUCCESS;
        }

        static QUIC_STATUS QUIC_API _stream_callback(MsQuicStream* stream, void *ctx, QUIC_STREAM_EVENT* event)
        {
            if (!ctx) [[unlikely]] {
                logger::error("jamsnp::stream_t: context cannot be nullptr!");
                return QUIC_STATUS_SUCCESS;
            }
            auto *req = reinterpret_cast<request_t *>(ctx);
            switch (event->Type) {
                case QUIC_STREAM_EVENT_START_COMPLETE: {
                    logger::debug("stream: start complete");
                    std::coroutine_handle<> h {};
                    {
                        std::scoped_lock lk { req->mutex };
                        req->stream = stream;
                        std::swap(req->starting, h);
                    }
                    logger::debug("stream: start complete: acquired the lock");
                    scheduler::get().submit("stream-start-complete", 100, [h] {
                        logger::debug("stream-start-complete processing started");
                        if (h && !h.done())
                            h.resume();
                        logger::debug("stream-start-complete processed");
                    });
                    break;
                }
                case QUIC_STREAM_EVENT_SEND_COMPLETE: {
                    logger::debug("stream: data-send-complete");
                    std::coroutine_handle<> h {};
                    {
                        std::scoped_lock lk { req->mutex };
                        std::swap(req->sending, h);
                    }
                    logger::debug("stream: data-send-complete: sending: {} done: {}", h.address(), h.done());
                    delete reinterpret_cast<QuicBufferScope *>(event->SEND_COMPLETE.ClientContext);
                    scheduler::get().submit("stream-send-complete", 100, [h] {
                        logger::debug("stream-send-complete processing started");
                        if (h && !h.done()) {
                            logger::debug("stream-send-complete calling resume");
                            h.resume();
                        }
                        logger::debug("stream-send-complete processed");
                    });
                    break;
                }
                case QUIC_STREAM_EVENT_RECEIVE: {
                    logger::debug("stream-receive processed");
                    std::coroutine_handle<> h {};
                    {
                        std::scoped_lock lk { req->mutex };
                        for (decltype(event->RECEIVE.BufferCount) bi = 0; bi < event->RECEIVE.BufferCount; ++bi) {
                            const QUIC_BUFFER *buf = event->RECEIVE.Buffers + bi;
                            req->receive_buf << buffer { buf->Buffer, buf->Length };
                        }
                        std::swap(req->receiving, h);
                    }
                    if (h && !h.done()) {
                        scheduler::get().submit("stream-receive", 100, [h] {
                            logger::debug("stream-receive processing started");
                            if (h && !h.done())
                                h.resume();
                            logger::debug("stream-receive processed");
                        });
                    }
                    break;
                }
                case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
                    logger::debug("stream: send aborted!");
                    break;
                case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
                    logger::debug("stream: peer shut down!");
                    break;
                case QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE:
                    logger::debug("stream: send closed!");
                    break;
                case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
                    logger::debug("stream: closed!");
                    break;
                default:
                    logger::debug("stream: other: {}!", static_cast<int>(event->Type));
                    break;
            }
            return QUIC_STATUS_SUCCESS;
        }

        [[nodiscard]] coro::task_t<void> _create_stream(const std::shared_ptr<request_t> &req)
        {
            logger::debug("create stream: started");
            std::unique_lock lk { _mutex };
            if (!_conn) {
                if (_connecting) [[unlikely]]
                    throw error("jamsnp::client: connection is already being established!");
                co_await coro::external_task_t{[&](auto h) {
                    _connecting = h;
                    _conn = new MsQuicConnection { _cfg.reg(), CleanUpAutoDelete, _connection_callback, this };
                    lk.unlock();
                    if (!_conn->IsValid()) [[unlikely]]
                        throw error(fmt::format("failed to initialize MsQuicConnection! Error: {}", quic::status_name(_conn->GetInitStatus())));
                    std::thread{[this] {
                        logger::debug("connection timeout thread: started");
                        std::this_thread::sleep_for(std::chrono::seconds{5U});
                        std::scoped_lock lk{_mutex};
                        if (_conn) {
                            logger::debug("connection timeout thread: calling shutdown");
                            _conn->Shutdown(1);
                        }
                        logger::debug("connection timeout thread: completed");
                    }}.detach();
                    logger::debug("created MSQUIC connection object");
                    if (const auto res = _conn->Start(_cfg.config(), QUIC_ADDRESS_FAMILY_INET6, _server_addr.host.c_str(), _server_addr.port); QUIC_FAILED(res)) [[unlikely]] {
                        _conn->Shutdown(1);
                        throw error(fmt::format("connection start failed with {}", quic::status_name(res)));
                    }
                    logger::debug("called MSQUIC connection start");
                }};
            }
            logger::debug("create stream: connection ready");
            lk.lock();
            co_await coro::external_task_t{[&](auto h) {
                auto &conn = *_conn;
                req->starting = h;
                lk.unlock();
                const auto st = new MsQuicStream { conn, QUIC_STREAM_OPEN_FLAG_NONE, CleanUpAutoDelete, _stream_callback, req.get() };
                if (!st->IsValid()) [[unlikely]] {
                    throw error("stream: failed to initialize");
                }
                logger::debug("created MSQUIC stream");
                if (const auto res = st->Start(); QUIC_FAILED(res)) [[unlikely]]
                    throw error(fmt::format("stream: start failed with code {}", quic::status_name(res)));
                logger::debug("called MSQUIC stream start");
            }};
            logger::debug("create stream: stream ready");
        }
    };

    template<typename CFG>
    client_t<CFG>::client_t(address_t server_addr, const std::string &app_name, const std::string &alpn_id, const std::string &cert_prefix):
        _impl { std::make_unique<impl_t>(std::move(server_addr), std::move(app_name), std::move(alpn_id), cert_prefix) }
    {
    }

    template<typename CFG>
    client_t<CFG>::~client_t() = default;

    template<typename CFG>
    coro::task_t<typename client_t<CFG>::block_list_t> client_t<CFG>::fetch_blocks(const header_hash_t &hh, uint32_t max_blocks, direction_t direction)
    {
        return _impl->fetch_blocks(hh, max_blocks, direction);
    }

    template<typename CFG>
    coro::task_t<state_resp_t> client_t<CFG>::fetch_state(const header_hash_t &hh, const merkle::trie::key_t &key_start, const merkle::trie::key_t &key_end, const uint32_t max_size)
    {
        return _impl->fetch_state(hh, key_start, key_end, max_size);
    }

    template struct client_t<config_prod>;
    template struct client_t<config_tiny>;
}