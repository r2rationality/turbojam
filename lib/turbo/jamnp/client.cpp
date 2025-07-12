#include <turbo/common/logger.hpp>
#include <turbo/common/scheduler.hpp>
#include "client.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#ifdef _WIN32
#   include <openssl/applink.c>
#endif

// include it the last since it includes Windows headers
#include <msquic.hpp>

const MsQuicApi *MsQuic = nullptr;

namespace turbo::jamnp {
    static std::string status_name(const QUIC_STATUS status)
    {
        static std::unordered_map<QUIC_STATUS, std::string> names {
            { QUIC_STATUS_SUCCESS, "QUIC_STATUS_SUCCESS" },
            { QUIC_STATUS_PENDING, "QUIC_STATUS_PENDING" },
            { QUIC_STATUS_CONTINUE, "QUIC_STATUS_CONTINUE" },
            { QUIC_STATUS_OUT_OF_MEMORY, "QUIC_STATUS_OUT_OF_MEMORY" },
            { QUIC_STATUS_INVALID_PARAMETER, "QUIC_STATUS_INVALID_PARAMETER" },
            { QUIC_STATUS_INVALID_STATE, "QUIC_STATUS_INVALID_STATE" },
            { QUIC_STATUS_NOT_SUPPORTED, "QUIC_STATUS_NOT_SUPPORTED" },
            { QUIC_STATUS_NOT_FOUND, "QUIC_STATUS_NOT_FOUND" },
            { QUIC_STATUS_BUFFER_TOO_SMALL, "QUIC_STATUS_BUFFER_TOO_SMALL" },
            { QUIC_STATUS_HANDSHAKE_FAILURE, "QUIC_STATUS_HANDSHAKE_FAILURE" },
            { QUIC_STATUS_ABORTED, "QUIC_STATUS_ABORTED" },
            { QUIC_STATUS_ADDRESS_IN_USE, "QUIC_STATUS_ADDRESS_IN_USE" },
            { QUIC_STATUS_INVALID_ADDRESS, "QUIC_STATUS_INVALID_ADDRESS" },
            { QUIC_STATUS_CONNECTION_TIMEOUT, "QUIC_STATUS_CONNECTION_TIMEOUT" },
            { QUIC_STATUS_CONNECTION_IDLE, "QUIC_STATUS_CONNECTION_IDLE" },
            { QUIC_STATUS_INTERNAL_ERROR, "QUIC_STATUS_INTERNAL_ERROR" },
            { QUIC_STATUS_UNREACHABLE, "QUIC_STATUS_UNREACHABLE" },
            { QUIC_STATUS_CONNECTION_REFUSED, "QUIC_STATUS_CONNECTION_REFUSED" },
            { QUIC_STATUS_PROTOCOL_ERROR, "QUIC_STATUS_PROTOCOL_ERROR" },
            { QUIC_STATUS_VER_NEG_ERROR, "QUIC_STATUS_VER_NEG_ERROR" },
            { QUIC_STATUS_USER_CANCELED, "QUIC_STATUS_USER_CANCELED" },
            { QUIC_STATUS_ALPN_NEG_FAILURE, "QUIC_STATUS_ALPN_NEG_FAILURE" },
            { QUIC_STATUS_STREAM_LIMIT_REACHED, "QUIC_STATUS_STREAM_LIMIT_REACHED" }
        };
        if (const auto it = names.find(status); it != names.end())
            return fmt::format("{} ({:08X})", it->second, status);
        return fmt::format("QUIC_STATUS_UNKNOWN {:08X}", status);
    }

    struct api_initializer_t {
        static void init_msquic_api()
        {
            static initializer_t api {};
        }

        api_initializer_t()
        {
            init_msquic_api();
        }
    private:
        struct initializer_t {
            initializer_t()
            {
                if (!_api.IsValid()) [[unlikely]]
                    throw error(fmt::format("failed to initialize MsQuic API! Error: {}", status_name(_api.GetInitStatus())));
                MsQuic = &_api;
            }
        private:
            MsQuicApi _api {};
        };
    };

    using receving_opt_t = std::optional<coro::task_t<uint8_vector>::promise_type>;

    struct request_t {
        std::function<void()> notify_shutdown_func {};
        std::mutex mutex alignas (64U) {};
        MsQuicStream *stream = nullptr;
        std::coroutine_handle<> starting {};
        std::coroutine_handle<> sending {};
        std::coroutine_handle<> receiving {};
        uint8_vector receive_buf {};

        coro::task_t<void> send(const buffer send_buf)
        {
            logger::debug("stream::send: called with {} bytes", send_buf.size());
            std::unique_lock lk { mutex };
            if (!stream) [[unlikely]]
                throw error("stream::send called on a non-active stream!");
            if (sending) [[unlikely]]
                throw error("stream::send called on a stream that is already sending!");
            co_await coro::external_task_t{[&](auto h) {
                sending = h;
                lk.unlock();
                const auto buf_scope = new QuicBufferScope { numeric_cast<uint32_t>(send_buf.size()) };
                const auto buf = static_cast<QUIC_BUFFER *>(*buf_scope);
                memcpy(buf->Buffer, send_buf.data(), send_buf.size());
                if (const auto res = stream->Send(buf, 1, QUIC_SEND_FLAG_FIN, buf_scope); QUIC_FAILED(res)) [[unlikely]] {
                    delete buf_scope;
                    throw error(fmt::format("stream: send failed with status {}", status_name(res)));
                }
                logger::debug("stream::send: created the send request with {} bytes", send_buf.size());
            }};
            logger::debug("stream::send: completed with {} bytes", send_buf.size());
        }

        coro::task_t<uint8_vector> receive()
        {
            std::unique_lock lk { mutex };
            if (receive_buf.empty()) {
                if (!stream) [[unlikely]]
                    throw error("stream::send called on a non-active stream!");
                if (receiving) [[unlikely]]
                    throw error("stream::send called on a stream that is already sending!");
                co_await coro::external_task_t{[&](auto h) {
                    receiving = h;
                    lk.unlock();
                }};
                lk.lock();
            }
            uint8_vector res {};
            std::swap(receive_buf, res);
            co_return res;
        }

        std::strong_ordering operator<=>(const request_t &o) const noexcept
        {
            return stream <=> o.stream;
        }
    };

    struct config_t {
        config_t(std::string app_name, std::string alpn_id, const std::string &cert_prefix):
            _app_name{std::move(app_name)},
            _alpn_id{std::move(alpn_id)},
            _pk_path{cert_prefix + ".key"},
            _cert_path{cert_prefix + ".cert"},
            _cred_file {
                 .PrivateKeyFile=_pk_path.c_str(),
                 .CertificateFile=_cert_path.c_str()
            }
        {
            if (!_reg.IsValid()) [[unlikely]]
                throw error(fmt::format("failed to initialize MsQuicRegistration! Error: {}", status_name(_reg.GetInitStatus())));
            if (!_config.IsValid()) [[unlikely]]
                throw error(fmt::format("failed to initialize MsQuicConfiguration! Error: {}", status_name(_config.GetInitStatus())));
        }

        const MsQuicRegistration &reg() const
        {
            return _reg;
        }
        
        const MsQuicConfiguration &config() const
        {
            return _config;
        }
    private:
        const std::string _app_name;
        const std::string _alpn_id;
        const MsQuicRegistration _reg{_app_name.c_str(), QUIC_EXECUTION_PROFILE_LOW_LATENCY, true};
        const MsQuicAlpn _alpn{_alpn_id.c_str()};
        const std::string _pk_path;
        const std::string _cert_path;
        QUIC_CERTIFICATE_FILE _cred_file;
        const QUIC_CREDENTIAL_CONFIG _cred_cfg{
            .Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE,
            .Flags = QUIC_CREDENTIAL_FLAG_CLIENT
                | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION
                | QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED,
            .CertificateFile = &_cred_file,
            .Principal = nullptr,
            .Reserved = nullptr
        };
        const MsQuicCredentialConfig _cred{_cred_cfg};
        MsQuicSettings _settings {};
        const MsQuicConfiguration _config { _reg, _alpn, _settings, _cred };
    };

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
        config_t _cfg;
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
                        event->SHUTDOWN_INITIATED_BY_TRANSPORT.ErrorCode, status_name(event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status));
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
                        throw error(fmt::format("failed to initialize MsQuicConnection! Error: {}", status_name(_conn->GetInitStatus())));
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
                        throw error(fmt::format("connection start failed with {}", status_name(res)));
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
                    throw error(fmt::format("stream: start failed with code {}", status_name(res)));
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