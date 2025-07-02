#include <turbo/common/logger.hpp>
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

namespace turbo::jamsnp {
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

    struct connection_t {
        std::mutex mutex alignas (64U) {};
        MsQuicConnection *conn = nullptr;
        std::coroutine_handle<> connecting {};

        void check_certificate(const X509 *)
        {
        }
    };

    using receving_opt_t = std::optional<coro::task_t<uint8_vector>::promise_type>;

    struct stream_t {
        std::mutex mutex alignas (64U) {};
        MsQuicStream *stream = nullptr;
        std::coroutine_handle<> creating {};
        std::coroutine_handle<> starting {};
        std::coroutine_handle<> sending {};
        std::coroutine_handle<> receiving {};
        uint8_vector receive_buf {};

        coro::task_t<void> send(const buffer send_buf)
        {
            std::unique_lock lk { mutex };
            if (!stream) [[unlikely]]
                throw error("stream::send called on a non-active stream!");
            if (sending) [[unlikely]]
                throw error("stream::send called on a stream that is already sending!");
            co_await coro::external_task_t {
                sending,
                [&] {
                    lk.unlock();
                    const auto buf_scope = new QuicBufferScope { numeric_cast<uint32_t>(send_buf.size()) };
                    const auto buf = static_cast<QUIC_BUFFER *>(*buf_scope);
                    memcpy(buf->Buffer, send_buf.data(), send_buf.size());
                    if (const auto res = stream->Send(buf, 1, QUIC_SEND_FLAG_FIN, buf_scope); QUIC_FAILED(res)) [[unlikely]] {
                        delete buf_scope;
                        throw error(fmt::format("stream: send failed with status {}", status_name(res)));
                    }
                }
            };
        }

        coro::task_t<uint8_vector> receive()
        {
            std::unique_lock lk { mutex };
            if (!stream) [[unlikely]]
                throw error("stream::send called on a non-active stream!");
            if (sending) [[unlikely]]
                throw error("stream::send called on a stream that is already sending!");
            co_await coro::external_task_t{receiving};
            uint8_vector res {};
            std::swap(receive_buf, res);
            co_return res;
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
            logger::info("fetch_blocks: started");
            auto stream = std::make_shared<stream_t>();
            co_await coro::external_task_t{stream->creating};
            logger::info("fetch_blocks: registered the handle");
            co_await _create_stream(stream);
            logger::info("fetch_blocks: created a stream");
            {
                const auto msg = _fetch_blocks_request(hh, max_blocks, direction);
                encoder enc {};
                enc.uint_fixed(1, 128U);
                enc.uint_fixed(4, msg.size());
                enc.next_bytes(msg);
                stream->send(enc.bytes());
            }
            logger::info("fetch_blocks: sent a request");
            block_list_t blocks {};
            uint8_vector resp {};
            for (size_t i = 0; i < max_blocks; ++i) {
                const auto rcv_buf = co_await stream->receive();
                logger::info("fetch_blocks: received a response");
                resp << rcv_buf;
                decoder dec { resp };
                const auto msg_len = dec.uint_fixed<size_t>(4U);
                if (dec.size() == msg_len)
                    break;
                if (dec.size() > msg_len) [[unlikely]]
                    throw error("jamsnp::client: received too much data!");
                while (!dec.empty()) {
                    blocks.emplace_back(codec::from<block_t<CFG>>(dec));
                }
                logger::info("fetch_blocks: returning blocks");
                co_return blocks;
            }
            throw error("jamsnp::client: received too little data!");
        }
    private:
        address_t _server_addr;
        api_initializer_t _init {};
        config_t _cfg;
        connection_t _conn {};

        static uint8_vector _fetch_blocks_request(const header_hash_t &hh, const uint32_t max_blocks, const direction_t direction=direction_t::ascending)
        {
            logger::info("making a block request: start hash: {} max_blocks: {} direction: {}", hh, max_blocks, static_cast<uint8_t>(direction));
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
            switch (event->Type) {
                case QUIC_CONNECTION_EVENT_CONNECTED: {
                    logger::trace("jamsnp::connection: connected!");
                    std::coroutine_handle<> conn_h {};
                    {
                        std::scoped_lock lk { self._conn.mutex };
                        self._conn.conn = conn;
                        std::swap(self._conn.connecting, conn_h);
                    }
                    if (conn_h)
                        conn_h.resume();
                    break;
                }
	            case QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED: {
	                self._conn.check_certificate(reinterpret_cast<X509 *>(event->PEER_CERTIFICATE_RECEIVED.Certificate));
		            break;
	            }
                case QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE:
                    logger::trace("connection: streams available uni: {} bidi: {}!",
                        event->STREAMS_AVAILABLE.UnidirectionalCount, event->STREAMS_AVAILABLE.BidirectionalCount);
                    break;
                case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
                    logger::trace("connection: resumption ticket received: {}!",
                        buffer { event->RESUMPTION_TICKET_RECEIVED.ResumptionTicket, event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength });
                    break;
                case QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED:
                    logger::trace("connection: datagram state changed: SendEnabled: {} MaxSendLength: {}!\n",
                        event->DATAGRAM_STATE_CHANGED.SendEnabled, event->DATAGRAM_STATE_CHANGED.MaxSendLength);
                    break;
                case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
                    logger::trace("connection: shut down by transport: ErrorCode: {:08X} Status: {}!",
                        event->SHUTDOWN_INITIATED_BY_TRANSPORT.ErrorCode, status_name(event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status));
                    self._conn.conn = nullptr;
                    break;
                case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
                    logger::trace("connection: shutdown by peer!");
                    break;
                case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE: {
                    logger::trace("connection: shutdown complete!");
                    std::scoped_lock lk { self._conn.mutex };
                    self._conn.conn = nullptr;
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
            auto &self = *reinterpret_cast<stream_t *>(ctx);
            switch (event->Type) {
                case QUIC_STREAM_EVENT_START_COMPLETE: {
                    logger::trace("stream: start complete");
                    std::coroutine_handle<> h {};
                    {
                        std::scoped_lock lk { self.mutex };
                        self.stream = stream;
                        std::swap(self.starting, h);
                    }
                    if (h)
                        h.resume();
                    break;
                }
                case QUIC_STREAM_EVENT_SEND_COMPLETE: {
                    logger::trace("stream: data sent!");
                    std::coroutine_handle<> h {};
                    {
                        std::scoped_lock lk { self.mutex };
                        std::swap(self.sending, h);
                    }
                    delete reinterpret_cast<QuicBufferScope *>(event->SEND_COMPLETE.ClientContext);
                    if (h)
                        h.resume();
                    break;
                }
                case QUIC_STREAM_EVENT_RECEIVE: {
                    std::coroutine_handle<> h {};
                    {
                        std::scoped_lock lk { self.mutex };
                        for (decltype(event->RECEIVE.BufferCount) bi = 0; bi < event->RECEIVE.BufferCount; ++bi) {
                            const QUIC_BUFFER *buf = event->RECEIVE.Buffers + bi;
                            self.receive_buf << buffer { buf->Buffer, buf->Length };
                        }
                        std::swap(self.receiving, h);
                    }
                    if (h)
                        h.resume();
                    break;
                }
                case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
                    logger::trace("stream: send aborted!");
                    break;
                case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
                    logger::trace("stream: peer shut down!");
                    break;
                case QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE:
                    logger::trace("stream: send closed!");
                    break;
                case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
                    logger::trace("stream: closed!");
                    break;
                default:
                    logger::trace("stream: other: {}!", static_cast<int>(event->Type));
                    break;
            }
            return QUIC_STATUS_SUCCESS;
        }

        [[nodiscard]] coro::task_t<void> _create_stream(const std::shared_ptr<stream_t> &stream)
        {
            std::unique_lock lk { _conn.mutex };
            if (!_conn.conn) {
                if (_conn.connecting) [[unlikely]]
                    throw error("jamsnp::client: connection is already being established!");
                co_await coro::external_task_t{
                    _conn.connecting,
                    [&] {
                        lk.unlock();
                        new MsQuicConnection { _cfg.reg(), CleanUpAutoDelete, _connection_callback, this };
                    }
                };
            }
            lk.lock();
            co_await coro::external_task_t{
                stream->starting,
                [&] {
                    auto &conn = *_conn.conn;
                    lk.unlock();
                    const auto st = new MsQuicStream { conn, QUIC_STREAM_OPEN_FLAG_NONE, CleanUpAutoDelete, _stream_callback, stream.get() };
                    if (!st->IsValid()) [[unlikely]]
                        throw error("stream: failed to initialize");
                    if (const auto res = st->Start(); QUIC_FAILED(res)) [[unlikely]]
                        throw error(fmt::format("stream: start failed with code {:08X}", res));
                }
            };
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
        logger::info("client_t::fetch_blocks_top_level");
        co_return co_await _impl->fetch_blocks(hh, max_blocks, direction);;
    }

    template struct client_t<config_prod>;
    template struct client_t<config_tiny>;
}