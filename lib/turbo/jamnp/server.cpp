/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/crypto/blake2b.hpp>
#include <turbo/common/numeric-cast.hpp>
#include <turbo/common/scope-exit.hpp>
#include "server.hpp"
#include "internal/msquic.hpp"

namespace turbo::jamnp {
    using namespace std::string_view_literals;
    using namespace quic;

    struct server_t::impl_t {
        impl_t(address_t addr, std::string app_name, std::string alpn_id, const std::string &cert_prefix):
            _addr{std::move(addr)},
            _cfg{std::move(app_name), std::move(alpn_id), cert_prefix}
        {
        }

        void run()
        {
            HQUIC listener = nullptr;
            if (const auto status = MsQuic->ListenerOpen(_cfg.reg(), _server_listener_callback, NULL, &listener); QUIC_FAILED(status)) [[unlikely]]
                throw error{"ListenerOpen failed", status};
            const QUIC_BUFFER alpn_id {
                .Length = numeric_cast<uint32_t>(_cfg.alpn_id().size()),
                .Buffer = const_cast<uint8_t*>(reinterpret_cast<const uint8_t *>(_cfg.alpn_id().data()))
            };
            QUIC_ADDR address {
                .Ipv6 = {
                    .sin6_family = AF_INET6,
                    .sin6_port=_addr.port,
                    .sin6_flowinfo = 0,
                    .sin6_addr = {},
                    .sin6_scope_id = 0
                }
            };
            if (const auto res = inet_pton(AF_INET6, _addr.host.c_str(), &address.Ipv6.sin6_addr); res != 1) [[unlikely]]
                throw error{fmt::format("inet_pton failed for address: {}", _addr.host)};
            if (const auto status = MsQuic->ListenerStart(listener, &alpn_id, 1, &address); QUIC_FAILED(status)) [[unlikely]]
                throw error{"ListenerStart failed", status};
            const scope_exit cleanup{[&] {
                if (listener)
                    MsQuic->ListenerClose(listener);
            }};
            logger::info("Server started - waiting for connections");
            while (!_done.load(std::memory_order_relaxed)) {
                std::this_thread::sleep_for(std::chrono::seconds{1});
            }
            logger::info("Server stopped");
        }
    private:
        api_initializer_t _init {};
        address_t _addr;
        config_server_t _cfg;
        std::atomic<bool> _done{true};

        static _IRQL_requires_max_(DISPATCH_LEVEL) _Function_class_(QUIC_STREAM_CALLBACK)
        QUIC_STATUS QUIC_API
        _server_stream_callback(HQUIC Stream, void* ctx, QUIC_STREAM_EVENT *ev)
        {
            switch (ev->Type) {
                case QUIC_STREAM_EVENT_SEND_COMPLETE:
                    free(ev->SEND_COMPLETE.ClientContext);
                    logger::info("QUIC_STREAM_EVENT_SEND_COMPLETE");
                    break;
                case QUIC_STREAM_EVENT_RECEIVE:
                    logger::info("QUIC_STREAM_EVENT_RECEIVE");
                    break;
                case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
                    logger::info("QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN");
                    break;
                case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
                    logger::info("QUIC_STREAM_EVENT_PEER_SEND_ABORTED");
                    MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
                    break;
                case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
                    logger::info("QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE");
                    MsQuic->StreamClose(Stream);
                    break;
                default:
                    break;
            }
            return QUIC_STATUS_SUCCESS;
        }

        static _IRQL_requires_max_(DISPATCH_LEVEL) _Function_class_(QUIC_CONNECTION_CALLBACK)
        QUIC_STATUS QUIC_API
        _server_connection_callback(HQUIC Connection, void *ctx, QUIC_CONNECTION_EVENT *ev)
        {
            switch (ev->Type) {
            case QUIC_CONNECTION_EVENT_CONNECTED:
                logger::info("QUIC_CONNECTION_EVENT_CONNECTED");
                MsQuic->ConnectionSendResumptionTicket(Connection, QUIC_SEND_RESUMPTION_FLAG_NONE, 0, NULL);
                break;
            case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
                logger::info("QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT");
                if (ev->SHUTDOWN_INITIATED_BY_TRANSPORT.Status == QUIC_STATUS_CONNECTION_IDLE) {
                    printf("[conn][%p] Successfully shut down on idle.\n", Connection);
                } else {
                    printf("[conn][%p] Shut down by transport, 0x%x\n", Connection, ev->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
                }
                break;
            case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
                logger::info("QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER");
                break;
            case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
                logger::info("QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE");
                MsQuic->ConnectionClose(Connection);
                break;
            case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
                logger::info("QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED");
                MsQuic->SetCallbackHandler(ev->PEER_STREAM_STARTED.Stream, (void*)_server_stream_callback, NULL);
                break;
            case QUIC_CONNECTION_EVENT_RESUMED:
                logger::info("QUIC_CONNECTION_EVENT_RESUMED");
                break;
            default:
                break;
            }
            return QUIC_STATUS_SUCCESS;
        }

        static _IRQL_requires_max_(PASSIVE_LEVEL) _Function_class_(QUIC_LISTENER_CALLBACK)
        QUIC_STATUS QUIC_API
        _server_listener_callback(HQUIC listener, void* ctx, QUIC_LISTENER_EVENT* ev)
        {
            auto &self = *reinterpret_cast<impl_t *>(ctx);
            QUIC_STATUS Status = QUIC_STATUS_NOT_SUPPORTED;
            switch (ev->Type) {
                case QUIC_LISTENER_EVENT_NEW_CONNECTION:
                    logger::info("QUIC_LISTENER_EVENT_NEW_CONNECTION");
                    MsQuic->SetCallbackHandler(ev->NEW_CONNECTION.Connection, _server_connection_callback, NULL);
                    Status = MsQuic->ConnectionSetConfiguration(ev->NEW_CONNECTION.Connection, self._cfg.config());
                    break;
                default:
                    break;
            }
            return Status;
        }
    };

    server_t::server_t(address_t addr, std::string app_name, std::string alpn_id, const std::string &cert_prefix):
        _impl{std::make_unique<impl_t>(std::move(addr), std::move(app_name), std::move(alpn_id), cert_prefix)}
    {
    }

    server_t::~server_t() = default;

    void server_t::run()
    {
        _impl->run();
    }

    [[nodiscard]] byte_array<32> dev_trivial_seed(uint32_t i)
    {
        static_assert(std::endian::native == std::endian::little);
        byte_array<32> seed;
        for (size_t j = 0; j < sizeof(seed) / sizeof(i); ++j) {
            memcpy(seed.data() + j * sizeof(i), &i, sizeof(i));
        }
        return seed;
    }

    [[nodiscard]] secure_byte_array<32> dev_secret_seed(const buffer prefix, const buffer input_seed)
    {
        uint8_vector seed {};
        seed << prefix << input_seed;
        return crypto::blake2b::digest<secure_byte_array<32>>(seed);
    }

    [[nodiscard]] crypto::ed25519::key_pair_t dev_ed25519(const buffer input_seed)
    {
        const auto secret_seed = dev_secret_seed("jam_val_key_ed25519"sv, input_seed);
        return crypto::ed25519::create_from_seed(secret_seed);
    }
}