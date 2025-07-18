#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <string>
#include <turbo/common/bytes.hpp>
#include <turbo/common/coro.hpp>
#include <turbo/common/logger.hpp>
#include <turbo/common/numeric-cast.hpp>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

// include it the last since it includes Windows headers
#include <msquic.hpp>

extern "C" const MsQuicApi *MsQuic;

namespace turbo::jamnp::quic {
    extern std::string status_name(long status);

    struct error: turbo::error {
        error(const std::string &msg):
            turbo::error{msg}
        {
        }

        error(const std::string &msg, long status):
            turbo::error{fmt::format("{}, status: {}", msg, status_name(status))}
        {
        }
    };

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

    using receiving_opt_t = std::optional<coro::task_t<uint8_vector>::promise_type>;

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
                    throw error(fmt::format("stream: send failed with status {}", quic::status_name(res)));
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

    struct config_base_t {
        config_base_t(std::string app_name, std::string alpn_id, const std::string &cert_prefix):
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
                throw error(fmt::format("failed to initialize MsQuicRegistration! Error: {}", quic::status_name(_reg.GetInitStatus())));
        }

        const MsQuicRegistration &reg() const
        {
            return _reg;
        }

        const std::string &app_name() const
        {
            return _app_name;
        }

        const std::string &alpn_id() const
        {
            return _alpn_id;
        }
    protected:
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
    };

    struct config_server_t: config_base_t {
        config_server_t(std::string app_name, std::string alpn_id, const std::string &cert_prefix):
            config_base_t{std::move(app_name), std::move(alpn_id), cert_prefix}
        {
            if (!_config.IsValid()) [[unlikely]]
                throw error(fmt::format("failed to initialize MsQuicConfiguration! Error: {}", quic::status_name(_config.GetInitStatus())));
        }

        const MsQuicConfiguration &config() const
        {
            return _config;
        }
    protected:
        static MsQuicSettings _init_settings()
        {
            MsQuicSettings s {};
            s.SetIdleTimeoutMs(1000);
            s.SetServerResumptionLevel(QUIC_SERVER_RESUME_AND_ZERORTT);
            s.SetPeerBidiStreamCount(1);
            return s;
        }

        MsQuicSettings _settings = _init_settings();
        const MsQuicConfiguration _config { _reg, _alpn, _settings, _cred };
    };

    struct config_client_t: config_base_t {
        config_client_t(std::string app_name, std::string alpn_id, const std::string &cert_prefix):
            config_base_t{std::move(app_name), std::move(alpn_id), cert_prefix}
        {
            if (!_config.IsValid()) [[unlikely]]
                throw error(fmt::format("failed to initialize MsQuicConfiguration! Error: {}", quic::status_name(_config.GetInitStatus())));
        }

        const MsQuicConfiguration &config() const
        {
            return _config;
        }
    protected:
        MsQuicSettings _settings {};
        const MsQuicConfiguration _config { _reg, _alpn, _settings, _cred };
    };
}