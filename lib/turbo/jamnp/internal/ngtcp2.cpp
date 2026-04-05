/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025-2026 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#ifdef _MSC_VER
#   include <SDKDDKVer.h>
#endif
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address_v6.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/system/error_code.hpp>
#include <chrono>
#include <exception>
#include <memory>
#include <optional>
#include <system_error>
#include <thread>
#include <utility>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
#include <gnutls/gnutls.h>

#include <turbo/common/logger.hpp>
#include <turbo/jamnp/client.hpp>

#include "ngtcp2.hpp"
#include "transport.hpp"

namespace turbo::jamnp::transport::ngtcp2 {
    namespace {
        using udp = boost::asio::ip::udp;
        using io_context = boost::asio::io_context;

        [[nodiscard]] uint64_t now_ns() noexcept
        {
            return static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()
                ).count()
            );
        }

        [[nodiscard]] std::string gnutls_error_text(const int code)
        {
            if (const char *msg = gnutls_strerror(code))
                return msg;
            return fmt::format("GnuTLS error {}", code);
        }

        [[nodiscard]] udp::endpoint make_server_endpoint(const address_t &server_addr)
        {
            return {
                boost::asio::ip::make_address_v6(server_addr.host),
                server_addr.port
            };
        }

        struct gnutls_global_state_t {
            gnutls_global_state_t()
            {
                if (const auto err = gnutls_global_init(); err != GNUTLS_E_SUCCESS) [[unlikely]]
                    throw transport_error{fmt::format("gnutls_global_init failed: {}", gnutls_error_text(err))};
            }

            ~gnutls_global_state_t()
            {
                gnutls_global_deinit();
            }
        };

        [[nodiscard]] gnutls_global_state_t &gnutls_global_state()
        {
            static gnutls_global_state_t state {};
            return state;
        }

        struct gnutls_state_t {
            explicit gnutls_state_t(const transport_config_t &cfg, const bool is_server)
            {
                [[maybe_unused]] auto &global = gnutls_global_state();
                if (const auto err = gnutls_certificate_allocate_credentials(&cred); err != GNUTLS_E_SUCCESS) [[unlikely]]
                    throw transport_error{fmt::format("gnutls_certificate_allocate_credentials failed: {}", gnutls_error_text(err))};

                if (!cfg.certificate_path.empty() && !cfg.private_key_path.empty()) {
                    if (const auto err = gnutls_certificate_set_x509_key_file(
                            cred,
                            cfg.certificate_path.c_str(),
                            cfg.private_key_path.c_str(),
                            GNUTLS_X509_FMT_PEM
                        ); err != GNUTLS_E_SUCCESS) [[unlikely]]
                        throw transport_error{fmt::format(
                            "failed to load certificate '{}' and key '{}': {}",
                            cfg.certificate_path,
                            cfg.private_key_path,
                            gnutls_error_text(err)
                        )};
                }

                if (const auto err = gnutls_init(&session, is_server ? GNUTLS_SERVER : GNUTLS_CLIENT); err != GNUTLS_E_SUCCESS) [[unlikely]]
                    throw transport_error{fmt::format("gnutls_init failed: {}", gnutls_error_text(err))};
                if (const auto err = gnutls_priority_set_direct(session, "NORMAL:-VERS-ALL:+VERS-TLS1.3", nullptr); err != GNUTLS_E_SUCCESS) [[unlikely]]
                    throw transport_error{fmt::format("gnutls_priority_set_direct failed: {}", gnutls_error_text(err))};
                if (const auto err = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cred); err != GNUTLS_E_SUCCESS) [[unlikely]]
                    throw transport_error{fmt::format("gnutls_credentials_set failed: {}", gnutls_error_text(err))};

                if (!is_server)
                    ngtcp2_crypto_gnutls_configure_client_session(session);
                else
                    ngtcp2_crypto_gnutls_configure_server_session(session);
            }

            ~gnutls_state_t()
            {
                if (session)
                    gnutls_deinit(session);
                if (cred)
                    gnutls_certificate_free_credentials(cred);
            }

            gnutls_state_t(const gnutls_state_t &) = delete;
            gnutls_state_t &operator=(const gnutls_state_t &) = delete;
            gnutls_state_t(gnutls_state_t &&) = delete;
            gnutls_state_t &operator=(gnutls_state_t &&) = delete;

            gnutls_certificate_credentials_t cred = nullptr;
            gnutls_session_t session = nullptr;
        };

        [[nodiscard]] std::string bootstrap_summary(const transport_config_t &, const bool is_server)
        {
            ngtcp2_settings settings;
            ngtcp2_settings_default(&settings);
            settings.initial_ts = now_ns();

            ngtcp2_transport_params params;
            ngtcp2_transport_params_default(&params);
            params.initial_max_streams_bidi = 1;

            return is_server
                ? "ngtcp2 server bootstrap prepared with TLS 1.3 state and transport params; listener and packet loop still pending"
                : "ngtcp2 client bootstrap prepared with TLS 1.3 state and transport params; session packet loop still pending";
        }

        struct pending_request_t {
            explicit pending_request_t(const buffer bytes):
                payload{bytes}
            {
            }

            uint8_vector payload {};
            uint8_vector response {};
            std::exception_ptr failure {};
            std::coroutine_handle<> waiter {};
        };

        struct client_runtime_t {
            client_runtime_t(const address_t &server_addr, transport_config_t cfg):
                config{std::move(cfg)},
                tls{config, false},
                endpoint{make_server_endpoint(server_addr)},
                work{boost::asio::make_work_guard(io)},
                timer{io},
                socket{io},
                summary_text{fmt::format(
                    "ngtcp2 client session prepared for [{}]:{} with Asio UDP socket and JAMNP stream framing",
                    endpoint.address().to_string(),
                    endpoint.port()
                )}
            {
                socket.open(udp::v6());
                socket.bind(udp::endpoint{udp::v6(), 0});
                worker = std::thread{[this] {
                    io.run();
                }};
            }

            ~client_runtime_t()
            {
                work.reset();
                boost::asio::post(io, [this] {
                    boost::system::error_code ec {};
                    timer.cancel();
                    socket.close(ec);
                });
                io.stop();
                if (worker.joinable())
                    worker.join();
            }

            void submit(const std::shared_ptr<pending_request_t> &req)
            {
                boost::asio::post(io, [this, req] {
                    try {
                        logger::info(
                            "jamnp ngtcp2 client request queued: {} bytes for [{}]:{}",
                            req->payload.size(),
                            endpoint.address().to_string(),
                            endpoint.port()
                        );
                        req->failure = std::make_exception_ptr(transport_error{
                            "ngtcp2 client stream request plumbing is present, but the QUIC handshake and packet loop are not implemented yet"
                        });
                    } catch (...) {
                        req->failure = std::current_exception();
                    }

                    if (const auto waiter = std::exchange(req->waiter, {}); waiter && !waiter.done())
                        waiter.resume();
                });
            }

            transport_config_t config;
            gnutls_state_t tls;
            udp::endpoint endpoint;
            io_context io {};
            boost::asio::executor_work_guard<io_context::executor_type> work;
            boost::asio::steady_timer timer;
            udp::socket socket;
            std::thread worker {};
            std::string summary_text;
        };
    }

    struct client_bootstrap_t::impl_t {
        explicit impl_t(transport_config_t cfg):
            _cfg{std::move(cfg)},
            _state{_cfg, false},
            _summary{bootstrap_summary(_cfg, false)}
        {
        }

        transport_config_t _cfg;
        gnutls_state_t _state;
        std::string _summary;
    };

    struct client_session_t::impl_t {
        impl_t(address_t server_addr, transport_config_t cfg):
            runtime{std::make_shared<client_runtime_t>(server_addr, std::move(cfg))}
        {
        }

        std::shared_ptr<client_runtime_t> runtime;
    };

    struct server_bootstrap_t::impl_t {
        explicit impl_t(transport_config_t cfg):
            _cfg{std::move(cfg)},
            _state{_cfg, true},
            _summary{bootstrap_summary(_cfg, true)}
        {
        }

        transport_config_t _cfg;
        gnutls_state_t _state;
        std::string _summary;
    };

    client_bootstrap_t::client_bootstrap_t(transport_config_t cfg):
        _impl{std::make_unique<impl_t>(std::move(cfg))}
    {
    }

    client_bootstrap_t::~client_bootstrap_t() = default;
    client_bootstrap_t::client_bootstrap_t(client_bootstrap_t &&) noexcept = default;
    client_bootstrap_t &client_bootstrap_t::operator=(client_bootstrap_t &&) noexcept = default;

    bool client_bootstrap_t::available() const noexcept
    {
        return compiled();
    }

    std::string client_bootstrap_t::summary() const
    {
        return _impl->_summary;
    }

    client_session_t::client_session_t(address_t server_addr, transport_config_t cfg):
        _impl{std::make_unique<impl_t>(std::move(server_addr), std::move(cfg))}
    {
    }

    client_session_t::~client_session_t() = default;
    client_session_t::client_session_t(client_session_t &&) noexcept = default;
    client_session_t &client_session_t::operator=(client_session_t &&) noexcept = default;

    coro::task_t<uint8_vector> client_session_t::request(const buffer payload)
    {
        auto req = std::make_shared<pending_request_t>(payload);
        co_await coro::external_task_t{[this, req](auto h) {
            req->waiter = h;
            _impl->runtime->submit(req);
        }};
        if (req->failure)
            std::rethrow_exception(req->failure);
        co_return std::move(req->response);
    }

    std::string client_session_t::summary() const
    {
        return _impl->runtime->summary_text;
    }

    server_bootstrap_t::server_bootstrap_t(transport_config_t cfg):
        _impl{std::make_unique<impl_t>(std::move(cfg))}
    {
    }

    server_bootstrap_t::~server_bootstrap_t() = default;
    server_bootstrap_t::server_bootstrap_t(server_bootstrap_t &&) noexcept = default;
    server_bootstrap_t &server_bootstrap_t::operator=(server_bootstrap_t &&) noexcept = default;

    bool server_bootstrap_t::available() const noexcept
    {
        return compiled();
    }

    std::string server_bootstrap_t::summary() const
    {
        return _impl->_summary;
    }

    bool compiled() noexcept
    {
        return true;
    }

    std::string compile_summary()
    {
        return "ngtcp2 backend compiled with GnuTLS crypto helpers";
    }
}
