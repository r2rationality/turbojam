/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025-2026 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#ifdef _MSC_VER
#   include <SDKDDKVer.h>
#endif
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address_v6.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/system/error_code.hpp>
#include <algorithm>
#include <array>
#include <chrono>
#include <deque>
#include <exception>
#include <memory>
#include <optional>
#include <random>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <turbo/common/logger.hpp>
#include "gnutls.hpp"
#include "ngtcp2.hpp"

namespace turbo::jamnp::transport::ngtcp2 {
    struct server_stream_t::impl_t {
        using read_fn_t = coro::task_t<uint8_vector> (*)(void *, int64_t, size_t);
        using read_available_fn_t = coro::task_t<uint8_vector> (*)(void *, int64_t);
        using write_fn_t = coro::task_t<void> (*)(void *, int64_t, buffer, bool);
        using done_fn_t = bool (*)(void *, int64_t);

        impl_t(void *owner, const int64_t stream_id, read_fn_t read, read_available_fn_t read_available,
            write_fn_t write, done_fn_t done):
            _owner{owner},
            _stream_id{stream_id},
            _read{read},
            _read_available{read_available},
            _write{write},
            _done{done}
        {
        }

        [[nodiscard]] uint64_t id() const noexcept {
            return static_cast<uint64_t>(_stream_id);
        }

        [[nodiscard]] coro::task_t<uint8_vector> read(const size_t sz) {
            return _read(_owner, _stream_id, sz);
        }

        [[nodiscard]] coro::task_t<uint8_vector> read_available() {
            return _read_available(_owner, _stream_id);
        }

        [[nodiscard]] coro::task_t<void> write(const buffer bytes, const bool fin) {
            return _write(_owner, _stream_id, bytes, fin);
        }

        [[nodiscard]] bool done() const noexcept {
            return _done(_owner, _stream_id);
        }
    private:
        void *_owner = nullptr;
        int64_t _stream_id = 0;
        read_fn_t _read;
        read_available_fn_t _read_available;
        write_fn_t _write;
        done_fn_t _done;
    };

    namespace {
        using udp = boost::asio::ip::udp;
        using io_context = boost::asio::io_context;
        using turbo::jamnp::internal::gnutls_error_text;
        using turbo::jamnp::internal::gnutls_global_state;

        [[nodiscard]] uint64_t now_ns() noexcept {
            return static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()
                ).count()
            );
        }

        [[nodiscard]] udp::endpoint make_server_endpoint(const address_t &server_addr) {
            return {boost::asio::ip::make_address_v6(server_addr.host), server_addr.port};
        }

        [[nodiscard]] std::string endpoint_key(const udp::endpoint &endpoint) {
            return fmt::format("{}:{}", endpoint.address().to_string(), endpoint.port());
        }

        [[nodiscard]] std::string cid_key(const ngtcp2_cid &cid) {
            return fmt::format("{}", buffer_lowercase{cid.data, cid.datalen});
        }

        void random_bytes(uint8_t *data, const size_t sz) {
            thread_local std::random_device rd{};
            for (size_t i = 0; i < sz; ++i)
                data[i] = static_cast<uint8_t>(rd());
        }

        struct gnutls_state_t {
            explicit gnutls_state_t(const transport_config_t &cfg, const bool is_server) {
                [[maybe_unused]] auto &global = gnutls_global_state();
                if (const auto err = gnutls_certificate_allocate_credentials(&_cred); err != GNUTLS_E_SUCCESS) [[unlikely]]
                    throw jamnp::error{fmt::format("gnutls_certificate_allocate_credentials failed: {}", gnutls_error_text(err))};

                if (!cfg.certificate.empty()) {
                    gnutls_x509_crt_t certs[]{cfg.certificate.certificate};
                    const auto err = gnutls_certificate_set_x509_key(_cred, certs, 1, cfg.certificate.private_key);
                    if (err != GNUTLS_E_SUCCESS) [[unlikely]]
                        throw jamnp::error{fmt::format("failed to load certificate and key: {}", gnutls_error_text(err))};
                }

                if (const auto err = gnutls_init(&_session, is_server ? GNUTLS_SERVER : GNUTLS_CLIENT); err != GNUTLS_E_SUCCESS) [[unlikely]]
                    throw jamnp::error{fmt::format("gnutls_init failed: {}", gnutls_error_text(err))};
                if (const auto err = gnutls_priority_set_direct(_session, "NORMAL:-VERS-ALL:+VERS-TLS1.3", nullptr); err != GNUTLS_E_SUCCESS) [[unlikely]]
                    throw jamnp::error{fmt::format("gnutls_priority_set_direct failed: {}", gnutls_error_text(err))};
                if (const auto err = gnutls_credentials_set(_session, GNUTLS_CRD_CERTIFICATE, _cred); err != GNUTLS_E_SUCCESS) [[unlikely]]
                    throw jamnp::error{fmt::format("gnutls_credentials_set failed: {}", gnutls_error_text(err))};
                if (is_server)
                    gnutls_certificate_server_set_request(_session, GNUTLS_CERT_REQUEST);

                const auto alpn = static_cast<std::string>(cfg.protocol_id);
                gnutls_datum_t protocols[]{
                    {
                        reinterpret_cast<unsigned char *>(const_cast<char *>(alpn.data())),
                        static_cast<unsigned int>(alpn.size())
                    }
                };
                if (const auto err = gnutls_alpn_set_protocols(_session, protocols, 1, 0); err != GNUTLS_E_SUCCESS) [[unlikely]]
                    throw jamnp::error{fmt::format("gnutls_alpn_set_protocols failed: {}", gnutls_error_text(err))};

                const auto err = is_server
                    ? ngtcp2_crypto_gnutls_configure_server_session(_session)
                    : ngtcp2_crypto_gnutls_configure_client_session(_session);
                if (err != 0) [[unlikely]]
                    throw jamnp::error{fmt::format("ngtcp2_crypto_gnutls_configure_{}_session failed: {}",
                        is_server ? "server" : "client", err)};
            }

            ~gnutls_state_t() {
                if (_session)
                    gnutls_deinit(_session);
                if (_cred)
                    gnutls_certificate_free_credentials(_cred);
            }

            gnutls_state_t(const gnutls_state_t &) = delete;
            gnutls_state_t &operator=(const gnutls_state_t &) = delete;
            gnutls_state_t(gnutls_state_t &&) = delete;
            gnutls_state_t &operator=(gnutls_state_t &&) = delete;

            [[nodiscard]] gnutls_session_t session() const noexcept {
                return _session;
            }
        private:
            gnutls_certificate_credentials_t _cred = nullptr;
            gnutls_session_t _session = nullptr;
        };

        struct gnutls_crt_scope_t {
            gnutls_crt_scope_t() {
                if (const auto err = gnutls_x509_crt_init(&value); err != GNUTLS_E_SUCCESS) [[unlikely]]
                    throw jamnp::error{fmt::format("gnutls_x509_crt_init failed: {}", gnutls_error_text(err))};
            }

            ~gnutls_crt_scope_t() {
                if (value)
                    gnutls_x509_crt_deinit(value);
            }

            gnutls_crt_scope_t(const gnutls_crt_scope_t &) = delete;
            gnutls_crt_scope_t &operator=(const gnutls_crt_scope_t &) = delete;

            gnutls_x509_crt_t value = nullptr;
        };

        struct gnutls_datum_scope_t {
            ~gnutls_datum_scope_t() {
                if (value.data)
                    gnutls_free(value.data);
            }

            gnutls_datum_t value{};
        };

        struct stream_buffer_t {
            void append(const uint64_t offset, const uint8_t *data, const size_t sz) {
                const auto expected_offset = _base_offset + _bytes.size();
                if (offset != expected_offset) [[unlikely]]
                    throw jamnp::error{fmt::format("stream buffer offset out of range got: {}, expected: {}", offset, expected_offset)};
                _bytes << buffer{data, sz};
            }

            [[nodiscard]] uint8_vector read(const size_t sz) {
                if (sz > size()) [[unlikely]]
                    throw jamnp::error{fmt::format("stream buffer read size out of range got: {}, available: {}", sz, size())};
                uint8_vector bytes{buffer{_bytes.data(), sz}};
                _bytes.erase(_bytes.begin(), _bytes.begin() + static_cast<std::ptrdiff_t>(sz));
                _base_offset += sz;
                return bytes;
            }

            [[nodiscard]] uint8_vector read_available() {
                const auto sz = _bytes.size();
                auto bytes = std::move(_bytes);
                _bytes.clear();
                _base_offset += sz;
                return bytes;
            }

            void finish() noexcept {
                _finished = true;
            }

            [[nodiscard]] bool finished() const noexcept {
                return _finished;
            }

            [[nodiscard]] bool empty() const noexcept {
                return _bytes.empty();
            }

            [[nodiscard]] bool done() const noexcept {
                return finished() && empty();
            }

            [[nodiscard]] size_t size() const noexcept {
                return _bytes.size();
            }

        private:
            uint64_t _base_offset = 0;
            uint8_vector _bytes{};
            bool _finished = false;
        };

        struct pending_request_t {
            explicit pending_request_t(const buffer bytes):
                _payload{bytes}
            {
            }

            [[nodiscard]] const uint8_vector &payload() const noexcept {
                return _payload;
            }

            [[nodiscard]] uint8_vector take_response() noexcept {
                return _response.read_available();
            }

            void append_response(const uint64_t offset, const uint8_t *data, const size_t sz) {
                _response.append(offset, data, sz);
            }

            [[nodiscard]] std::exception_ptr failure() const noexcept {
                return _failure;
            }

            void set_failure(const std::exception_ptr failure) noexcept {
                _failure = failure;
            }

            void set_waiter(const std::coroutine_handle<> waiter) noexcept {
                _waiter = waiter;
            }

            void resume_waiter() {
                if (const auto waiter = std::exchange(_waiter, {}); waiter && !waiter.done())
                    waiter.resume();
            }
        private:
            uint8_vector _payload{};
            stream_buffer_t _response{};
            std::exception_ptr _failure{};
            std::coroutine_handle<> _waiter{};
        };

        [[nodiscard]] ngtcp2_settings make_settings() {
            ngtcp2_settings settings{};
            ngtcp2_settings_default(&settings);
            settings.initial_ts = now_ns();
            return settings;
        }

        [[nodiscard]] ngtcp2_transport_params make_transport_params() {
            ngtcp2_transport_params params{};
            ngtcp2_transport_params_default(&params);
            params.initial_max_stream_data_bidi_local = 1 << 20;
            params.initial_max_stream_data_bidi_remote = 1 << 20;
            params.initial_max_stream_data_uni = 1 << 20;
            params.initial_max_data = 1 << 22;
            params.initial_max_streams_bidi = 16;
            params.initial_max_streams_uni = 16;
            return params;
        }

        void rand_cb(uint8_t *data, const size_t sz, const ngtcp2_rand_ctx *) {
            random_bytes(data, sz);
        }

        int get_new_connection_id_cb(ngtcp2_conn *, ngtcp2_cid *cid, uint8_t *token, const size_t cidlen, void *) {
            byte_array<NGTCP2_MAX_CIDLEN> bytes{};
            random_bytes(bytes.data(), cidlen);
            random_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN);
            ngtcp2_cid_init(cid, bytes.data(), cidlen);
            return 0;
        }

        [[nodiscard]] ngtcp2_callbacks make_common_callbacks() {
            ngtcp2_callbacks callbacks{};
            callbacks.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
            callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
            callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
            callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
            callbacks.rand = rand_cb;
            callbacks.get_new_connection_id = get_new_connection_id_cb;
            callbacks.update_key = ngtcp2_crypto_update_key_cb;
            callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
            callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
            callbacks.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
            callbacks.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
            return callbacks;
        }

        template<typename SendFn>
        void flush_quic_packets(ngtcp2_conn *conn, const ngtcp2_path &path, SendFn send) {
            byte_array<NGTCP2_MAX_UDP_PAYLOAD_SIZE> out{};
            for (;;) {
                ngtcp2_pkt_info pi{};
                auto write_path = path;
                const auto n = ngtcp2_conn_write_pkt(conn, &write_path, &pi, out.data(), out.size(), now_ns());
                if (n == 0)
                    break;
                if (n < 0) [[unlikely]]
                    throw jamnp::error{fmt::format("ngtcp2_conn_write_pkt failed: {}", ngtcp2_strerror(static_cast<int>(n)))};
                send(buffer{out.data(), static_cast<size_t>(n)});
            }
        }

        template<typename SendFn>
        void write_quic_stream(ngtcp2_conn *conn, const ngtcp2_path &path, const int64_t stream_id, const buffer bytes, const bool fin, SendFn send) {
            byte_array<NGTCP2_MAX_UDP_PAYLOAD_SIZE> out{};
            size_t offset = 0;
            bool fin_sent = false;
            while (offset < bytes.size() || (fin && !fin_sent)) {
                const auto remaining = bytes.size() - offset;
                ngtcp2_vec datav{
                    remaining > 0 ? const_cast<uint8_t *>(bytes.data() + offset) : nullptr,
                    remaining
                };
                ngtcp2_ssize data_written = 0;
                auto write_path = path;
                ngtcp2_pkt_info pi{};
                const auto flags = fin && offset == bytes.size() ? NGTCP2_WRITE_STREAM_FLAG_FIN : NGTCP2_WRITE_STREAM_FLAG_NONE;
                const auto n = ngtcp2_conn_writev_stream(conn, &write_path, &pi, out.data(), out.size(),
                    &data_written, flags, stream_id, &datav, datav.len > 0 ? 1 : 0, now_ns());
                if (n < 0) [[unlikely]]
                    throw jamnp::error{fmt::format("ngtcp2_conn_writev_stream failed: {}", ngtcp2_strerror(static_cast<int>(n)))};
                if (n == 0 && data_written == 0) [[unlikely]]
                    throw jamnp::error{"ngtcp2_conn_writev_stream produced no packet or stream progress"};
                if (data_written > 0)
                    offset += static_cast<size_t>(data_written);
                if (n > 0)
                    send(buffer{out.data(), static_cast<size_t>(n)});
                fin_sent = flags == NGTCP2_WRITE_STREAM_FLAG_FIN && n > 0;
            }
        }

        void read_quic_packet(ngtcp2_conn *conn, const ngtcp2_path &path, const buffer packet) {
            ngtcp2_pkt_info pi{};
            pi.ecn = NGTCP2_ECN_NOT_ECT;
            const auto rv = ngtcp2_conn_read_pkt(conn, &path, &pi, packet.data(), packet.size(), now_ns());
            if (rv != 0) [[unlikely]]
                throw jamnp::error{fmt::format("ngtcp2_conn_read_pkt failed: {}", ngtcp2_strerror(rv))};
        }

        template<typename Owner>
        void bind_tls_to_conn(ngtcp2_conn *conn, gnutls_state_t &tls, ngtcp2_crypto_conn_ref &conn_ref, Owner *owner,
            ngtcp2_conn *(*get_conn)(ngtcp2_crypto_conn_ref *))
        {
            conn_ref.get_conn = get_conn;
            conn_ref.user_data = owner;
            gnutls_session_set_ptr(tls.session(), &conn_ref);
            ngtcp2_conn_set_tls_native_handle(conn, tls.session());
        }

        template<typename Handler>
        void async_receive_udp(udp::socket &socket, byte_array<64 * 1024> &buffer, udp::endpoint &remote, Handler handler)
        {
            socket.async_receive_from(
                boost::asio::buffer(buffer),
                remote,
                [handler=std::move(handler)](const boost::system::error_code &ec, const size_t bytes_received) mutable {
                    handler(ec, bytes_received);
                }
            );
        }

        struct server_runtime_t;

        struct server_connection_t {
            server_connection_t(server_runtime_t &owner, udp::endpoint remote_addr, ngtcp2_pkt_hd initial_hd);
            ~server_connection_t();

            server_connection_t(const server_connection_t &) = delete;
            server_connection_t &operator=(const server_connection_t &) = delete;

            void read_packet(buffer packet);
            void flush();
            void recv_stream_data(uint32_t flags, int64_t stream_id, uint64_t offset, const uint8_t *data, size_t sz);
            [[nodiscard]] coro::task_t<uint8_vector> read_stream(int64_t stream_id, size_t sz);
            [[nodiscard]] coro::task_t<uint8_vector> read_available_stream(int64_t stream_id);
            void write_stream(int64_t stream_id, buffer bytes, bool fin);
            [[nodiscard]] bool stream_done(int64_t stream_id) const noexcept;
            [[nodiscard]] server_stream_t make_stream(int64_t stream_id);
            [[nodiscard]] const peer_info_t &peer_info();

            [[nodiscard]] const ngtcp2_cid &scid() const noexcept {
                return _scid;
            }
        private:
            server_runtime_t &_runtime;
            udp::endpoint _remote;
            gnutls_state_t _tls;
            ngtcp2_crypto_conn_ref _conn_ref{};
            ngtcp2_path_storage _path{};
            ngtcp2_conn *_conn = nullptr;
            ngtcp2_cid _scid{};
            std::unordered_map<int64_t, stream_buffer_t> _stream_buffers{};
            std::unordered_map<int64_t, std::coroutine_handle<>> _stream_waiters{};
            std::unordered_set<int64_t> _dispatched_streams{};
            std::deque<std::shared_ptr<coro::task_t<void>>> _active_handlers{};
            std::optional<peer_info_t> _peer_info{};

            static ngtcp2_conn *_get_conn(ngtcp2_crypto_conn_ref *ref);
            static coro::task_t<uint8_vector> _read_stream_cb(void *owner, int64_t stream_id, size_t sz);
            static coro::task_t<uint8_vector> _read_available_stream_cb(void *owner, int64_t stream_id);
            static coro::task_t<void> _write_stream_cb(void *owner, int64_t stream_id, buffer bytes, bool fin);
            static bool _stream_done_cb(void *owner, int64_t stream_id);
        };

        struct server_runtime_t {
            server_runtime_t(const address_t &bind_addr, const transport_config_t &cfg, server_peer_handler_t peer_handler,
                server_stream_handler_t default_handler):
                _config{cfg},
                _endpoint{make_server_endpoint(bind_addr)},
                _socket{_io},
                _peer_handler{std::move(peer_handler)},
                _handler{std::move(default_handler)}
            {
                if (!_peer_handler) [[unlikely]]
                    throw jamnp::error{"ngtcp2 server requires a peer handler"};
                if (!_handler) [[unlikely]]
                    throw jamnp::error{"ngtcp2 server requires a default stream handler"};
                _socket.open(udp::v6());
                _socket.bind(_endpoint);
            }

            void run_forever() {
                logger::info("ngtcp2 server listening on [{}]:{} with first-byte stream dispatch", _endpoint.address().to_string(), _endpoint.port());
                _start_receive();
                _io.run();
            }
        private:
            using connection_map_t = std::unordered_map<std::string, std::unique_ptr<server_connection_t>>;
            friend struct server_connection_t;

            [[nodiscard]] coro::task_t<void> _dispatch_stream(const peer_info_t &peer, server_stream_t stream) {
                const auto first = co_await stream.read(1);
                if (!first.empty()) [[likely]]
                    co_await _handler(first[0], peer, std::move(stream));
            }

            void _start_receive() {
                async_receive_udp(_socket, _recv_buffer, _remote_endpoint, [this](const boost::system::error_code &ec, const size_t bytes_received) {
                    _handle_receive(ec, bytes_received);
                });
            }

            void _handle_receive(const boost::system::error_code &ec, const size_t bytes_received) {
                if (ec) [[unlikely]] {
                    if (ec != boost::asio::error::operation_aborted)
                        logger::warn("ngtcp2 server receive failed: {}", ec.message());
                    return;
                }
                logger::run_log_errors([&] {
                    _process_quic_packet(_remote_endpoint, buffer{_recv_buffer.data(), bytes_received});
                });
                _start_receive();
            }

            void _process_quic_packet(const udp::endpoint &remote, const buffer packet) {
                if (ngtcp2_pkt_hd hd{}; ngtcp2_accept(&hd, packet.data(), packet.size()) == 0) {
                    auto it = _connections.find(cid_key(hd.dcid));
                    if (it == _connections.end()) {
                        it = _accept_connection(remote, hd);
                    }
                    it->second->read_packet(packet);
                } else {
                    const auto dcid = _extract_dcid(packet);
                    const auto it = _connections.find(cid_key(dcid));
                    if (it == _connections.end()) {
                        logger::debug("ngtcp2 server dropped {} bytes from unknown connection {}", packet.size(), endpoint_key(remote));
                        return;
                    }
                    it->second->read_packet(packet);
                }
            }

            [[nodiscard]] connection_map_t::iterator _accept_connection(const udp::endpoint &remote, const ngtcp2_pkt_hd &hd) {
                auto connection = std::make_unique<server_connection_t>(*this, remote, hd);
                const auto key = cid_key(connection->scid());
                logger::info("ngtcp2 server created connection {} for {}", key, endpoint_key(remote));
                auto [it, inserted] = _connections.emplace(key, std::move(connection));
                if (!inserted) [[unlikely]]
                    throw jamnp::error{fmt::format("duplicate ngtcp2 connection id {}", key)};
                return it;
            }

            [[nodiscard]] static ngtcp2_cid _extract_dcid(const buffer packet) {
                ngtcp2_version_cid version_cid{};
                if (ngtcp2_pkt_decode_version_cid(&version_cid, packet.data(), packet.size(), server_cid_len) != 0)
                    throw jamnp::error{"failed to parse ngtcp2 packet destination connection id"};
                ngtcp2_cid cid{};
                ngtcp2_cid_init(&cid, version_cid.dcid, version_cid.dcidlen);
                return cid;
            }

            void _send_to(const udp::endpoint &remote, const buffer packet) {
                boost::system::error_code ec{};
                _socket.send_to(boost::asio::buffer(packet.data(), packet.size()), remote, 0, ec);
                if (ec) [[unlikely]]
                    throw jamnp::error{fmt::format("ngtcp2 server send failed: {}", ec.message())};
            }

            [[nodiscard]] static ngtcp2_callbacks _make_callbacks() {
                auto callbacks = make_common_callbacks();
                callbacks.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
                callbacks.recv_stream_data = _recv_stream_data_cb;
                return callbacks;
            }

            static int _recv_stream_data_cb(ngtcp2_conn *, const uint32_t flags, const int64_t stream_id, const uint64_t offset,
                const uint8_t *data, const size_t datalen, void *user_data, void *)
            {
                static_cast<server_connection_t *>(user_data)->recv_stream_data(flags, stream_id, offset, data, datalen);
                return 0;
            }

            static constexpr size_t server_cid_len = 8;
            static_assert(server_cid_len <= NGTCP2_MAX_CIDLEN);
            const transport_config_t &_config;
            udp::endpoint _endpoint;
            io_context _io{};
            udp::socket _socket;
            server_peer_handler_t _peer_handler;
            server_stream_handler_t _handler;
            udp::endpoint _remote_endpoint{};
            byte_array<64 * 1024> _recv_buffer{};
            connection_map_t _connections{};
        };

        ngtcp2_conn *server_connection_t::_get_conn(ngtcp2_crypto_conn_ref *ref) {
            return static_cast<server_connection_t *>(ref->user_data)->_conn;
        }

        server_connection_t::server_connection_t(server_runtime_t &owner, udp::endpoint remote_addr, ngtcp2_pkt_hd initial_hd):
            _runtime{owner},
            _remote{std::move(remote_addr)},
            _tls{_runtime._config, true}
        {
            _scid.datalen = server_runtime_t::server_cid_len;
            random_bytes(_scid.data, _scid.datalen);

            ngtcp2_path_storage_init(
                &_path,
                reinterpret_cast<const ngtcp2_sockaddr *>(_runtime._endpoint.data()),
                static_cast<ngtcp2_socklen>(_runtime._endpoint.size()),
                reinterpret_cast<const ngtcp2_sockaddr *>(_remote.data()),
                static_cast<ngtcp2_socklen>(_remote.size()),
                nullptr
            );

            auto callbacks = _runtime._make_callbacks();
            auto settings = make_settings();
            auto params = make_transport_params();
            params.original_dcid = initial_hd.dcid;
#if defined(NGTCP2_VERSION_NUM) && NGTCP2_VERSION_NUM >= 0x010c00
            params.original_dcid_present = 1;
#endif

            const auto rv = ngtcp2_conn_server_new(&_conn, &initial_hd.scid, &_scid, &_path.path,
                initial_hd.version, &callbacks, &settings, &params, nullptr, this);
            if (rv != 0) [[unlikely]]
                throw jamnp::error{fmt::format("ngtcp2_conn_server_new failed: {}", ngtcp2_strerror(rv))};

            bind_tls_to_conn(_conn, _tls, _conn_ref, this, _get_conn);
        }

        server_connection_t::~server_connection_t() {
            if (_conn)
                ngtcp2_conn_del(_conn);
        }

        void server_connection_t::read_packet(const buffer packet) {
            read_quic_packet(_conn, _path.path, packet);
            flush();
        }

        void server_connection_t::flush() {
            flush_quic_packets(_conn, _path.path, [this](const buffer packet) {
                _runtime._send_to(_remote, packet);
            });
        }

        void server_connection_t::recv_stream_data(const uint32_t flags, const int64_t stream_id, const uint64_t offset, const uint8_t *data, const size_t sz) {
            auto &stream_buffer = _stream_buffers[stream_id];
            stream_buffer.append(offset, data, sz);
            if ((flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0)
                stream_buffer.finish();

            if (!stream_buffer.empty() && _dispatched_streams.emplace(stream_id).second) {
                const auto &peer = peer_info();
                auto &task = _active_handlers.emplace_back(std::make_shared<coro::task_t<void>>(_runtime._dispatch_stream(peer, make_stream(stream_id))));
                task->resume();
            }

            if (const auto it = _stream_waiters.find(stream_id); it != _stream_waiters.end()) {
                const auto waiter = std::exchange(it->second, {});
                _stream_waiters.erase(it);
                if (waiter && !waiter.done())
                    waiter.resume();
            }
        }

        coro::task_t<uint8_vector> server_connection_t::read_stream(const int64_t stream_id, const size_t sz) {
            if (sz == 0)
                co_return {};

            auto &stream_buffer = _stream_buffers[stream_id];
            while (stream_buffer.size() < sz && !stream_buffer.finished()) {
                co_await coro::external_task_t{[this, stream_id](auto h) {
                    if (const auto [_, inserted] = _stream_waiters.emplace(stream_id, h); !inserted) [[unlikely]]
                        throw jamnp::error{fmt::format("duplicate ngtcp2 read waiter for stream {}", stream_id)};
                }};
            }

            if (stream_buffer.size() < sz) [[unlikely]]
                throw jamnp::error{fmt::format("ngtcp2 stream {} ended before {} bytes were available", stream_id, sz)};
            co_return stream_buffer.read(sz);
        }

        coro::task_t<uint8_vector> server_connection_t::read_available_stream(const int64_t stream_id) {
            auto &stream_buffer = _stream_buffers[stream_id];
            while (stream_buffer.empty() && !stream_buffer.finished()) {
                co_await coro::external_task_t{[this, stream_id](auto h) {
                    if (const auto [_, inserted] = _stream_waiters.emplace(stream_id, h); !inserted) [[unlikely]]
                        throw jamnp::error{fmt::format("duplicate ngtcp2 read waiter for stream {}", stream_id)};
                }};
            }

            co_return stream_buffer.read_available();
        }

        void server_connection_t::write_stream(const int64_t stream_id, const buffer bytes, const bool fin) {
            write_quic_stream(_conn, _path.path, stream_id, bytes, fin, [this](const buffer packet) {
                _runtime._send_to(_remote, packet);
            });
        }

        bool server_connection_t::stream_done(const int64_t stream_id) const noexcept {
            const auto it = _stream_buffers.find(stream_id);
            return it != _stream_buffers.end() && it->second.done();
        }

        server_stream_t server_connection_t::make_stream(const int64_t stream_id) {
            auto impl = std::make_unique<server_stream_t::impl_t>(
                this,
                stream_id,
                _read_stream_cb,
                _read_available_stream_cb,
                _write_stream_cb,
                _stream_done_cb
            );
            return server_stream_t{std::move(impl)};
        }

        const peer_info_t &server_connection_t::peer_info() {
            if (!_peer_info) {
                unsigned int cert_count = 0;
                const auto *certs = gnutls_certificate_get_peers(_tls.session(), &cert_count);
                if (!certs || cert_count != 1) {
                    throw jamnp::error{fmt::format("ngtcp2 client [{}]:{} supplied {} certificates",
                        _remote.address().to_string(), _remote.port(), cert_count)};
                }

                gnutls_crt_scope_t cert{};
                if (const auto err = gnutls_x509_crt_import(cert.value, &certs[0], GNUTLS_X509_FMT_DER); err != GNUTLS_E_SUCCESS) [[unlikely]]
                    throw jamnp::error{fmt::format("gnutls_x509_crt_import failed: {}", gnutls_error_text(err))};

                gnutls_ecc_curve_t curve{};
                gnutls_datum_scope_t x{};
                gnutls_datum_scope_t y{};
                if (const auto err = gnutls_x509_crt_get_pk_ecc_raw(cert.value, &curve, &x.value, &y.value); err != GNUTLS_E_SUCCESS) [[unlikely]]
                    throw jamnp::error{fmt::format("gnutls_x509_crt_get_pk_ecc_raw failed: {}", gnutls_error_text(err))};
                if (curve != GNUTLS_ECC_CURVE_ED25519 || x.value.size != sizeof(crypto::ed25519::vkey_t)) [[unlikely]]
                    throw jamnp::error{"ngtcp2 client certificate does not contain an Ed25519 public key"};

                crypto::ed25519::vkey_t public_key{};
                std::copy_n(x.value.data, public_key.size(), public_key.data());
                _peer_info = peer_info_t{
                    .remote_addr = address_t{_remote.address().to_string(), _remote.port()},
                    .public_key = public_key
                };
                logger::info("ngtcp2 server accepted client [{}]:{} with public key {}",
                    _peer_info->remote_addr.host,
                    _peer_info->remote_addr.port,
                    buffer_lowercase{_peer_info->public_key.data(), _peer_info->public_key.size()});
                _runtime._peer_handler(*_peer_info);
            }
            return *_peer_info;
        }

        coro::task_t<uint8_vector> server_connection_t::_read_stream_cb(void *owner, int64_t stream_id, size_t sz) {
            co_return co_await static_cast<server_connection_t *>(owner)->read_stream(stream_id, sz);
        }

        coro::task_t<uint8_vector> server_connection_t::_read_available_stream_cb(void *owner, int64_t stream_id) {
            co_return co_await static_cast<server_connection_t *>(owner)->read_available_stream(stream_id);
        }

        coro::task_t<void> server_connection_t::_write_stream_cb(void *owner, int64_t stream_id, buffer bytes, bool fin) {
            static_cast<server_connection_t *>(owner)->write_stream(stream_id, bytes, fin);
            co_return;
        }

        bool server_connection_t::_stream_done_cb(void *owner, const int64_t stream_id) {
            return static_cast<server_connection_t *>(owner)->stream_done(stream_id);
        }

        struct client_runtime_t;

        struct client_connection_t {
            client_connection_t(client_runtime_t &owner, const transport_config_t &cfg, udp::endpoint local, udp::endpoint remote);
            ~client_connection_t();

            client_connection_t(const client_connection_t &) = delete;
            client_connection_t &operator=(const client_connection_t &) = delete;

            void start();
            void read_packet(buffer packet);
            void submit(const std::shared_ptr<pending_request_t> &req);
            void recv_stream_data(uint32_t flags, int64_t stream_id, uint64_t offset, const uint8_t *data, size_t datalen);
            void fail_all(std::exception_ptr failure);
        private:
            client_runtime_t &_runtime;
            gnutls_state_t _tls;
            ngtcp2_crypto_conn_ref _conn_ref{};
            ngtcp2_path_storage _path{};
            ngtcp2_conn *_conn = nullptr;
            ngtcp2_cid _dcid{};
            ngtcp2_cid _scid{};
            std::deque<std::shared_ptr<pending_request_t>> _pending_requests{};
            std::unordered_map<int64_t, std::shared_ptr<pending_request_t>> _requests{};

            static ngtcp2_conn *_get_conn(ngtcp2_crypto_conn_ref *ref);
            void _flush();
            void _drain_requests();
            void _complete_request(int64_t stream_id);
            void _fail_request(const std::shared_ptr<pending_request_t> &req, std::exception_ptr failure);
        };

        struct client_runtime_t {
            client_runtime_t(const address_t &server_addr, transport_config_t cfg):
                _config{std::move(cfg)},
                _endpoint{make_server_endpoint(server_addr)},
                _work{boost::asio::make_work_guard(_io)},
                _timer{_io},
                _socket{_io}
            {
                _socket.open(udp::v6());
                _socket.bind(udp::endpoint{udp::v6(), 0});
                _connection = std::make_unique<client_connection_t>(*this, _config, _socket.local_endpoint(), _endpoint);
                _worker = std::thread{[this] {
                    _io.run();
                }};
                boost::asio::post(_io, [this] {
                    logger::run_log_errors([this] {
                        _start_receive();
                        _connection->start();
                    });
                });
            }

            ~client_runtime_t() {
                boost::asio::post(_io, [this] {
                    boost::system::error_code ec{};
                    _timer.cancel();
                    if (_connection)
                        _connection->fail_all(std::make_exception_ptr(jamnp::error{"ngtcp2 client session closed"}));
                    _socket.close(ec);
                });
                _work.reset();
                if (_worker.joinable())
                    _worker.join();
                _io.stop();
            }

            void submit(const std::shared_ptr<pending_request_t> &req) {
                boost::asio::post(_io, [this, req] {
                    try {
                        logger::info("jamnp ngtcp2 client request queued: {} bytes for [{}]:{}", req->payload().size(),
                            _endpoint.address().to_string(), _endpoint.port());
                        _connection->submit(req);
                    } catch (...) {
                        req->set_failure(std::current_exception());
                        req->resume_waiter();
                    }
                });
            }

            void send_to_server(const buffer packet) {
                boost::system::error_code ec{};
                _socket.send_to(boost::asio::buffer(packet.data(), packet.size()), _endpoint, 0, ec);
                if (ec) [[unlikely]]
                    throw jamnp::error{fmt::format("ngtcp2 client send failed: {}", ec.message())};
            }
        private:
            friend struct client_connection_t;

            [[nodiscard]] static ngtcp2_callbacks _make_callbacks() {
                auto callbacks = make_common_callbacks();
                callbacks.client_initial = ngtcp2_crypto_client_initial_cb;
                callbacks.recv_retry = ngtcp2_crypto_recv_retry_cb;
                callbacks.recv_stream_data = _recv_stream_data_cb;
                return callbacks;
            }

            static int _recv_stream_data_cb(ngtcp2_conn *, const uint32_t flags, const int64_t stream_id, const uint64_t offset,
                const uint8_t *data, const size_t datalen, void *user_data, void *)
            {
                static_cast<client_connection_t *>(user_data)->recv_stream_data(flags, stream_id, offset, data, datalen);
                return 0;
            }

            void _start_receive() {
                async_receive_udp(_socket, _recv_buffer, _remote_endpoint, [this](const boost::system::error_code &ec, const size_t bytes_received) {
                    _handle_receive(ec, bytes_received);
                });
            }

            void _handle_receive(const boost::system::error_code &ec, const size_t bytes_received) {
                if (ec) [[unlikely]] {
                    if (ec != boost::asio::error::operation_aborted)
                        logger::warn("ngtcp2 client receive failed: {}", ec.message());
                    return;
                }
                logger::run_log_errors([&] {
                    if (_remote_endpoint == _endpoint)
                        _connection->read_packet(buffer{_recv_buffer.data(), bytes_received});
                    else
                        logger::debug("ngtcp2 client dropped {} bytes from {}", bytes_received, endpoint_key(_remote_endpoint));
                });
                _start_receive();
            }

            transport_config_t _config;
            udp::endpoint _endpoint;
            io_context _io{};
            boost::asio::executor_work_guard<io_context::executor_type> _work;
            boost::asio::steady_timer _timer;
            udp::socket _socket;
            udp::endpoint _remote_endpoint{};
            byte_array<64 * 1024> _recv_buffer{};
            std::unique_ptr<client_connection_t> _connection{};
            std::thread _worker{};
        };

        ngtcp2_conn *client_connection_t::_get_conn(ngtcp2_crypto_conn_ref *ref) {
            return static_cast<client_connection_t *>(ref->user_data)->_conn;
        }

        client_connection_t::client_connection_t(client_runtime_t &owner, const transport_config_t &cfg, udp::endpoint local, udp::endpoint remote):
            _runtime{owner},
            _tls{cfg, false}
        {
            _dcid.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
            random_bytes(_dcid.data, _dcid.datalen);
            _scid.datalen = 8;
            random_bytes(_scid.data, _scid.datalen);

            ngtcp2_path_storage_init(&_path,
                reinterpret_cast<const ngtcp2_sockaddr *>(local.data()), static_cast<ngtcp2_socklen>(local.size()),
                reinterpret_cast<const ngtcp2_sockaddr *>(remote.data()), static_cast<ngtcp2_socklen>(remote.size()),
                nullptr
            );

            auto callbacks = client_runtime_t::_make_callbacks();
            auto settings = make_settings();
            auto params = make_transport_params();
            const auto rv = ngtcp2_conn_client_new(&_conn, &_dcid, &_scid, &_path.path, NGTCP2_PROTO_VER_V1,
                &callbacks, &settings, &params, nullptr, this);
            if (rv != 0) [[unlikely]]
                throw jamnp::error{fmt::format("ngtcp2_conn_client_new failed: {}", ngtcp2_strerror(rv))};

            bind_tls_to_conn(_conn, _tls, _conn_ref, this, _get_conn);
        }

        client_connection_t::~client_connection_t() {
            if (_conn)
                ngtcp2_conn_del(_conn);
        }

        void client_connection_t::start() {
            _flush();
        }

        void client_connection_t::read_packet(const buffer packet) {
            read_quic_packet(_conn, _path.path, packet);
            _drain_requests();
            _flush();
        }

        void client_connection_t::submit(const std::shared_ptr<pending_request_t> &req) {
            _pending_requests.emplace_back(req);
            _drain_requests();
            _flush();
        }

        void client_connection_t::recv_stream_data(const uint32_t flags, const int64_t stream_id, const uint64_t offset,
            const uint8_t *data, const size_t datalen) {
            const auto it = _requests.find(stream_id);
            if (it == _requests.end()) {
                logger::debug("ngtcp2 client ignored data for unknown stream {}", stream_id);
                return;
            }

            it->second->append_response(offset, data, datalen);
            if ((flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0)
                _complete_request(stream_id);
        }

        void client_connection_t::fail_all(const std::exception_ptr failure) {
            auto pending_requests = std::move(_pending_requests);
            _pending_requests.clear();
            for (auto &req: pending_requests) {
                req->set_failure(failure);
                req->resume_waiter();
            }

            auto requests = std::move(_requests);
            _requests.clear();
            for (auto &[_, req]: requests) {
                req->set_failure(failure);
                req->resume_waiter();
            }
        }

        void client_connection_t::_flush() {
            flush_quic_packets(_conn, _path.path, [this](const buffer packet) {
                _runtime.send_to_server(packet);
            });
        }

        void client_connection_t::_drain_requests() {
            while (!_pending_requests.empty()) {
                auto req = _pending_requests.front();
                int64_t stream_id = -1;
                const auto rv = ngtcp2_conn_open_bidi_stream(_conn, &stream_id, nullptr);
                if (rv == NGTCP2_ERR_STREAM_ID_BLOCKED)
                    return;
                _pending_requests.pop_front();

                if (rv != 0) [[unlikely]] {
                    _fail_request(req, std::make_exception_ptr(jamnp::error{
                        fmt::format("ngtcp2_conn_open_bidi_stream failed: {}", ngtcp2_strerror(rv))
                    }));
                    continue;
                }

                const auto [it, inserted] = _requests.emplace(stream_id, req);
                if (!inserted) [[unlikely]] {
                    _fail_request(req, std::make_exception_ptr(jamnp::error{
                        fmt::format("duplicate ngtcp2 client stream id {}", stream_id)
                    }));
                    continue;
                }

                try {
                    write_quic_stream(_conn, _path.path, stream_id, req->payload(), true, [this](const buffer packet) {
                        _runtime.send_to_server(packet);
                    });
                } catch (...) {
                    _requests.erase(it);
                    _fail_request(req, std::current_exception());
                }
            }
        }

        void client_connection_t::_complete_request(const int64_t stream_id) {
            const auto it = _requests.find(stream_id);
            if (it == _requests.end())
                return;
            auto req = std::move(it->second);
            _requests.erase(it);
            req->resume_waiter();
        }

        void client_connection_t::_fail_request(const std::shared_ptr<pending_request_t> &req, const std::exception_ptr failure) {
            req->set_failure(failure);
            req->resume_waiter();
        }
    }

    struct client_t::impl_t {
        impl_t(address_t server_addr, transport_config_t cfg):
            _runtime{std::make_shared<client_runtime_t>(server_addr, std::move(cfg))}
        {
        }

        void submit(const std::shared_ptr<pending_request_t> &req) {
            _runtime->submit(req);
        }
    private:
        std::shared_ptr<client_runtime_t> _runtime;
    };

    struct server_t::impl_t {
        explicit impl_t(transport_config_t cfg):
            _cfg{std::move(cfg)}
        {
        }

        void run(address_t bind_addr, server_peer_handler_t peer_handler, server_stream_handler_t default_handler) {
            server_runtime_t runtime{std::move(bind_addr), _cfg, std::move(peer_handler), std::move(default_handler)};
            runtime.run_forever();
        }
    private:
        transport_config_t _cfg;
    };

    client_t::client_t(address_t server_addr, transport_config_t cfg):
        _impl{std::make_unique<impl_t>(std::move(server_addr), std::move(cfg))}
    {
    }

    client_t::~client_t() = default;
    client_t::client_t(client_t &&) noexcept = default;
    client_t &client_t::operator=(client_t &&) noexcept = default;

    coro::task_t<uint8_vector> client_t::request(const buffer payload) {
        auto req = std::make_shared<pending_request_t>(payload);
        co_await coro::external_task_t{[this, req](auto h) {
            req->set_waiter(h);
            _impl->submit(req);
        }};
        if (req->failure())
            std::rethrow_exception(req->failure());
        co_return req->take_response();
    }

    server_stream_t::server_stream_t(std::unique_ptr<impl_t> impl):
        _impl{std::move(impl)}
    {
        if (!_impl) [[unlikely]]
            throw jamnp::error{"ngtcp2 server stream impl cannot be null!"};
    }

    server_stream_t::~server_stream_t() = default;
    server_stream_t::server_stream_t(server_stream_t &&) noexcept = default;
    server_stream_t &server_stream_t::operator=(server_stream_t &&) noexcept = default;

    coro::task_t<uint8_vector> server_stream_t::read(const size_t sz) {
        return _impl->read(sz);
    }

    coro::task_t<uint8_vector> server_stream_t::read_available() {
        return _impl->read_available();
    }

    coro::task_t<void> server_stream_t::write(const buffer bytes, const bool fin) {
        return _impl->write(bytes, fin);
    }

    uint64_t server_stream_t::id() const noexcept {
        return _impl->id();
    }

    bool server_stream_t::done() const noexcept {
        return _impl->done();
    }

    server_t::server_t(transport_config_t cfg):
        _impl{std::make_unique<impl_t>(std::move(cfg))}
    {
        if (!_impl) [[unlikely]]
            throw jamnp::error{"ngtcp2 server_bootstrap_t impl cannot be null!"};
    }

    server_t::~server_t() = default;
    server_t::server_t(server_t &&) noexcept = default;
    server_t &server_t::operator=(server_t &&) noexcept = default;

    void server_t::run(address_t bind_addr, server_peer_handler_t peer_handler, server_stream_handler_t default_handler) {
        _impl->run(std::move(bind_addr), std::move(peer_handler), std::move(default_handler));
    }
} // namespace turbo::jamnp::transport::ngtcp2
