/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <optional>

#include "internal/ngtcp2.hpp"
#include "internal/transport.hpp"
#include "server.hpp"
#include <turbo/common/logger.hpp>
#include <turbo/crypto/blake2b.hpp>

namespace turbo::jamnp {
    using namespace std::string_view_literals;
    using transport::transport_error;

    struct server_t::impl_t {
        impl_t(address_t addr, std::string app_name, std::string alpn_id, const std::string &cert_prefix):
            _addr{std::move(addr)}
        {
            logger::info("jamnp server requested transport backend: {}", transport::requested_backend_name());
            if (!transport::backend_selectable(_backend)) [[unlikely]]
                throw transport_error{fmt::format(
                    "requested JAMNP transport backend '{}' is not compiled in",
                    transport::backend_name(_backend)
                )};
            _ngtcp2.emplace(transport::ngtcp2::transport_config_t{
                .app_name = std::move(app_name),
                .alpn_id = std::move(alpn_id),
                .private_key_path = cert_prefix + ".key",
                .certificate_path = cert_prefix + ".cert"
            });
            logger::info("jamnp server ngtcp2 bootstrap: {}", _ngtcp2->summary());
        }

        void run()
        {
            logger::info("jamnp server target bind host: {}:{}", transport::bind_host(_addr), _addr.port);
            throw transport_error{
                "JAMNP server transport has been switched to ngtcp2 only, but the listener/packet loop is not implemented yet"
            };
        }
    private:
        address_t _addr;
        transport::backend_kind_t _backend = transport::requested_backend();
        std::optional<transport::ngtcp2::server_bootstrap_t> _ngtcp2 {};
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
