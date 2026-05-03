/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <optional>

#include "internal/ngtcp2.hpp"
#include "internal/transport.hpp"
#include "server.hpp"

#include "turbo/jam/chain.hpp"

#include <turbo/common/logger.hpp>
#include <turbo/crypto/blake2b.hpp>

namespace turbo::jamnp {
    using namespace std::string_view_literals;
    using transport::transport_error;

    struct server_t::impl_t {
        impl_t(address_t addr, const std::string &cert_prefix, const std::string &spec_path, const std::string &data_path):
            _addr{std::move(addr)},
            _chain{_load_chain(spec_path, data_path)}
        {
            _ngtcp2.emplace(transport::ngtcp2::transport_config_t{
                .protocol_id = _protocol_id,
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
        chain_t<config_tiny> _chain;
        protocol_id_t _protocol_id{_chain.genesis_header().hash()};
        std::optional<transport::ngtcp2::server_bootstrap_t> _ngtcp2{};

        static chain_t<config_tiny> _load_chain(const std::string &spec_path, const std::string &data_path) {
            const auto j_spec = codec::json::load(file::install_path("etc/devnet/dev-spec.json"));
            const auto snap = codec::json::from_json<state_snapshot_t>(j_spec.at("genesis_state"));
            return chain_t<config_tiny>{"dev", data_path, snap};
        }
    };

    server_t::server_t(address_t addr, const std::string &cert_prefix, const std::string &spec_path, const std::string &data_path):
        _impl{std::make_unique<impl_t>(std::move(addr), cert_prefix, spec_path, data_path)}
    {
    }

    server_t::~server_t() = default;

    void server_t::run()
    {
        _impl->run();
    }

    [[nodiscard]] byte_array<32> dev_trivial_seed(const uint32_t i)
    {
        static_assert(std::endian::native == std::endian::little);
        byte_array<32> seed;
        static_assert(sizeof(seed) % sizeof(i) == 0);
        for (size_t j = 0; j < sizeof(seed) / sizeof(i); ++j) {
            memcpy(seed.data() + j * sizeof(i), &i, sizeof(i));
        }
        return seed;
    }

    [[nodiscard]] secure_byte_array<32> dev_secret_seed(const buffer prefix, const buffer input_seed)
    {
        uint8_vector seed{};
        seed.reserve(prefix.size() + input_seed.size());
        seed << prefix << input_seed;
        return crypto::blake2b::digest<secure_byte_array<32>>(seed);
    }

    [[nodiscard]] crypto::ed25519::key_pair_t dev_ed25519(const buffer input_seed)
    {
        const auto secret_seed = dev_secret_seed("jam_val_key_ed25519"sv, input_seed);
        return crypto::ed25519::create_from_seed(secret_seed);
    }
}
