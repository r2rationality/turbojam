/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/logger.hpp>
#include <turbo/crypto/blake2b.hpp>
#include <turbo/jam/chain.hpp>
#include "internal/ngtcp2.hpp"
#include "server.hpp"

namespace turbo::jamnp {
    using namespace std::string_view_literals;

    template<typename CFG>
    template<typename ICFG>
    struct server_t<CFG>::impl_t {
        explicit impl_t(address_t addr, cert_pair_t cert, const std::string &spec_path, const std::string &data_path):
            _addr{std::move(addr)},
            _chain{_load_chain(spec_path, data_path)},
            _ngtcp2{transport::ngtcp2::transport_config_t{
                .protocol_id = _protocol_id,
                .certificate = std::move(cert)
            }}
        {
            logger::info("jamnp server ngtcp2 bootstrap");
        }

        void run()
        {
            logger::info("jamnp server target bind host: {}:{}", _addr, _addr.port);
            _ngtcp2.run(_addr, [this](const uint8_t first_byte, transport::ngtcp2::server_stream_t stream) -> coro::task_t<void> {
                co_await _handle_stream(first_byte, std::move(stream));
            });
        }
    private:
        address_t _addr;
        chain_t<ICFG> _chain;
        protocol_id_t _protocol_id{_chain.genesis_header().hash()};
        transport::ngtcp2::server_t _ngtcp2;

        template<typename T>
        static bool _try_decode(T &val, uint8_vector &data) {
            try {
                decoder dec{data};
                val = jam::from<T>(dec);
                data.erase(data.begin(), data.begin() + dec.consumed());
                return true;
            } catch (...) {
                return false;
            }
        }

        coro::task_t<void> _handle_block_announcement(transport::ngtcp2::server_stream_t stream)
        {
            logger::info("jamnp stream {}: server received block announcement", stream.id());
            uint8_vector data{};
            handshake_t handshake{};
            while (!_try_decode(handshake, data)) {
                if (stream.done())
                    throw error{fmt::format("jamnp stream {} ended before the handshake was complete", stream.id())};
                data << co_await stream.read_available();
            }
            logger::info("jamnp stream {}: handshake: {}", stream.id(), handshake);
            for (;;) {
                for (;;) {
                    block_announcement_t<ICFG> announcement{};
                    if (!_try_decode(announcement, data))
                        break;
                    logger::info("jamnp stream {}: announcement header: {} final: {}", stream.id(), announcement.header.hash(), announcement.final);
                }
                if (stream.done())
                    break;
                data << co_await stream.read_available();
                logger::trace("jamnp stream {}: pending announcement data size: {}", stream.id(), data.size());
            }
            logger::info("jamnp stream {}: server received block announcement completed", stream.id());
        }

        [[nodiscard]] coro::task_t<void> _handle_stream(const uint8_t first_byte, transport::ngtcp2::server_stream_t stream)
        {
            logger::info("jamnp server accepted stream {} with first byte {}", stream.id(), first_byte);
            switch (first_byte) {
            case 0:
                co_await _handle_block_announcement(std::move(stream));
                break;
            default:
                break;
            }
            co_return;
        }

        static chain_t<ICFG> _load_chain(const std::string &spec_path, const std::string &data_path) {
            (void) spec_path;
            const auto snap = local_genesis_state();
            return chain_t<ICFG>{"dev", data_path, snap};
        }
    };

    template<typename CFG>
    server_t<CFG>::server_t(address_t addr, cert_pair_t cert, const std::string &spec_path, const std::string &data_path):
        _impl{std::make_unique<impl_t<CFG>>(std::move(addr), std::move(cert), spec_path, data_path)}
    {
    }

    template<typename CFG>
    server_t<CFG>::~server_t() = default;

    template<typename CFG>
    void server_t<CFG>::run()
    {
        _impl->run();
    }

    template struct server_t<config_tiny>;

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
