#include <turbo/common/numeric-cast.hpp>
#include <turbo/common/logger.hpp>
#include <turbo/jam/encoding.hpp>

#include "client.hpp"
#include "internal/ngtcp2.hpp"
#include "internal/transport.hpp"

namespace turbo::jamnp {
    using transport::transport_error;

    template<typename CFG>
    struct client_t<CFG>::impl_t {
        impl_t(address_t server_addr, std::string app_name, std::string alpn_id, const std::string &cert_prefix):
            _server_addr{std::move(server_addr)}
        {
            logger::info("jamnp client requested transport backend: {}", transport::requested_backend_name());
            if (!transport::backend_selectable(_backend)) [[unlikely]]
                throw transport_error{fmt::format(
                    "requested JAMNP transport backend '{}' is not compiled in",
                    transport::backend_name(_backend)
                )};
            _ngtcp2 = std::make_unique<transport::ngtcp2::client_session_t>(_server_addr, transport::ngtcp2::transport_config_t{
                .app_name = std::move(app_name),
                .alpn_id = std::move(alpn_id),
                .private_key_path = cert_prefix + ".key",
                .certificate_path = cert_prefix + ".cert"
            });
            logger::info("jamnp client ngtcp2 session: {}", _ngtcp2->summary());
        }

        [[nodiscard]] coro::task_t<block_list_t> fetch_blocks(const header_hash_t &hh, const uint32_t max_blocks, const direction_t direction)
        {
            const auto response = co_await _ngtcp2->request(_fetch_blocks_request(hh, max_blocks, direction));
            co_return _decode_blocks_response(response);
        }

        [[nodiscard]] coro::task_t<state_resp_t> fetch_state(const header_hash_t &hh, const merkle::trie::key_t &key_start, const merkle::trie::key_t &key_end, const uint32_t max_size)
        {
            const auto response = co_await _ngtcp2->request(_fetch_state_request(hh, key_start, key_end, max_size));
            co_return _decode_state_response(response);
        }
    private:
        static uint8_vector _fetch_blocks_request(const header_hash_t &hh, const uint32_t max_blocks, const direction_t direction)
        {
            logger::debug("making a block request: start hash: {} max_blocks: {} direction: {}", hh, max_blocks, static_cast<uint8_t>(direction));
            uint8_vector body {};
            body.reserve(sizeof(hh) + 1 + sizeof(max_blocks));
            body << hh;
            body << static_cast<uint8_t>(direction);
            body << buffer::from(max_blocks);

            encoder enc {};
            enc.uint_fixed(1, 128U);
            enc.uint_fixed(4, body.size());
            enc.next_bytes(body);
            return enc.bytes();
        }

        static uint8_vector _fetch_state_request(const header_hash_t &hh, const merkle::trie::key_t &key_start, const merkle::trie::key_t &key_end, const uint32_t max_size)
        {
            encoder enc {};
            enc.uint_fixed(1, 129U);
            enc.uint_fixed(4, 0);
            enc.next_bytes(hh);
            enc.next_bytes(key_start);
            enc.next_bytes(key_end);
            enc.uint_fixed(4, max_size);
            const auto msg_len = numeric_cast<uint32_t>(enc.bytes().size() - 5U);
            encoder::uint_fixed(std::span { enc.bytes().data() + 1, 4 }, 4, msg_len);
            return enc.bytes();
        }

        static block_list_t _decode_blocks_response(const buffer response)
        {
            decoder dec { response };
            const auto msg_len = dec.uint_fixed<size_t>(4U);
            if (dec.size() != msg_len) [[unlikely]]
                throw transport_error{fmt::format(
                    "fetch_blocks: invalid response size: expected {} body bytes but received {}",
                    msg_len,
                    dec.size()
                )};

            block_list_t blocks {};
            while (!dec.empty()) {
                blocks.emplace_back(codec::from<block_t<CFG>>(dec));
            }
            return blocks;
        }

        static state_resp_t _decode_state_response(const buffer response)
        {
            decoder dec { response };
            const auto msg_len = dec.uint_fixed<size_t>(4U);
            if (dec.size() != msg_len) [[unlikely]]
                throw transport_error{fmt::format(
                    "fetch_state: invalid response size: expected {} body bytes but received {}",
                    msg_len,
                    dec.size()
                )};

            state_resp_t result {};
            dec.process(result);
            return result;
        }

        address_t _server_addr;
        transport::backend_kind_t _backend = transport::requested_backend();
        std::unique_ptr<transport::ngtcp2::client_session_t> _ngtcp2;
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
