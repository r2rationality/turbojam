#include <turbo/common/logger.hpp>
#include <turbo/jam/encoding.hpp>
#include "internal/ngtcp2.hpp"
#include "client.hpp"

namespace turbo::jamnp {
    template<typename CFG>
    struct client_t<CFG>::impl_t {
        impl_t(address_t server_addr, std::string app_name, std::string alpn_id, cert_pair_t cert):
            _app_name{std::move(app_name)}
        {
            _ngtcp2 = std::make_unique<transport::ngtcp2::client_t>(std::move(server_addr), transport::ngtcp2::transport_config_t{
                .protocol_id = protocol_id_t::from_text(alpn_id),
                .certificate = std::move(cert)
            });
            logger::info("jamnp client '{}' ngtcp2 session with ALPN {}", _app_name, alpn_id);
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
            return _request_message(128U, body);
        }

        static uint8_vector _fetch_state_request(const header_hash_t &hh, const merkle::trie::key_t &key_start, const merkle::trie::key_t &key_end, const uint32_t max_size)
        {
            uint8_vector body {};
            body << hh;
            body << key_start;
            body << key_end;
            body << buffer::from(max_size);
            return _request_message(129U, body);
        }

        static block_list_t _decode_blocks_response(const buffer response)
        {
            decoder dec{_checked_response_body(response, "fetch_blocks")};
            block_list_t blocks{};
            while (!dec.empty()) {
                blocks.emplace_back(codec::from<block_t<CFG>>(dec));
            }
            return blocks;
        }

        static state_resp_t _decode_state_response(const buffer response)
        {
            decoder dec { _checked_response_body(response, "fetch_state") };

            state_resp_t result {};
            dec.process(result);
            return result;
        }

        static uint8_vector _request_message(const uint8_t kind, const buffer body)
        {
            encoder enc {};
            enc.uint_fixed(1, kind);
            enc.uint_fixed(4, body.size());
            enc.next_bytes(body);
            return enc.bytes();
        }

        static buffer _checked_response_body(const buffer response, const char *context)
        {
            decoder dec{response};
            const auto msg_len = dec.uint_fixed<size_t>(4U);
            return dec.next_bytes(msg_len);
        }

        std::string _app_name;
        std::unique_ptr<transport::ngtcp2::client_t> _ngtcp2;
    };

    template<typename CFG>
    client_t<CFG>::client_t(address_t server_addr, const std::string &app_name, const std::string &alpn_id, cert_pair_t cert):
        _impl { std::make_unique<impl_t>(std::move(server_addr), std::move(app_name), std::move(alpn_id), std::move(cert)) }
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
