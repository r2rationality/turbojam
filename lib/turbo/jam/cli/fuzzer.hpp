#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/jam/fuzzer.hpp>

#ifdef _MSC_VER
#   include <SDKDDKVer.h>
#endif
#include <boost/asio/buffer.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/local/stream_protocol.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>

namespace turbo::cli::fuzzer {
    using namespace turbo::jam;
    using namespace turbo::jam::fuzzer;
    using boost::asio::local::stream_protocol;

    template<typename CFG>
    static boost::asio::awaitable<message_t<CFG>> read_message(stream_protocol::socket &conn)
    {
        uint32_t msg_len = 0;
        uint8_vector msg_buf {};
        co_await boost::asio::async_read(conn, boost::asio::buffer(&msg_len, sizeof(msg_len)), boost::asio::use_awaitable);
        co_await boost::asio::async_read(conn, boost::asio::buffer(msg_buf.data(), msg_buf.size()), boost::asio::use_awaitable);
        decoder dec { msg_buf };
        co_return codec::from<message_t<CFG>>(dec);
    }

    template<typename CFG>
    static boost::asio::awaitable<void> write_message(stream_protocol::socket &conn, message_t<CFG> msg)
    {
        const encoder enc { msg };
        const uint32_t msg_len = enc.bytes().size();
        co_await boost::asio::async_write(conn, boost::asio::buffer(&msg_len, sizeof(msg_len)), boost::asio::use_awaitable);
        co_await boost::asio::async_write(conn, boost::asio::buffer(enc.bytes()), boost::asio::use_awaitable);
    }
}
