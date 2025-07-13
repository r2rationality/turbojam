/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <future>

#include <turbo/common/cli.hpp>
#include <turbo/common/logger.hpp>
#include <turbo/crypto/ed25519.hpp>
#include <turbo/jamnp/client.hpp>
#include <turbo/jamnp/cert.hpp>

namespace {
    using namespace turbo;
    using namespace turbo::jam;
}

namespace turbo::cli::jamnp_fetch_blocks {
    struct cmd: command {
        void configure(config &cmd) const override
        {
            cmd.name = "jamnp-fetch-blocks";
            cmd.desc = "Execute a CE128, fetch blocks, request";
            cmd.opts.try_emplace("host", "an IPv6 address of a JAMNP server", "::1");
            cmd.opts.try_emplace("port", "a UDP port at which the target JAMNP server listens", "40000");
        }

        void run(const arguments &args, const options &opts) const override
        {
            const file::tmp_directory tmp_dir { "tj" };
            const auto cert_prefix = (static_cast<std::filesystem::path>(tmp_dir) / "client").string();
            {
                const auto key_pair = crypto::ed25519::create_from_seed(crypto::ed25519::seed_t::from_hex("0000000000000000000000000000000000000000000000000000000000000000"));
                jamnp::write_cert(cert_prefix + ".cert", cert_prefix + ".key", key_pair);
            }
            jamnp::address_t server_addr {
                opts.at("host").value(),
                from_str<uint16_t>(opts.at("port").value().c_str())
            };
            logger::info("connecting to {}", server_addr);
            jamnp::client_t<config_tiny> client { server_addr, "turbojam", "jamnp-s/0/b5af8eda", cert_prefix };
            logger::info("created a client instance");
            logger::info("fetch-blocks: {}", client.fetch_blocks({}, 10).wait());
        }
    };
    static auto instance = command::reg(std::make_shared<cmd>());
}
