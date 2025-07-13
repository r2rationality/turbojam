/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <filesystem>
#include <future>

#include <turbo/common/cli.hpp>
#include <turbo/common/file.hpp>
#include <turbo/common/logger.hpp>
#include <turbo/crypto/ed25519.hpp>
#include <turbo/jamnp/client.hpp>
#include <turbo/jamnp/cert.hpp>
#include <turbo/jamnp/server.hpp>

namespace {
    using namespace std::string_view_literals;
    using namespace turbo;
    using namespace turbo::jamnp;
}

namespace turbo::cli::jamnp_server {
    struct cmd: command {
        void configure(config &cmd) const override
        {
            cmd.name = "jamnp-server";
            cmd.desc = "Start a JAMNP server";
            cmd.opts.try_emplace("dev-validator", "Configure this node as the dev chain validator with the given index.", "0");
            cmd.opts.try_emplace("data-path", "Base data path; use a temporary path by default");
        }

        void run(const arguments &args, const options &opts) const override
        {
            std::optional<file::tmp_directory> tmp_dir {};
            std::optional<std::filesystem::path> data_path {};
            if (const auto opt_it = opts.find("data-path"); opt_it != opts.end() && opt_it->second) {
                data_path.emplace(*opt_it->second);
            } else {
                tmp_dir.emplace("tjam-jamnp-server");
                data_path.emplace(static_cast<std::filesystem::path>(*tmp_dir));
            }
            const auto dev_val_idx = from_str<uint32_t>(opts.at("dev-validator").value().c_str());
            const auto cert_prefix = (*data_path / "client").string();
            {
                const auto key_pair = dev_ed25519(dev_trivial_seed(dev_val_idx));
                write_cert(cert_prefix + ".cert", cert_prefix + ".key", key_pair);
            }
            address_t server_addr {
                "::1",
                numeric_cast<uint16_t>(40000U + dev_val_idx)
            };
            logger::info("dev validator index {}", dev_val_idx);
            logger::info("starting a server listening at {}", server_addr);
        }
    };
    static auto instance = command::reg(std::make_shared<cmd>());
}
