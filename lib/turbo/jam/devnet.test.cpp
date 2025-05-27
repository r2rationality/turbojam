/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <boost/json.hpp>
#include <turbo/common/file.hpp>
#include <turbo/common/test.hpp>
#include "types.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jam;
}

suite turbo_devnet_suite = [] {
    "turbo::devnet"_test = [] {
        try {
            const auto j_cfg = codec::json::load(file::install_path("etc/devnet/dev-spec.json"));
            const auto genesis_header_bytes = uint8_vector::from_hex(boost::json::value_to<std::string_view>(j_cfg.at("genesis_header")));
            decoder dec { genesis_header_bytes };
            const auto genesis_header = codec::from<header_t<config_tiny>>(dec);
            expect(true);
        } catch (const std::exception &ex) {
            expect(false) << ex.what();
        } catch (...) {
            expect(false) << "Unknown exception";
        }
    };
};
