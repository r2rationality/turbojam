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

suite turbo_jam_devnet_suite = [] {
    "turbo::jam::devnet"_test = [] {
        try {
            const auto j_cfg = codec::json::load(file::install_path("etc/devnet/dev-spec.json"));
            const auto genesis_header_bytes = uint8_vector::from_hex(boost::json::value_to<std::string_view>(j_cfg.at("genesis_header")));
            decoder dec { genesis_header_bytes };
            const auto genesis_header = codec::from<header_t<config_tiny>>(dec);
            expect(true);

            const auto &genesis_state = j_cfg.at("genesis_state").as_object();
            state_dict_t state_dict {};
            for (const auto &[k, v]: genesis_state) {
                state_dict.emplace(state_key_t::from_hex(k), byte_sequence_t::from_hex(v.as_string()));
            }
            const auto genesis_root = state_dict.root();
            expect_equal(state_root_t::from_hex("DB29024A82CA5F628A2DABE26B896DAA7C8AF44D6752CD31528589E68ECC84C9"), genesis_root);
        } catch (const std::exception &ex) {
            expect(false) << ex.what();
        } catch (...) {
            expect(false) << "Unknown exception";
        }
    };
};
