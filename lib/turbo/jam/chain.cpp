/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include "chain.hpp"

namespace turbo::jam {
    template<typename CONFIG>
    chain_t<CONFIG>::chain_t(const std::string &spec_path)
    {
        const auto j_cfg = codec::json::load(file::install_path("etc/devnet/dev-spec.json"));

        _id = boost::json::value_to<std::string_view>(j_cfg.at("id"));

        const auto genesis_header_raw = uint8_vector::from_hex(boost::json::value_to<std::string_view>(j_cfg.at("genesis_header")));
        decoder dec { genesis_header_raw };
        dec.process(_genesis_header);

        _state = j_cfg.at("genesis_state").as_object();
    }

    template struct chain_t<config_prod>;
    template struct chain_t<config_tiny>;
}