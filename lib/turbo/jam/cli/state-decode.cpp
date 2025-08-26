/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/cli.hpp>
#include <turbo/jam/state.hpp>

namespace turbo::cli::state_decode {
    struct cmd: command {
        void configure(config &cmd) const override
        {
            cmd.name = "state-decode";
            cmd.desc = "Decode a JAM state value described by a pair of hex-encoded strings <key> and <value>";
            cmd.args.expect({"<key>", "<val>", "[<val> ...]"});
        }

        void run(const arguments &args) const override
        {
            using namespace turbo::jam;
            const auto key = uint8_vector::from_hex(args.at(0));
            for (const auto &val: args | std::views::drop(1)) {
                logger::info("{}", state_t<config_tiny>::decode_val(key, uint8_vector::from_hex(val)));
            }
        }
    };
    static auto instance = command::reg(std::make_shared<cmd>());
}
