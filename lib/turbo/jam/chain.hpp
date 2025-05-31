#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/jam/types/s04-overview.hpp>

namespace turbo::jam {
    template<typename CONFIG>
    struct chain_t {
        explicit chain_t(const std::string &spec_path);
        [[nodiscard]] const std::string &id() const { return _id; }
        [[nodiscard]] const header_t<CONFIG> &genesis_header() const { return _genesis_header; }
        [[nodiscard]] const state_t<CONFIG> &state() const { return _state; }
    private:
        std::string _id;
        header_t<CONFIG> _genesis_header;
        state_t<CONFIG> _state {};
    };
}