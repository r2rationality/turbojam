#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <memory>
#include <turbo/common/bytes.hpp>

namespace turbo::storage::filedb {
    using value_t = std::optional<write_vector>;

    struct client_t {
        client_t(std::string_view dir_path);
        ~client_t();
        void erase(buffer key);
        void set(buffer key, buffer val);
        value_t get(buffer key) const;
    private:
        struct impl;
        std::unique_ptr<impl> _impl;
    };
}
