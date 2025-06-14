#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <functional>
#include <memory>
#include <turbo/common/bytes.hpp>

namespace turbo::storage::filedb {
    using value_t = std::optional<write_vector>;
    using observer_t = std::function<void(uint8_vector, write_vector)>;

    // Designed to support data loading from a json snapshot using the serialize method.
    // For that reason must be default-constructible.
    struct client_t {
        client_t(std::string_view dir_path);
        ~client_t();
        void erase(buffer key);
        void foreach(const observer_t &);
        value_t get(buffer key) const;
        void set(buffer key, buffer val);
    private:
        struct impl;
        std::unique_ptr<impl> _impl;
    };
}
