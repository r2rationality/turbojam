#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include "file.hpp"

namespace turbo::storage::memory {
    // Designed to support data loading from a json snapshot using the serialize method.
    // For that reason must be default-constructible.
    struct db_t: storage::db_t {
        explicit db_t();
        ~db_t() override;
        void clear() override;
        void erase(buffer key) override;
        void foreach(const observer_t &) const override;
        value_t get(buffer key) const override;
        void set(buffer key, buffer val) override;
        [[nodiscard]] size_t size() const override;
        void commit();
    private:
        struct impl;
        std::unique_ptr<impl> _impl;
    };
}
