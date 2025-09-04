#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <functional>
#include <memory>
#include <turbo/common/bytes.hpp>

namespace turbo::storage {
    using value_t = std::optional<uint8_vector>;
    using observer_t = std::function<void(uint8_vector, uint8_vector)>;

    struct db_t {
        virtual ~db_t() = default;
        virtual void clear() = 0;
        virtual void erase(buffer key) = 0;
        virtual void foreach(const observer_t &) const = 0;
        [[nodiscard]] virtual value_t get(buffer key) const = 0;
        virtual void set(buffer key, buffer val) = 0;
        [[nodiscard]] virtual size_t size() const = 0;

        [[nodiscard]] bool empty() const
        {
            return size() == 0;
        }

        [[nodiscard]] bool operator==(const db_t &o) const
        {
            if (size() != o.size())
                return false;
            size_t num_mismatches = 0;
            foreach([&](const auto &k, const auto &v) {
                const auto ov = o.get(k);
                if (v != ov)
                    ++num_mismatches;
            });
            return num_mismatches == 0;
        }
    };
    using db_ptr_t = std::shared_ptr<db_t>;
}
