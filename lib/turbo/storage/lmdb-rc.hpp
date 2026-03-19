#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/file.hpp>
#include "common.hpp"

namespace turbo::storage::lmdb_rc {
    struct error: turbo::error {
        using turbo::error::error;
    };

    struct map_info_t {
        size_t map_size;   // total virtual address space reserved for the environment
        size_t used_size;  // bytes consumed by committed + pending dirty pages
    };

    struct db_t: storage::db_t {
        explicit db_t(std::string_view dir_path, size_t initial_mapsize = 1ULL << 30U);
        ~db_t() override;
        void clear() override;
        void erase(buffer key) override;
        void foreach(const observer_t &obs) const override;
        value_t get(buffer key) const override;
        void set(buffer key, buffer val) override;
        [[nodiscard]] size_t size() const override;
        [[nodiscard]] map_info_t map_info() const;
        void commit();
        void rollback();
    private:
        struct impl;
        std::unique_ptr<impl> _impl;
    };
    using db_ptr_t = std::shared_ptr<db_t>;
}
