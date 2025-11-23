#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <memory>
#include <turbo/common/error.hpp>

namespace turbo::jam {
    template<typename T>
    struct mutable_value_t {
        using element_type = T;
        using ptr_type = std::shared_ptr<element_type>;

        explicit mutable_value_t(ptr_type ptr):
            _ptr{std::move(ptr)}
        {
            if (!_ptr) [[unlikely]]
                throw error(fmt::format("mutable_value_t<{}> cannot be empty!", typeid(element_type).name()));
        }

        explicit mutable_value_t(const element_type &val):
            mutable_value_t{std::make_shared<element_type>(val)}
        {
        }

        [[nodiscard]] const element_type &get() const
        {
            return *_ptr;
        }

        [[nodiscard]] element_type &get_mutable()
        {
            if (!_updated) {
                _ptr = std::make_shared<element_type>(*_ptr);
                _updated = true;
            }
            return *_ptr;
        }

        const element_type *operator->() const
        {
            return &get();
        }

        void set(ptr_type new_val)
        {
            _ptr = std::move(new_val);
            _updated = true;
        }

        void commit(ptr_type &dst)
        {
            dst = _ptr;
            _updated = false;
        }

        [[nodiscard]] bool updated() const
        {
            return _updated;
        }

        bool operator==(const mutable_value_t &o) const = delete;
    private:
        ptr_type _ptr;
        bool _updated = false;
    };
}
