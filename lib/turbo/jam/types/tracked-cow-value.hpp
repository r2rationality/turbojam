#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025-2026 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <memory>
#include <thread>
#include <utility>
#include <turbo/common/error.hpp>

namespace turbo::jam {
    template<typename T>
    struct tracked_cow_value_t {
        using element_type = T;
        using ptr_type = std::shared_ptr<element_type>;

        tracked_cow_value_t(tracked_cow_value_t &&) noexcept = default;
        tracked_cow_value_t &operator=(tracked_cow_value_t &&) noexcept = default;

        tracked_cow_value_t(const tracked_cow_value_t &o):
            _base{o._base},
            _coordinator_thread{o._coordinator_thread}
        {
            if (o._update)
                _update = std::make_shared<element_type>(*o._update);
        }

        tracked_cow_value_t &operator=(const tracked_cow_value_t &o)
        {
            if (this != &o)
                *this = tracked_cow_value_t{o};
            return *this;
        }

        explicit tracked_cow_value_t(const element_type &val):
            _base{std::make_shared<const element_type>(val)},
            _coordinator_thread{std::this_thread::get_id()}
        {
        }

        explicit tracked_cow_value_t(element_type &&val):
            _base{std::make_shared<const element_type>(std::move(val))},
            _coordinator_thread{std::this_thread::get_id()}
        {
        }

        [[nodiscard]] tracked_cow_value_t fork() const
        {
            _require_coordinator_thread();
            return tracked_cow_value_t{
                _update ? std::make_shared<const element_type>(*_update) : _base,
                _coordinator_thread
            };
        }

        [[nodiscard]] const element_type &get() const noexcept
        {
            return _update ? *_update : *_base;
        }

        [[nodiscard]] element_type &update()
        {
            if (!_update)
                _update = std::make_shared<element_type>(*_base);
            return *_update;
        }

        void set(element_type &&new_val)
        {
            _update = std::make_shared<element_type>(std::move(new_val));
        }

        [[nodiscard]] ptr_type consume()
        {
            _require_coordinator_thread();
            return std::exchange(_update, {});
        }

        [[nodiscard]] bool updated() const noexcept
        {
            return static_cast<bool>(_update);
        }
    private:
        tracked_cow_value_t(std::shared_ptr<const element_type> base, const std::thread::id coordinator_thread) noexcept:
            _base{std::move(base)},
            _coordinator_thread{coordinator_thread}
        {
        }

        void _require_coordinator_thread() const
        {
            if (std::this_thread::get_id() != _coordinator_thread) [[unlikely]]
                throw error("tracked_cow_value_t fork and consume must use the coordinator thread");
        }

        std::shared_ptr<const element_type> _base;
        ptr_type _update{};
        std::thread::id _coordinator_thread;
    };
}
