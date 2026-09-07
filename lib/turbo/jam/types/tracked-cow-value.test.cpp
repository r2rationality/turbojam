/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025-2026 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <memory>
#include <thread>
#include <type_traits>
#include <utility>
#include <turbo/common/test.hpp>
#include "tracked-cow-value.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jam;

    using value_t = tracked_cow_value_t<int>;
    static_assert(std::is_nothrow_move_constructible_v<value_t>);
    static_assert(std::is_nothrow_move_assignable_v<value_t>);
    static_assert(!std::is_constructible_v<value_t, value_t::ptr_type>);
    static_assert(!std::is_constructible_v<value_t, std::shared_ptr<const int>>);
}

suite turbo_jam_tracked_cow_value_suite = [] {
    "turbo::jam::tracked_cow_value"_test = [] {
        "copy_fork_and_move"_test = [] {
            const int base = 1;
            value_t value{base};
            auto copy = value;
            auto branch = value.fork();
            expect_equal(base, value.get());
            expect(&value.get() == &copy.get());
            expect(&value.get() == &branch.get());
            expect(!copy.updated() && !branch.updated());

            auto &update = value.update();
            update = 2;
            copy = value;
            branch = value.fork();
            expect(copy.updated() && !branch.updated());
            update = 3;
            expect_equal(2, copy.get());
            expect_equal(2, branch.get());

            value = std::as_const(value);
            expect(&value.update() == &update);
            auto moved = std::move(value);
            expect(moved.updated());
            expect_equal(3, moved.get());
            copy = branch;
            expect(!copy.updated());
            expect_equal(2, copy.get());
        };

        "update_set_and_consume"_test = [] {
            value_t value{1};
            expect(!value.consume());
            value.set(2);
            expect(value.updated());
            auto &update = value.update();
            expect(value.updated());
            auto consumed = value.consume();
            expect(consumed.get() == &update);
            expect_equal(1L, consumed.use_count());
            expect(consumed && *consumed == 2);
            expect(!value.updated());
            expect_equal(1, value.get());
            expect(!value.consume());

            expect_equal(1, value.update());
            value.set(3);
            expect_equal(3, value.get());
            const auto next = value.consume();
            expect(next && *next == 3);
            expect(consumed && *consumed == 2);
        };

        "thread_boundaries"_test = [] {
            value_t value{1};
            auto branch = value.fork();
            bool fork_rejected = false;
            bool consume_rejected = false;
            std::jthread worker{[&] {
                branch.update() += 1;
                branch.update() += 1; // repeated calls use the same storage
                fork_rejected = throws<error>([&] { (void)branch.fork(); });
                consume_rejected = throws<error>([&] { (void)branch.consume(); });
            }};
            value.update() = 4;
            worker.join();
            expect(fork_rejected);
            expect(consume_rejected);
            expect_equal(3, branch.get());
            expect_equal(4, value.get());
            expect(static_cast<bool>(branch.consume()));
        };
    };
};
