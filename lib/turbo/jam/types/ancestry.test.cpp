/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2026 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include "ancestry.hpp"
#include <turbo/common/test.hpp>

namespace {
    using namespace turbo;
    using namespace turbo::jam;

    struct config_test: config_tiny {
        static constexpr size_t L_max_lookup_anchor_age = 6;
        static constexpr size_t H_max_blocks_history = 1;
    };

    header_hash_t hash(const uint8_t id) {
        header_hash_t res{};
        res[0] = id;
        return res;
    }

    struct test_ancestors_t: ancestry_t<config_test> {
        void append(const uint32_t slot) {
            add(slot, hash(static_cast<uint8_t>(slot)), state_root_t{}, storage::update::undo_list_t{});
        }

        void check(const std::vector<uint32_t> &slots, const std::vector<uint32_t> &undo_slots={},
                   const std::source_location &loc=std::source_location::current()) const {
            std::vector<uint32_t> actual_slots{}, actual_undo_slots{};
            for (const auto &item: *this) {
                actual_slots.emplace_back(item.slot.slot());
                if (item.undo)
                    actual_undo_slots.push_back(item.slot.slot());
            }
            expect_equal(slots, actual_slots, loc);
            expect_equal(undo_slots, actual_undo_slots, loc);
            expect_equal(slots.size(), size(), loc);
        }
    };

    static_assert(std::ranges::random_access_range<test_ancestors_t::range_t>);
    static_assert(std::is_const_v<std::remove_reference_t<std::ranges::range_reference_t<test_ancestors_t>>>);
    static_assert(std::is_nothrow_move_constructible_v<test_ancestors_t::item_t>);
    static_assert(std::is_nothrow_move_assignable_v<test_ancestors_t::item_t>);
}

suite turbo_jam_ancestry_suite = [] {
    "turbo::jam::ancestry"_test = [] {
        "basic operations"_test = [] {
            test_ancestors_t ancestors{};
            expect(ancestors.empty());
            for (uint32_t slot = 1; slot <= 4; ++slot)
                ancestors.append(slot);
            ancestors.check({1, 2, 3, 4}, {1, 2, 3, 4});
            ancestors.append(5);
            ancestors.check({1, 2, 3, 4, 5}, {2, 3, 4, 5});
            ancestors.append(6);
            expect(throws([&] { ancestors.add(6U, hash(6)); }));
            ancestors.append(7); // Wrap and evict only the oldest lookup entry.
            ancestors.check({2, 3, 4, 5, 6, 7}, {4, 5, 6, 7});
            expect(ancestors.begin()->state_root.has_value());
            expect(ancestors.begin()->header_hash == hash(2));
            expect(throws<err_unknown_parent_t>([&] { (void)ancestors.known(hash(1), {}); }));

            const auto cut = ancestors.known(hash(5), {});
            const test_ancestors_t::range_t prefix{ancestors.begin(), cut};
            const test_ancestors_t::range_t suffix{cut, ancestors.end()};
            std::vector<uint32_t> rollback_slots{};
            for (const auto &item: suffix | std::views::reverse)
                rollback_slots.emplace_back(item.slot.slot());
            expect_equal(std::vector<uint32_t>{7, 6}, rollback_slots);
            ancestors.truncate(prefix.size());
            ancestors.check({2, 3, 4, 5}, {4, 5}); // Expired undo is never restored.
            ancestors.append(8); // Slot gaps do not consume extra undo entries.
            ancestors.check({2, 3, 4, 5, 8}, {4, 5, 8});
            const auto prev_sz = ancestors.size();
            ancestors.truncate(prev_sz);
            expect_equal(prev_sz, ancestors.size());
            expect(throws([&] { ancestors.truncate(ancestors.size() + 1); }));
            ancestors.truncate(0);
            expect(ancestors.empty());
            ancestors.append(9);
            ancestors.check({9}, {9});
            test_ancestors_t other{};
            other.add(9, hash(99), state_root_t{});
            expect(!(ancestors == other));
            ancestors.clear();
            expect(ancestors.empty());
            expect(!(ancestors == other));
        };

        "parent matching"_test = [] {
            test_ancestors_t ancestors{};
            state_root_t root{};
            root[0] = 1;
            expect(throws<err_unknown_parent_t>([&] { (void)ancestors.known(hash(1), root); }));
            ancestors.add(1, hash(1), std::nullopt); // Unknown root accepts any root.
            expect(ancestors.known(hash(1), root) == ancestors.end());
            expect(!ancestors.begin()->state_root);
            ancestors.add(2, hash(2), root);
            expect(ancestors.known(hash(1), {}) == ancestors.begin() + 1);
            expect(ancestors.known(hash(2), root) == ancestors.end());
            expect(throws<err_bad_state_root_t>([&] { (void)ancestors.known(hash(2), {}); }));
            expect(throws<err_unknown_parent_t>([&] { (void)ancestors.known(hash(3), root); }));
            ancestors.add(3, hash(3), state_root_t{}); // Zero is a known root, not an unknown-root marker.
            expect(ancestors.known(hash(3), {}) == ancestors.end());
            expect(ancestors.view().back().state_root.has_value());
            expect(throws<err_bad_state_root_t>([&] { (void)ancestors.known(hash(3), root); }));
            ancestors.check({1, 2, 3});
        };

        "binary round trip"_test = [] {
            test_ancestors_t ancestors{};
            for (uint32_t slot = 1; slot <= 6; ++slot)
                ancestors.add(slot, hash(static_cast<uint8_t>(slot)), hash(static_cast<uint8_t>(slot + 16)));
            ancestors.add(7, hash(7), std::nullopt,
                storage::update::undo_list_t{ {uint8_vector{1}, std::nullopt}, {uint8_vector{2}, uint8_vector{3, 4}}}
            );
            for (const bool checks_enabled: {false, true}) {
                ancestors.checks_enabled(checks_enabled);
                const auto decoded = from_bytes<test_ancestors_t>(to_bytes(ancestors));
                expect(decoded == ancestors);
                expect_equal(checks_enabled, decoded.checks_enabled());
                expect(std::ranges::equal(decoded, ancestors, [](const auto &actual, const auto &expected) { return actual.undo == expected.undo; }));
            }
        };
    };
};
