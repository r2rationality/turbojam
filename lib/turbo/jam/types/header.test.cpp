/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2026 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/test.hpp>
#include "header.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jam;

    // Small, distinct limits make the retention boundaries visible in each test.
    struct test_config: config_tiny {
        static constexpr size_t L_max_lookup_anchor_age = 6;
        static constexpr size_t H_max_blocks_history = 1;
    };
    using ancestors_t = ancestry_t<test_config>;
    static_assert(std::ranges::random_access_range<ancestors_t::range_t>);
    static_assert(std::is_const_v<std::remove_reference_t<std::ranges::range_reference_t<ancestors_t>>>);
    static_assert(std::is_nothrow_move_constructible_v<ancestors_t::item_t>);
    static_assert(std::is_nothrow_move_assignable_v<ancestors_t::item_t>);

    header_hash_t hash(const uint8_t id) {
        header_hash_t res{};
        res[0] = id;
        return res;
    }

    void append(ancestors_t &ancestors, const uint32_t slot) {
        ancestors.add(slot, hash(static_cast<uint8_t>(slot)), state_root_t{}, storage::update::undo_list_t{});
    }

    void check(const ancestors_t &ancestors, const std::vector<uint32_t> &slots, const std::vector<uint32_t> &undo_slots={}) {
        std::vector<uint32_t> actual_slots{}, actual_undo_slots{};
        for (const auto &item: ancestors) {
            actual_slots.emplace_back(item.slot.slot());
            if (item.undo)
                actual_undo_slots.push_back(item.slot.slot());
        }
        expect_equal(slots, actual_slots);
        expect_equal(undo_slots, actual_undo_slots);
        expect_equal(slots.size(), ancestors.size());
    }
}

suite turbo_jam_ancestry_suite = [] {
    "turbo::jam::ancestry"_test = [] {
        "basic operations"_test = [] {
            ancestors_t ancestors{};
            expect(ancestors.empty());
            for (uint32_t slot = 1; slot <= 4; ++slot)
                append(ancestors, slot);
            check(ancestors, {1, 2, 3, 4}, {1, 2, 3, 4});
            append(ancestors, 5);
            check(ancestors, {1, 2, 3, 4, 5}, {2, 3, 4, 5});
            append(ancestors, 6);
            append(ancestors, 7); // Wrap and evict only the oldest lookup entry.
            check(ancestors, {2, 3, 4, 5, 6, 7}, {4, 5, 6, 7});
            expect(ancestors.begin()->state_root.has_value());
            expect(ancestors.begin()->header_hash == hash(2));
            expect(throws([&] { (void)ancestors.known(hash(1), {}); }));

            const auto cut = ancestors.known(hash(5), {});
            const ancestors_t::range_t prefix{ancestors.begin(), cut};
            const ancestors_t::range_t suffix{cut, ancestors.end()};
            std::vector<uint32_t> rollback_slots{};
            for (const auto &item: suffix | std::views::reverse)
                rollback_slots.emplace_back(item.slot.slot());
            expect_equal(std::vector<uint32_t>{7, 6}, rollback_slots);
            expect(std::lower_bound(ancestors.begin(), ancestors.end(), 7U,
                [](const auto &item, const uint32_t slot) { return item.slot.slot() < slot; }) == ancestors.end() - 1);
            ancestors.truncate(prefix.size());
            check(ancestors, {2, 3, 4, 5}, {4, 5}); // Expired undo is never restored.
            append(ancestors, 8); // Slot gaps do not consume extra undo entries.
            check(ancestors, {2, 3, 4, 5, 8}, {4, 5, 8});
            const auto prev_sz = ancestors.size();
            ancestors.truncate(prev_sz);
            expect_equal(prev_sz, ancestors.size());
            expect(throws([&] { ancestors.truncate(ancestors.size() + 1); }));
            ancestors.truncate(0);
            expect(ancestors.empty());
            append(ancestors, 9);
            check(ancestors, {9}, {9});
        };

        "parent matching"_test = [] {
            ancestors_t ancestors{};
            state_root_t root{};
            root[0] = 1;
            expect(throws([&] { (void)ancestors.known(hash(1), root); }));
            ancestors.add(hash(1), {}); // Unknown root accepts any root.
            expect(ancestors.known(hash(1), root) == ancestors.end());
            expect(!ancestors.begin()->state_root);
            ancestors.add(hash(2), root);
            expect(ancestors.known(hash(1), {}) == ancestors.begin() + 1);
            expect(ancestors.known(hash(2), root) == ancestors.end());
            expect(throws([&] { (void)ancestors.known(hash(2), {}); }));
            expect(throws([&] { (void)ancestors.known(hash(3), root); }));
            check(ancestors, {0, 0});
        };

        "codec insertion and binary round trip"_test = [] {
            ancestors_t ancestors{};
            for (uint32_t slot = 1; slot <= 6; ++slot)
                ancestors.emplace_back({slot, hash(static_cast<uint8_t>(slot)), {}, storage::update::undo_list_t{}});
            check(ancestors, {1, 2, 3, 4, 5, 6}, {3, 4, 5, 6});
            expect(throws([&] { ancestors.emplace_back({7U, hash(7)}); }));
            append(ancestors, 7);
            const encoder encoded{ancestors};
            ancestors_t decoded{};
            append(decoded, 99); // Decode must replace existing contents.
            decoder dec{encoded.bytes()};
            dec.process(decoded);
            expect(dec.empty());
            expect(decoded == ancestors);
            // Equality covers slots and hashes; runtime metadata is not serialized.
            expect(std::ranges::all_of(decoded, [](const auto &item) { return !item.state_root && !item.undo; }));
            decoded.clear();
            expect(decoded.empty());
            expect(!(decoded == ancestors));
            decoded.emplace_back({2U, hash(99)});
            ancestors.truncate(1);
            expect(!(decoded == ancestors)); // Same slot, different hash.
            encoder oversized{};
            oversized.uint_varlen(7);
            decoder oversized_dec{oversized.bytes()};
            expect(throws([&] { oversized_dec.process(decoded); }));
        };

        "JSON decoding"_test = [] {
            boost::json::array items{};
            for (uint32_t slot: {2U, 3U})
                items.emplace_back(boost::json::object{{"slot", slot}, {"header_hash", std::string(64, '0')}});
            ancestors_t ancestors{};
            append(ancestors, 99); // must be replaced by the decode operation
            codec::json::decoder::decode(items, ancestors);
            check(ancestors, {2, 3});
            expect(ancestors.begin()->header_hash == header_hash_t{});
            expect(!ancestors.begin()->state_root);
            expect(throws([&] { codec::json::decoder::decode(boost::json::array(7, nullptr), ancestors); }));
        };
    };
};
