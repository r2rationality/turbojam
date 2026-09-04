/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025-2026 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/test.hpp>
#include "state.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jam;
    using namespace turbo::storage;

    using slot_t = time_slot_t<config_prod>;
    using pv_t = persistent_value_t<slot_t>;

    db_ptr_t make_db()
    {
        return std::make_shared<memory::db_t>();
    }

    db_ptr_t make_db_with(const uint8_t code, const slot_t &val)
    {
        auto db = make_db();
        db->set(state_dict_t::make_key(code), encoder{val}.bytes());
        return db;
    }
}

suite turbo_jam_state_suite = [] {
    "turbo::jam::persistent_value"_test = [] {
        "null_db_throws"_test = [] {
            expect(throws([] { pv_t{nullptr, 1U}; }));
        };
        "missing_key_throws"_test = [] {
            pv_t pv{make_db(), 1U};
            expect(throws([&] { (void)pv.unmodified(); }));
        };
        "lazy_load"_test = [] {
            const slot_t exp{42U};
            pv_t pv{make_db_with(1U, exp), 1U};
            expect_equal(exp, pv.unmodified());
            expect_equal(exp, pv.unmodified()); // does not throw
        };
        "set_stages_and_accepts"_test = [] {
            const slot_t orig{1U};
            const slot_t updated{2U};
            const auto db = make_db_with(1U, orig);
            pv_t pv{db, 1U};
            auto replacement = std::make_shared<slot_t>(updated);
            pv.set(std::move(replacement));
            expect(!replacement);
            expect(pv.updated());
            expect(throws([&]{ (void)pv.unmodified(); }));
            expect(throws([&]{ (void)pv.update(); }));
            expect_equal(orig, pv_t{db, 1U}.unmodified());

            pv.stage();
            expect(pv.updated());
            expect(throws([&]{ (void)pv.unmodified(); }));
            expect_equal(updated, pv_t{db, 1U}.unmodified());

            pv.accept();
            expect(!pv.updated());
            expect_equal(updated, pv.unmodified());
        };
        "reset_discards_update"_test = [] {
            const slot_t orig{1U};
            const auto db = make_db_with(1U, orig);
            pv_t pv{db, 1U};
            pv.set(std::make_shared<slot_t>(slot_t{2U}));
            pv.reset();
            expect(!pv.updated());
            expect_equal(orig, pv.unmodified());
        };
        "reset_reloads_from_db"_test = [] {
            const slot_t v1{10U};
            const slot_t v2{20U};
            const auto key = state_dict_t::make_key(1U);
            const auto db = make_db_with(1U, v1);
            pv_t pv{db, 1U};
            (void)pv.unmodified(); // populate cache
            db->set(key, encoder{v2}.bytes()); // update DB externally
            pv.reset();
            expect_equal(v2, pv.unmodified());
        };
        "update_stages_and_accepts"_test = [] {
            const slot_t orig{5U};
            const auto db = make_db_with(1U, orig);
            pv_t pv{db, 1U};
            auto &updated = pv.update();
            updated = slot_t{99U};
            expect(throws([&]{ (void)pv.unmodified(); }));
            pv.stage();
            pv.accept();
            expect_equal(slot_t{99U}, pv.unmodified());
            expect_equal(slot_t{99U}, pv_t{db, 1U}.unmodified());
        };
        "update_can_be_called_only_once"_test = [] {
            const slot_t orig{7U};
            const auto db = make_db_with(1U, orig);
            pv_t pv{db, 1U};
            auto &updated = pv.update();
            updated = slot_t{100U};
            expect(throws([&]{ (void)pv.update(); }));
            expect(throws([&]{ pv.set(std::make_shared<slot_t>(slot_t{101U})); }));
            expect_equal(slot_t{100U}, updated);
        };
        "set_requires_exclusive_ownership"_test = [] {
            const slot_t orig{7U};
            const auto db = make_db_with(1U, orig);
            pv_t pv{db, 1U};
            auto shared = std::make_shared<slot_t>(slot_t{100U});
            const auto alias = shared;
            expect(throws([&] { pv.set(std::move(shared)); }));
            expect_equal(orig, pv.unmodified());
            expect_equal(slot_t{100U}, *alias);
        };
        "set_null_throws"_test = [] {
            pv_t pv{make_db_with(1U, slot_t{1U}), 1U};
            expect(throws([&] { pv.set(pv_t::ptr_type{}); }));
        };
    };
};
