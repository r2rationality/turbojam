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
    using staged_slot_t = staged_value_t<slot_t>;
    using staged_delta_t = staged_accounts_t<config_prod>;

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
    "turbo::jam::staged_value"_test = [] {
        "null_db_throws"_test = [] {
            expect(throws([] { staged_slot_t{nullptr, 1U}; }));
        };
        "missing_key_throws"_test = [] {
            staged_slot_t sv{make_db(), 1U};
            expect(throws([&] { (void)sv.unmodified(); }));
        };
        "lazy_load"_test = [] {
            const slot_t exp{42U};
            staged_slot_t sv{make_db_with(1U, exp), 1U};
            expect_equal(exp, sv.unmodified());
            expect_equal(exp, sv.unmodified()); // does not throw
        };
        "set_stages_and_accepts"_test = [] {
            const slot_t orig{1U};
            const slot_t updated{2U};
            const auto db = make_db_with(1U, orig);
            staged_slot_t sv{db, 1U};
            auto replacement = std::make_shared<slot_t>(updated);
            sv.set(std::move(replacement));
            expect(!replacement);
            expect(throws([&]{ (void)sv.unmodified(); }));
            expect(throws([&]{ (void)sv.update(); }));
            expect_equal(orig, staged_slot_t{db, 1U}.unmodified());

            sv.stage();
            expect(throws([&]{ (void)sv.unmodified(); }));
            expect_equal(updated, staged_slot_t{db, 1U}.unmodified());

            sv.accept();
            expect_equal(updated, sv.unmodified());
        };
        "reset_discards_update"_test = [] {
            const slot_t orig{1U};
            const auto db = make_db_with(1U, orig);
            staged_slot_t sv{db, 1U};
            sv.set(std::make_shared<slot_t>(slot_t{2U}));
            sv.reset();
            expect_equal(orig, sv.unmodified());
        };
        "reset_reloads_from_db"_test = [] {
            const slot_t v1{10U};
            const slot_t v2{20U};
            const auto key = state_dict_t::make_key(1U);
            const auto db = make_db_with(1U, v1);
            staged_slot_t sv{db, 1U};
            (void)sv.unmodified(); // populate cache
            db->set(key, encoder{v2}.bytes()); // update DB externally
            sv.reset();
            expect_equal(v2, sv.unmodified());
        };
        "update_stages_and_accepts"_test = [] {
            const slot_t orig{5U};
            const auto db = make_db_with(1U, orig);
            staged_slot_t sv{db, 1U};
            auto &updated = sv.update();
            updated = slot_t{99U};
            expect(throws([&]{ (void)sv.unmodified(); }));
            sv.stage();
            sv.accept();
            expect_equal(slot_t{99U}, sv.unmodified());
            expect_equal(slot_t{99U}, staged_slot_t{db, 1U}.unmodified());
        };
        "update_can_be_called_only_once"_test = [] {
            const slot_t orig{7U};
            const auto db = make_db_with(1U, orig);
            staged_slot_t sv{db, 1U};
            auto &updated = sv.update();
            updated = slot_t{100U};
            expect(throws([&]{ (void)sv.update(); }));
            expect(throws([&]{ sv.set(std::make_shared<slot_t>(slot_t{101U})); }));
            expect_equal(slot_t{100U}, updated);
        };
        "set_requires_exclusive_ownership"_test = [] {
            const slot_t orig{7U};
            const auto db = make_db_with(1U, orig);
            staged_slot_t sv{db, 1U};
            auto shared = std::make_shared<slot_t>(slot_t{100U});
            const auto alias = shared;
            expect(throws([&] { sv.set(std::move(shared)); }));
            expect_equal(orig, sv.unmodified());
            expect_equal(slot_t{100U}, *alias);
        };
        "set_null_throws"_test = [] {
            staged_slot_t sv{make_db_with(1U, slot_t{1U}), 1U};
            expect(throws([&] { sv.set(staged_slot_t::ptr_type{}); }));
        };
    };

    "turbo::jam::staged_accounts"_test = [] {
        constexpr service_id_t service_id = 42U;
        service_info_t<config_prod> original{};
        original.balance = 100U;
        auto changed = original;
        changed.balance = 200U;

        const auto db = make_db();
        accounts_t<config_prod>{db}.info_set(service_id, original);
        staged_delta_t delta{db};

        auto &updates = delta.update();
        updates.info_set(service_id, changed);
        expect_equal(original, *delta.info_get(service_id));
        expect(throws([&] { (void)delta.update(); }));

        delta.stage();
        expect_equal(changed, *delta.info_get(service_id));
        expect(throws([&] { (void)delta.update(); }));

        delta.accept();
        expect_equal(changed, *delta.info_get(service_id));
        (void)delta.update();
        delta.reset();
    };

    "staged_accounts_discards_with_database_rollback"_test = [] {
        constexpr service_id_t service_id = 42U;
        service_info_t<config_prod> original{};
        original.balance = 100U;
        auto changed = original;
        changed.balance = 200U;

        const auto base_db = make_db();
        accounts_t<config_prod>{base_db}.info_set(service_id, original);
        const auto transaction_db = std::make_shared<update::db_t>(base_db);
        staged_delta_t delta{transaction_db};

        delta.update().info_set(service_id, changed);
        delta.stage();
        expect_equal(changed, *delta.info_get(service_id));
        expect_equal(original, *accounts_t<config_prod>{base_db}.info_get(service_id));

        delta.reset();
        transaction_db->rollback();
        expect_equal(original, *delta.info_get(service_id));
    };
};
