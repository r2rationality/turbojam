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
            expect(throws([&] { pv.get(); }));
        };
        "lazy_load"_test = [] {
            const slot_t exp{42U};
            pv_t pv{make_db_with(1U, exp), 1U};
            expect_equal(exp, pv.get());
        };
        "set_and_commit"_test = [] {
            const slot_t orig{1U};
            const slot_t updated{2U};
            const auto db = make_db_with(1U, orig);
            pv_t pv{db, 1U};
            pv.set(std::make_shared<slot_t>(updated));
            expect_equal(updated, pv.get());
            // DB unchanged before commit
            expect_equal(orig, pv_t{db, 1U}.get());
            pv.commit();
            // DB has new value after commit
            expect_equal(updated, pv_t{db, 1U}.get());
        };
        "rollback"_test = [] {
            const slot_t orig{1U};
            const auto db = make_db_with(1U, orig);
            pv_t pv{db, 1U};
            pv.set(std::make_shared<slot_t>(slot_t{2U}));
            pv.rollback();
            expect_equal(orig, pv.get());
        };
        "reset_reloads_from_db"_test = [] {
            const slot_t v1{10U};
            const slot_t v2{20U};
            const auto key = state_dict_t::make_key(1U);
            const auto db = make_db_with(1U, v1);
            pv_t pv{db, 1U};
            pv.get(); // populate cache
            db->set(key, encoder{v2}.bytes()); // update DB externally
            pv.reset();
            expect_equal(v2, pv.get());
        };
        "update_modifies_value"_test = [] {
            const slot_t orig{5U};
            const auto db = make_db_with(1U, orig);
            pv_t pv{db, 1U};
            pv.update() = slot_t{99U};
            pv.commit();
            expect_equal(slot_t{99U}, pv_t{db, 1U}.get());
        };
        "update_cow"_test = [] {
            const slot_t orig{7U};
            const auto db = make_db_with(1U, orig);
            pv_t pv1{db, 1U};
            pv1.get(); // load ptr
            pv_t pv2{pv1}; // share the same _ptr (use_count == 2)
            pv1.update() = slot_t{100U}; // triggers deep copy for pv1
            expect_equal(orig, pv2.get()); // pv2 still sees original
        };
        "storage_ptr_cow"_test = [] {
            const slot_t orig{7U};
            const auto db = make_db_with(1U, orig);
            pv_t pv{db, 1U};
            const auto ptr = pv.storage(); // external shared ownership raises use_count to 2
            expect_equal(orig, *ptr);
            pv.update() = slot_t{100U}; // triggers deep copy since use_count > 1
            expect_equal(orig, *ptr); // external ptr still holds the original
            expect_equal(slot_t{100U}, pv.get());
        };
        "equality"_test = [] {
            const slot_t v1{3U};
            const slot_t v2{4U};
            const auto db = make_db_with(1U, v1);
            db->set(state_dict_t::make_key(2U), encoder{v2}.bytes());
            pv_t pva{db, 1U};
            pv_t pvb{db, 1U};
            pv_t pvc{db, 2U};
            expect(pva == pvb);
            expect(!(pva == pvc));
        };
        "set_null_throws"_test = [] {
            pv_t pv{make_db_with(1U, slot_t{1U}), 1U};
            expect(throws([&] { pv.set(nullptr); }));
        };
    };
};
