/* Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com) */

#include <turbo/common/test.hpp>
#include "memory.hpp"
#include "update.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::storage;
    using namespace turbo::storage::update;
    using namespace std::string_view_literals;

    template<typename DB>
    std::map<uint8_vector, uint8_vector> get_contents(DB &db)
    {
        std::map<uint8_vector, uint8_vector> act{};
        db.foreach([&](auto &&k, auto &&v) {
            act.try_emplace(std::move(k), std::move(v));
        });
        return act;
    }

    storage::db_ptr_t make_base_db(std::initializer_list<std::pair<std::string_view, std::string_view>> init={}) {
        auto db = std::make_shared<memory::db_t>();
        for (auto &&[k, v]: init)
            db->set(k, v);
        return db;
    }
}

suite turbo_storage_update_suite = [] {
    "turbo::storage::update"_test = [] {
        "get, set, and erase"_test = [] {
            const auto base_db = make_base_db();  // empty base
            update::db_t db{base_db};
            expect_equal(value_t{}, db.get("AB"sv));
            db.set("AB"sv, "CD"sv);
            expect_equal(value_t{"CD"sv}, db.get("AB"sv));
            db.set("AB"sv, "EF"sv);
            expect_equal(value_t{"EF"sv}, db.get("AB"sv));
            db.erase("AB"sv);
            expect_equal(value_t{}, db.get("AB"sv));
        };

        "foreach_only_overlay"_test = [] {
            const auto base_db = make_base_db();  // empty base
            update::db_t db{base_db};
            const std::map<uint8_vector, uint8_vector> exp{
                {uint8_vector::from_hex("AABB"), uint8_vector::from_hex("0011")},
                {uint8_vector::from_hex("CCDD"), uint8_vector::from_hex("2233")}
            };
            for (const auto &[k, v]: exp)
                db.set(k, v);
            const auto act = get_contents(db);
            expect_equal(exp, act);
        };

        "foreach_with_base_and_updates"_test = [] {
            const auto base_db = make_base_db({
                {"10", "aa"},
                {"20", "bb"},
                {"30", "cc"},
            });
            update::db_t db{base_db};
            db.set("05"sv, "x"sv);
            db.set("20"sv, "yy"sv);
            db.set("25"sv, "z"sv);
            db.erase("30"sv);
            const auto act = get_contents(db);
            const std::map<uint8_vector, uint8_vector> exp{
                {uint8_vector{"05"sv}, uint8_vector{"x"sv}},
                {uint8_vector{"10"sv}, uint8_vector{"aa"sv}},
                {uint8_vector{"20"sv}, uint8_vector{"yy"sv}},
                {uint8_vector{"25"sv}, uint8_vector{"z"sv}},
            };
            expect_equal(exp, act);
        };

        "effects_on_base"_test = [] {
            const auto base_db = make_base_db();
            update::db_t db{base_db};
            expect_equal(size_t{0}, get_contents(*base_db).size());
            db.set("AB"sv, "CD"sv);
            db.set("AC"sv, "EF"sv);
            db.erase("AB"sv);
            expect_equal(size_t{0}, get_contents(*base_db).size());
            db.commit();
            expect_equal(size_t{1}, get_contents(*base_db).size());
        };

        "undo_redo"_test = [] {
            const auto base_db = make_base_db({
                {"AC", "EF"},
            });
            update::db_t db{base_db};
            db.set("AC"sv, "XY"sv);
            db.set("AD"sv, "GH"sv);
            db.erase("AB"sv);
            const auto trace = db.commit();
            expect_equal(size_t{2}, get_contents(*base_db).size());
            expect_equal(undo_list_t{
                {uint8_vector{"AC"sv}, value_t{"EF"sv}},
                {uint8_vector{"AD"sv}, value_t{}},
            }, trace.undo);
            expect_equal(update_map_t{
                {uint8_vector{"AB"sv}, value_t{}},
                {uint8_vector{"AC"sv}, value_t{"XY"sv}},
                {uint8_vector{"AD"sv}, value_t{"GH"sv}},
            }, trace.redo);
        };

        "size_tracking"_test = [] {
            const auto base_db = make_base_db({
                {"B", "baseB"},
            });
            update::db_t db{base_db};
            expect_equal(base_db->size(), db.size());
            db.set("A"sv, "valA"sv);
            expect_equal(base_db->size() + 1, db.size());
            db.set("A"sv, "valA2"sv);
            expect_equal(base_db->size() + 1, db.size());
            db.erase("B"sv);
            expect_equal(base_db->size(), db.size());
            db.erase("A"sv);
            expect_equal(base_db->size() - 1, db.size());
        };

        "reset_clears_updates"_test = [] {
            const auto base_db = make_base_db({
                {"K", "base"},
            });
            update::db_t db{base_db};
            db.set("K"sv, "overlay"sv);
            db.set("N"sv, "new"sv);
            expect_equal(value_t{"overlay"sv}, db.get("K"sv));
            expect_equal(value_t{"new"sv}, db.get("N"sv));
            db.reset();
            expect_equal(value_t{"base"sv}, db.get("K"sv));
            expect_equal(value_t{}, db.get("N"sv));
            expect_equal(base_db->size(), db.size());
        };

        "updates_accessor"_test = [] {
            const auto base_db = make_base_db({
                {"B", "baseB"},
            });
            update::db_t db{base_db};
            db.set("A"sv, "valA"sv);
            db.erase("B"sv);
            const auto &u = db.updates();
            expect_equal(size_t{2}, u.size());
            expect_equal(value_t{"valA"sv}, u.at(uint8_vector{"A"sv}));
            expect_equal(value_t{}, u.at(uint8_vector{"B"sv}));
        };

        "clear_throws"_test = [] {
            const auto base_db = make_base_db();
            update::db_t db{base_db};
            expect(throws([&] { db.clear(); }));
        };

        "commit_no_op_update"_test = [] {
            const auto base_db = make_base_db({
                {"K", "VAL"},
            });
            update::db_t db{base_db};
            db.set("K"sv, "VAL"sv);
            const auto trace = db.commit();
            expect_equal(value_t{"VAL"sv}, base_db->get("K"sv));
            expect(trace.undo.empty());
            expect_equal(size_t{1}, trace.redo.size());
        };

        "layered_consume_overlapping_keys"_test = [] {
            const auto base_db = make_base_db();
            update::db_t db_main{base_db};
            update::db_t db_src1{base_db};
            update::db_t db_src2{base_db};
            db_src1.set("K"sv, "V1"sv);
            db_src2.set("K"sv, "V2"sv);
            db_main.consume_from(std::move(db_src1));
            db_main.consume_from(std::move(db_src2));
            expect_equal(value_t{"V2"sv}, db_main.get("K"sv));
            expect_equal(base_db->size() + 1, db_main.size());
        };

        "layered_consume_original_case"_test = [] {
            const auto base_db = make_base_db({
                {"XYZ", "YES"},
            });
            expect_equal(value_t{"YES"sv}, base_db->get("XYZ"sv));
            const auto lev1 = std::make_shared<update::db_t>(base_db);

            update::db_t lev2_1{lev1};
            lev2_1.erase("XYZ"sv);
            expect_equal(value_t{}, lev2_1.get("XYZ"sv));
            update::db_t lev2_2{lev1};
            lev2_2.set("XYZ"sv, "YES"sv);
            expect_equal(value_t{"YES"sv}, lev2_2.get("XYZ"sv));

            update::db_t lev2_all{lev1};
            lev2_all.consume_from(std::move(lev2_1));
            lev2_all.consume_from(std::move(lev2_2));
            expect_equal(value_t{"YES"sv}, lev2_all.get("XYZ"sv));
        };
    };
};