/* Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com) */

#include <turbo/common/test.hpp>
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
}

suite turbo_storage_update_suite = [] {
    "turbo::storage::update"_test = [] {
        const turbo::file::tmp_directory tmp_dir {"test-turbo-updatedb"};
        const auto base_db = std::make_shared<storage::file::db_t>(tmp_dir.path());
        "get, set, and erase"_test = [&] {
            update::db_t db{base_db};
            expect_equal(value_t{}, db.get("AB"sv));
            db.set("AB"sv, "CD"sv);
            expect_equal(value_t{ "CD"sv }, db.get("AB"sv));
            db.set("AB"sv, "EF"sv);
            expect_equal(value_t{ "EF"sv }, db.get("AB"sv));
            db.erase("AB"sv);
            expect_equal(value_t{}, db.get("AB"sv));
        };
        "foreach"_test = [&] {
            update::db_t db{base_db};
            std::map<uint8_vector, uint8_vector> exp{};
            exp.try_emplace(uint8_vector::from_hex("AABB"), uint8_vector::from_hex("0011"));
            exp.try_emplace(uint8_vector::from_hex("CCDD"), uint8_vector::from_hex("2233"));
            for (const auto &[k, v]: exp)
                db.set(k, v);
            const auto act = get_contents(db);
            expect_equal(exp, act);
        };
        "effects on base"_test = [&] {
            update::db_t db{base_db};
            expect_equal(size_t{0}, get_contents(*base_db).size());
            db.set("AB"sv, "CD"sv);
            db.set("AC"sv, "EF"sv);
            db.erase("AB"sv);
            expect_equal(size_t{0}, get_contents(*base_db).size());
            db.commit();
            expect_equal(size_t{1}, get_contents(*base_db).size());
        };
        "undo_redo"_test = [&] {
            expect_equal(size_t{1}, get_contents(*base_db).size());
            update::db_t db{base_db};
            db.set("AC"sv, "XY"sv);
            db.set("AD"sv, "GH"sv);
            db.erase("AB"sv);
            const auto trace = db.commit();
            expect_equal(size_t{2}, get_contents(*base_db).size());
            expect_equal(update::db_t::undo_list_t{
                {uint8_vector{"AC"sv}, value_t{"EF"sv}},
                {uint8_vector{"AD"sv}, value_t{}}
            }, trace.undo);
            expect_equal(update::db_t::update_map_t{
                {uint8_vector{"AC"sv}, value_t{"XY"sv}},
                {uint8_vector{"AD"sv}, value_t{"GH"sv}}
            }, trace.redo);
        };
    };
};