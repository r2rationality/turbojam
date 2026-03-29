/* Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÃœ (info at r2rationality dot com) */

#include <turbo/common/test.hpp>
#include "lmdb.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::storage;
    using namespace std::string_view_literals;
}

suite turbo_storage_lmdb_suite = [] {
    "turbo::storage::lmdb"_test = [] {
        const file::tmp_directory tmp_dir{"test-turbo-lmdb-test"};
        "get, set, and erase"_test = [&] {
            lmdb::db_t db{tmp_dir.path()};
            expect_equal(value_t {}, db.get("AB"sv));
            db.set("AB"sv, "CD"sv);
            expect_equal(value_t { "CD"sv }, db.get("AB"sv));
            db.erase("AB"sv);
            expect_equal(value_t {}, db.get("AB"sv));
        };
        "foreach"_test = [&] {
            lmdb::db_t client {tmp_dir.path()};
            std::map<uint8_vector, uint8_vector> exp {};
            exp.try_emplace(uint8_vector::from_hex("AABB"), uint8_vector::from_hex("0011"));
            exp.try_emplace(uint8_vector::from_hex("CCDD"), uint8_vector::from_hex("2233"));
            for (const auto &[k, v]: exp)
                client.set(k, v);
            std::map<uint8_vector, uint8_vector> act {};
            client.foreach([&](auto &&k, auto &&v) {
                act.try_emplace(std::move(k), std::move(v));
            });
            expect_equal(exp, act);
        };
        "overwrite and erase"_test = [&] {
            lmdb::db_t db{tmp_dir.path()};
            db.clear();
            expect_equal(size_t{0}, db.size());
            db.set("ABC"sv, "ABC"sv);
            expect_equal(size_t{1}, db.size());
            db.set("ABC"sv, "000"sv);
            expect_equal(size_t{1}, db.size());
            db.set("ABC"sv, "111"sv);
            expect_equal(size_t{1}, db.size());
            expect_equal(value_t{"111"sv}, db.get("ABC"sv));
            db.erase("ABC"sv);
            expect_equal(size_t{0}, db.size());
            expect_equal(value_t{}, db.get("ABC"sv));
            db.set("ABC"sv, "111"sv);
            expect_equal(size_t{1}, db.size());
            expect_equal(value_t{"111"sv}, db.get("ABC"sv));
        };
        "mapsize growth"_test = [&] {
            const file::tmp_directory growth_dir{"test-turbo-lmdb-growth"};
            lmdb::db_t db{growth_dir.path(), 1ULL << 17U};
            const uint8_vector val(5000, uint8_t{'x'});
            const auto initial_map_size = db.map_info().map_size;
            for (int i = 0; db.map_info().map_size == initial_map_size; ++i) {
                const auto key = fmt::format("growth-key-{:04d}", i);
                db.set(buffer{reinterpret_cast<const uint8_t*>(key.data()), key.size()}, val);
                db.commit();
            }

            expect_equal(initial_map_size * 2, db.map_info().map_size);
            const size_t n = db.size();
            lmdb::db_t db2{growth_dir.path()};
            expect_equal(n, db2.size());
        };
    };
};
