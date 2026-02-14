/* Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com) */

#include <turbo/common/test.hpp>
#include "lmdb-rc.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::storage;
    using namespace std::string_view_literals;
}

suite turbo_storage_lmdb_rc_suite = [] {
    "turbo::storage::lmdb_rc"_test = [] {
        const file::tmp_directory tmp_dir{"test-turbo-lmdb-rc-test"};
        "get, set, and erase"_test = [&] {
            lmdb_rc::db_t db{tmp_dir.path()};
            expect_equal(value_t {}, db.get("AB"sv));
            db.set("AB"sv, "CD"sv);
            expect_equal(value_t { "CD"sv }, db.get("AB"sv));
            db.erase("AB"sv);
            expect_equal(value_t {}, db.get("AB"sv));
        };
        "foreach"_test = [&] {
            lmdb_rc::db_t client {tmp_dir.path()};
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
        "reference counting"_test = [&] {
            lmdb_rc::db_t db{tmp_dir.path()};
            db.clear();
            expect_equal(size_t{0}, db.size());
            db.set("ABC"sv, "ABC"sv);
            expect_equal(size_t{1}, db.size());
            db.set("ABC"sv, "000"sv);
            expect_equal(size_t{1}, db.size());
            db.set("ABC"sv, "111"sv);
            expect_equal(size_t{1}, db.size());
            expect_equal("111"sv, db.get("ABC"sv));
            db.erase("ABC"sv);
            expect_equal(size_t{1}, db.size());
            expect_equal("111"sv, db.get("ABC"sv));
            db.erase("ABC"sv);
            expect_equal(size_t{1}, db.size());
            expect_equal("111"sv, db.get("ABC"sv));
            db.erase("ABC"sv);
            expect_equal(size_t{0}, db.size());
            db.set("ABC"sv, "111"sv);
            expect_equal(size_t{1}, db.size());
            expect_equal("111"sv, db.get("ABC"sv));
        };
    };
};