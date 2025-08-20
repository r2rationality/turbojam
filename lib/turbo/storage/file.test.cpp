/* Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com) */

#include <turbo/common/test.hpp>
#include "file.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::storage;
    using namespace std::string_view_literals;
}

suite turbo_storage_file_suite = [] {
    "turbo::storage::file"_test = [] {
        const turbo::file::tmp_directory tmp_dir { "test-turbo-filedb" };
        "get, set, and erase"_test = [&] {
            storage::file::db_t db{ tmp_dir.path() };
            expect_equal(value_t {}, db.get("AB"sv));
            expect(throws([&] { db.set(""sv, ""sv); }));
            expect(throws([&] { db.set("A"sv, ""sv); }));
            db.set("AB"sv, "CD"sv);
            expect_equal(value_t { "CD"sv }, db.get("AB"sv));
            db.set("AB"sv, "EF"sv);
            expect_equal(value_t { "EF"sv }, db.get("AB"sv));
            db.erase("AB"sv);
            expect_equal(value_t {}, db.get("AB"sv));
        };
        "foreach"_test = [&] {
            storage::file::db_t client { tmp_dir.path() };
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
    };
};