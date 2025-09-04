/* Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com) */

#include <turbo/common/test.hpp>
#include "memory.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::storage;
    using namespace turbo::storage::memory;
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

suite turbo_storage_memory_suite = [] {
    "turbo::storage::memory"_test = [] {
        "get, set, and erase"_test = [&] {
            memory::db_t db{};
            expect_equal(value_t{}, db.get("AB"sv));
            db.set("AB"sv, "CD"sv);
            expect_equal(value_t{ "CD"sv }, db.get("AB"sv));
            db.set("AB"sv, "EF"sv);
            expect_equal(value_t{ "EF"sv }, db.get("AB"sv));
            db.erase("AB"sv);
            expect_equal(value_t{}, db.get("AB"sv));
        };
        "foreach"_test = [&] {
            memory::db_t db{};
            std::map<uint8_vector, uint8_vector> exp{};
            exp.try_emplace(uint8_vector::from_hex("AABB"), uint8_vector::from_hex("0011"));
            exp.try_emplace(uint8_vector::from_hex("CCDD"), uint8_vector::from_hex("2233"));
            for (const auto &[k, v]: exp)
                db.set(k, v);
            const auto act = get_contents(db);
            expect_equal(exp, act);
        };
    };
};