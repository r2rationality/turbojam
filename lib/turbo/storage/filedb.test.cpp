/* Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com) */

#include <turbo/common/test.hpp>
#include "filedb.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::storage::filedb;
    using namespace std::string_view_literals;
}

suite turbo_storage_filedb_suite = [] {
    "turbo::storage::filedb"_test = [] {
        const file::tmp_directory tmp_dir { "test-turbo-filedb" };
        client_t client { tmp_dir.path() };
        expect_equal(value_t {}, client.get("AB"sv));
        expect(throws([&] { client.set(""sv, ""sv); }));
        expect(throws([&] { client.set("A"sv, ""sv); }));
        client.set("AB"sv, "CD"sv);
        expect_equal(value_t { "CD"sv }, client.get("AB"sv));
        client.set("AB"sv, "EF"sv);
        expect_equal(value_t { "EF"sv }, client.get("AB"sv));
        client.erase("AB"sv);
        expect_equal(value_t {}, client.get("AB"sv));
    };
};