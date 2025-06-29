/* Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com) */

#include <boost/json.hpp>
#include <turbo/common/test.hpp>
#include "json.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::codec::json;
}

suite turbo_codec_json_suite = [] {
    using boost::ext::ut::v2_1_0::nothrow;
    "turbo::codec::json"_test = [] {
        "save_pretty + reload object"_test = [] {
            file::tmp t { "json-save-pretty-object-test.json" };
            const auto j = object {
                { "name", "abc" },
                { "version", 123 }
            };
            save_pretty(t.path(), j);
            const auto buf = file::read(t.path());
            expect_equal(std::string_view { "{\n  \"name\": \"abc\",\n  \"version\": 123\n}" }, buf);
            const auto loaded = load(t.path());
            expect(j == loaded);
        };
        "save_pretty + reload array"_test = [] {
            file::tmp t { "json-save-pretty-array-test.json" };
            auto j = array {
                "name",
                123
            };
            save_pretty(t.path(), j);
            auto act = file::read(t.path());
            std::string_view exp { "[\n  \"name\",\n  123\n]" };
            expect(act.size() == exp.size()) << act.size() << exp.size();
            expect(act == exp) << static_cast<buffer>(act);
            const auto loaded = load(t.path());
            expect(j == loaded);
        };
    };  
};
