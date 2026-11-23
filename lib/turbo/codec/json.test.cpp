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
        "optional vector of pairs"_test = [] {
            using records_t = std::vector<std::pair<uint8_vector, std::optional<uint8_vector>>>;
            const records_t records{
                {uint8_vector{1}, std::nullopt},
                {uint8_vector{1}, uint8_vector{}},
                {uint8_vector{1}, uint8_vector{2}}
            };
            const value inputs[]{nullptr, array{}, boost::json::parse(R"([["0x01",null],["0x01","0x"],["0x01","0x02"]])")};
            const std::optional<records_t> expected[]{std::nullopt, records_t{}, records};
            for (size_t i = 0; i < std::size(inputs); ++i) {
                std::optional<records_t> actual{records};
                decoder::decode(inputs[i], actual);
                expect(actual == expected[i]);
            }
            expect(from_json<records_t>(inputs[2]) == records);
            expect(throws<turbo::error>([] { (void)from_json<std::pair<uint32_t, uint32_t>>(array{1}); }));
            expect(throws<turbo::error>([] { (void)from_json<std::pair<uint32_t, uint32_t>>(array{1, 2, 3}); }));
            expect(from_json<std::vector<uint8_t>>(value{"0x0102"}) == std::vector<uint8_t>{1, 2});
        };

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
