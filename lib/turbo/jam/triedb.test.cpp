/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/test.hpp>
#include "triedb.hpp"

namespace {
    using namespace std::string_view_literals;
    using namespace turbo;
    using namespace turbo::jam;
    using namespace turbo::jam::triedb;
}

suite turbo_jam_triedb_suite = [] {
    "turbo::jam::triedb"_test = [] {
        "set get and erase"_test = [] {
            const file::tmp_directory db_dir { "test-turbo-jam-triedb-1" };
            client_t client { db_dir.path() };

            // small inplace value
            {
                const auto k = state_dict_t::make_key(1U);
                const auto v1 = uint8_vector::from_hex("00112233");
                const auto v2 = uint8_vector::from_hex("44556677");

                expect(!client.get(k));
                client.set(k, v1);
                expect(v1 == client.get(k));
                client.set(k, v2);
                expect(v2 == client.get(k));
                client.erase(k);
                expect(!client.get(k));
            }

            // large external value
            {
                const auto k = state_dict_t::make_key(1U);
                const uint8_vector v1(0x10000ULL);
                const uint8_vector v2(0x20000ULL);

                expect(!client.get(k));
                client.set(k, v1);
                expect(v1 == client.get(k));
                client.set(k, v2);
                expect(v2 == client.get(k));
                client.erase(k);
                expect(!client.get(k));
            }
        };

        "foreach and clear"_test = [] {
            const file::tmp_directory db_dir { "test-turbo-jam-triedb-2" };
            client_t client { db_dir.path() };

            const std::map<client_t::key_t, uint8_vector> expected {
                { state_dict_t::make_key(1U), uint8_vector::from_hex("00112233") },
                { state_dict_t::make_key(2U), uint8_vector(0x1000U) },
                { state_dict_t::make_key(3U), uint8_vector::from_hex("AABBCCDD") },
            };

            for (const auto &[k, v]: expected)
                client.set(k, v);

            {
                std::map<client_t::key_t, uint8_vector> observed {};
                client.foreach([&](const auto& k, auto v) {
                    observed.emplace(k, v);
                });
                expect_equal(expected, observed);
            }

            client.clear();
            {
                std::map<client_t::key_t, uint8_vector> observed {};
                client.foreach([&](const auto& k, auto v) {
                    observed.emplace(k, v);
                });
                expect(observed.empty());
            }
        };

        "erase of deep node"_test = [&] {
            const file::tmp_directory db_dir { "test-turbo-jam-triedb-3" };
            client_t client { db_dir.path() };
            for (const auto &k: {
                "00FF00FF00FF00FF2109EB7C5B05BBFB96DBC5F4898F506E8E4FBE3457C497"sv,
                "00FF00FF00FF00FF2109EB7C5B05BBFB96DBC5F4898F506E8E4FBE3457C497"sv,
                "004700B0000000000B0CCE53C35439DFE73087B1439C846B5FF0B18EC0052E"sv,
                "008700BB00010000AAA431E289495BA5A09618DB06C890AD8E342A0F285C15"sv,
                "00FE00FF00FF00FF42A295A93AC7F3BA564F0BE83089A647A9BD3861798CF9"sv,
                "00FE00FF00FF00FFC9D707CB3CAF787278FBA6A1F55630443736CCCB8B771D"sv,
                "00FF00FF00FF00FF0D4BBB181695EDA4AE707A081A2C564515AF1E5D15D9A5"sv,
                "00FF00FF00FF00FF2109EB7C5B05BBFB96DBC5F4898F506E8E4FBE3457C497"sv,
                "00FF00FF00FF00FF2C8EA9585FD170A4BE7405A0967EE61AD25E5C6FAB55A9"sv,
                "00FF00FF00FF00FF43BACAF626CDCADD9D1C73DBFE3A9B1EDE2B7EA752D042"sv,
                "00FF00FF00FF00FF5B7E41D1A75DBEE402B241659367231E09EB2A14761A1C"sv,
                "00FF00FF00FF00FF6817AA75EA46C2512D2D1DC0CA2B4EE158F0EDE599F353"sv,
                "00FF00FF00FF00FF69D6F38A4DDA314F8193A3D5E9F41F68A3EC49F5A521B8"sv,
                "00FF00FF00FF00FFD8838102A37E4A6598B497829C88915657105E74FD6147"sv,
                "00FF00FF00FF00FFEADC80C9230C15C9583B31843F94DE3A6AD199CC8005CC"sv
            }) {
                client.set(merkle::key_t::from_hex<merkle::key_t>(k), uint8_vector::from_hex(""));
            }
            client.erase(merkle::key_t::from_hex<merkle::key_t>("00FF00FF00FF00FF2C8EA9585FD170A4BE7405A0967EE61AD25E5C6FAB55A9"));
        };
    };
};
