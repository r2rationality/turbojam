/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/test.hpp>
#include "triedb.hpp"

namespace {
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
    };
};
