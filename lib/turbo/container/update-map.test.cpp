/* Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com) */

#include <turbo/common/test.hpp>
#include "update-map.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::container;
}

suite turbo_container_versioned_map_suite = [] {
    "turbo::container::versioned_map"_test = [] {
        "update & merge: 1 version"_test = [] {
            std::map<size_t, uint8_vector> base {};
            update_map_t m { base };
            static_assert(m.max_updates == 1);
            expect_equal(uint8_vector {}, m.get(22));
            expect_equal(uint8_vector {}, m.get(33));
            m.set(22, uint8_vector {});
            expect_equal(uint8_vector {}, m.get(22));
            m.set(33, uint8_vector::from_hex("00112233"));
            expect_equal(uint8_vector::from_hex("00112233"), m.get(33));
            expect(throws([&] { m.set(22, uint8_vector::from_hex("00112233")); }));
        };
        "update & merge: 2 versions"_test = [] {
            std::map<size_t, uint8_vector> base {};
            update_map_t<decltype(base), 2> m { base };
            static_assert(m.max_updates == 2);
            expect_equal(uint8_vector {}, m.get(22));
            expect_equal(uint8_vector {}, m.get(33));
            m.set(22, uint8_vector {});
            expect_equal(uint8_vector {}, m.get(22));
            m.set(33, uint8_vector::from_hex("00112233"));
            expect_equal(uint8_vector::from_hex("00112233"), m.get(33));
            m.set(22, uint8_vector::from_hex("00112233"));
            expect_equal(uint8_vector::from_hex("00112233"), m.get(22));
            expect_equal(0ULL, m.get_updates(11).size());
            expect_equal(2ULL, m.get_updates(22).size());
            expect_equal(1ULL, m.get_updates(33).size());
            expect_equal(0ULL, base.size());
            m.merge();
            expect_equal(2ULL, base.size());
            expect_equal(uint8_vector {}, m.get(11));
            expect_equal(uint8_vector::from_hex("00112233"), m.get(22));
            expect_equal(uint8_vector::from_hex("00112233"), m.get(33));
            expect_equal(0ULL, m.get_updates(11).size());
            expect_equal(0ULL, m.get_updates(22).size());
            expect_equal(0ULL, m.get_updates(33).size());
        };
        "update & merge: 3 versions"_test = [] {
            std::map<size_t, uint8_vector> base {};
            update_map_t<decltype(base), 3> m { base };
            static_assert(m.max_updates == 3);
            m.set(22, uint8_vector {});
            expect_equal(uint8_vector {}, m.get(22));
            m.set(22, uint8_vector::from_hex("00112233"));
            expect_equal(uint8_vector::from_hex("00112233"), m.get(22));
            m.set(22, uint8_vector {});
            expect_equal(uint8_vector {}, m.get(22));
            expect(throws([&] { m.set(22, uint8_vector::from_hex("00112233")); }));
            expect_equal(3ULL, m.get_updates(22).size());
            expect_equal(0ULL, base.size());
            m.merge();
            expect_equal(0ULL, base.size());
            expect_equal(uint8_vector {}, m.get(22));
            expect_equal(0ULL, m.get_updates(22).size());
        };
        "revert: 3 versions"_test = [] {
            std::map<size_t, uint8_vector> base {};
            update_map_t<decltype(base), 3> m { base };
            static_assert(m.max_updates == 3);
            m.set(22, uint8_vector {});
            expect_equal(uint8_vector {}, m.get(22));
            m.set(22, uint8_vector::from_hex("00112233"));
            expect_equal(uint8_vector::from_hex("00112233"), m.get(22));
            m.set(22, uint8_vector {});
            expect_equal(uint8_vector {}, m.get(22));
            expect(throws([&] { m.set(22, uint8_vector::from_hex("00112233")); }));
            expect_equal(3ULL, m.get_updates(22).size());
            expect_equal(0ULL, base.size());
            m.revert();
            expect_equal(0ULL, base.size());
            expect_equal(uint8_vector {}, m.get(22));
        };
    };
};