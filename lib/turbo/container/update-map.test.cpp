/* Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com) */

#include <turbo/common/test.hpp>
#include "update-map.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::container;
}

suite turbo_container_update_map_suite = [] {
    "turbo::container::update_map"_test = [] {
        "update & merge"_test = [] {
            std::map<size_t, uint8_vector> base {};
            update_map_t m { std_map_update_api_t { base } };
            expect_equal(uint8_vector {}, m.get(22));
            expect_equal(uint8_vector {}, m.get(33));
            m.set(22, uint8_vector {});
            expect_equal(uint8_vector {}, m.get(22));
            m.set(33, uint8_vector::from_hex("00112233"));
            expect_equal(uint8_vector::from_hex("00112233"), m.get(33));
            expect_equal(0ULL, base.size());
            m.commit(base);
            expect_equal(1ULL, base.size());
        };
        "revert"_test = [] {
            std::map<size_t, uint8_vector> base {};
            update_map_t m { std_map_update_api_t { base } };
            m.set(22, uint8_vector {});
            expect_equal(uint8_vector {}, m.get(22));
            m.set(22, uint8_vector::from_hex("00112233"));
            expect_equal(uint8_vector::from_hex("00112233"), m.get(22));
            m.set(22, uint8_vector {});
            expect_equal(uint8_vector {}, m.get(22));
            expect_equal(0ULL, base.size());
            m.rollback();
            expect_equal(0ULL, base.size());
            expect_equal(uint8_vector {}, m.get(22));
        };
    };
};