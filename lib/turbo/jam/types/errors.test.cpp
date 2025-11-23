/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/test.hpp>
#include "errors.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jam;
}

suite turbo_jam_types_errors_suite = [] {
    "turbo::jam::types::errors"_test = [] {
        const auto e1 = err_bad_attestation_parent_t{};
        const auto e2 = err_bad_validator_index_t{};
        expect_equal(false, e1 == e2);
        expect_equal(false, e2 == e1);
        expect_equal(true, e1 == err_bad_attestation_parent_t{});
        expect_equal(true, e2 == err_bad_validator_index_t{});
        expect(strcmp(e1.what(), e2.what()) != 0);
        expect(strcmp(e1.what(), err_bad_attestation_parent_t{}.what()) == 0);
        expect(strcmp(e2.what(), err_bad_validator_index_t{}.what()) == 0);
    };
};
