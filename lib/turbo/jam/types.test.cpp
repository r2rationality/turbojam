/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/file.hpp>
#include <turbo/common/test.hpp>
#include "types.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jam;

    template<typename T>
    void test_decode(const std::string &path, const std::source_location &loc=std::source_location::current())
    {
        const auto bytes = file::read(path);
        codec::decoder dec { bytes };
        expect(!dec.empty(), loc);
        const auto val = T::from_bytes(dec);
        expect(dec.empty(), loc) << path;
    }
}

suite turbo_jam_types_suite = [] {
    "turbo::jam::types"_test = [] {
        test_decode<assurances_extrinsic_t<config_tiny>>(file::install_path("test/jam-test-vectors/codec/data/assurances_extrinsic.bin"));
        test_decode<block_t<config_tiny>>(file::install_path("test/jam-test-vectors/codec/data/block.bin"));
        test_decode<disputes_extrinsic_t<config_tiny>>(file::install_path("test/jam-test-vectors/codec/data/disputes_extrinsic.bin"));
        test_decode<extrinsic_t<config_tiny>>(file::install_path("test/jam-test-vectors/codec/data/extrinsic.bin"));
        test_decode<guarantees_extrinsic_t<config_tiny>>(file::install_path("test/jam-test-vectors/codec/data/guarantees_extrinsic.bin"));
        test_decode<header_t<config_tiny>>(file::install_path("test/jam-test-vectors/codec/data/header_0.bin"));
        test_decode<header_t<config_tiny>>(file::install_path("test/jam-test-vectors/codec/data/header_1.bin"));
        test_decode<preimages_extrinsic_t>(file::install_path("test/jam-test-vectors/codec/data/preimages_extrinsic.bin"));
        test_decode<refine_context_t>(file::install_path("test/jam-test-vectors/codec/data/refine_context.bin"));
        test_decode<tickets_extrinsic_t<config_tiny>>(file::install_path("test/jam-test-vectors/codec/data/tickets_extrinsic.bin"));
        test_decode<work_item_t>(file::install_path("test/jam-test-vectors/codec/data/work_item.bin"));
        test_decode<work_package_t>(file::install_path("test/jam-test-vectors/codec/data/work_package.bin"));
        test_decode<work_report_t>(file::install_path("test/jam-test-vectors/codec/data/work_report.bin"));
        test_decode<work_result_t>(file::install_path("test/jam-test-vectors/codec/data/work_result_0.bin"));
        test_decode<work_result_t>(file::install_path("test/jam-test-vectors/codec/data/work_result_1.bin"));
    };
};
