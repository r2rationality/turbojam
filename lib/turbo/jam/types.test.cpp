/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <boost/json.hpp>
#include <turbo/common/file.hpp>
#include <turbo/common/test.hpp>
#include <turbo/codec/json.hpp>
#include "types.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jam;

    template<typename T>
    void test_decode(const std::string &prefix)
    {
        const auto b_val = jam::load_obj<T>(prefix + ".bin");
        const auto j_val = codec::json::load_obj<T>(prefix + ".json");
        expect(j_val == b_val) << prefix;
    }

    template<typename T>
    void test_roundtrip(const std::string &prefix)
    {
        try {
            const auto bytes = file::read(prefix + ".bin");
            decoder dec { bytes };
            const auto b = codec::from<T>(dec);
            encoder enc {};
            enc.process(b);
            expect(enc.bytes() == bytes) << prefix;
        } catch (const std::exception &ex) {
            expect(false) << prefix << ex.what();
        } catch (...) {
            expect(false) << prefix << "Unknown exception";
        }
    }
}

suite turbo_jam_types_suite = [] {
    "turbo::jam::types"_test = [] {
        for (const auto *testset: { "jam-test-vectors", "w3f-test-vectors" }) {
            "serialization roundtrip"_test = [&] {
                test_roundtrip<assurances_extrinsic_t<config_tiny>>(file::install_path(fmt::format("test/{}/codec/data/assurances_extrinsic", testset)));
                test_roundtrip<block_t<config_tiny>>(file::install_path(fmt::format("test/{}/codec/data/block", testset)));
                test_roundtrip<disputes_extrinsic_t<config_tiny>>(file::install_path(fmt::format("test/{}/codec/data/disputes_extrinsic", testset)));
                test_roundtrip<extrinsic_t<config_tiny>>(file::install_path(fmt::format("test/{}/codec/data/extrinsic", testset)));
                test_roundtrip<guarantees_extrinsic_t<config_tiny>>(file::install_path(fmt::format("test/{}/codec/data/guarantees_extrinsic", testset)));
                test_roundtrip<header_t<config_tiny>>(file::install_path(fmt::format("test/{}/codec/data/header_0", testset)));
                test_roundtrip<header_t<config_tiny>>(file::install_path(fmt::format("test/{}/codec/data/header_1", testset)));
                test_roundtrip<preimages_extrinsic_t>(file::install_path(fmt::format("test/{}/codec/data/preimages_extrinsic", testset)));
                test_roundtrip<refine_context_t<config_tiny>>(file::install_path(fmt::format("test/{}/codec/data/refine_context", testset)));
                test_roundtrip<tickets_extrinsic_t<config_tiny>>(file::install_path(fmt::format("test/{}/codec/data/tickets_extrinsic", testset)));
                test_roundtrip<work_item_t>(file::install_path(fmt::format("test/{}/codec/data/work_item", testset)));
                test_roundtrip<work_package_t<config_tiny>>(file::install_path(fmt::format("test/{}/codec/data/work_package", testset)));
                test_roundtrip<work_report_t<config_tiny>>(file::install_path(fmt::format("test/{}/codec/data/work_report", testset)));
                test_roundtrip<work_result_t>(file::install_path(fmt::format("test/{}/codec/data/work_result_0", testset)));
                test_roundtrip<work_result_t>(file::install_path(fmt::format("test/{}/codec/data/work_result_1", testset)));
            };
            "decode"_test = [&] {
                test_decode<assurances_extrinsic_t<config_tiny>>(file::install_path(fmt::format("test/{}/codec/data/assurances_extrinsic", testset)));
                test_decode<block_t<config_tiny>>(file::install_path(fmt::format("test/{}/codec/data/block", testset)));
                test_decode<disputes_extrinsic_t<config_tiny>>(file::install_path(fmt::format("test/{}/codec/data/disputes_extrinsic", testset)));
                test_decode<extrinsic_t<config_tiny>>(file::install_path(fmt::format("test/{}/codec/data/extrinsic", testset)));
                test_decode<guarantees_extrinsic_t<config_tiny>>(file::install_path(fmt::format("test/{}/codec/data/guarantees_extrinsic", testset)));
                test_decode<header_t<config_tiny>>(file::install_path(fmt::format("test/{}/codec/data/header_0", testset)));
                test_decode<header_t<config_tiny>>(file::install_path(fmt::format("test/{}/codec/data/header_1", testset)));
                test_decode<preimages_extrinsic_t>(file::install_path(fmt::format("test/{}/codec/data/preimages_extrinsic", testset)));
                test_decode<refine_context_t<config_tiny>>(file::install_path(fmt::format("test/{}/codec/data/refine_context", testset)));
                test_decode<tickets_extrinsic_t<config_tiny>>(file::install_path(fmt::format("test/{}/codec/data/tickets_extrinsic", testset)));
                test_decode<work_item_t>(file::install_path(fmt::format("test/{}/codec/data/work_item", testset)));
                test_decode<work_package_t<config_tiny>>(file::install_path(fmt::format("test/{}/codec/data/work_package", testset)));
                test_decode<work_report_t<config_tiny>>(file::install_path(fmt::format("test/{}/codec/data/work_report", testset)));
                test_decode<work_result_t>(file::install_path(fmt::format("test/{}/codec/data/work_result_0", testset)));
                test_decode<work_result_t>(file::install_path(fmt::format("test/{}/codec/data/work_result_1", testset)));
            };
        }
    };
};
