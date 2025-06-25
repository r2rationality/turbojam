/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <boost/json.hpp>
#include <turbo/common/file.hpp>
#include <turbo/common/test.hpp>
#include <turbo/codec/json.hpp>
#include "types/header.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jam;

    template<typename T>
    void test_decode(const std::string &prefix)
    {
        try {
            const auto b_val = jam::load_obj<T>(prefix + ".bin");
            const auto j_val = codec::json::load_obj<T>(prefix + ".json");
            expect(j_val == b_val) << prefix;
        } catch (const std::exception &ex) {
            expect(false) << prefix << ex.what();
        } catch (...) {
            expect(false) << prefix << "Unknown exception";
        }
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

    template<typename T>
    void test_all(const std::string &prefix)
    {
        test_decode<T>(prefix);
        test_roundtrip<T>(prefix);
    }

    template<template <typename> typename T>
    void test_all(const std::string &prefix)
    {
        test_all<T<config_tiny>>(file::install_path(fmt::format(fmt::runtime(prefix), "tiny")));
        test_all<T<config_prod>>(file::install_path(fmt::format(fmt::runtime(prefix), "full")));
    }
}

suite turbo_jam_types_suite = [] {
    "turbo::jam::types"_test = [] {
        test_all<assurances_extrinsic_t>("test/jam-test-vectors/codec/{}/assurances_extrinsic");
        test_all<block_t>("test/jam-test-vectors/codec/{}/block");
        test_all<disputes_extrinsic_t>("test/jam-test-vectors/codec/{}/disputes_extrinsic");
        test_all<extrinsic_t>("test/jam-test-vectors/codec/{}/extrinsic");
        test_all<guarantees_extrinsic_t>("test/jam-test-vectors/codec/{}/guarantees_extrinsic");
        test_all<header_t>("test/jam-test-vectors/codec/{}/header_0");
        test_all<header_t>("test/jam-test-vectors/codec/{}/header_1");
        test_all<refine_context_t>("test/jam-test-vectors/codec/{}/refine_context");
        test_all<tickets_extrinsic_t>("test/jam-test-vectors/codec/{}/tickets_extrinsic");
        test_all<work_package_t>("test/jam-test-vectors/codec/{}/work_package");
        test_all<work_report_t>("test/jam-test-vectors/codec/{}/work_report");
        // config independent
        test_all<preimages_extrinsic_t>("test/jam-test-vectors/codec/tiny/preimages_extrinsic");
        test_all<preimages_extrinsic_t>("test/jam-test-vectors/codec/full/preimages_extrinsic");
        test_all<work_item_t>("test/jam-test-vectors/codec/tiny/work_item");
        test_all<work_item_t>("test/jam-test-vectors/codec/full/work_item");
        test_all<work_result_t>("test/jam-test-vectors/codec/tiny/work_result_0");
        test_all<work_result_t>("test/jam-test-vectors/codec/full/work_result_0");
        test_all<work_result_t>("test/jam-test-vectors/codec/tiny/work_result_1");
        test_all<work_result_t>("test/jam-test-vectors/codec/full/work_result_1");
    };
};
