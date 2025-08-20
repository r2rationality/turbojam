/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <boost/json.hpp>
#include <turbo/codec/json.hpp>
#include "types/header.hpp"
#include "test-vectors.hpp"

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
        const auto full_prefix = test_vector_dir("codec/" + prefix);
        test_decode<T>(full_prefix);
        test_roundtrip<T>(full_prefix);
    }

    template<template <typename> typename T>
    void test_all(const std::string &prefix)
    {
        test_all<T<config_tiny>>(fmt::format(fmt::runtime(prefix), "tiny"));
        test_all<T<config_prod>>(fmt::format(fmt::runtime(prefix), "full"));
    }
}

suite turbo_jam_types_suite = [] {
    "turbo::jam::types"_test = [] {
        test_all<assurances_extrinsic_t>("{}/assurances_extrinsic");
        test_all<block_t>("{}/block");
        test_all<disputes_extrinsic_t>("{}/disputes_extrinsic");
        test_all<extrinsic_t>("{}/extrinsic");
        test_all<guarantees_extrinsic_t>("{}/guarantees_extrinsic");
        test_all<header_t>("{}/header_0");
        test_all<header_t>("{}/header_1");
        test_all<refine_context_t>("{}/refine_context");
        test_all<tickets_extrinsic_t>("{}/tickets_extrinsic");
        test_all<work_package_t>("{}/work_package");
        test_all<work_report_t>("{}/work_report");
        // config independent
        test_all<preimages_extrinsic_t>("tiny/preimages_extrinsic");
        test_all<preimages_extrinsic_t>("full/preimages_extrinsic");
        test_all<work_item_t>("tiny/work_item");
        test_all<work_item_t>("full/work_item");
        test_all<work_result_t>("tiny/work_result_0");
        test_all<work_result_t>("full/work_result_0");
        test_all<work_result_t>("tiny/work_result_1");
        test_all<work_result_t>("full/work_result_1");
    };
};
