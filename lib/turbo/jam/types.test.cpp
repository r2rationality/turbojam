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

    template<typename CFG>
    void test_package_limits()
    {
        work_package_t<CFG> p{};
        expect(throws([&] { p.validate_limits(); }));
        p.items.resize(2);
        auto &a = p.items[0];
        auto &b = p.items[1];
        a.refine_gas_limit = CFG::GR_max_refine_gas - 1;
        b.refine_gas_limit = 1;
        a.accumulate_gas_limit = CFG::GA_max_accumulate_gas - 1;
        b.accumulate_gas_limit = 1;
        a.import_segments.resize(CFG::WM_max_work_package_imports - 1);
        b.import_segments.resize(1);
        a.export_count = CFG::WX_max_package_exports - 1;
        b.export_count = 1;
        a.extrinsic.resize(CFG::T_max_package_extrinsics - 1);
        b.extrinsic.resize(1);
        p.authorization.resize(3);
        p.authorizer_config.resize(5);
        a.payload.resize(7);
        b.extrinsic[0].len = CFG::WI_max_work_package_input_size
            - CFG::WM_max_work_package_imports * CFG::WF_segment_footprint - 15;
        expect(nothrow([&] { p.validate_limits(); })) << "all aggregate limits inclusive";

        const auto rejects = [&](auto change) {
            auto invalid = p;
            change(invalid);
            expect(throws([&] { invalid.validate_limits(); }));
        };
        rejects([](auto &v) { ++v.items[1].refine_gas_limit; });
        rejects([](auto &v) { ++v.items[1].accumulate_gas_limit; });
        rejects([](auto &v) { v.items[1].import_segments.emplace_back(); });
        rejects([](auto &v) { ++v.items[1].export_count; });
        rejects([](auto &v) { v.items[1].extrinsic.emplace_back(); });
        // Together with the exact-limit case, this detects any omitted input-size contribution.
        rejects([](auto &v) { ++v.items[1].extrinsic[0].len; });
        rejects([](auto &v) { v.items.resize(CFG::I_max_work_items + 1); });
        rejects([](auto &v) { v.context.prerequisites.resize(CFG::J_max_report_dependencies + 1); });
        // Exercise the shared bounded-addition helper with a sum that would wrap uint64_t.
        rejects([](auto &v) { v.items[1].refine_gas_limit = std::numeric_limits<gas_t>::max(); });
    }
}

suite turbo_jam_types_suite = [] {
    "turbo::jam::types::common::epoch_mark_validators"_test = [] {
        using validators_t = epoch_mark_validators_t<config_tiny>;
        for (const size_t count: {size_t{0}, config_tiny::V_validator_count_min - 1, config_tiny::V_validator_count_max}) {
            const encoder enc{sequence_t<epoch_mark_validator_keys_t>(count)};
            expect_equal(count, jam::from_bytes<validators_t>(enc.bytes()).size());
        }
        const encoder oversized{sequence_t<epoch_mark_validator_keys_t>(config_tiny::V_validator_count_max + 1)};
        expect(throws([&] { (void)jam::from_bytes<validators_t>(oversized.bytes()); }));
    };
    "turbo::jam::types::common::work_package"_test = [] {
        test_package_limits<config_tiny>();
        test_package_limits<config_prod>();
    };
    "turbo::jam::types::common::work_digest"_test = [] {
        work_item_t item{};
        item.import_segments.resize(129);
        item.extrinsic.resize(2);
        item.extrinsic[0].len = 7;
        item.extrinsic[1].len = 11;
        const work_digest_t digest{item, work_result_ok_t{}, 42};
        expect_equal(uint16_t{129}, digest.refine_load.imports.value());
        expect_equal(uint16_t{2}, digest.refine_load.extrinsic_count.value());
        expect_equal(uint32_t{18}, digest.refine_load.extrinsic_size.value());
        item.extrinsic[0].len = std::numeric_limits<uint32_t>::max();
        expect(throws([&] { (void)work_digest_t{item, work_result_ok_t{}, 0}; }));
    };
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
        test_all<work_digest_t>("tiny/work_result_0");
        test_all<work_digest_t>("full/work_result_0");
        test_all<work_digest_t>("tiny/work_result_1");
        test_all<work_digest_t>("full/work_result_1");
    };
};
