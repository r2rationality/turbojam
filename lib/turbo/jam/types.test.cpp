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
    void test_decode(const std::string &prefix, const std::source_location &loc=std::source_location::current())
    {
        const auto bytes = file::read(prefix + ".bin");
        decoder dec { bytes };
        expect(!dec.empty(), loc);
        const auto j = codec::json::load(prefix + ".json");
        if constexpr (codec::serializable_c<T>) {
            codec::json::decoder j_dec { j };
            const auto j_val = T::from(j_dec);
            const auto b_val = T::from(dec);
            expect(dec.empty(), loc) << prefix;
            expect(j_val == b_val) << prefix;
        } else if constexpr (from_json_c<T> && from_bytes_c<T>) {
            const auto b_val = T::from_bytes(dec);
            expect(dec.empty(), loc) << prefix;
            const auto j_val = T::from_json(j);
            expect(j_val == b_val) << prefix;
        } else {
            throw error(fmt::format("serialization to supported for {}", typeid(T).name()));
        }
    }

    template<typename T>
    void test_roundtrip(const std::string &prefix)
    {
        const auto bytes = file::read(prefix + ".bin");
        decoder dec { bytes };
        const auto b = T::from(dec);
        encoder enc {};
        b.serialize(enc);
        expect(enc.bytes() == bytes) << prefix;
    }
}

suite turbo_jam_types_suite = [] {
    "turbo::jam::types"_test = [] {
        "serialization round trip"_test = [] {
            test_roundtrip<assurances_extrinsic_t<config_tiny>>(file::install_path("test/jam-test-vectors/codec/data/assurances_extrinsic"));
            test_roundtrip<block_t<config_tiny>>(file::install_path("test/jam-test-vectors/codec/data/block"));
            test_roundtrip<disputes_extrinsic_t<config_tiny>>(file::install_path("test/jam-test-vectors/codec/data/disputes_extrinsic"));
            test_roundtrip<extrinsic_t<config_tiny>>(file::install_path("test/jam-test-vectors/codec/data/extrinsic"));
            test_roundtrip<guarantees_extrinsic_t<config_tiny>>(file::install_path("test/jam-test-vectors/codec/data/guarantees_extrinsic"));
            test_roundtrip<header_t<config_tiny>>(file::install_path("test/jam-test-vectors/codec/data/header_0"));
            test_roundtrip<header_t<config_tiny>>(file::install_path("test/jam-test-vectors/codec/data/header_1"));
            test_roundtrip<preimages_extrinsic_t>(file::install_path("test/jam-test-vectors/codec/data/preimages_extrinsic"));
            test_roundtrip<refine_context_t<config_tiny>>(file::install_path("test/jam-test-vectors/codec/data/refine_context"));
            test_roundtrip<tickets_extrinsic_t<config_tiny>>(file::install_path("test/jam-test-vectors/codec/data/tickets_extrinsic"));
            test_roundtrip<work_item_t>(file::install_path("test/jam-test-vectors/codec/data/work_item"));
            test_roundtrip<work_package_t<config_tiny>>(file::install_path("test/jam-test-vectors/codec/data/work_package"));
            test_roundtrip<work_report_t<config_tiny>>(file::install_path("test/jam-test-vectors/codec/data/work_report"));
            test_roundtrip<work_result_t>(file::install_path("test/jam-test-vectors/codec/data/work_result_0"));
            test_roundtrip<work_result_t>(file::install_path("test/jam-test-vectors/codec/data/work_result_1"));
        };
        "conformance test vectors"_test = [] {
            test_decode<assurances_extrinsic_t<config_tiny>>(file::install_path("test/jam-test-vectors/codec/data/assurances_extrinsic"));
            test_decode<block_t<config_tiny>>(file::install_path("test/jam-test-vectors/codec/data/block"));
            test_decode<disputes_extrinsic_t<config_tiny>>(file::install_path("test/jam-test-vectors/codec/data/disputes_extrinsic"));
            test_decode<extrinsic_t<config_tiny>>(file::install_path("test/jam-test-vectors/codec/data/extrinsic"));
            test_decode<guarantees_extrinsic_t<config_tiny>>(file::install_path("test/jam-test-vectors/codec/data/guarantees_extrinsic"));
            test_decode<header_t<config_tiny>>(file::install_path("test/jam-test-vectors/codec/data/header_0"));
            test_decode<header_t<config_tiny>>(file::install_path("test/jam-test-vectors/codec/data/header_1"));
            test_decode<preimages_extrinsic_t>(file::install_path("test/jam-test-vectors/codec/data/preimages_extrinsic"));
            test_decode<refine_context_t<config_tiny>>(file::install_path("test/jam-test-vectors/codec/data/refine_context"));
            test_decode<tickets_extrinsic_t<config_tiny>>(file::install_path("test/jam-test-vectors/codec/data/tickets_extrinsic"));
            test_decode<work_item_t>(file::install_path("test/jam-test-vectors/codec/data/work_item"));
            test_decode<work_package_t<config_tiny>>(file::install_path("test/jam-test-vectors/codec/data/work_package"));
            test_decode<work_report_t<config_tiny>>(file::install_path("test/jam-test-vectors/codec/data/work_report"));
            test_decode<work_result_t>(file::install_path("test/jam-test-vectors/codec/data/work_result_0"));
            test_decode<work_result_t>(file::install_path("test/jam-test-vectors/codec/data/work_result_1"));
        };
    };
};
