/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/test.hpp>
#include "types/common.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jam;
}

suite turbo_jam_mmr_suite = [] {
    "turbo::jam::mmr"_test = [] {
        "append to empty"_test = [] {
            mmr_t r{};
            expect_equal(opaque_hash_t{}, r.root());
            r.append(opaque_hash_t::from_hex<opaque_hash_t>("8720B97DDD6ACC0F6EB66E095524038675A4E4067ADC10EC39939EAEFC47D842"));
            expect_equal(
                mmr_peaks_t{
                    opaque_hash_t::from_hex<opaque_hash_t>("8720B97DDD6ACC0F6EB66E095524038675A4E4067ADC10EC39939EAEFC47D842")
                },
                r
            );
            expect_equal(opaque_hash_t::from_hex<opaque_hash_t>("8720B97DDD6ACC0F6EB66E095524038675A4E4067ADC10EC39939EAEFC47D842"), r.root());
            r.append(opaque_hash_t::from_hex<opaque_hash_t>("7507515A48439DC58BC318C48A120B656136699F42BFD2BD45473BECBA53462D"));
            expect_equal(
                mmr_peaks_t{
                    std::nullopt,
                    opaque_hash_t::from_hex<opaque_hash_t>("7076C31882A5953E097AEF8378969945E72807C4705E53A0C5AACC9176F0D56B")
                },
                r
            );
            expect_equal(opaque_hash_t::from_hex<opaque_hash_t>("7076C31882A5953E097AEF8378969945E72807C4705E53A0C5AACC9176F0D56B"), r.root());
        };
        "append to non-empty"_test = [] {
            mmr_t r{std::initializer_list<mmr_peak_t>{
                opaque_hash_t::from_hex<opaque_hash_t>("F986BFEFF7411437CA6A23163A96B5582E6739F261E697DC6F3C05A1ADA1ED0C"),
                opaque_hash_t::from_hex<opaque_hash_t>("CA29F72B6D40CFDB5814569CF906B3D369AE5F56B63D06F2B6BB47BE191182A6"),
                opaque_hash_t::from_hex<opaque_hash_t>("E17766E385AD36F22FF2357053AB8AF6A6335331B90DE2AA9C12EC9F397FA414"),
            }};
            r.append(opaque_hash_t::from_hex<opaque_hash_t>("8223D5EAA57CCEF85993B7180A593577FD38A65FB41E4BCEA2933D8B202905F0"));
            expect_equal(
                mmr_peaks_t{
                    std::nullopt,
                    std::nullopt,
                    std::nullopt,
                    opaque_hash_t::from_hex<opaque_hash_t>("658B919F734BD39262C10589AA1AFC657471D902A6A361C044F78DE17D660BC6")
                },
                r
            );
            expect_equal(opaque_hash_t::from_hex<opaque_hash_t>("658B919F734BD39262C10589AA1AFC657471D902A6A361C044F78DE17D660BC6"), r.root());
        };
        "root"_test = [] {
            mmr_t r{std::initializer_list<mmr_peak_t>{
                std::nullopt,
                opaque_hash_t::from_hex<opaque_hash_t>("4ABFFEBD18DC4A8E7E87F60A38D362ACDC2C10735C582D73C233222E99997CA1"),
                opaque_hash_t::from_hex<opaque_hash_t>("4BEBAC8EBC0C117690C1C2987388D72DA201E1571957820C1691541B74F850E8"),
                opaque_hash_t::from_hex<opaque_hash_t>("8A600CAEC569C90A3D8D34AB0CA199D6303A6B6EB356017EEA611AF52EAEDA71"),
                opaque_hash_t::from_hex<opaque_hash_t>("65C3B194F6910870ED1089730A2A70F60F8CEA24675CE5946ECAFB69456A4954"),
                opaque_hash_t::from_hex<opaque_hash_t>("44CF06DD58140FC47A44D2950AF3366568029A422AFBAC9A3254BBA88FA8C17E"),
                std::nullopt,
                opaque_hash_t::from_hex<opaque_hash_t>("12C6A3318C7F39B36694A39FB1A3846796B8E97F1D70ED141DB7B0851C28640E"),
            }};
            expect_equal(opaque_hash_t::from_hex<opaque_hash_t>("2BF5412022971EFBC2EAE2B13DD5FABC3F921CB683840B54C1A76820EF3E3F0A"), r.root());
        };
    };
};
