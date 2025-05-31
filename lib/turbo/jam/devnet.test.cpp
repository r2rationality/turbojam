/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <boost/json.hpp>
#include <turbo/common/file.hpp>
#include <turbo/common/test.hpp>
#include "types.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jam;
}

suite turbo_jam_devnet_suite = [] {
    "turbo::jam::devnet"_test = [] {
        "import block"_test = [] {
            const auto block_raw = uint8_vector::from_hex("F00200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001EE155ACE9C40292074CB6AFF8C9CCDD273C81648FF1149EF36BCEA6EBB8A3E25BB30A42C1E62F0AFDA5F0A4E8A562F7A13A24CEA00EE81917B86B89E801314AAFF71C6C03FF88ADB5ED52C9681DE1629A54E702FC14729F6B50D2F0A76F185B34418FB8C85BB3985394A8C2756D3643457CE614546202A2F50B093D762499ACEDEE6D555B82024F1CCF8A1E37E60FA60FD40B1958C4BB3006AF78647950E1B91AD93247BD01307550EC7ACD757CE6FB805FCF73DB364063265B30A949E90D9339326EDB21E5541717FDE24EC085000B28709847B8AAB1AC51F84E94B37CA1B66CAB2B9FF25C2410FBE9B8A717ABB298C716A03983C98CEB4DEF2087500B8E3410746846D17469FB2F95EF365EFCAB9F4E22FA1FEB53111C995376BE8019981CCF30AA5444688B3CAB47697B37D5CAC5707BB3289E986B19B17DB437206931A8D151E5C8FE2B9D8A606966A79EDD2F9E5DB47E83947CE368CCBA53BF6BA20A40B8B8C5D436F92ECF605421E873A99EC528761EB52A88A2F9A057B3B3003E6F32A2105650944FCD101621FD5BB3124C9FD191D114B7AD936C1D79D734F9F21392EAB0084D01534B31C1DD87C81645FD762482A90027754041CA1B56133D0466C060000FFFF00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
            decoder dec { block_raw };
            const auto msg_size = dec.uint_fixed<size_t>(4);
            expect_equal(msg_size, block_raw.size() - 4);
            const auto block = codec::from<block_t<config_tiny>>(dec);
            expect_equal(
                header_hash_t::from_hex("B5AF8EDAD70D962097EEFA2CEF92C8284CF0A7578B70A6B7554CF53AE6D51222"),
                block.header.hash()
            );
        };
        "parse config"_test = [] {
            const auto j_cfg = codec::json::load(file::install_path("etc/devnet/dev-spec.json"));
            const auto genesis_header_bytes = uint8_vector::from_hex(boost::json::value_to<std::string_view>(j_cfg.at("genesis_header")));
            decoder dec { genesis_header_bytes };
            const auto genesis_header = codec::from<header_t<config_tiny>>(dec);
            expect_equal(
                header_hash_t::from_hex("B5AF8EDAD70D962097EEFA2CEF92C8284CF0A7578B70A6B7554CF53AE6D51222"),
                genesis_header.hash()
            );

            const auto &genesis_state = j_cfg.at("genesis_state").as_object();
            state_dict_t state_dict {};
            for (const auto &[k, v]: genesis_state) {
                state_dict.emplace(state_key_t::from_hex(k), byte_sequence_t::from_hex(v.as_string()));
            }
            const auto genesis_root = state_dict.root();
            expect_equal(state_root_t::from_hex("DB29024A82CA5F628A2DABE26B896DAA7C8AF44D6752CD31528589E68ECC84C9"), genesis_root);
        };
    };
};
