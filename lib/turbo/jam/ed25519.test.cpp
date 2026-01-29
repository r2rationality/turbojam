/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <ed25519-consensus.hpp>
#include <turbo/crypto/ed25519.hpp>
#include <turbo/common/test.hpp>
#include "chain.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jam;
    using namespace turbo::crypto::ed25519;
}

suite turbo_jam_ed25519_suite = [] {
    "turbo::jam::ed25519"_test = [] {
        const auto vectors = codec::json::load(file::install_path("test/jam-conformance/crypto/ed25519/vectors.json")).as_array();
        expect(!vectors.empty());
        for (const auto &v: vectors) {
            const auto pk = vkey_t::from_hex(v.at("pk").as_string());
            signature_t sig;
            init_from_hex_no_prefix(std::span{sig.begin(), sig.begin() + 32U}, v.at("r").as_string());
            init_from_hex_no_prefix(std::span{sig.begin() + 32, sig.end()}, v.at("s").as_string());
            const auto msg = uint8_vector::from_hex(v.at("msg").as_string());
            expect(ed25519_consensus::zip215_verify(sig, msg, pk));
        }
    };
};
