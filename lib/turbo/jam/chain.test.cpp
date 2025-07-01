/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/test.hpp>
#include "chain.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jam;
}

suite turbo_jam_chain_suite = [] {
    "turbo::jam::chain"_test = [] {
        auto chain = chain_t<config_tiny>::from_json_spec(file::install_path("tmp/dev-chain"), file::install_path("etc/devnet/dev-spec.json"));
        logger::info("genesis header hash: {}", chain.genesis_header().hash());
        logger::info("genesis state root: {}", chain.genesis_state().root());
        for (const auto &[k, v]: chain.genesis_state()) {
            logger::info("genesis {}: size: {} hash: {}", k, v.size(), crypto::blake2b::digest(v));
        }
        const auto bytes = file::read(file::install_path("data/devnet-blocks.bin"));
        decoder dec { bytes };
        for (size_t i = 0; !dec.empty() && i < 2; ++i) {
            auto blk = codec::from<block_t<config_tiny>>(dec);
            logger::info("block #{} slot: {} hash: {} parent_root: {} bytes left: {}", i, blk.header.slot, blk.header.hash(), blk.header.parent_state_root, dec.size());
            const auto pre_root = chain.state_root();
            chain.apply(blk);
            logger::info("block #{} pre_root: {} post_root: {}", i, pre_root, chain.state_root());
            chain.state().foreach([](const auto &k, const auto &v) {
                logger::info("{}: size: {} hash: {}", k, v.size(), crypto::blake2b::digest(v));
            });
        }
    };
};
