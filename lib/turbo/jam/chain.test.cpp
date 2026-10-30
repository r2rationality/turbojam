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
    "turbo::jam::chain::restore"_test = [] {
        using cfg = config_tiny;
        const auto encode = [](const auto &value) {
            const encoder enc{value};
            return byte_sequence_t{enc.bytes().begin(), enc.bytes().end()};
        };
        safrole_state_t<cfg> gamma{};
        gamma.p = validators_data_t<cfg>{validators_data_t<cfg>::storage_type(cfg::V_validator_count_min)};
        state_snapshot_t genesis{
            {state_dict_t::make_key(3), encode(recent_blocks_t<cfg>{})},
            {state_dict_t::make_key(4), encode(gamma)},
            {state_dict_t::make_key(6), encode(entropy_buffer_t{})}
        };
        const auto genesis_hash = state_t<cfg>::make_genesis_header(genesis).hash();
        header_hash_t tip_hash{};
        tip_hash[0] = 1;
        recent_blocks_t<cfg> beta{};
        beta.history.emplace_back(block_info_t<cfg>{.header_hash = tip_hash, .slot = 7});
        auto snapshot = genesis;
        snapshot[state_dict_t::make_key(3)] = encode(beta);

        // Exercise both entry points through their observable parent-validation errors.
        for (const bool via_reset: {false, true}) {
            const auto check = [&](const state_snapshot_t &previous, std::optional<ancestry_t<cfg>> ancestry,
                const auto &verify) {
                file::tmp_directory dir{"turbo-jam-chain-restore"};
                chain_t<cfg> chain{"restore", dir.path(), genesis,
                    via_reset ? state_snapshot_t{} : previous, via_reset ? std::nullopt : ancestry, false};
                if (via_reset)
                    chain.reset(genesis, previous, std::move(ancestry));
                verify(chain);
            };
            block_t<cfg> block{};
            check(snapshot, std::nullopt, [&](auto &chain) {
                block.header.parent = genesis_hash;
                expect(throws<err_bad_state_root_t>([&] { chain.apply(block); })) << "genesis is known with its root";
                block.header.parent = tip_hash;
                expect(throws<err_bad_state_root_t>([&] { chain.apply(block); })) << "beta tip is known";
            });

            ancestry_t<cfg> supplied{};
            supplied.add(7, tip_hash);
            check(snapshot, supplied, [&](auto &chain) {
                block.header.parent = genesis_hash;
                expect(throws<err_unknown_parent_t>([&] { chain.apply(block); })) << "explicit ancestry excludes genesis";
                block.header.parent = tip_hash;
                expect(throws<err_bad_state_root_t>([&] { chain.apply(block); })) << "beta must not duplicate the supplied tip";
            });
            check(snapshot, ancestry_t<cfg>{}, [&](auto &chain) {
                block.header.parent = tip_hash;
                expect(throws<err_unknown_parent_t>([&] { chain.apply(block); })) << "explicit empty ancestry stays empty";
            });

            auto genesis_beta = beta;
            genesis_beta.history.front().header_hash = genesis_hash;
            genesis_beta.history.front().slot = 0;
            auto genesis_in_beta = genesis;
            genesis_in_beta[state_dict_t::make_key(3)] = encode(genesis_beta);
            check(genesis_in_beta, std::nullopt, [&](auto &chain) {
                block.header.parent = genesis_hash;
                block.header.parent_state_root = genesis.root();
                expect(throws<err_bad_state_root_t>([&] { chain.apply(block); })) << "genesis must not be duplicated by beta";
            });
        }
    };
    "turbo::jam::chain"_test = [] {
        /*auto chain = chain_t<config_tiny>::from_json_spec(file::install_path("tmp/dev-chain"), file::install_path("etc/devnet/dev-spec.json"));
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
        }*/
    };
};
