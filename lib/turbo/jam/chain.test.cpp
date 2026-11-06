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
        state_snapshot_t genesis_state{
            {state_dict_t::make_key(3), encode(recent_blocks_t<cfg>{})},
            {state_dict_t::make_key(4), encode(gamma)},
            {state_dict_t::make_key(6), encode(entropy_buffer_t{})}
        };
        genesis_t<cfg> genesis{genesis_state, state_t<cfg>::make_genesis_header(genesis_state)};
        // Exercise a supplied header that cannot be recovered by deriving it from state.
        genesis.header.slot = 3;
        const auto genesis_hash = genesis.header.hash();
        header_hash_t tip_hash{};
        tip_hash[0] = 1;
        recent_blocks_t<cfg> beta{};
        beta.history.emplace_back(block_info_t<cfg>{.header_hash = tip_hash, .slot = 7});
        auto snapshot = genesis.state;
        snapshot[state_dict_t::make_key(3)] = encode(beta);

        using reset_t = chain_t<cfg>::reset_t;
        // Reset and reopening must both restore a usable state and derived ancestry.
        for (const bool reopen: {false, true}) {
            const auto check = [&](const state_snapshot_t &previous,
                const auto &verify) {
                file::tmp_directory dir{"turbo-jam-chain-restore"};
                {
                    chain_t<cfg> chain{"restore", dir.path(), genesis, reset_t{previous}};
                    if (!reopen)
                        verify(chain);
                }
                if (reopen) {
                    chain_t<cfg> chain{"restore", dir.path(), genesis};
                    verify(chain);
                }
            };
            block_t<cfg> block{};
            check(snapshot, [&](auto &chain) {
                expect(chain.state().snapshot() == snapshot);
                expect_equal(chain.state_root(), snapshot.root());
                expect_equal(chain.parent(), tip_hash);
                block.header.parent = genesis_hash;
                expect(throws<err_bad_state_root_t>([&] { chain.apply(block); })) << "genesis is known with its root";
                block.header.parent = tip_hash;
                expect(throws<err_bad_state_root_t>([&] { chain.apply(block); })) << "beta tip is known";
            });

            auto genesis_beta = beta;
            genesis_beta.history.front().header_hash = genesis_hash;
            genesis_beta.history.front().slot = genesis.header.slot;
            auto genesis_in_beta = genesis.state;
            genesis_in_beta[state_dict_t::make_key(3)] = encode(genesis_beta);
            check(genesis_in_beta, [&](auto &chain) {
                block.header.parent = genesis_hash;
                block.header.parent_state_root = genesis.state.root();
                expect(throws<err_bad_state_root_t>([&] { chain.apply(block); })) << "genesis must not be duplicated by beta";
            });
        }
        file::tmp_directory dir{"turbo-jam-chain-reset"};
        const auto check_genesis = [&](const auto &chain) {
            expect(chain.state().snapshot() == genesis.state);
            expect_equal(chain.state_root(), genesis.state.root());
            expect_equal(chain.genesis_header(), genesis.header);
            expect_equal(chain.parent(), genesis_hash);
        };
        {
            chain_t<cfg> chain{"restore", dir.path(), genesis};
            check_genesis(chain);
        }
        ancestry_t<cfg> supplied{};
        supplied.add(7, tip_hash);
        // This key must disappear when resetting to genesis.
        snapshot[state_dict_t::make_key(250)] = byte_sequence_t{1, 2, 3};
        {
            chain_t<cfg> chain{"restore", dir.path(), genesis, reset_t{snapshot, supplied}};
            block_t<cfg> block{};
            block.header.parent = genesis_hash;
            expect(throws<err_unknown_parent_t>([&] { chain.apply(block); })) << "supplied ancestry excludes genesis";
            block.header.parent = tip_hash;
            expect(throws<err_bad_state_root_t>([&] { chain.apply(block); })) << "supplied ancestry remains usable after rejection";
        }
        expect(throws<error>([&] {
            chain_t<cfg> chain{"restore", dir.path(), genesis, reset_t{{}, supplied}};
        })) << "ancestry without state is invalid";
        {
            chain_t<cfg> chain{"restore", dir.path(), genesis};
            expect(chain.state().snapshot() == snapshot) << "invalid reset preserves storage";
        }
        {
            chain_t<cfg> chain{"restore", dir.path(), genesis, reset_t{}};
            check_genesis(chain);
            block_t<cfg> block{};
            block.header.parent = genesis_hash;
            expect(throws<err_bad_state_root_t>([&] { chain.apply(block); })) << "reset restores genesis ancestry";
            check_genesis(chain);
        }
        {
            chain_t<cfg> chain{"restore", dir.path(), genesis};
            check_genesis(chain);
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
