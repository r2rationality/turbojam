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
        using cfg = config_tiny;
        using reset_t = chain_t<cfg>::reset_t;

        const auto encode = [](const auto &value) {
            encoder enc{value};
            return byte_sequence_t{std::move(enc.bytes())};
        };
        const state_snapshot_t genesis_state{
            {state_dict_t::make_key(3), encode(recent_blocks_t<cfg>{})},
            {state_dict_t::make_key(4), encode(safrole_state_t<cfg>{
                .p = validators_data_t<cfg>{validators_data_t<cfg>::storage_type(cfg::V_validator_count_min)}
            })},
            {state_dict_t::make_key(6), encode(entropy_buffer_t{})}
        };
        const genesis_t<cfg> genesis{genesis_state, state_t<cfg>::make_genesis_header(genesis_state, 3)};
        const auto genesis_hash = genesis.header.hash();
        const auto genesis_root = genesis.state.root();

        header_hash_t tip_hash{};
        tip_hash[0] = 1;
        recent_blocks_t<cfg> recent_blocks{};
        recent_blocks.history.emplace_back(block_info_t<cfg>{.header_hash = tip_hash, .slot = 7});
        auto snapshot = genesis.state;
        snapshot[state_dict_t::make_key(3)] = encode(recent_blocks);
        snapshot[state_dict_t::make_key(250)] = byte_sequence_t{1, 2, 3};
        const auto snapshot_root = snapshot.root();
        const genesis_t<cfg> snapshot_genesis{snapshot, genesis.header};
        partial_ancestry_t<cfg> supplied_ancestry{};
        supplied_ancestry.emplace_back(7, tip_hash);

        block_t<cfg> bad_genesis_block{};
        bad_genesis_block.header.parent = genesis_hash;
        bad_genesis_block.header.parent_state_root = genesis_root;
        bad_genesis_block.header.parent_state_root[0] ^= 1;
        block_t<cfg> bad_tip_block{};
        bad_tip_block.header.parent = tip_hash;
        bad_tip_block.header.parent_state_root = snapshot_root;
        bad_tip_block.header.parent_state_root[0] ^= 1;

        "opening an uninitialized database fails"_test = [] {
            file::tmp_directory dir{"turbo-jam-chain-empty"};

            expect(throws<error>([&] {
                chain_t<cfg> chain{"restore", dir.path()};
            }));
        };

        "reset restores the supplied genesis"_test = [&] {
            file::tmp_directory dir{"turbo-jam-chain-genesis"};
            chain_t<cfg> chain{"restore", dir.path(), reset_t{genesis}};

            expect(chain.state().snapshot() == genesis.state);
            expect_equal(chain.state_root(), genesis_root);
            expect_equal(chain.genesis().slot, genesis.header.slot);
            expect_equal(chain.genesis().header_hash, genesis_hash);
            expect(chain.genesis().state_root == genesis_root);
            expect_equal(chain.parent(), genesis_hash);
        };

        "reopening restores the supplied genesis"_test = [&] {
            file::tmp_directory dir{"turbo-jam-chain-reopen-genesis"};
            {
                chain_t<cfg> initialized{"restore", dir.path(), reset_t{genesis}};
            }
            chain_t<cfg> chain{"restore", dir.path()};

            expect(chain.state().snapshot() == genesis.state);
            expect_equal(chain.state_root(), genesis_root);
            expect_equal(chain.genesis().slot, genesis.header.slot);
            expect_equal(chain.genesis().header_hash, genesis_hash);
            expect(chain.genesis().state_root == genesis_root);
            expect_equal(chain.parent(), genesis_hash);
        };

        "empty ancestry falls back to recent block tip"_test = [&] {
            file::tmp_directory dir{"turbo-jam-chain-recent-blocks"};
            chain_t<cfg> chain{"restore", dir.path(), reset_t{snapshot_genesis}};
            block_t<cfg> stale_root_block{};
            stale_root_block.header.parent = genesis_hash;
            stale_root_block.header.parent_state_root = genesis_root;

            expect(chain.state().snapshot() == snapshot);
            expect_equal(chain.state_root(), snapshot_root);
            expect_equal(chain.parent(), tip_hash);
            expect(throws<err_unknown_parent_t>([&] { chain.apply(stale_root_block); }));
            expect(throws<err_bad_state_root_t>([&] { chain.apply(bad_tip_block); }));
        };

        "supplied ancestry excludes genesis and survives rejection"_test = [&] {
            file::tmp_directory dir{"turbo-jam-chain-ancestry"};
            chain_t<cfg> chain{"restore", dir.path(), reset_t{snapshot_genesis, supplied_ancestry}};

            expect_equal(chain.parent(), tip_hash);
            expect(throws<err_unknown_parent_t>([&] { chain.apply(bad_genesis_block); }));
            expect(throws<err_bad_state_root_t>([&] { chain.apply(bad_tip_block); }));
            expect(chain.state().snapshot() == snapshot);
            expect_equal(chain.state_root(), snapshot_root);
            expect_equal(chain.parent(), tip_hash);
        };

        "reopening restores supplied ancestry"_test = [&] {
            file::tmp_directory dir{"turbo-jam-chain-reopen-ancestry"};
            {
                chain_t<cfg> initialized{"restore", dir.path(), reset_t{snapshot_genesis, supplied_ancestry}};
            }
            chain_t<cfg> chain{"restore", dir.path()};

            expect(chain.state().snapshot() == snapshot);
            expect_equal(chain.state_root(), snapshot_root);
            expect_equal(chain.genesis().header_hash, genesis_hash);
            expect(chain.genesis().state_root == snapshot_root);
            expect_equal(chain.parent(), tip_hash);
            expect(throws<err_unknown_parent_t>([&] { chain.apply(bad_genesis_block); }));
            expect(throws<err_bad_state_root_t>([&] { chain.apply(bad_tip_block); }));
        };

        "reset replaces stored state and ancestry"_test = [&] {
            file::tmp_directory dir{"turbo-jam-chain-reset"};
            {
                chain_t<cfg> initialized{"restore", dir.path(), reset_t{snapshot_genesis, supplied_ancestry}};
            }
            chain_t<cfg> chain{"restore", dir.path(), reset_t{genesis}};

            expect(chain.state().snapshot() == genesis.state);
            expect_equal(chain.state_root(), genesis_root);
            expect_equal(chain.genesis().header_hash, genesis_hash);
            expect(chain.genesis().state_root == genesis_root);
            expect_equal(chain.parent(), genesis_hash);
            expect(throws<err_unknown_parent_t>([&] { chain.apply(bad_tip_block); }));
            expect(throws<err_bad_state_root_t>([&] { chain.apply(bad_genesis_block); }));
            expect(chain.state().snapshot() == genesis.state);
            expect_equal(chain.state_root(), genesis_root);
            expect_equal(chain.parent(), genesis_hash);
        };

        "reopening preserves the reset"_test = [&] {
            file::tmp_directory dir{"turbo-jam-chain-reopen-reset"};
            {
                chain_t<cfg> initialized{"restore", dir.path(), reset_t{snapshot_genesis, supplied_ancestry}};
            }
            {
                chain_t<cfg> reset{"restore", dir.path(), reset_t{genesis}};
            }
            chain_t<cfg> chain{"restore", dir.path()};

            expect(chain.state().snapshot() == genesis.state);
            expect_equal(chain.state_root(), genesis_root);
            expect_equal(chain.genesis().header_hash, genesis_hash);
            expect(chain.genesis().state_root == genesis_root);
            expect_equal(chain.parent(), genesis_hash);
            expect(throws<err_unknown_parent_t>([&] { chain.apply(bad_tip_block); }));
            expect(throws<err_bad_state_root_t>([&] { chain.apply(bad_genesis_block); }));
        };
    };
};
