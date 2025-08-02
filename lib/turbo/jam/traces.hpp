#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/jam/types/header.hpp>
#include <turbo/jam/types/state-dict.hpp>

namespace turbo::jam::traces {
    struct raw_state_t {
        state_root_t state_root;
        state_snapshot_t keyvals;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("state_root"sv, state_root);
            archive.process("keyvals"sv, keyvals);
        }

        bool operator==(const raw_state_t &o) const
        {
            if (state_root != o.state_root)
                return false;
            if (keyvals != o.keyvals)
                return false;
            return true;
        }
    };

    struct test_genesis_state_t {
        state_root_t state_root;
        state_snapshot_t keyvals;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("state_root"sv, state_root);
            archive.process("keyvals"sv, keyvals);
        }
    };

    template<typename CFG>
    struct test_genesis_t {
        header_t<CFG> header;
        test_genesis_state_t state;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("header"sv, header);
            archive.process("state"sv, state);
        }
    };

    struct test_case_t {
        raw_state_t pre;
        block_t<config_tiny> block;
        raw_state_t post;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("pre_state"sv, pre);
            archive.process("block"sv, block);
            archive.process("post_state"sv, post);
        }

        bool operator==(const test_case_t &o) const
        {
            if (pre != o.pre)
                return false;
            if (block != o.block)
                return false;
            if (post != o.post)
                return false;
            return true;
        }
    };
}
