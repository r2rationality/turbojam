/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025-2026 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/test.hpp>
#include "jamnp.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jamnp;
}

const suite turbo_jamnp_jamnp_suite = [] {
    "turbo::jamnp::jamnp"_test = [] {
        "protocol_id_t formats the canonical ALPN"_test = [] {
            const protocol_id_t protocol_id { 0, protocol_id_t::hash4_t::from_hex("0123abcd") };
            expect_equal(0U, protocol_id.version);
            expect_equal(false, protocol_id.builder);
            expect_equal(protocol_id_t::hash4_t::from_hex("0123abcd"), protocol_id.genesis_hash4);
            expect_equal("jamnp-s/0/0123abcd", static_cast<std::string>(protocol_id));
        };
        "protocol_id_t formats the builder ALPN"_test = [] {
            const protocol_id_t protocol_id { 0, protocol_id_t::hash4_t::from_hex("89abcdef"), true };
            expect_equal(true, protocol_id.builder);
            expect_equal("jamnp-s/0/89abcdef/builder", static_cast<std::string>(protocol_id));
        };
        "protocol_id_t parses the canonical ALPN"_test = [] {
            const auto protocol_id = protocol_id_t::from_text("jamnp-s/0/0123abcd");
            expect_equal(0U, protocol_id.version);
            expect_equal(false, protocol_id.builder);
            expect_equal(protocol_id_t::hash4_t::from_hex("0123abcd"), protocol_id.genesis_hash4);
        };
        "protocol_id_t accepts the builder suffix"_test = [] {
            const auto protocol_id = protocol_id_t::from_text("jamnp-s/0/0123abcd/builder");
            expect_equal(0U, protocol_id.version);
            expect_equal(true, protocol_id.builder);
            expect_equal(protocol_id_t::hash4_t::from_hex("0123abcd"), protocol_id.genesis_hash4);
        };
        "protocol_id_t compatibility ignores builder role"_test = [] {
            const auto peer = protocol_id_t::from_text("jamnp-s/0/0123abcd");
            const auto builder = protocol_id_t::from_text("jamnp-s/0/0123abcd/builder");
            expect(peer.compatible(peer));
            expect(peer.compatible(builder));
            expect(builder.compatible(builder));
            expect(builder.compatible(peer));
            expect(!peer.compatible(protocol_id_t {1, protocol_id_t::hash4_t::from_hex("0123abcd")}));
            expect(!peer.compatible(protocol_id_t{0, protocol_id_t::hash4_t::from_hex("89abcdef")}));
        };
        "protocol_id_t rejects malformed ALPNs"_test = [] {
            expect(throws([] { protocol_id_t::from_text("jamnp-s/0"); }));
            expect(throws([] { protocol_id_t::from_text("jamnp-s/0/0123abcd/builder/extra"); }));
            expect(throws([] { protocol_id_t::from_text("jamnp-s/0/0123abcd/not-builder"); }));
            expect(throws([] { protocol_id_t::from_text("other/0/0123abcd"); }));
        };
        "protocol_id_t rejects non-zero protocol versions"_test = [] {
            expect(throws([] { protocol_id_t::from_text("jamnp-s/1/0123abcd"); }));
        };
        "protocol_id_t rejects non-lowercase genesis hash text"_test = [] {
            expect(throws([] { protocol_id_t::from_text("jamnp-s/0/0123ABCD"); }));
        };
    };
};
