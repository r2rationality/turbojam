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
        "protocol_id_t"_test = [] {
            "formats the canonical ALPN"_test = [] {
                const protocol_id_t protocol_id { 0, protocol_id_t::hash4_t::from_hex("0123abcd") };
                expect_equal(0U, protocol_id.version);
                expect_equal(false, protocol_id.builder);
                expect_equal(protocol_id_t::hash4_t::from_hex("0123abcd"), protocol_id.genesis_hash4);
                expect_equal("jamnp-s/0/0123abcd", static_cast<std::string>(protocol_id));
            };
            "formats the builder ALPN"_test = [] {
                const protocol_id_t protocol_id { 0, protocol_id_t::hash4_t::from_hex("89abcdef"), true };
                expect_equal(true, protocol_id.builder);
                expect_equal("jamnp-s/0/89abcdef/builder", static_cast<std::string>(protocol_id));
            };
            "parses the canonical ALPN"_test = [] {
                const auto protocol_id = protocol_id_t::from_text("jamnp-s/0/0123abcd");
                expect_equal(0U, protocol_id.version);
                expect_equal(false, protocol_id.builder);
                expect_equal(protocol_id_t::hash4_t::from_hex("0123abcd"), protocol_id.genesis_hash4);
            };
            "accepts the builder suffix"_test = [] {
                const auto protocol_id = protocol_id_t::from_text("jamnp-s/0/0123abcd/builder");
                expect_equal(0U, protocol_id.version);
                expect_equal(true, protocol_id.builder);
                expect_equal(protocol_id_t::hash4_t::from_hex("0123abcd"), protocol_id.genesis_hash4);
            };
            "compatibility ignores builder role"_test = [] {
                const auto peer = protocol_id_t::from_text("jamnp-s/0/0123abcd");
                const auto builder = protocol_id_t::from_text("jamnp-s/0/0123abcd/builder");
                expect(peer.compatible(peer));
                expect(peer.compatible(builder));
                expect(builder.compatible(builder));
                expect(builder.compatible(peer));
                expect(!peer.compatible(protocol_id_t {1, protocol_id_t::hash4_t::from_hex("0123abcd")}));
                expect(!peer.compatible(protocol_id_t{0, protocol_id_t::hash4_t::from_hex("89abcdef")}));
            };
            "rejects malformed ALPNs"_test = [] {
                expect(throws([] { protocol_id_t::from_text("jamnp-s/0"); }));
                expect(throws([] { protocol_id_t::from_text("jamnp-s/0/0123abcd/builder/extra"); }));
                expect(throws([] { protocol_id_t::from_text("jamnp-s/0/0123abcd/not-builder"); }));
                expect(throws([] { protocol_id_t::from_text("other/0/0123abcd"); }));
            };
            "rejects non-zero protocol versions"_test = [] {
                expect(throws([] { protocol_id_t::from_text("jamnp-s/1/0123abcd"); }));
            };
            "rejects non-lowercase genesis hash text"_test = [] {
                expect(throws([] { protocol_id_t::from_text("jamnp-s/0/0123ABCD"); }));
            };
        };

        "alternative_name"_test = [] {
            using crypto::ed25519::vkey_t;

            struct test_vector_t {
                const char *exp;
                const char *input;
            };

            const std::array<test_vector_t, 5> varlen_test_vectors{{
                {"", ""},
                {"ba", "01"},
                {"ae", "80"},
                {"aiaa", "0001"},
                {"byikutfrlnt7o", "0123456789abcdef"},
            }};
            for (const auto &[exp, input]: varlen_test_vectors)
                expect_equal(exp, alternative_name_varlen(uint8_vector::from_hex(input)));

            const std::array<test_vector_t, 7> test_vectors{{
                {"eaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "0000000000000000000000000000000000000000000000000000000000000000"},
                {"e777777777777777777777777777777777777777777777777777b", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"},
                {"e3r2oc62zwfj3crnuifuvsxvbtlzetk4o5qyhetkhagsc2fgl2oka", "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"},
                {"ebaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "0100000000000000000000000000000000000000000000000000000000000000"},
                {"eaeaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "8000000000000000000000000000000000000000000000000000000000000000"},
                {"eaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaiaa", "0000000000000000000000000000000000000000000000000000000000000001"},
                {"eaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab", "0000000000000000000000000000000000000000000000000000000000000080"},
            }};
            for (const auto &[exp, input]: test_vectors)
                expect_equal(exp, alternative_name(vkey_t::from_hex(input)));
        };
    };
};
