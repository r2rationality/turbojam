/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025-2026 R2 Rationality OÃœ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <utility>
#include <turbo/common/logger.hpp>
#include <turbo/common/numeric-cast.hpp>
#include <turbo/jam/types/state-dict.hpp>
#include <turbo/jam/chain.hpp>
#include "jamnp.hpp"
#include "internal/gnutls.hpp"

namespace turbo::jamnp {
    namespace {
        void check_gnutls(const int err, const std::string_view what) {
            if (err < 0) [[unlikely]]
                throw error(fmt::format("{} failed: {}", what, internal::gnutls_error_text(err)));
        }

        struct gnutls_crt_scope_t {
            gnutls_crt_scope_t() {
                check_gnutls(gnutls_x509_crt_init(&value), "gnutls_x509_crt_init");
            }

            ~gnutls_crt_scope_t() {
                if (value)
                    gnutls_x509_crt_deinit(value);
            }

            [[nodiscard]] gnutls_x509_crt_t release() noexcept {
                return std::exchange(value, nullptr);
            }

            gnutls_x509_crt_t value = nullptr;
        };

        struct gnutls_privkey_scope_t {
            gnutls_privkey_scope_t() {
                check_gnutls(gnutls_x509_privkey_init(&value), "gnutls_x509_privkey_init");
            }

            ~gnutls_privkey_scope_t() {
                if (value)
                    gnutls_x509_privkey_deinit(value);
            }

            [[nodiscard]] gnutls_x509_privkey_t release() noexcept {
                return std::exchange(value, nullptr);
            }

            gnutls_x509_privkey_t value = nullptr;
        };
    }

    cert_pair_t::~cert_pair_t() {
        if (certificate)
            gnutls_x509_crt_deinit(certificate);
        if (private_key)
            gnutls_x509_privkey_deinit(private_key);
    }

    cert_pair_t::cert_pair_t(cert_pair_t &&o) noexcept:
        certificate{std::exchange(o.certificate, nullptr)},
        private_key{std::exchange(o.private_key, nullptr)}
    {
    }

    cert_pair_t &cert_pair_t::operator=(cert_pair_t &&o) noexcept {
        if (this != &o) {
            cert_pair_t tmp{std::move(o)};
            std::swap(certificate, tmp.certificate);
            std::swap(private_key, tmp.private_key);
        }
        return *this;
    }

    bool cert_pair_t::empty() const noexcept {
        return !certificate || !private_key;
    }

    std::string alternative_name_varlen(const buffer bytes) {
        static std::array<char, 32> dict {
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
            'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
            'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
            'y', 'z', '2', '3', '4', '5', '6', '7'
        };
        std::string res {};
        for (size_t bit_pos = 0, bit_end = bytes.size() * 8; bit_pos < bit_end; bit_pos += 5) {
            const auto byte_pos = bit_pos / 8;
            const auto byte_shift = bit_pos % 8;
            uint8_t x = (bytes[byte_pos] >> byte_shift) & 0x1F;
            const auto bits_avail = 8 - byte_shift;
            if (bits_avail < 5 && byte_pos + 1 < bytes.size()) {
                const auto bits_missing = 5 - bits_avail;
                x |= (bytes[byte_pos + 1] % (1UL << bits_missing)) << bits_avail;
            }
            res.push_back(dict[x % dict.size()]);
        }
        return res;
    }

    std::string alternative_name(const crypto::ed25519::vkey_t &vk) {
        std::string res{'e'};
        res += alternative_name_varlen(vk);
        return res;
    }

    static void cert_set_alt_name(gnutls_x509_crt_t x509, const std::string &name) {
        check_gnutls(gnutls_x509_crt_set_subject_alt_name(
            x509,
            GNUTLS_SAN_DNSNAME,
            name.data(),
            numeric_cast<unsigned int>(name.size()),
            GNUTLS_FSAN_SET
        ), "gnutls_x509_crt_set_subject_alt_name");
    }

    static std::string stringify_cert(gnutls_x509_crt_t x509) {
        if (x509) {
            gnutls_datum_t out{};
            const auto err = gnutls_x509_crt_print(x509, GNUTLS_CRT_PRINT_FULL, &out);
            if (err == GNUTLS_E_SUCCESS) {
                std::string res{reinterpret_cast<char *>(out.data), out.size};
                gnutls_free(out.data);
                return res;
            }
            return fmt::format("failed to print the cert: {}", internal::gnutls_error_text(err));
        }
        return "nullptr";
    }

    cert_pair_t make_cert(const crypto::ed25519::key_pair_t &kp) {
        [[maybe_unused]] auto &global = internal::gnutls_global_state();
        gnutls_privkey_scope_t pkey{};
        gnutls_crt_scope_t x509{};
        const auto vk_name = jamnp::alternative_name(kp.vk);

        // GnuTLS and Sodium's Secret Key sizes do not match.
        static_assert(sizeof(kp.sk) >= 32);
        gnutls_datum_t public_key{const_cast<uint8_t *>(kp.vk.data()), numeric_cast<unsigned int>(kp.vk.size())};
        gnutls_datum_t private_key{const_cast<uint8_t *>(kp.sk.data()), 32};
        check_gnutls(gnutls_x509_privkey_import_ecc_raw(
            pkey.value,
            GNUTLS_ECC_CURVE_ED25519,
            &public_key,
            nullptr,
            &private_key
        ), "gnutls_x509_privkey_import_ecc_raw");

        check_gnutls(gnutls_x509_crt_set_version(x509.value, 3), "gnutls_x509_crt_set_version");
        const uint8_t serial = 1;
        check_gnutls(gnutls_x509_crt_set_serial(x509.value, &serial, sizeof(serial)), "gnutls_x509_crt_set_serial");
        const auto now = std::time(nullptr);
        constexpr auto cert_validity = static_cast<time_t>(100) * static_cast<time_t>(265) * static_cast<time_t>(24) * static_cast<time_t>(60) * static_cast<time_t>(60);
        if (now > std::numeric_limits<time_t>::max() - cert_validity) [[unlikely]]
            throw error("Certificate expiration time is out of range");
        check_gnutls(gnutls_x509_crt_set_activation_time(x509.value, now), "gnutls_x509_crt_set_activation_time");
        check_gnutls(gnutls_x509_crt_set_expiration_time(x509.value, now + cert_validity), "gnutls_x509_crt_set_expiration_time");
        check_gnutls(gnutls_x509_crt_set_key(x509.value, pkey.value), "gnutls_x509_crt_set_key");
        cert_set_alt_name(x509.value, vk_name);

        check_gnutls(gnutls_x509_crt_set_dn_by_oid(
            x509.value,
            GNUTLS_OID_X520_COMMON_NAME,
            0,
            vk_name.c_str(),
            numeric_cast<unsigned int>(vk_name.size())
        ), "gnutls_x509_crt_set_dn_by_oid");

        check_gnutls(gnutls_x509_crt_sign2(x509.value, x509.value, pkey.value, GNUTLS_DIG_SHA512, 0), "gnutls_x509_crt_sign2");

        logger::info("Generated X509 certificate for peer {}", vk_name);
        cert_pair_t cert{};
        cert.certificate = x509.release();
        cert.private_key = pkey.release();
        return cert;
    }

    jam::state_snapshot_t local_genesis_state() {
        const auto j_spec = codec::json::load(file::install_path("etc/devnet/dev-spec.json"));
        const auto &j_snap = j_spec.at("genesis_state").as_object();
        jam::state_snapshot_t snap{};
        for (const auto &[k, v]: j_snap) {
            snap.emplace(jam::merkle::trie::key_t::from_hex(k), jam::byte_sequence_t::from_hex(v.as_string()));
        }
        return snap;
    }

    protocol_id_t protocol_id_t::from_local_dev_spec() {
        const auto snap = local_genesis_state();
        const auto genesis_header = jam::state_t<jam::config_tiny>::make_genesis_header(snap);
        return {genesis_header.hash()};
    }
}
