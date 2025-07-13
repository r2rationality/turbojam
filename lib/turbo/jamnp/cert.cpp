#include <iostream>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <turbo/common/logger.hpp>
#include <turbo/common/numeric-cast.hpp>
#include "cert.hpp"

namespace turbo::jamnp {
    std::string cert_name_base32(const buffer bytes)
    {
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

    std::string cert_name_from_vk(const crypto::ed25519::vkey_t &vk)
    {
        std::string res { 'e' };
        res += cert_name_base32(vk);
        return res;
    }

    static void cert_set_alt_name(X509 *x509, const std::string &name)
    {
        // TODO: add error checking
        GENERAL_NAMES *gens = sk_GENERAL_NAME_new_null();
        GENERAL_NAME *gen = GENERAL_NAME_new();
        ASN1_IA5STRING *dns = ASN1_IA5STRING_new();
        ASN1_STRING_set(dns, name.data(), name.size());
        GENERAL_NAME_set0_value(gen, GEN_DNS, dns);
        sk_GENERAL_NAME_push(gens, gen);
        X509_EXTENSION *ext = X509V3_EXT_i2d(NID_subject_alt_name, 0, gens);
        X509_add_ext(x509, ext, -1);
        X509_EXTENSION_free(ext);
        sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);
    }

    static std::string stringify_cert(X509 *x509)
    {
        if (x509) {
            BIO *bio = BIO_new(BIO_s_mem());
            if (bio) {
                X509_print(bio, x509);
                char *data;
                auto data_len = BIO_get_mem_data(bio, &data);
                std::string res { data, numeric_cast<size_t>(data_len) };
                BIO_free(bio);
                return res;
            }
            return "failed to allocate a BIO for the cert";
        }
        return "nullptr";
    }

    void write_cert(const std::string &cert_path, const std::string &key_path, const crypto::ed25519::key_pair_t &kp)
    {
        const char *err_msg = nullptr;
        X509 *x509 = nullptr;
        FILE *f = nullptr;
        X509_NAME *name = nullptr;
        const auto vk_name = jamnp::cert_name_from_vk(kp.vk);

        // OpenSSL and Sodium's Secret Key sizes do not match
        static_assert(sizeof(kp.sk) >= 32);
        EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, kp.sk.data(), size_t { 32 });
        if (!pkey) [[unlikely]] {
            err_msg = "Failed to import a private key!";
            goto err;
        }

        x509 = X509_new();
        if (!x509) {
            err_msg = "Failed to create a x509 certificate!";
            goto err;
        }
	    X509_set_version(x509, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
        X509_gmtime_adj(X509_get_notBefore(x509), 0);
        X509_gmtime_adj(X509_get_notAfter(x509), 3600L * 24 * 265 * 100);
        X509_set_pubkey(x509, pkey);
        cert_set_alt_name(x509, vk_name);

        name = X509_get_subject_name(x509);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const uint8_t *>(vk_name.c_str()), -1, -1, 0);
        X509_set_issuer_name(x509, name);

        // 4. Self-sign
        X509_sign(x509, pkey, NULL); // For Ed25519, digest is ignored

        // 5. Output private key and cert
        f = fopen(key_path.c_str(), "wb");
        PEM_write_PrivateKey(f, pkey, NULL, NULL, 0, NULL, NULL);
        fclose(f);

        f = fopen(cert_path.c_str(), "wb");
        PEM_write_X509(f, x509);
        // closed in the clean up section

	    logger::info("Generated {}", stringify_cert(x509));
        logger::info("Key path: {}", key_path);
        logger::info("Cert path: {}", cert_path);
    err:
        if (f)
            fclose(f);
        if (x509)
            X509_free(x509);
        if (pkey)
            EVP_PKEY_free(pkey);
        if (err_msg)
            throw error(err_msg);
    }
}