
#include <future>

#include <turbo/common/logger.hpp>
#include <turbo/crypto/ed25519.hpp>
#include <turbo/jamsnp/client.hpp>
#include <turbo/jamsnp/cert.hpp>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace {
    using namespace turbo;
    using namespace turbo::jam;

    template<typename T>
    T from_str(const char *str)
    {
        char *end;
        errno = 0;
        long val = strtoll(str, &end, 10);
        if (errno || end == str || *end != '\0') [[unlikely]]
            throw error_sys(fmt::format("failed to parse {} from '{}'", typeid(T).name(), str));
        return numeric_cast<T>(val);
    }

    void cert_set_alt_name(X509 *x509, const std::string &name)
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

    std::string stringify_cert(X509 *x509)
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
        const auto vk_name = jamsnp::cert_name_from_vk(kp.vk);

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

    template<typename T, typename A>
    coro::task_t<void> notify_future(std::promise<T> &promise, A &awaitable)
    {
        promise.set_value(co_await awaitable);
        co_return;
    }

    template <typename Awaitable>
    auto to_future(Awaitable&& awaitable) {
        using T = decltype(awaitable.await_resume());
        std::promise<T> promise;
        auto future = promise.get_future();

        std::thread([promise = std::move(promise), awaitable = std::forward<Awaitable>(awaitable)]() {
            try {
                if (!awaitable.await_ready())
                    awaitable.await_suspend();
                promise.set_value(awaitable.await_resume());
            } catch (...) {
                promise.set_exception(std::current_exception());
            }
        }).detach();

        return future;
    }
}

int main(int argc, char **argv)
{
    try {
        if (argc != 3) [[unlikely]]
            throw error("Usage: jamsnp-test <ipv6-addr> <port>");
        const file::tmp_directory tmp_dir { "jamnp-fetch-blocks" };
        const auto cert_prefix = (static_cast<std::filesystem::path>(tmp_dir) / "client").string();
        {
            const auto key_pair = crypto::ed25519::create_from_seed(crypto::ed25519::seed_t::from_hex("0000000000000000000000000000000000000000000000000000000000000000"));
            write_cert(cert_prefix + ".cert", cert_prefix + ".key", key_pair);
        }
        jamsnp::address_t server_addr { argv[1], from_str<uint16_t>(argv[2]) };
        jamsnp::client_t<config_tiny> client { server_addr, "jamsnp-fetch-blocks", "jamnp-s/0/b5af8eda", cert_prefix };
        logger::info("created a client instance");
        auto blocks_fut = to_future(client.fetch_blocks({}, 10));
        blocks_fut.wait();
        const auto &blocks = blocks_fut.get();
        return 0;
    } catch (const std::exception &ex) {
        logger::error("Terminating due to an exception: {}", ex.what());
        return 1;
    } catch (...) {
        logger::error("Terminating due to an unknown exception");
        return 2;
    }
}
