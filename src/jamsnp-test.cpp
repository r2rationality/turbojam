
#include <condition_variable>
#include <iostream>
#include <mutex>

#include <turbo/crypto/ed25519.hpp>
#include <turbo/common/bytes.hpp>
#include <turbo/common/error.hpp>
#include <turbo/common/format.hpp>
#include <turbo/jam/types/common.hpp>
#include <turbo/jamsnp/cert.hpp>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
// include it the last since it include Windows headers
#include <msquic.hpp>

namespace {
    using namespace turbo;

    std::mutex wait_mutex {};
    std::condition_variable wait_cv {};
    size_t wait_count = 0;

    enum class block_direction_t: uint8_t {
        ascending = 0,
        descending = 1
    };

    uint8_vector make_block_request(const jam::header_hash_t &hh, const uint32_t max_blocks, const block_direction_t direction=block_direction_t::ascending)
    {
        uint8_vector res {};
        res.reserve(1 + sizeof(hh) + 1 + sizeof(max_blocks));
        res << 128;
        res << hh;
        res << static_cast<uint8_t>(direction);
        res << buffer::from(max_blocks);
        return res;
    }

    QUIC_STATUS QUIC_API stream_callback(MsQuicStream* stream, void* /*ctx*/, QUIC_STREAM_EVENT* event) {
        switch (event->Type) {
            case QUIC_STREAM_EVENT_START_COMPLETE: {
                std::cerr << fmt::format("stream: start complete\n");
                // CE 128: Block request
                const auto msg = make_block_request({}, 1);
                const auto buf_scope = new QuicBufferScope { numeric_cast<uint32_t>(msg.size()) };
                const auto buf = static_cast<QUIC_BUFFER *>(*buf_scope);
                memcpy(buf->Buffer, msg.data(), msg.size());
                if (const auto res = stream->Send(buf, 1, QUIC_SEND_FLAG_FIN, buf_scope); QUIC_FAILED(res)) [[unlikely]] {
                    std::cerr << fmt::format("stream: send failed with code {:08X}\n", res);
                    stream->ConnectionShutdown(1);
                }
                break;
            }
            case QUIC_STREAM_EVENT_SEND_COMPLETE:
                std::cerr << fmt::format("stream: data sent!\n");
                delete reinterpret_cast<QuicBufferScope *>(event->SEND_COMPLETE.ClientContext);
                break;
            case QUIC_STREAM_EVENT_RECEIVE: {
                std::ostringstream ss {};
                ss << fmt::format("stream: data received: off: {} len: {} ", event->RECEIVE.AbsoluteOffset, event->RECEIVE.TotalBufferLength);
                for (decltype(event->RECEIVE.BufferCount) bi = 0; bi < event->RECEIVE.BufferCount; ++bi) {
                    const QUIC_BUFFER *buf = event->RECEIVE.Buffers + bi;
                    ss << fmt::format("#{}: {} ", bi, buffer { buf->Buffer, buf->Length });
                }
                ss << '\n';
                std::cerr << ss.str();
                break;
            }
            case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
                std::cerr << fmt::format("stream: send aborted!\n");
                break;
            case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
                std::cerr << fmt::format("stream: peer shut down!\n");
                break;
            case QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE:
                std::cerr << fmt::format("stream: send closed!\n");
                break;
            case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
                std::cerr << fmt::format("stream: closed!\n");
                break;
            default:
                std::cerr << fmt::format("stream: other: {}!\n", static_cast<int>(event->Type));
                break;
        }
        return QUIC_STATUS_SUCCESS;
    }

    void send_data(MsQuicConnection &conn)
    {
        const auto st = new MsQuicStream { conn, QUIC_STREAM_OPEN_FLAG_NONE, CleanUpAutoDelete, stream_callback };
        if (!st->IsValid()) [[unlikely]] {
            std::cerr << fmt::format("stream: failed to initialize\n");
            conn.Shutdown(1);
            return;
        }
        if (const auto res = st->Start(); QUIC_FAILED(res)) [[unlikely]] {
            std::cerr << fmt::format("stream: start failed with code {:08X}\n", res);
            st->Close();
            conn.Shutdown(1);
        }
    }

    QUIC_STATUS QUIC_API connection_callback(MsQuicConnection* conn, void* /*ctx*/, QUIC_CONNECTION_EVENT *event)
    {
        switch (event->Type) {
            case QUIC_CONNECTION_EVENT_CONNECTED:
                std::cerr << fmt::format("connection: connected!\n");
                send_data(*conn);
                break;
            case QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE:
                std::cerr << fmt::format("connection: streams available uni: {} bidi: {}!\n",
                    event->STREAMS_AVAILABLE.UnidirectionalCount, event->STREAMS_AVAILABLE.BidirectionalCount);
                break;
            case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
                std::cerr << fmt::format("connection: resumption ticket received: {}!\n",
                    buffer { event->RESUMPTION_TICKET_RECEIVED.ResumptionTicket, event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength });
                break;
            case QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED:
                std::cerr << fmt::format("connection: datagram state changed: SendEnabled: {} MaxSendLength: {}!\n",
                    event->DATAGRAM_STATE_CHANGED.SendEnabled, event->DATAGRAM_STATE_CHANGED.MaxSendLength);
                break;
            case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT: {
                MsQuicSettings settings;
                conn->GetSettings(&settings);
                std::cerr << fmt::format("connection: shut down by transport: ErrorCode: {:08X} Status: {:08X}!\n",
                    event->SHUTDOWN_INITIATED_BY_TRANSPORT.ErrorCode, (unsigned long)event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
                break;
            }
            case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
                std::cerr << fmt::format("connection: shut down by peer!\n");
                break;
            case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
                std::cerr << fmt::format("connection: closed!\n");
                {
                    std::unique_lock<std::mutex> lk { wait_mutex };
                    --wait_count;
                    wait_cv.notify_one();
                }
                break;
            default:
                std::cerr << fmt::format("connection: other: {}!\n", static_cast<int>(event->Type));
                break;
        }
        return QUIC_STATUS_SUCCESS;
    }

    void cert_set_alt_name(X509 *x509, const std::string &name)
    {
        const char *err_msg = nullptr;
        X509_EXTENSION *extension_san = nullptr;
        ASN1_OCTET_STRING *subject_alt_name_ASN1 = nullptr;

        subject_alt_name_ASN1 = ASN1_OCTET_STRING_new();
        if (!subject_alt_name_ASN1) [[unlikely]] {
            err_msg = "OpenSSL failed to allocate memory for the alternative name!";
            goto err;
        }
        if (!ASN1_OCTET_STRING_set(subject_alt_name_ASN1, reinterpret_cast<const uint8_t*>(name.data()), name.size())) [[unlikely]] {
            err_msg = "OpenSSL failed to copy an alternative name value!";
            goto err;
        }
        if (!X509_EXTENSION_create_by_NID(&extension_san, NID_subject_alt_name, 0, subject_alt_name_ASN1)) [[unlikely]] {
            err_msg = "OpenSSL failed to set an alternative name value!";
            goto err;
        }
        if (!X509_add_ext(x509, extension_san, -1)) [[unlikely]] {
            err_msg = "OpenSSL failed to set the alternative name extension!";
            goto err;
        }
    err:
        if (subject_alt_name_ASN1)
            ASN1_OCTET_STRING_free(subject_alt_name_ASN1);
        if (extension_san)
            X509_EXTENSION_free(extension_san);
        if (err_msg)
            throw error(err_msg);
    }

    void write_cert(const QUIC_CERTIFICATE_FILE &cert_file, const crypto::ed25519::key_pair_t &kp)
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
        ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
        X509_gmtime_adj(X509_get_notBefore(x509), 0);
        X509_gmtime_adj(X509_get_notAfter(x509), 31536000L); // valid for 1 year
        X509_set_pubkey(x509, pkey);
        cert_set_alt_name(x509, vk_name);

        name = X509_get_subject_name(x509);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const uint8_t *>(vk_name.c_str()), -1, -1, 0);
        X509_set_issuer_name(x509, name);

        // 4. Self-sign
        X509_sign(x509, pkey, NULL); // For Ed25519, digest is ignored

        // 5. Output private key and cert
        f = fopen(cert_file.PrivateKeyFile, "wb");
        PEM_write_PrivateKey(f, pkey, NULL, NULL, 0, NULL, NULL);
        fclose(f);

        f = fopen(cert_file.CertificateFile, "wb");
        PEM_write_X509(f, x509);
        // closed in the clean up section

        std::cerr << fmt::format("Generated {} and {}\n", cert_file.PrivateKeyFile, cert_file.CertificateFile);
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

const MsQuicApi *MsQuic = nullptr;

int main()
{
    auto exit_code = EXIT_SUCCESS;
    try {
        const MsQuicApi quic {};
        if (!quic.IsValid()) [[unlikely]]
            throw error(fmt::format("failed to initialize MsQuic API! Error: {:08X}", static_cast<unsigned long>(quic.GetInitStatus())));
        MsQuic = &quic;
        const MsQuicRegistration reg { "jamnp-test", QUIC_EXECUTION_PROFILE_LOW_LATENCY, true };
        const MsQuicAlpn alpn { "jamnp-s/0/00000000" };
        QUIC_CERTIFICATE_FILE cred_file {
            .PrivateKeyFile="client.key",
            .CertificateFile="client.cert"
        };
        {
            const auto key_pair = crypto::ed25519::create_from_seed(crypto::ed25519::seed_t::from_hex("0000000000000000000000000000000000000000000000000000000000000000"));
            write_cert(cred_file, key_pair);
        }
        QUIC_CREDENTIAL_CONFIG cred_cfg;
        cred_cfg.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
        cred_cfg.Flags = QUIC_CREDENTIAL_FLAG_CLIENT | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
        cred_cfg.CertificateFile = &cred_file;
        const MsQuicCredentialConfig cred { cred_cfg };
        MsQuicSettings settings {};
        const MsQuicConfiguration config { reg, alpn, settings, cred };
        const auto conn = new MsQuicConnection { reg, CleanUpAutoDelete, connection_callback };
        if (const auto res = conn->Start(config, "127.0.0.1", 4567); QUIC_FAILED(res)) [[unlikely]] {
            conn->Shutdown(1);
            throw error(fmt::format("connection start failed with {:08X}", res));
        }
        std::cerr << fmt::format("connection: initiating\n");
        {
            std::unique_lock<std::mutex> lk { wait_mutex };
            ++wait_count;
            wait_cv.notify_one();
        }
        {
            std::unique_lock<std::mutex> lk { wait_mutex };
            wait_cv.wait(lk, [&](){ return wait_count == 0; });
        }
    } catch (const std::exception &ex) {
        std::cerr << fmt::format("Terminating due to an exception: {}\n", ex.what());
        exit_code = 1;
    } catch (...) {
        std::cerr << fmt::format("Terminating due to an unknown exception\n");
        exit_code = 2;
    }
    std::cerr << fmt::format("all MsQuic objects have been destroyed\n");
    return exit_code;
}
