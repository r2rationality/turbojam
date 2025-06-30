
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <unordered_map>

#include <turbo/crypto/ed25519.hpp>
#include <turbo/common/bytes.hpp>
#include <turbo/common/error.hpp>
#include <turbo/common/format.hpp>
#include <turbo/jam/types/header.hpp>
#include <turbo/jam/encoding.hpp>
#include <turbo/jam/chain.hpp>
#include <turbo/jamsnp/cert.hpp>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#ifdef _WIN32
#   include <openssl/applink.c>
#endif

// include it the last since it includes Windows headers
#include <msquic.hpp>

namespace {
    using namespace turbo;
    using namespace turbo::jam;

    std::mutex wait_mutex {};
    std::condition_variable wait_cv {};
    size_t wait_count = 0;

    enum class block_direction_t: uint8_t {
        ascending = 0,
        descending = 1
    };

    uint8_vector &chain_buffer()
    {
        static uint8_vector buf {};
        return buf;
    }

    chain_t<config_tiny> &chain()
    {
        static chain_t<config_tiny> c = chain_t<config_tiny>::from_json_spec(file::install_path("tmp/dev-chain"), file::install_path("etc/devnet/dev-spec.json"));
        return c;
    }

    uint8_vector make_block_request(const jam::header_hash_t &hh, const uint32_t max_blocks, const block_direction_t direction=block_direction_t::ascending)
    {
        logger::info("making a block request: start hash: {} max_blocks: {} direction: {}", hh, max_blocks, static_cast<uint8_t>(direction));
        uint8_vector res {};
        res.reserve(sizeof(hh) + 1 + sizeof(max_blocks));
        res << hh;
        res << static_cast<uint8_t>(direction);
        res << buffer::from(max_blocks);
        return res;
    }

    void ce128_block_request(MsQuicStream* stream)
    {
        const auto msg = make_block_request(chain().parent(), 0x10000);
        const uint32_t msg_len = msg.size();
        static_assert(sizeof(msg_len) == 4);
        const auto buf_scope = new QuicBufferScope { numeric_cast<uint32_t>(1ULL + sizeof(msg_len) + msg.size()) };
        const auto buf = static_cast<QUIC_BUFFER *>(*buf_scope);
        // CE 128: Block request
        buf->Buffer[0] = 128;
        memcpy(buf->Buffer + 1, &msg_len, sizeof(msg_len));
        memcpy(buf->Buffer + 5, msg.data(), msg.size());
        if (const auto res = stream->Send(buf, 1, QUIC_SEND_FLAG_FIN, buf_scope); QUIC_FAILED(res)) [[unlikely]] {
            std::cerr << fmt::format("stream: send failed with code {:08X}\n", res);
            stream->ConnectionShutdown(1);
        }
    }

    QUIC_STATUS QUIC_API stream_callback(MsQuicStream* stream, void* /*ctx*/, QUIC_STREAM_EVENT* event) {
        switch (event->Type) {
            case QUIC_STREAM_EVENT_START_COMPLETE: {
                std::cerr << fmt::format("stream: start complete\n");
                ce128_block_request(stream);
                break;
            }
            case QUIC_STREAM_EVENT_SEND_COMPLETE:
                std::cerr << fmt::format("stream: data sent!\n");
                delete reinterpret_cast<QuicBufferScope *>(event->SEND_COMPLETE.ClientContext);
                break;
            case QUIC_STREAM_EVENT_RECEIVE: {
                for (decltype(event->RECEIVE.BufferCount) bi = 0; bi < event->RECEIVE.BufferCount; ++bi) {
                    const QUIC_BUFFER *buf = event->RECEIVE.Buffers + bi;
                    chain_buffer() << buffer { buf->Buffer, buf->Length };
                }
                decoder dec { chain_buffer() };
                const auto msg_len = dec.uint_fixed<size_t>(4);
                std::cerr << fmt::format("CE128 msg_len: {} received: {}\n", msg_len, chain_buffer().size() - 4);
                if (msg_len > 0 && chain_buffer().size() == 4ULL + msg_len) {
                    for (size_t i = 0; !dec.empty(); ++i) {
                        auto blk = codec::from<block_t<config_tiny>>(dec);
                        std::cerr << fmt::format("block #{} slot: {} hash: {} parent_root: {} bytes left: {}\n", i, blk.header.slot, blk.header.hash(), blk.header.parent_state_root, dec.size());
                        const auto pre_root = chain().state_root();
                        chain().apply(blk);
                        std::cerr << fmt::format("block #{} pre_root: {} post_root: {}\n", i, pre_root, chain().state_root());
                    }
                    file::write(file::install_path("data/devnet-blocks.bin"), static_cast<buffer>(chain_buffer()).subbuf(4));
                    chain_buffer().clear();
                    ce128_block_request(stream);
                }
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

    static std::string status_name(const QUIC_STATUS status)
    {
        static std::unordered_map<QUIC_STATUS, std::string> names {
            { QUIC_STATUS_SUCCESS, "QUIC_STATUS_SUCCESS" },
            { QUIC_STATUS_PENDING, "QUIC_STATUS_PENDING" },
            { QUIC_STATUS_CONTINUE, "QUIC_STATUS_CONTINUE" },
            { QUIC_STATUS_OUT_OF_MEMORY, "QUIC_STATUS_OUT_OF_MEMORY" },
            { QUIC_STATUS_INVALID_PARAMETER, "QUIC_STATUS_INVALID_PARAMETER" },
            { QUIC_STATUS_INVALID_STATE, "QUIC_STATUS_INVALID_STATE" },
            { QUIC_STATUS_NOT_SUPPORTED, "QUIC_STATUS_NOT_SUPPORTED" },
            { QUIC_STATUS_NOT_FOUND, "QUIC_STATUS_NOT_FOUND" },
            { QUIC_STATUS_BUFFER_TOO_SMALL, "QUIC_STATUS_BUFFER_TOO_SMALL" },
            { QUIC_STATUS_HANDSHAKE_FAILURE, "QUIC_STATUS_HANDSHAKE_FAILURE" },
            { QUIC_STATUS_ABORTED, "QUIC_STATUS_ABORTED" },
            { QUIC_STATUS_ADDRESS_IN_USE, "QUIC_STATUS_ADDRESS_IN_USE" },
            { QUIC_STATUS_INVALID_ADDRESS, "QUIC_STATUS_INVALID_ADDRESS" },
            { QUIC_STATUS_CONNECTION_TIMEOUT, "QUIC_STATUS_CONNECTION_TIMEOUT" },
            { QUIC_STATUS_CONNECTION_IDLE, "QUIC_STATUS_CONNECTION_IDLE" },
            { QUIC_STATUS_INTERNAL_ERROR, "QUIC_STATUS_INTERNAL_ERROR" },
            { QUIC_STATUS_UNREACHABLE, "QUIC_STATUS_UNREACHABLE" },
            { QUIC_STATUS_CONNECTION_REFUSED, "QUIC_STATUS_CONNECTION_REFUSED" },
            { QUIC_STATUS_PROTOCOL_ERROR, "QUIC_STATUS_PROTOCOL_ERROR" },
            { QUIC_STATUS_VER_NEG_ERROR, "QUIC_STATUS_VER_NEG_ERROR" },
            { QUIC_STATUS_USER_CANCELED, "QUIC_STATUS_USER_CANCELED" },
            { QUIC_STATUS_ALPN_NEG_FAILURE, "QUIC_STATUS_ALPN_NEG_FAILURE" },
            { QUIC_STATUS_STREAM_LIMIT_REACHED, "QUIC_STATUS_STREAM_LIMIT_REACHED" }
        };
        if (const auto it = names.find(status); it != names.end())
            return fmt::format("{} ({:08X})", it->second, status);
        return fmt::format("QUIC_STATUS_UNKNOWN {:08X}", status);
    }

    QUIC_STATUS QUIC_API connection_callback(MsQuicConnection* conn, void* /*ctx*/, QUIC_CONNECTION_EVENT *event)
    {
        switch (event->Type) {
            case QUIC_CONNECTION_EVENT_CONNECTED:
                std::cerr << fmt::format("connection: connected!\n");
                send_data(*conn);
                break;
	        case QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED: {
		        X509 *x509 = reinterpret_cast<X509 *>(event->PEER_CERTIFICATE_RECEIVED.Certificate);
                std::cerr << fmt::format("connection: peer certificate received:\n{}!\n", stringify_cert(x509));
		        break;
	        }
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
            case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
                std::cerr << fmt::format("connection: shut down by transport: ErrorCode: {:08X} Status: {}!\n",
                    event->SHUTDOWN_INITIATED_BY_TRANSPORT.ErrorCode, status_name(event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status));
                break;
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
        f = fopen(cert_file.PrivateKeyFile, "wb");
        PEM_write_PrivateKey(f, pkey, NULL, NULL, 0, NULL, NULL);
        fclose(f);

        f = fopen(cert_file.CertificateFile, "wb");
        PEM_write_X509(f, x509);
        // closed in the clean up section

        std::cerr << fmt::format("Generated {} and {}\n", cert_file.PrivateKeyFile, cert_file.CertificateFile);
	    std::cerr << fmt::format("{}\n", stringify_cert(x509));
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
}

const MsQuicApi *MsQuic = nullptr;

int main(int argc, char **argv)
{
    auto exit_code = EXIT_SUCCESS;
    try {
        if (argc != 3) [[unlikely]]
            throw error("Usage: jamsnp-test <ipv6-addr> <port>");
        const char *server_addr = argv[1];
        const auto server_port = from_str<uint16_t>(argv[2]);
        const MsQuicApi quic {};
        if (!quic.IsValid()) [[unlikely]]
            throw error(fmt::format("failed to initialize MsQuic API! Error: {:08X}", static_cast<unsigned long>(quic.GetInitStatus())));
        MsQuic = &quic;
        const MsQuicRegistration reg { "jamnp-test", QUIC_EXECUTION_PROFILE_LOW_LATENCY, true };
        if (!reg.IsValid()) [[unlikely]]
            throw error(fmt::format("failed to initialize MsQuicRegistration! Error: {:08X}", static_cast<unsigned long>(reg.GetInitStatus())));
        const MsQuicAlpn alpn { "jamnp-s/0/b5af8eda" };
        QUIC_CERTIFICATE_FILE cred_file {
            .PrivateKeyFile="client.key",
            .CertificateFile="client.cert"
        };
        {
            const auto key_pair = crypto::ed25519::create_from_seed(crypto::ed25519::seed_t::from_hex("0000000000000000000000000000000000000000000000000000000000000000"));
            write_cert(cred_file, key_pair);
        }
        QUIC_CREDENTIAL_CONFIG cred_cfg {};
        cred_cfg.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
        cred_cfg.Flags = QUIC_CREDENTIAL_FLAG_CLIENT
		| QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION
		| QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED;
        cred_cfg.CertificateFile = &cred_file;
        const MsQuicCredentialConfig cred { cred_cfg };
        MsQuicSettings settings {};
        const MsQuicConfiguration config { reg, alpn, settings, cred };
        if (!config.IsValid()) [[unlikely]]
            throw error(fmt::format("failed to initialize MsQuicConfiguration! Error: {:08X}", static_cast<unsigned long>(config.GetInitStatus())));
        const auto conn = new MsQuicConnection { reg, CleanUpAutoDelete, connection_callback };
        if (!conn->IsValid()) [[unlikely]]
            throw error(fmt::format("failed to initialize MsQuicConnection! Error: {:08X}", static_cast<unsigned long>(conn->GetInitStatus())));
        if (const auto res = conn->Start(config, QUIC_ADDRESS_FAMILY_INET6, server_addr, server_port); QUIC_FAILED(res)) [[unlikely]] {
            conn->Shutdown(1);
            throw error(fmt::format("connection start failed with {:08X}", static_cast<unsigned long>(res)));
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
