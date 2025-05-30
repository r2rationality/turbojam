
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <turbo/common/bytes.hpp>
#include <turbo/common/error.hpp>
#include <turbo/common/format.hpp>

// include it the last since it include Windows headers
#include <msquic.hpp>

namespace {
    using namespace turbo;

    std::mutex wait_mutex;
    std::condition_variable wait_cv;
    size_t wait_count = 0;

    QUIC_STATUS QUIC_API stream_callback(MsQuicStream* stream, void* /*ctx*/, QUIC_STREAM_EVENT* event) {
        switch (event->Type) {
            case QUIC_STREAM_EVENT_START_COMPLETE: {
                std::cerr << fmt::format("stream: start complete\n");
                const auto buf_scope = new QuicBufferScope { 0x8 };
                const auto buf = static_cast<QUIC_BUFFER *>(*buf_scope);
                memcpy(buf->Buffer, "DEADBEAF", 8);
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
        const MsQuicRegistration reg { "quicksample", QUIC_EXECUTION_PROFILE_LOW_LATENCY, true };
        const MsQuicAlpn alpn { "sample" };
        const MsQuicCredentialConfig cred {
            QUIC_CREDENTIAL_FLAG_CLIENT | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION
        };
        MsQuicSettings settings {};
        const MsQuicConfiguration config { reg, alpn, settings, cred };
        const auto conn = new MsQuicConnection { reg, CleanUpAutoDelete, connection_callback };
        if (const auto res = conn->Start(config, "127.0.0.1", 4567); QUIC_FAILED(res)) [[unlikely]]
            throw error(fmt::format("connection start failed with {:08X}", res));
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
