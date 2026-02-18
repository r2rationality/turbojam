#include <turbo/jam/cli/fuzzer.hpp>

namespace {
    static constexpr size_t FuzzMaxInputSize = 64ULL << 20U;
    static constexpr std::string_view FuzzImpl1Sock{"/tmp/jam-impl-1.sock"};
    static constexpr std::string_view FuzzImpl2Sock{"/tmp/jam-impl-2.sock"};
    static constexpr std::string_view FuzzCrashPath{"/tmp"};

    static void run_one(turbo::buffer input) {
        turbo::cli::fuzzer::impl_vs_impl_client_t<turbo::jam::config_tiny, turbo::cli::fuzzer::unix_socket_processor_t> client{
            std::make_unique<turbo::cli::fuzzer::unix_socket_processor_t<turbo::jam::config_tiny>>(FuzzImpl1Sock),
            std::make_unique<turbo::cli::fuzzer::unix_socket_processor_t<turbo::jam::config_tiny>>(FuzzImpl2Sock)
        };
        if (input.size() > FuzzMaxInputSize) {
            input = input.subbuf(0, FuzzMaxInputSize);
        }
        if (!client.test_sample(input)) {
            const auto input_hash = turbo::crypto::blake2b::digest(input);
            const auto crash_path = fmt::format("{}/crash-{}.bin", FuzzCrashPath, input_hash);
            turbo::logger::error("sample failed: input size={} hash={} crash_path={}", input.size(), input_hash, crash_path);
            turbo::file::write(crash_path, input);
            std::abort();
        }
    }
}

int main(int, char**) {
#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif
#ifdef __AFL_LOOP
    // AFL++ persistent mode: keeps process alive for many testcases.
    static std::array<uint8_t, FuzzMaxInputSize> buf{};
    while (__AFL_LOOP(1000)) {
        ssize_t n = ::read(0, buf.data(), buf.size());
        if (n <= 0)
            break;
        run_one({buf.data(), static_cast<size_t>(n)});
    }
    return 0;
#else
    // Fallback (non-AFL build): read from stdin once.
    auto v = ReadAllStdin();
    run_one({v.data(), v.size()});
    return 0;
#endif
}