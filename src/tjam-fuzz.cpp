#include <turbo/jam/cli/fuzzer.hpp>

namespace {
    using namespace turbo;

    static constexpr std::string_view FuzzImpl1Sock{"/tmp/jam-impl-1.sock"};
    static constexpr std::string_view FuzzImpl2Sock{"/tmp/jam-impl-2.sock"};
    static constexpr std::string_view FuzzCrashPath{"/tmp"};

    static void run_one(const buffer input) {
        const auto input_hash = turbo::crypto::blake2b::digest(input);
        cli::fuzzer::impl_vs_impl_client_t<turbo::jam::config_tiny, turbo::cli::fuzzer::unix_socket_processor_t> client{
            std::make_unique<turbo::cli::fuzzer::unix_socket_processor_t<turbo::jam::config_tiny>>(FuzzImpl1Sock),
            std::make_unique<turbo::cli::fuzzer::unix_socket_processor_t<turbo::jam::config_tiny>>(FuzzImpl2Sock)
        };
        if (!client.test_sample(input)) [[unlikely]] {
            const auto crash_path = fmt::format("{}/crash-{}.bin", FuzzCrashPath, input_hash);
            logger::error("sample failed: input size={} hash={} crash_path={}", input.size(), input_hash, crash_path);
            file::write(crash_path, input);
            std::abort();
        }
        logger::info("sample succeeded: input size={} hash={}", input.size(), input_hash);
    }

    inline uint8_vector read_all_stdin() {
        uint8_vector buf{};
        std::array<uint8_t, 0x10000> rd_buf;
        while (true) {
            const auto n = ::read(0, rd_buf.data(), rd_buf.size());
            if (n <= 0)
                break;
            buf.insert(buf.end(), rd_buf.data(), rd_buf.data() + numeric_cast<size_t>(n));
        }
        return buf;
    }
}

int main(int, char**) {
#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif
#ifdef __AFL_LOOP
    logger::info("automatic evaluation within of an AFL loop");
    // AFL++ persistent mode: keeps process alive for many testcases.
    static uint8_vector buf{};
    while (__AFL_LOOP(1000)) {
        const auto input = read_all_stdin();
        if (input.empty())
            break;
        run_one(input);
    }
    return 0;
#else
    // Fallback (non-AFL build): read from stdin once.
    logger::info("manual evaluation of a sample read from stdin");
    const auto input = read_all_stdin();
    run_one(input);
    return 0;
#endif
}