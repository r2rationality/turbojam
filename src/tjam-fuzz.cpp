#include <turbo/jam/cli/fuzzer.hpp>

namespace {
    using namespace turbo;

    template<typename CLNT>
    static void run_one(CLNT &client, turbo::buffer input) {
        const auto input_hash = turbo::crypto::blake2b::digest(input);
        const auto ok = client.test_block(input);
        if (ok) {
            logger::info("sample succeeded: input size={} hash={}", input.size(), input_hash);
        } else {
            logger::error("sample failed: input size={} hash={}", input.size(), input_hash);
        }
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

int main(int argc, const char**argv) {
#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif
    if (argc < 2) {
        logger::error("Usage: {} <init-state-path> [<sock-path>] [<state-dir>]\n", argv[0]);
        return 1;
    }
    const std::string init_state_path{argv[1]};
    std::string sock_path{"/tmp/jam_target.sock"};
    if (argc >= 3) {
        sock_path = argv[2];
    }
    std::optional<file::tmp_directory> tmp_dir{};
    std::optional<std::string> chain_dir{};
    if (argc >= 4) {
        chain_dir.emplace(argv[3]);
    } else {
        tmp_dir.emplace("turbo-jam-fuzzer");
        chain_dir.emplace(tmp_dir->path());
    }
    logger::info("initializing the fuzzer client with init state: {} and socket path: {}", init_state_path, sock_path);
    cli::fuzzer::impl_vs_impl_client_t<turbo::jam::config_tiny, cli::fuzzer::unix_socket_processor_t, cli::fuzzer::processor_t> client{
        std::make_unique<cli::fuzzer::unix_socket_processor_t<jam::config_tiny>>(sock_path),
        std::make_unique<cli::fuzzer::processor_t<turbo::jam::config_tiny>>("dev", *chain_dir)
    };
    auto init = jam::load_obj<jam::fuzzer::initialize_t<jam::config_tiny>>(init_state_path);
    if (!client.set_state(std::move(init))) {
        logger::error("failed to set the initial state for the fuzzer client");
        return 1;
    }
#ifdef __AFL_LOOP
    logger::info("automatic evaluation within of an AFL loop");
    while (__AFL_LOOP(1000)) {
        const auto input = read_all_stdin();
        if (input.empty())
            break;
        run_one(client, input);
    }
    return 0;
#else
    // Fallback (non-AFL build): read a single sample from stdin once.
    logger::info("manual evaluation of a sample read from stdin");
    const auto input = read_all_stdin();
    run_one(client, input);
    return 0;
#endif
}