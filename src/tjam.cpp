#ifdef MI_OVERRIDE
#   include <mimalloc-new-delete.h>
#endif
#include <iostream>
#include <turbo/common/cli.hpp>

int main(const int argc, const char **argv)
{
#ifdef MI_OVERRIDE
    std::cerr << "INIT: mimalloc " << mi_version() << '\n';
#endif
    using namespace turbo;
    if (const auto *data_path = std::getenv("JAM_FUZZ_DATA_PATH"); std::getenv("JAM_FUZZ") && data_path) {
        const auto log_path = fmt::format("{}/tjam-fuzz.log", data_path);
        std::cerr << fmt::format("INIT: JAM_FUZZ log path override: {}\n", log_path);
        logger::init_log_path(log_path);
    }
    return cli::run(argc, argv);
}