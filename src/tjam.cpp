#ifdef MI_OVERRIDE
#   include <mimalloc-new-delete.h>
#endif
#include <turbo/common/cli.hpp>

int main(const int argc, const char **argv)
{
#ifdef MI_OVERRIDE
    std::cerr << "DT_INIT: mimalloc " << mi_version() << '\n';
#endif
    using namespace turbo;
    return cli::run(argc, argv);
}