#include <turbo/jam/chain.hpp>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, const size_t size)
{
    using namespace turbo::jam;
    try {
        decoder dec { buffer { data, size } };
        const auto blk = code::from<block_t<config_tiny>>(dec);
        const auto val = cbor::zero2::parse(buffer { data, size });
    } catch (const error &err) {
        // ignore the library's exceptions
    }
    return 0;
}