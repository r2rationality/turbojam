#include <iostream>
#include "cert.hpp"

namespace turbo::jamnp {
    std::string cert_name_base32(const buffer bytes)
    {
        static std::array<char, 32> dict {
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
            'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
            'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
            'y', 'z', '2', '3', '4', '5', '6', '7'
        };
        std::string res {};
        for (size_t bit_pos = 0, bit_end = bytes.size() * 8; bit_pos < bit_end; bit_pos += 5) {
            const auto byte_pos = bit_pos / 8;
            const auto byte_shift = bit_pos % 8;
            uint8_t x = (bytes[byte_pos] >> byte_shift) & 0x1F;
            const auto bits_avail = 8 - byte_shift;
            if (bits_avail < 5 && byte_pos + 1 < bytes.size()) {
                const auto bits_missing = 5 - bits_avail;
                x |= (bytes[byte_pos + 1] % (1UL << bits_missing)) << bits_avail;
            }
            res.push_back(dict[x % dict.size()]);
        }
        return res;
    }

    std::string cert_name_from_vk(const crypto::ed25519::vkey_t &vk)
    {
        std::string res { 'e' };
        res += cert_name_base32(vk);
        return res;
    }
}