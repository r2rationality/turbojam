/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <iostream>
#include <turbo/common/test.hpp>

int main(const int argc, const char **argv)
{
    if (argc >= 2) {
        std::cerr << "using test-filter mask: " << argv[1] << '\n';
        boost::ut::cfg<boost::ut::override> = { .filter = argv[1] };
    }
    const bool res = boost::ut::cfg<boost::ut::override>.run();
    return res ? 1 : 0;
}
