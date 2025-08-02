/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#ifndef _WIN32
#   include <sys/resource.h>
#endif
#include <iostream>
#include <turbo/common/test.hpp>
#include <turbo/common/timer.hpp>

int main(const int argc, const char **argv)
{
    using namespace turbo;
    const timer t { "run-test", logger::level::info };
    if (argc >= 2) {
        std::cerr << fmt::format("using test-filter mask: {}\n", argv[1]);
        boost::ut::cfg<boost::ut::override> = { .filter = argv[1] };
    }
    // On Windows with Visual C++ compiler option is used to set the stack size
#   ifndef _MSC_VER
    {
#       ifdef DT_STACK_SIZE
            static constexpr size_t stack_size = DT_STACK_SIZE;
#       else
            static constexpr size_t stack_size = 32ULL << 20U;
#       endif
        struct rlimit rl;
        if (getrlimit(RLIMIT_STACK, &rl) != 0) [[unlikely]]
            throw error_sys("getrlimit RLIMIT_STACK failed!");
        if (rl.rlim_cur < stack_size) {
            rl.rlim_cur = stack_size;
            if (setrlimit(RLIMIT_STACK, &rl) != 0) [[unlikely]]
                throw error_sys("setrlimit RLIMIT_STACK failed!");
        }
        std::cerr << fmt::format("stack size: {} MB\n", rl.rlim_cur >> 20);
    }
#   endif
    const bool res = boost::ut::cfg<boost::ut::override>.run();
    return res ? 1 : 0;
}
