/* Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com) */

#ifndef _WIN32
#    include <sys/resource.h>
#endif
#include "file.hpp"

namespace turbo::file {
    void set_max_open_files()
    {
        static size_t current_max_open_files = 0;
        if (current_max_open_files != max_open_files) {
#           ifdef _WIN32
            if (_setmaxstdio(max_open_files) != max_open_files)
                throw error_sys(fmt::format("can't increase the max number of open files to {}!", max_open_files));
#           else
            struct rlimit lim;
            if (getrlimit(RLIMIT_NOFILE, &lim) != 0)
                throw error_sys("getrlimit failed");
            if (lim.rlim_cur < max_open_files || lim.rlim_max < max_open_files) {
                lim.rlim_cur = max_open_files;
                lim.rlim_max = max_open_files;
                if (setrlimit(RLIMIT_NOFILE, &lim) != 0)
                    throw error_sys(fmt::format("failed to increase the max number of open files to {}", max_open_files));
                if (getrlimit(RLIMIT_NOFILE, &lim) != 0)
                    throw error_sys("getrlimit failed");
            }
#           endif
            current_max_open_files = max_open_files;
        }
    }

    void read_stream::seek(std::streampos off)
    {
#if     _WIN32
        if (_fseeki64(_f, off, SEEK_SET) != 0)
#else
        if (fseek(_f, off, SEEK_SET) != 0)
#endif
            throw error_sys(fmt::format("failed to seek in {}", _path));
    }

    void write_stream::seek(std::streampos off)
    {
#if     _WIN32
        if (_fseeki64(_f, off, SEEK_SET) != 0)
#else
        if (fseek(_f, off, SEEK_SET) != 0)
#endif
            throw error_sys(fmt::format("failed to seek in {}", _path));
    }

    uint64_t write_stream::tellp()
    {
#if     _WIN32
        auto pos = _ftelli64(_f);
#else
        auto pos = ftell(_f);
#endif
        if (pos < 0)
            throw error_sys(fmt::format("failed to tell the stream position in {}", _path));
        return pos;
    }

}
