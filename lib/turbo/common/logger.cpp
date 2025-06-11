/* Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com) */

#include <fstream>
#include <iostream>

#if defined(__GNUC__) && !defined(__clang__)
#   pragma GCC diagnostic push
#   pragma GCC diagnostic ignored "-Warray-bounds"
#   pragma GCC diagnostic ignored "-Wstringop-overflow"
#endif
#ifndef SPDLOG_FMT_EXTERNAL
#   define SPDLOG_FMT_EXTERNAL 1
#endif
#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#if defined(__GNUC__) && !defined(__clang__)
#   pragma GCC diagnostic pop
#endif

#include "error.hpp"
#include "file.hpp"
#include "logger.hpp"

namespace turbo::logger {
    bool &tracing_enabled()
    {
        static bool enabled = std::getenv("TURBO_DEBUG") != nullptr;
        return enabled;
    }

    static std::string log_path()
    {
        const char *env_log_path = std::getenv("TURBO_LOG");
        return file::install_path(env_log_path ? env_log_path : "./log/turbo.log");
    }

    static bool console_enabled()
    {
        return !std::getenv("TURBO_LOG_NO_CONSOLE");
    }

    static spdlog::logger create(const std::string &path)
    {
        std::cerr << fmt::format("INIT: log path: {}\n", path);
        {
            std::ofstream os { path, std::ios_base::app };
            if (!os) {
                std::cerr << fmt::format("INIT: Unable to write to the log file: {}; terminating.\n", path);
                std::terminate();
            }
        }

        std::shared_ptr<spdlog::sinks::stderr_color_sink_mt> console_sink {};
        if (console_enabled()) {
            console_sink = std::make_shared<spdlog::sinks::stderr_color_sink_mt>();
            console_sink->set_level(spdlog::level::info);
            console_sink->set_pattern("[%^%l%$] %v");
        }
        auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(path);
        file_sink->set_level(spdlog::level::trace);
        file_sink->set_pattern("[%Y-%m-%d %T %z] [%P:%t] [%n] [%l] %v");
        auto logger = console_sink
            ? spdlog::logger("turbo", { file_sink, console_sink })
            : spdlog::logger("turbo", { file_sink });
        if (tracing_enabled()) {
            logger.set_level(spdlog::level::trace);
        } else {
            logger.set_level(spdlog::level::debug);
        }
        logger.flush_on(spdlog::level::debug);
        logger.log(spdlog::level::debug, fmt::format("Installation directory: {}", file::install_path("")));
        return logger;
    }

    static spdlog::logger &get()
    {
        static spdlog::logger logger = create(log_path());
        return logger;
    }

    void log(level lev, const std::string &msg)
    {
        // A supposed bug in GCC leads to false positive warnings in several open source libraries
        // with spdlog being one of them
        switch (lev) {
            case level::trace:
                get().log(spdlog::level::trace, msg);
                break;
            case level::debug:
                get().log(spdlog::level::debug, msg);
                break;
            case level::info:
                get().log(spdlog::level::info, msg);
                break;
            case level::warn:
                get().log(spdlog::level::warn, msg);
                break;
            case level::error: {
                get().log(spdlog::level::err, msg);
                break;
            }
            default:
                throw turbo::error(fmt::format("unsupported log level: {}", static_cast<int>(lev)));
        }
    }
}
