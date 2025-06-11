#pragma once
/* Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com) */

#include <exception>
#include <functional>
#include <turbo/common/format.hpp>

namespace turbo::logger {
    enum class level {
        trace, debug, info, warn, error
    };

    extern std::shared_ptr<std::string> last_error();
    extern void reset_last_error();

    extern bool &tracing_enabled();
    extern void log(level lev, const std::string &msg);

    template<typename... Args>
    void log(const level lev, const std::string_view &fmt, Args&&... a)
    {
        log(lev, format(fmt::runtime(fmt), std::forward<Args>(a)...));
    }

    template<typename... Args>
    void trace(const std::string_view &fmt, Args&&... a)
    {
        log(level::trace, fmt, std::forward<Args>(a)...);
    }

    template<typename... Args>
    void debug(const std::string_view &fmt, Args&&... a)
    {
        log(level::debug, fmt, std::forward<Args>(a)...);
    }

    template<typename... Args>
    void info(const std::string_view &fmt, Args&&... a)
    {
        log(level::info, fmt, std::forward<Args>(a)...);
    }

    template<typename... Args>
    void warn(const std::string_view &fmt, Args&&... a)
    {
        log(level::warn, fmt, std::forward<Args>(a)...);
    }

    template<typename... Args>
    void error(const std::string_view &fmt, Args&&... a)
    {
        log(level::error, fmt, std::forward<Args>(a)...);
    }

    using action = std::function<void()>;
    using optional_action = std::optional<action>;

    inline std::exception_ptr run_log_errors(const action &main, const optional_action &cleanup={},
            const std::source_location &loc=std::source_location::current())
    {
        std::exception_ptr cur_ex {};
        try {
            main();
            if (cleanup)
                (*cleanup)();
        } catch (const std::exception &ex) {
            cur_ex = std::current_exception();
            error("block at {}:{} failed with std::exception: {}", loc.file_name(), loc.line(), ex.what());
            if (cleanup)
                (*cleanup)();
        } catch (...) {
            cur_ex = std::current_exception();
            error("block at {}:{} failed with an unknown error", loc.file_name(), loc.line());
            if (cleanup)
                (*cleanup)();
        }
        return cur_ex;
    }

    inline void run_log_errors_rethrow(const action &main, const optional_action &cleanup={},
        const std::source_location &loc=std::source_location::current())
    {
        if (const auto cur_ex = run_log_errors(main, cleanup, loc))
            std::rethrow_exception(cur_ex);
    }
}