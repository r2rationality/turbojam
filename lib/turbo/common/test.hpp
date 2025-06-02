#pragma once
/* Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com) */

#include <cmath>
#include <source_location>
#define BOOST_UT_DISABLE_MODULE 1
#include <boost/ut.hpp>
#include "file.hpp"
#include "format.hpp"

namespace turbo {
    using namespace boost::ut;

    struct test_printer: boost::ut::printer {
        template<class T>
        test_printer& operator<<(T &&t) {
            if constexpr (std::is_convertible_v<T, std::span<const uint8_t>>) {
                std::cerr << fmt::format("{}", t);
            } else {
                std::cerr << std::forward<T>(t);
            }
            return *this;
        }

        test_printer& operator<<(const std::string_view sv) {
            std::cerr << sv;
            return *this;
        }
    };

    template<typename X, typename Y>
    bool expect_equal(const X &x, const Y &y, const std::source_location &loc=std::source_location::current())
    {
        const auto res = x == y;
        expect(res, loc) << fmt::format("{} != {}", x, y);
        return res;
    }

    template<typename X, typename Y>
    bool expect_equal(const X &x, const Y &y, const std::string_view name, const std::source_location &loc=std::source_location::current())
    {
        const auto res = x == y;
        expect(res, loc) << fmt::format("{}: {} != {}", name, x, y);
        return res;
    }
}

template <class... Ts>
inline auto boost::ut::cfg<boost::ut::override, Ts...> = boost::ut::runner<boost::ut::reporter<turbo::test_printer>> {};