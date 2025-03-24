#pragma once
/* Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com) */

#include <boost/json/fwd.hpp>
#include <turbo/common/bytes.hpp>

namespace turbo::codec::json {
    using namespace boost::json;

    extern object canonical(const object &obj);
    extern std::string serialize_canon(const object &obj);
    extern value parse(const buffer &buf);
    extern value load(const std::string &path);
    extern void save_pretty(std::ostream& os, value const &jv, std::string *indent = nullptr);
    extern std::string serialize_pretty(const value &jv);
    extern void save_pretty(const std::string &path, const value &jv);
}