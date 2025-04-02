/* Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com) */

#include <boost/json.hpp>
#include <turbo/common/file.hpp>
#include "json.hpp"

namespace turbo::codec::json {
    object canonical(const object &obj)
    {
        std::vector<std::pair<std::string, value>> items {};
        items.reserve(obj.size());
        for (const auto &[k, v]: obj) {
            if (v.is_object()) {
                items.emplace_back(k, canonical(v.as_object()));
            } else {
                items.emplace_back(k, v);
            }
        }
        std::sort(items.begin(), items.end(), [](const auto &l, const auto &r) { return l.first < r.first; } );
        object res {};
        for (auto &&[k, v]: items) {
            res.emplace(std::move(k), std::move(v));
        }
        return res;
    }

    std::string serialize_canon(const object &obj)
    {
        return serialize(canonical(obj));
    }

    value parse(const buffer &buf)
    {
        return boost::json::parse(static_cast<std::string_view>(buf));
    }

    value load(const std::string &path)
    {
        return parse(file::read(path));
    }

    void save_pretty(std::ostream& os, value const &jv, std::string *indent)
    {
        static constexpr size_t indent_step = 2;
        std::string indent_ {};
        if(!indent)
            indent = &indent_;
        switch (jv.kind()) {
            case kind::object: {
                os << "{\n";
                indent->append(indent_step, ' ');
                const auto &obj = jv.get_object();
                for (auto it = obj.begin(), last = std::prev(obj.end()); it != obj.end(); ++it) {
                    os << *indent << json::serialize(it->key()) << ": ";
                    save_pretty(os, it->value(), indent);
                    if (it != last)
                        os << ',';
                    os << '\n';
                }
                indent->resize(indent->size() - indent_step);
                os << *indent << "}";
                break;
            }
            case kind::array: {
                os << "[\n";
                indent->append(indent_step, ' ');
                const auto &arr = jv.get_array();
                for (auto it = arr.begin(), last = std::prev(arr.end()); it != arr.end(); ++it) {
                    os << *indent;
                    save_pretty(os, *it, indent);
                    if (it != last)
                        os << ',';
                    os << '\n';
                }
                indent->resize(indent->size() - indent_step);
                os << *indent << "]";
                break;
            }
            case kind::string:
                os << serialize(jv.get_string());
                break;
            case kind::uint64:
                os << jv.get_uint64();
                break;
            case kind::int64:
                os << jv.get_int64();
                break;
            case kind::double_:
                os << jv.get_double();
                break;
            case kind::bool_:
                if(jv.get_bool())
                    os << "true";
                else
                    os << "false";
                break;
            case kind::null:
                os << "null";
                break;
        }
    }

    std::string serialize_pretty(const value &jv)
    {
        std::ostringstream ss {};
        save_pretty(ss, jv);
        return ss.str();
    }

    void save_pretty(const std::string &path, const value &jv)
    {
        file::write(path, serialize_pretty(jv));
    }
}
