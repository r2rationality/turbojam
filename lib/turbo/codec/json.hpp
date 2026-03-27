#pragma once
/* Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com) */

#include <boost/json.hpp>
#include <turbo/common/bytes.hpp>
#include <turbo/common/serializable.hpp>

namespace turbo::codec::json {
    using namespace boost::json;

    template<typename T>
    concept from_json_c = requires(T t, boost::json::value jv)
    {
        { T::from_json(jv) };
    };

    template<typename T>
    concept optional_c = requires(T t)
    {
        { t.reset() };
        { t.emplace() };
    };

    extern object canonical(const object &obj);
    extern std::string serialize_canon(const object &obj);
    extern value parse(const buffer &buf);
    extern value load(const std::string &path);
    extern void save_pretty(std::ostream& os, value const &jv, std::string *indent = nullptr);
    extern std::string serialize_pretty(const value &jv);
    extern void save_pretty(const std::string &path, const value &jv);

    struct decoder: archive_t {
        decoder(const boost::json::value &jv)
        {
            _vals.emplace_back(jv);
        }

        void push(const std::string_view name)
        {
            _vals.emplace_back(_top().at(name));
        }

        void pop()
        {
            if (_vals.size() == 1) [[unlikely]]
                throw error("cannot pop the top element!");
            _vals.pop_back();
        }

        template<typename T>
        static void decode(const boost::json::value &jv, T &val)
        {
            if constexpr (from_json_c<T>) {
                val = T::from_json(jv);
            } else if constexpr (serializable_c<T>) {
                decoder dec { jv };
                val.serialize(dec);
            } else  if constexpr (varlen_uint_c<T>) {
                val = boost::json::value_to<typename T::base_type>(jv);
            } else if constexpr (optional_like_c<T>) {
                val.reset();
                if (!jv.is_null()) {
                    val.emplace();
                    decode(jv, *val);
                }
            } else if constexpr (bounded_range_c<T>) {
                const auto &j_arr = jv.get_array();
                check_bounds<T>(j_arr.size());
                val.clear();
                if constexpr (requires { val.reserve(j_arr.size()); })
                    val.reserve(j_arr.size());
                for (size_t i = 0; i < j_arr.size(); ++i) {
                    typename T::value_type v;
                    decode(j_arr[i], v);
                    if constexpr (has_emplace_c<T>) {
                        val.emplace_hint_unique(val.end(), std::move(v));
                    } else {
                        val.emplace_back(std::move(v));
                    }
                }
            } else if constexpr (map_like_c<T>) {
                const auto key_name = T::config().key_name;
                const auto val_name = T::config().val_name;
                const auto &ja = jv.as_array();
                val.clear();
                for (const auto &jv_item: ja) {
                    decoder jv_dec { jv_item };
                    typename T::key_type k;
                    jv_dec.process(key_name, k);
                    typename T::mapped_type v;
                    jv_dec.process(val_name, v);
                    const auto [it, created] = val.try_emplace(std::move(k), std::move(v));
                    if (!created) [[unlikely]]
                        throw error(fmt::format("a map contains non-unique items: {}", typeid(val).name()));
                }
            } else if constexpr (fixed_array_like_c<T>) {
                const auto &j_arr = jv.get_array();
                if (j_arr.size() != val.size()) [[unlikely]]
                    throw error(fmt::format("fixed array: expected size {} but got {}", val.size(), j_arr.size()));
                for (size_t i = 0; i < j_arr.size(); ++i)
                    decode(j_arr[i], val[i]);
            } else if constexpr (byte_array_like_c<T>) {
                const auto hex = boost::json::value_to<std::string_view>(jv);
                if (!hex.starts_with("0x")) [[unlikely]]
                    throw error(fmt::format("expected a hex string but got: {}", hex));
                init_from_hex(std::span<uint8_t>{val.data(), val.size()}, hex.substr(2));
            } else if constexpr (byte_sequence_like_c<T>) {
                if (jv.is_string()) {
                    const auto hex = boost::json::value_to<std::string_view>(jv);
                    if (!hex.starts_with("0x")) [[unlikely]]
                        throw error(fmt::format("expected a hex string but got: {}", hex));
                    const auto hex_data = hex.substr(2);
                    val.resize(hex_data.size() / 2);
                    init_from_hex(val, hex_data);
                } else if (jv.is_array()) {
                    const auto &ja = jv.as_array();
                    val.clear();
                    val.reserve(ja.size());
                    for (const auto &byte: ja)
                        val.emplace_back(boost::json::value_to<uint8_t>(byte));
                } else {
                    throw error(fmt::format("expected a bytestring got: {}", serialize_pretty(jv)));
                }
            } else if constexpr (std::is_same_v<T, uint8_t>
                    || std::is_same_v<T, uint16_t>
                    || std::is_same_v<T, uint32_t>
                    || std::is_same_v<T, uint64_t>
                    || std::is_same_v<T, int64_t>
                    || std::is_same_v<T, bool>) {
                val = boost::json::value_to<T>(jv);
            } else if constexpr (std::is_same_v<T, std::string>) {
                val = boost::json::value_to<std::string_view>(jv);
            } else {
                throw error(fmt::format("json serialization is not enabled for type {}", typeid(T).name()));
            }
        }

        template<typename T>
        static void decode(const boost::json::value &jv, codec::as_variant_t<T> av)
        {
            if (jv.is_object()) {
                const auto &jo = jv.as_object();
                size_t idx = 0;
                for (const auto &name: av.names) {
                    if (jo.contains(name)) {
                        decoder inner { jo.at(name) };
                        variant_set_type<T, 0>(av.val, idx, inner);
                        return;
                    }
                    ++idx;
                }
                throw error(fmt::format("an invalid value for type {}: {}", typeid(T).name(), json::serialize_pretty(jv)));
            } else if (jv.is_string()) {
                const auto req_name = json::value_to<std::string_view>(jv);
                size_t idx = 0;
                for (const auto &name: av.names) {
                    if (name == req_name) {
                        decoder inner { jv };
                        variant_set_type<T, 0>(av.val, idx, inner);
                        return;
                    }
                    ++idx;
                }
                throw error(fmt::format("an invalid value for type {}: {}", typeid(T).name(), json::serialize_pretty(jv)));
            } else {
                throw error(fmt::format("an invalid value for type {}: {}", typeid(T).name(), json::serialize_pretty(jv)));
            }
        }

        void process(auto &val)
        {
            decode(_top(), val);
        }

        void process(const std::string_view name, auto &val)
        {
            using T = std::decay_t<decltype(val)>;
            const auto &jo = _top().as_object();
            const auto it = jo.find(name);
            if (it != jo.end()) {
                decode(it->value(), val);
            } else {
                if constexpr (optional_c<T>) {
                    val.reset();
                } else {
                    throw error(fmt::format("an unsupported value for type {}: {}", typeid(T).name(), codec::json::serialize_pretty(jo)));
                }
            }
        }

        template<typename T>
        void process(codec::as_variant_t<T> av)
        {
            decode(_top(), av);
        }

    private:
        std::vector<std::reference_wrapper<const boost::json::value>> _vals {};

        const boost::json::value &_top() const
        {
            return _vals.back().get();
        }
    };

    template<typename T>
    T load_obj(const std::string &path)
    {
        const auto j = load(path);
        if constexpr (from_json_c<T>) {
            return T::from_json(j);
        } else if constexpr (codec::archive_formattable_c<T>) {
            codec::json::decoder j_dec { j };
            return codec::from<T>(j_dec);
        } else {
            throw error(fmt::format("JSON serialization not supported for {}", typeid(T).name()));
        }
    }
}
