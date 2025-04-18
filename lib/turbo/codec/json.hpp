#pragma once
/* Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com) */

#include <boost/json.hpp>
#include <turbo/common/bytes.hpp>
#include "serializable.hpp"

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

    struct decoder: archive_t {
        decoder(const boost::json::value &jv):
            _jv { jv }
        {
        }

        template<typename T>
        static void decode(const boost::json::value &jv, T &val)
        {
            if constexpr (from_json_c<T>) {
                val = T::from_json(jv);
            } else if constexpr (serializable_c<T>) {
                decoder dec { jv };
                val.serialize(dec);
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
                throw error(fmt::format("serialization is not enabled for type {}", typeid(T).name()));
            }
        }

        template<typename T>
        void process_varlen_uint(T &val)
        {
            val = boost::json::value_to<T>(_jv);
        }

        template<typename T>
        void process_uint(T &val)
        {
            process_varlen_uint(val);
        }

        void process(const std::string_view name, auto &val)
        {
            using T = std::decay_t<decltype(val)>;
            const auto &jo = _jv.as_object();
            const auto it = jo.find(name);
            if (it != jo.end()) {
                decode(_jv.at(name), val);
            } else {
                if constexpr (optional_c<T>) {
                    val.reset();
                } else {
                    throw error(fmt::format("serialization of missing values not enabled for type {} with key {}", typeid(T).name(), name));
                }
            }
        }

        void process_map(auto &m, const std::string_view key_name, const std::string_view val_name)
        {
            using T = std::decay_t<decltype(m)>;
            const auto &ja = _jv.as_array();
            m.clear();
            for (const auto &jv: ja) {
                decoder jv_dec { jv };
                typename T::key_type k;
                jv_dec.process(key_name, k);
                typename T::mapped_type v;
                jv_dec.process(val_name, v);
                const auto [it, created] = m.try_emplace(std::move(k), std::move(v));
                if (!created) [[unlikely]]
                    throw error(fmt::format("a map contains non-unique items: {}", typeid(m).name()));
            }
        }

        void process_array(auto &self, const size_t min_sz=0, const size_t max_sz=std::numeric_limits<size_t>::max())
        {
            using T = std::decay_t<decltype(self)>;
            const auto &j_arr = _jv.get_array();
            if (!(static_cast<int>(j_arr.size() >= min_sz) & static_cast<int>(j_arr.size() <= max_sz))) [[unlikely]]
                throw error(fmt::format("array size {} is out of allowed bounds: [{}, {}]", j_arr.size(), min_sz, max_sz));
            self.clear();
            self.reserve(j_arr.size());
            for (size_t i = 0; i < j_arr.size(); ++i) {
                typename T::value_type v;
                decode(j_arr[i], v);
                if constexpr (has_emplace_c<T>) {
                    self.emplace_hint_unique(self.end(), std::move(v));
                } else {
                    self.emplace_back(std::move(v));
                }
            }
        }

        void process_array_fixed(auto &self)
        {
            const auto &j_arr = _jv.get_array();
            if (j_arr.size() != self.size()) [[unlikely]]
                throw error(fmt::format("fixed array: expected size {} but got {}", self.size(), j_arr.size()));
            for (size_t i = 0; i < j_arr.size(); ++i) {
                decode(j_arr[i], self[i]);
            }
        }

        template<typename T>
        void process_optional(T &val)
        {
            val.reset();
            if (!_jv.is_null()) {
                val.emplace();
                decode(_jv, *val);
            }
        }

        void process_bytes(std::vector<uint8_t> &bytes)
        {
            const auto hex = boost::json::value_to<std::string_view>(_jv);
            if (!hex.starts_with("0x")) [[unlikely]]
                throw error(fmt::format("expected a hex string but got: {}", hex));
            const auto hex_data = hex.substr(2);
            bytes.resize(hex_data.size() / 2);
            init_from_hex(bytes, hex_data);
        }

        void process_bytes_fixed(std::span<uint8_t> bytes)
        {
            const auto hex = boost::json::value_to<std::string_view>(_jv);
            if (!hex.starts_with("0x")) [[unlikely]]
                throw error(fmt::format("expected a hex string but got: {}", hex));
            init_from_hex(bytes, hex.substr(2));
        }
    private:
        const boost::json::value &_jv;
    };

    extern object canonical(const object &obj);
    extern std::string serialize_canon(const object &obj);
    extern value parse(const buffer &buf);
    extern value load(const std::string &path);
    extern void save_pretty(std::ostream& os, value const &jv, std::string *indent = nullptr);
    extern std::string serialize_pretty(const value &jv);
    extern void save_pretty(const std::string &path, const value &jv);
}
