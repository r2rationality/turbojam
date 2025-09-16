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
        void process_varlen_uint(T &val)
        {
            val = boost::json::value_to<T>(_top());
        }

        void process_string(std::string &val)
        {
            val = boost::json::value_to<std::string_view>(_top());
        }

        template<typename T>
        void process_uint(T &val)
        {
            process_varlen_uint(val);
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
                decode(_top().at(name), val);
            } else {
                if constexpr (optional_c<T>) {
                    val.reset();
                } else {
                    throw error(fmt::format("an unsupported value for type {}: {}", typeid(T).name(), codec::json::serialize_pretty(jo)));
                }
            }
        }

        void process_map(auto &m, const std::string_view key_name, const std::string_view val_name)
        {
            using T = std::decay_t<decltype(m)>;
            const auto &ja = _top().as_array();
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
            const auto &j_arr = _top().get_array();
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
            const auto &j_arr = _top().get_array();
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
            if (!_top().is_null()) {
                val.emplace();
                decode(_top(), *val);
            }
        }

        template<typename T>
        void process_variant(T &val, const codec::variant_names_t<T> &names, const variant_index_overrides_t *overrides=nullptr)
        {
            (void)overrides;
            if (_top().is_object()) {
                const auto &jo = _top().as_object();
                size_t idx = 0;
                for (const auto &name: names) {
                    if (jo.contains(name)) {
                        push(name);
                        variant_set_type<T, 0>(val, idx, *this);
                        pop();
                        return;
                    }
                    ++idx;
                }
                throw error(fmt::format("an invalid value for type {}: {}", typeid(T).name(), json::serialize_pretty(_top())));
            } else if (_top().is_string()) {
                const auto req_name = json::value_to<std::string_view>(_top());
                size_t idx = 0;
                for (const auto &name: names) {
                    if (name == req_name) {
                        variant_set_type<T, 0>(val, idx, *this);
                        return;
                    }
                    ++idx;
                }
                throw error(fmt::format("an invalid value for type {}: {}", typeid(T).name(), json::serialize_pretty(_top())));
            } else {
                throw error(fmt::format("an invalid value for type {}: {}", typeid(T).name(), json::serialize_pretty(_top())));
            }
        }

        void process_bytes(std::vector<uint8_t> &bytes)
        {
            const auto &jv = _top();
            if (jv.is_string()) {
                const auto hex = boost::json::value_to<std::string_view>(_top());
                if (!hex.starts_with("0x")) [[unlikely]]
                    throw error(fmt::format("expected a hex string but got: {}", hex));
                const auto hex_data = hex.substr(2);
                bytes.resize(hex_data.size() / 2);
                init_from_hex(bytes, hex_data);
            } else if (jv.is_array()) {
                const auto &ja = jv.as_array();
                bytes.clear();
                bytes.reserve(ja.size());
                for (const auto &byte: ja) {
                    bytes.emplace_back(boost::json::value_to<uint8_t>(byte));
                }
            } else {
                throw error(fmt::format("expected a bytestring got: {}", serialize_pretty(jv)));
            }
        }

        void process_bytes_fixed(std::span<uint8_t> bytes)
        {
            const auto hex = boost::json::value_to<std::string_view>(_top());
            if (!hex.starts_with("0x")) [[unlikely]]
                throw error(fmt::format("expected a hex string but got: {}", hex));
            init_from_hex(bytes, hex.substr(2));
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
        } else if constexpr (codec::serializable_c<T>) {
            codec::json::decoder j_dec { j };
            return codec::from<T>(j_dec);
        } else {
            throw error(fmt::format("JSON serialization not supported for {}", typeid(T).name()));
        }
    }
}
