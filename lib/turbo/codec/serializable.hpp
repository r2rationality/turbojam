#pragma once
/* Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com) */

namespace turbo::codec {
    struct archive_t {
        /*void process_varlen_uint(auto &val);
        void process_uint(auto &val);
        void process(std::string_view name, auto &val);
        void process_array(auto &self, size_t min_sz, size_t max_sz);
        void process_array_fixed(auto &self);
        void process_optional(auto &val);
        void process_bytes(std::vector<uint8_t> &bytes);
        void process_bytes_fixed(std::span<uint8_t> bytes);*/
    };

    template<typename T>
    concept has_emplace_c = requires(T t)
    {
        { t.emplace() };
    };

    template<typename T>
    concept serializable_c = requires(T t, archive_t a)
    {
        { t.serialize(a) };
        { T::from(a) };
    };

    template<typename T>
    struct serializable_t {
        template<typename C=T>
        static C from(auto &archive)
        {
            C res;
            res.serialize(archive);
            return res;
        }
    };
}
