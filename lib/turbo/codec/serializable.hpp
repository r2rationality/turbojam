#pragma once
/* Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com) */

#include <variant>

namespace turbo::codec {
    struct archive_t {
    };

    template<typename T>
    T from(auto &archive)
    {
        T res;
        res.serialize(archive);
        return res;
    }

    template<typename T>
    using variant_names_t = std::array<std::string_view, std::variant_size_v<T>>;

    template<typename T, size_t I>
    void variant_set_type(T &val, const size_t requested_type, auto &archive)
    {
        if (requested_type >= std::variant_size_v<T>) [[unlikely]]
            throw error(fmt::format("an unsupported type value {} for {}", requested_type, typeid(T).name()));
        if constexpr (I < std::variant_size_v<T>) {
            if (requested_type > I)
                return variant_set_type<T, I + 1>(val, requested_type, archive);
            if (requested_type < I) [[unlikely]]
                throw error(fmt::format("internal error: an incomplete traversal of type {}", typeid(T).name()));
            val = codec::from<std::variant_alternative_t<I, T>>(archive);
        }
    }

    template<typename T, size_t I>
    void variant_get_type(T &val, const size_t requested_type, auto &archive)
    {
        if (requested_type >= std::variant_size_v<T>) [[unlikely]]
            throw error(fmt::format("an unsupported type value {} for {}", requested_type, typeid(T).name()));
        if constexpr (I < std::variant_size_v<T>) {
            if (requested_type > I)
                return variant_set_type<T, I + 1>(val, requested_type, archive);
            if (requested_type < I) [[unlikely]]
                throw error(fmt::format("internal error: an incomplete traversal of type {}", typeid(T).name()));
            val = codec::from<std::variant_alternative_t<I, T>>(archive);
        }
    }

    template<typename T>
    concept has_emplace_c = requires(T t)
    {
        { t.emplace() };
    };

    template<typename T>
    concept serializable_c = requires(T t, archive_t a)
    {
        { t.serialize(a) };
    };
}
