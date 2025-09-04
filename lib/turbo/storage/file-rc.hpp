#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/file.hpp>
#include "common.hpp"

// reference-counted file storage
// expects that a unique key implies the same content

namespace turbo::storage::file_rc {
    struct db_t: storage::db_t {
        db_t(const std::string_view dir_path):
            _dir_path{dir_path}
        {
        }

        ~db_t() override = default;

        void clear() override
        {
            for (auto &dir: _sub_dirs) {
                if (dir) {
                    std::filesystem::remove_all(*dir);
                    dir.reset();
                }
            }
            _size = 0;
        }

        void erase(const buffer key) override
        {
            const auto path = _key_path(key);
            if (std::filesystem::exists(path)) {
                const auto ref_count = _get_ref_count(path) - 1U;
                _set_ref_count(path, ref_count);
                if (ref_count == 0) {
                    --_size;
                    std::filesystem::remove(path);
                }
            }
        }

        void foreach(const observer_t &obs) const override
        {
            for (const auto &e: std::filesystem::recursive_directory_iterator(_dir_path)) {
                if (!e.is_regular_file())
                    continue;
                const auto p = e.path();
                if (p.extension() != "")
                    continue;
                const auto key = uint8_vector::from_hex(p.filename().string());
                auto val = get(key);
                if (!val) [[unlikely]]
                    throw error(fmt::format("filedb: unable to get data for the key: {}", key));
                obs(std::move(key), std::move(*val));
            }
        }

        value_t get(buffer key) const override
        {
            const auto key_path = _key_path(key);
            if (std::filesystem::exists(key_path))
                return turbo::file::read(key_path);
            return {};
        }

        void set(buffer key, buffer val) override
        {
            const auto final_path = _key_path(key);
            const auto ref_count = _get_ref_count(final_path) + 1U;
            if (ref_count == 1) {
                ++_size;
                turbo::file::write(final_path, val);
            }
            _set_ref_count(final_path, ref_count);
        }

        [[nodiscard]] size_t size() const override
        {
            return _size;
        }
    private:
        const std::filesystem::path _dir_path;
        mutable std::array<std::optional<std::string>, 256> _sub_dirs{};
        size_t _size{0};

        const std::string &_subdir_path(const uint8_t byte0) const
        {
            auto &sub_dir = _sub_dirs[byte0];
            if (!sub_dir) {
                const auto path = _dir_path / fmt::format("{:02X}", byte0);
                sub_dir.emplace(path.string());
                std::filesystem::create_directories(*sub_dir);
            }
            return *sub_dir;
        }

        static size_t _get_ref_count(const std::string &final_path)
        {
            if (!std::filesystem::exists(final_path))
                return 0U;
            const auto ref_path = final_path + ".ref";
            if (!std::filesystem::exists(ref_path))
                return 1U;
            return static_cast<buffer>(turbo::file::read(ref_path)).to<size_t>();
        }

        static void _set_ref_count(const std::string &final_path, const size_t ref_count)
        {
            const auto ref_path = final_path + ".ref";
            if (ref_count < 2)
                std::filesystem::remove(ref_path);
            else
                turbo::file::write(ref_path, buffer::from(ref_count));
        }

        std::string _key_path(const buffer key) const
        {
            if (key.size() < 2) [[unlikely]]
                throw error("filedb: a key must have at least two bytes!!");
            return fmt::format("{}/{}", _subdir_path(key[0]), key);
        }
    };
    using db_ptr_t = std::shared_ptr<db_t>;
}
