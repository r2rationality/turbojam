/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <filesystem>
#include <turbo/common/file.hpp>
#include <turbo/common/logger.hpp>
#include "file.hpp"

namespace turbo::storage::file {
    /*
     * This is intended as a low-overhead (RAM, CPU) storage for up to a million 10k+ objects.
     * It stores file in 256 subdirectories based on the first byte of the key.
     * It expects the max of 65536 files per subdirectory for optimal access performance.
     *
     * Assumptions:
     * 1) Value size: 10+ KBytes.
     * 2) Number of keys: under 1 million.
     * 3) The keys' first bytes to be close to randomly distributed.
     *
     *
     */
    struct db_t::impl {
        explicit impl(const std::string_view dir_path):
            _dir_path{dir_path}
        {
        }

        void clear()
        {
            for (auto &dir: _sub_dirs) {
                if (dir) {
                    std::filesystem::remove_all(*dir);
                    dir.reset();
                }
            }
        }

        size_t size() const
        {
            return _size;
        }

        void erase(const buffer key)
        {
            const auto path = _key_path(key);
            if (std::filesystem::exists(path)) {
                --_size;
                std::filesystem::remove(path);
            }
        }

        void foreach(const observer_t &obs)
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

        std::optional<uint8_vector> get(const buffer key) const
        {
            const auto key_path = _key_path(key);
            if (std::filesystem::exists(key_path))
                return turbo::file::read(key_path);
            return {};
        }

        void set(const buffer key, const buffer val)
        {
            const auto final_path = _key_path(key);
            if (!std::filesystem::exists(final_path))
                ++_size;
            // Write as a single OS call to ensure. The OS guarantees the call to be atomic with regard to other OS processes.
            turbo::file::write(final_path, val);
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

        std::string _key_path(const buffer key) const
        {
            if (key.size() < 2) [[unlikely]]
                throw error("filedb: a key must have at least two bytes!!");
            return fmt::format("{}/{}", _subdir_path(key[0]), key);
        }
    };

    db_t::db_t(const std::string_view dir_path):
        _impl{std::make_unique<impl>(dir_path)}
    {
    }

    db_t::~db_t() = default;

    void db_t::clear()
    {
        return _impl->clear();
    }

    size_t db_t::size() const
    {
        return _impl->size();
    }

    void db_t::erase(const buffer key)
    {
        _impl->erase(key);
    }

    void db_t::foreach(const observer_t &obs) const
    {
        _impl->foreach(obs);
    }

    std::optional<uint8_vector> db_t::get(const buffer key) const
    {
        return _impl->get(key);
    }

    void db_t::set(const buffer key, const buffer val)
    {
        _impl->set(key, val);
    }
}
