/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <filesystem>
#include <turbo/common/file.hpp>
#include <turbo/common/logger.hpp>
#include "filedb.hpp"

namespace turbo::storage::filedb {
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
    struct client_t::impl {
        explicit impl(const std::string_view dir_path):
            _dir_path { dir_path }
        {
            for (size_t byte0 = 0; byte0 < 0x100; ++byte0) {
                std::filesystem::create_directories(_subdir_path(byte0));
            }
        }

        void erase(const buffer key)
        {
            std::filesystem::remove(_key_path(key));
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

        std::optional<write_vector> get(const buffer key) const
        {
            const auto key_path = _key_path(key);
            if (std::filesystem::exists(key_path))
                return file::read(key_path);
            return {};
        }

        void set(const buffer key, const buffer val)
        {
            const auto final_path = _key_path(key);
            const auto tmp_path = final_path + ".tmp";
            // write into a temporary file + rename ensures partial values are never kept/returned.
            file::write(tmp_path, val);
            std::filesystem::rename(tmp_path, final_path);
        }
    private:
        std::filesystem::path _dir_path;

        std::filesystem::path _subdir_path(const uint8_t byte0) const
        {
            return _dir_path / fmt::format("{:02X}", byte0);
        }

        std::string _key_path(const buffer key) const
        {
            if (key.size() < 2) [[unlikely]]
                throw error("filedb: a key must have at least two bytes!!");
            return (_subdir_path(key[0]) / fmt::format("{}", key)).string();
        }
    };

    client_t::client_t(const std::string_view dir_path):
        _impl { std::make_unique<impl>(dir_path) }
    {
    }

    client_t::~client_t() = default;

    void client_t::erase(const buffer key)
    {
        _impl->erase(key);
    }

    void client_t::foreach(const observer_t &obs)
    {
        _impl->foreach(obs);
    }

    std::optional<write_vector> client_t::get(const buffer key) const
    {
        return _impl->get(key);
    }

    void client_t::set(const buffer key, const buffer val)
    {
        _impl->set(key, val);
    }
}
