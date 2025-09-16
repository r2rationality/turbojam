/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include "fuzzer.hpp"
#include "test-vectors.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jam;
    using namespace turbo::jam::fuzzer;

    template<typename T>
    void test_file(const std::string &path)
    {
        const auto tc = jam::load_obj<T>(path + ".bin");
        {
            const auto j_tc = codec::json::load_obj<T>(path + ".json");
            expect(tc == j_tc) << "json test case does not match the binary one" << path;
        }
    }

    void test_file(const std::filesystem::path &path)
    {
        const auto stem = path.stem().string();
        const auto path_s = path.string();
        const auto path_base = path_s.substr(0, path_s.size() - 4);
        test_file<message_t<config_tiny>>(path_base);
    }
}

suite turbo_jam_fuzzer_suite = [] {
    "turbo::jam::fuzzer"_test = [] {
        static const auto test_dir = file::install_path("test/jam-conformance/fuzz-proto/examples/v1/");
        static std::optional<std::string> override_test{};
        if (!override_test) {
            for (const auto &path: file::files_with_ext_path(test_dir, ".bin")) {
                test_file(path);
            }
        } else {
            test_file(test_dir + *override_test);
        }
    };
};
