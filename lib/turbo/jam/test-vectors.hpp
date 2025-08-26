#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/test.hpp>

namespace turbo::jam {
    inline std::string test_vector_dir(const std::string_view subdir)
    {
        static const std::filesystem::path test_dir{file::install_path("test/jam-test-vectors")};
        return (test_dir / subdir).string();
    }
}
