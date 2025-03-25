/* Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com) */

#include <hash-library/keccak.h>
#include "keccak.hpp"

namespace turbo::crypto::keccak {
    void digest(hash_t &out, const buffer &in)
    {
        Keccak hasher {};
        hasher.add(in.data(), in.size());
        hasher.getHashBin(out);
    }
}
