/* Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
* Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com) */

#include <turbo/common/benchmark.hpp>
#include <turbo/crypto/blake2b.hpp>
#include "lmdb-rc.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::storage;
    using namespace turbo::crypto;
}

suite turbo_storage_lmdb_rc_bench_suite = [] {
    "turbo::storage::lmdb_rc"_test = [] {
        ankerl::nanobench::Bench b{};
        b.title("turbo::storage::lmdb_rc")
            .output(&std::cerr)
            .unit("ops")
            .performanceCounters(true);
        std::map<blake2b::hash_t, uint8_vector> kvs{};
        for (size_t i = 0; i < 250; ++i) {
            kvs.emplace(blake2b::digest(buffer::from(i)), uint8_vector(i * 1000));
        }
        const file::tmp_directory tmp_dir{"test-turbo-lmdb-rc-bench"};
        lmdb_rc::db_t db{tmp_dir.path()};
        b.batch(kvs.size());
        b.run("writes",[&] {
            for (const auto &[k, v]: kvs) {
                db.set(k, v);
            }
        });
        b.run("reads",[&] {
            for (const auto &[k, v]: kvs) {
                expect(db.get(k) == v) << k;
            }
        });
    };
};