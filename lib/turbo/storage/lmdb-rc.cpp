
extern "C" {
    #include <lmdb.h>
}

#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>
#include "lmdb-rc.hpp"

namespace turbo::storage::lmdb_rc {
    struct db_t::impl {
        explicit impl(const std::string_view dir_path):
            _dir_path{dir_path}
        {
            std::filesystem::create_directories(_dir_path);
            _throw_lmdb(mdb_env_create(&_env), "_env_create");
            _throw_lmdb(mdb_env_set_maxdbs(_env, 2), "_env_set_maxdbs");
            _throw_lmdb(mdb_env_set_mapsize(_env, 1ULL << 30U), "_env_set_mapsize");
            _throw_lmdb(mdb_env_open(_env, _dir_path.c_str(), 0, 0664), "_env_open");
            _throw_lmdb(mdb_txn_begin(_env, nullptr, 0, &_txn), "txn_begin(open)");
            if (const int rc = mdb_dbi_open(_txn, "file_rc.data", MDB_CREATE, &_dbi_data); rc != MDB_SUCCESS) {
                mdb_txn_abort(_txn);
                _throw_lmdb(rc, "_dbi_open(data)");
            }
            if (const int rc = mdb_dbi_open(_txn, "file_rc.counts", MDB_CREATE, &_dbi_counts); rc != MDB_SUCCESS) {
                mdb_txn_abort(_txn);
                _throw_lmdb(rc, "_dbi_open(counts)");
            }
        }

        ~impl() {
            if (_env) {
                mdb_txn_abort(_txn);
                mdb_dbi_close(_env, _dbi_data);
                mdb_dbi_close(_env, _dbi_counts);
                mdb_env_close(_env);
                _env = nullptr;
            }
        }

        impl(impl&&) = delete;
        impl& operator=(impl&&) = delete;
        impl(const impl&) = delete;
        impl& operator=(const impl&) = delete;

        value_t get(buffer key) const {
            MDB_val k = _to_mdb_val(key);
            MDB_val v{};

            const auto rc = mdb_get(_txn, _dbi_data, &k, &v);
            if (rc == MDB_NOTFOUND) {
                return {};
            }
            if (rc != MDB_SUCCESS) {
                _throw_lmdb(rc, "mdb_get(data)");
            }

            uint8_vector out(v.mv_size);
            if (!out.empty())
                std::memcpy(out.data(), v.mv_data, v.mv_size);
            return value_t{std::move(out)};
        }

        void set(const buffer key, const buffer val) {
            std::lock_guard<std::mutex> _g{_write_mutex};

            MDB_val k = _to_mdb_val(key);

            uint64_t refc = 0;
            MDB_val cv{};
            auto rc = mdb_get(_txn, _dbi_counts, &k, &cv);
            if (rc == MDB_NOTFOUND) {
                refc = 0;
            } else if (rc != MDB_SUCCESS) {
                _throw_lmdb(rc, "mdb_get(counts)");
            } else {
                refc = _parse_count_value(cv);
            }

            if (refc == 0) {
                MDB_val dv = _to_mdb_val(val);
                _throw_lmdb(mdb_put(_txn, _dbi_data, &k, &dv, 0), "mdb_put(data,insert)");
            } else {
                MDB_val existing{};
                rc = mdb_get(_txn, _dbi_data, &k, &existing);
                if (rc == MDB_NOTFOUND) [[unlikely]] {
                    throw error("lmdb_rc: counts present but data missing (corruption)");
                }
                if (rc != MDB_SUCCESS) {
                    _throw_lmdb(rc, "mdb_get(data,verify)");
                }
                if (existing.mv_size != val.size() ||
                    (existing.mv_size > 0 &&
                     std::memcmp(existing.mv_data, val.data(), existing.mv_size) != 0))
                {
                    MDB_val dv = _to_mdb_val(val);
                    _throw_lmdb(mdb_put(_txn, _dbi_data, &k, &dv, 0), "mdb_put(data,update)");
                }
            }

            const uint64_t new_refc = refc + 1;
            uint8_vector count_blob(sizeof(uint64_t));
            _store_u64_le(count_blob.data(), new_refc);
            MDB_val mv = _vec_to_mdb_val(count_blob);
            _throw_lmdb(mdb_put(_txn, _dbi_counts, &k, &mv, 0), "mdb_put(counts,update)");
        }

        void erase(buffer key) {
            std::lock_guard<std::mutex> _g{_write_mutex};

            MDB_val k = _to_mdb_val(key);

            MDB_val cv{};
            auto rc = mdb_get(_txn, _dbi_counts, &k, &cv);
            if (rc == MDB_NOTFOUND) {
                return;
            }
            if (rc != MDB_SUCCESS) {
                _throw_lmdb(rc, "mdb_get(counts,erase)");
            }

            const uint64_t refc = _parse_count_value(cv);

            if (refc <= 1) {
                _throw_lmdb(mdb_del(_txn, _dbi_counts, &k, nullptr), "mdb_del(counts)");
                rc = mdb_del(_txn, _dbi_data, &k, nullptr);
                if (rc != MDB_SUCCESS && rc != MDB_NOTFOUND) {
                    _throw_lmdb(rc, "mdb_del(data)");
                }
            } else {
                const uint64_t new_refc = refc - 1;
                uint8_vector count_blob(sizeof(uint64_t));
                _store_u64_le(count_blob.data(), new_refc);
                MDB_val mv = _vec_to_mdb_val(count_blob);
                _throw_lmdb(mdb_put(_txn, _dbi_counts, &k, &mv, 0), "mdb_put(counts,decrement)");
            }
        }

        void clear() {
            std::lock_guard<std::mutex> _g{_write_mutex};
            _throw_lmdb(mdb_drop(_txn, _dbi_data, 0), "mdb_drop(data,clear)");
            _throw_lmdb(mdb_drop(_txn, _dbi_counts, 0), "mdb_drop(counts,clear)");
        }

        void foreach(const observer_t& obs) const {
            MDB_cursor* cur = nullptr;
            _throw_lmdb(mdb_cursor_open(_txn, _dbi_data, &cur), "cursor_open(data)");

            MDB_val k{}, v{};
            auto rc = mdb_cursor_get(cur, &k, &v, MDB_FIRST);
            while (rc == MDB_SUCCESS) {
                uint8_vector val_vec(v.mv_size);
                if (!val_vec.empty())
                    std::memcpy(val_vec.data(), v.mv_data, v.mv_size);
                obs(buffer{static_cast<const uint8_t*>(k.mv_data), k.mv_size}, std::move(val_vec));
                rc = mdb_cursor_get(cur, &k, &v, MDB_NEXT);
            }
            if (rc != MDB_NOTFOUND) {
                mdb_cursor_close(cur);
                _throw_lmdb(rc, "cursor_get(data)");
            }
            mdb_cursor_close(cur);
        }

        size_t size() const {
            MDB_stat st{};
            if (const auto rc = mdb_stat(_txn, _dbi_data, &st); rc != MDB_SUCCESS) {
                mdb_txn_abort(_txn);
                _throw_lmdb(rc, "mdb_stat(data)");
            }
            return static_cast<size_t>(st.ms_entries);
        }

        void commit() {
            _throw_lmdb(mdb_txn_commit(_txn), "txn_commit(open)");
            _throw_lmdb(mdb_txn_begin(_env, nullptr, 0, &_txn), "txn_begin(open)");
        }

        void rollback() {
            mdb_txn_abort(_txn);
            _throw_lmdb(mdb_txn_begin(_env, nullptr, 0, &_txn), "txn_begin(open)");
        }

    private:
        std::string _dir_path;
        MDB_env *_env{nullptr};

        MDB_dbi _dbi_data{0};
        MDB_dbi _dbi_counts{0};

        MDB_txn *_txn{nullptr};
        mutable std::mutex _write_mutex;

        static void _throw_lmdb(int rc, const char* what) {
            if (rc == MDB_SUCCESS) [[likely]]
                return;
            throw error(fmt::format("lmdb_rc: {}: {}", what, mdb_strerror(rc)));
        }

        static MDB_val _to_mdb_val(const buffer b) {
            MDB_val v{};
            v.mv_size = b.size();
            v.mv_data = const_cast<void*>(static_cast<const void*>(b.data()));
            return v;
        }

        static uint64_t _load_u64_le(const void* p) {
            uint64_t x;
            std::memcpy(&x, p, sizeof(x));
            return x;
        }

        static void _store_u64_le(void* p, uint64_t x) {
            std::memcpy(p, &x, sizeof(x));
        }

        static uint64_t _parse_count_value(const MDB_val& v) {
            if (v.mv_size != sizeof(uint64_t)) {
                throw error("lmdb_rc: corrupted refcount entry (expected 8 bytes)");
            }
            return _load_u64_le(v.mv_data);
        }

        template<typename Vec>
        static MDB_val _vec_to_mdb_val(Vec& v) {
            MDB_val mv{};
            mv.mv_size = v.size();
            mv.mv_data = v.data();
            return mv;
        }
    };

    db_t::db_t(std::string_view dir_path):
        _impl{std::make_unique<impl>(dir_path)}
    {}

    db_t::~db_t() = default;

    void db_t::clear() { _impl->clear(); }
    void db_t::erase(buffer key) { _impl->erase(key); }
    void db_t::foreach(const observer_t& obs) const { _impl->foreach(obs); }
    value_t db_t::get(buffer key) const { return _impl->get(key); }
    void db_t::set(buffer key, buffer val) { _impl->set(key, val); }
    size_t db_t::size() const { return _impl->size(); }
    void db_t::commit() { _impl->commit(); }
    void db_t::rollback() { _impl->rollback(); }
}
