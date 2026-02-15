
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
            if (const int rc = mdb_txn_begin(_env, nullptr, 0, &_txn); rc != MDB_SUCCESS) [[unlikely]] {
                _txn = nullptr;
                _throw_lmdb(rc, "txn_begin(open)");
            }
            if (const int rc = mdb_dbi_open(_txn, "file_rc.data", MDB_CREATE, &_dbi_data); rc != MDB_SUCCESS) [[unlikely]]
                _throw_lmdb(rc, "_dbi_open(data)");
            if (const int rc = mdb_dbi_open(_txn, "file_rc.counts", MDB_CREATE, &_dbi_counts); rc != MDB_SUCCESS) [[unlikely]]
                _throw_lmdb(rc, "_dbi_open(counts)");
        }

        ~impl() {
            // mdb_env_close will abort all open transactions and close all open DB handles
            if (_env) [[likely]] {
                if (_txn) [[likely]]
                    mdb_txn_abort(_txn);
                mdb_env_close(_env);
            }
        }

        value_t get(const buffer key) const {
            MDB_val k = _to_mdb_val(key);
            MDB_val v;
            const auto rc = mdb_get(_txn, _dbi_data, &k, &v);
            if (rc == MDB_NOTFOUND)
                return {};
            if (rc != MDB_SUCCESS) [[unlikely]]
                _throw_lmdb(rc, "mdb_get(data)");
            return value_t{_from_mdb_val(v)};
        }

        void set(const buffer key, const buffer val) {
            std::lock_guard<std::mutex> _g{_write_mutex};
            MDB_val k = _to_mdb_val(key);

            uint64_t refc = 0;
            MDB_val cv;
            auto rc = mdb_get(_txn, _dbi_counts, &k, &cv);
            if (rc == MDB_NOTFOUND) {
                refc = 0;
            } else if (rc != MDB_SUCCESS) [[unlikely]] {
                _throw_lmdb(rc, "mdb_get(counts)");
            } else {
                refc = _from_mdb_val(cv).to<uint64_t>();
            }

            if (refc == 0) {
                MDB_val dv = _to_mdb_val(val);
                _throw_lmdb(mdb_put(_txn, _dbi_data, &k, &dv, 0), "mdb_put(data,insert)");
            } else {
                MDB_val existing;
                rc = mdb_get(_txn, _dbi_data, &k, &existing);
                if (rc == MDB_NOTFOUND) [[unlikely]]
                    throw error("lmdb_rc: counts present but data missing (corruption)");
                if (rc != MDB_SUCCESS) [[unlikely]]
                    _throw_lmdb(rc, "mdb_get(data,verify)");
                if (existing.mv_size != val.size() ||
                    (existing.mv_size > 0 &&
                     std::memcmp(existing.mv_data, val.data(), existing.mv_size) != 0))
                {
                    MDB_val dv = _to_mdb_val(val);
                    _throw_lmdb(mdb_put(_txn, _dbi_data, &k, &dv, 0), "mdb_put(data,update)");
                }
            }

            ++refc;
            MDB_val mv = _to_mdb_val(buffer::from(refc));
            _throw_lmdb(mdb_put(_txn, _dbi_counts, &k, &mv, 0), "mdb_put(counts,update)");
        }

        void erase(const buffer key) {
            std::lock_guard<std::mutex> _g{_write_mutex};
            MDB_val k = _to_mdb_val(key);
            MDB_val cv;
            auto rc = mdb_get(_txn, _dbi_counts, &k, &cv);
            if (rc == MDB_NOTFOUND)
                return;
            if (rc != MDB_SUCCESS) [[unlikely]]
                _throw_lmdb(rc, "mdb_get(counts,erase)");

            auto refc = _from_mdb_val(cv).to<uint64_t>();
            if (refc <= 1U) {
                _throw_lmdb(mdb_del(_txn, _dbi_counts, &k, nullptr), "mdb_del(counts)");
                rc = mdb_del(_txn, _dbi_data, &k, nullptr);
                if (rc != MDB_SUCCESS && rc != MDB_NOTFOUND) [[unlikely]]
                    _throw_lmdb(rc, "mdb_del(data)");
            } else {
                --refc;
                MDB_val mv = _to_mdb_val(buffer::from(refc));
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
            for (;;) {
                MDB_val k, v;
                const auto rc = mdb_cursor_get(cur, &k, &v, MDB_NEXT);
                if (rc != MDB_SUCCESS) {
                    mdb_cursor_close(cur);
                    if (rc != MDB_NOTFOUND) [[unlikely]]
                        _throw_lmdb(rc, "cursor_get(data)");
                    break;
                }
                obs(_from_mdb_val(k), _from_mdb_val(v));
            }
        }

        size_t size() const {
            MDB_stat st;
            if (const auto rc = mdb_stat(_txn, _dbi_data, &st); rc != MDB_SUCCESS) [[unlikely]]
                _throw_lmdb(rc, "mdb_stat(data)");
            return static_cast<size_t>(st.ms_entries);
        }

        void commit() {
            if (const auto rc = mdb_txn_commit(_txn); rc != MDB_SUCCESS) [[unlikely]] {
                _txn = nullptr;
                _throw_lmdb(rc, "txn_commit");
            }
            if (const int rc = mdb_txn_begin(_env, nullptr, 0, &_txn); rc != MDB_SUCCESS) [[unlikely]] {
                _txn = nullptr;
                _throw_lmdb(rc, "txn_begin");
            }
        }

        void rollback() {
            mdb_txn_abort(_txn);
            if (const int rc = mdb_txn_begin(_env, nullptr, 0, &_txn); rc != MDB_SUCCESS) [[unlikely]] {
                _txn = nullptr;
                _throw_lmdb(rc, "txn_begin");
            }
        }
    private:
        std::string _dir_path;
        MDB_env *_env{nullptr};
        MDB_dbi _dbi_data{0};
        MDB_dbi _dbi_counts{0};
        MDB_txn *_txn{nullptr};
        mutable std::mutex _write_mutex{};

        static void _throw_lmdb(int rc, const char* what) {
            if (rc != MDB_SUCCESS) [[unlikely]]
                throw error(fmt::format("lmdb_rc: {}: {}", what, mdb_strerror(rc)));
        }

        static MDB_val _to_mdb_val(const buffer b) {
            return {b.size(), const_cast<void*>(static_cast<const void*>(b.data()))};
        }

        static buffer _from_mdb_val(const MDB_val v) {
            return {static_cast<const uint8_t*>(v.mv_data), v.mv_size};
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
