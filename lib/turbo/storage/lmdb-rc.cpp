
extern "C" {
    #include <lmdb.h>
}

#include <climits>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <string>
#include "lmdb-rc.hpp"

namespace turbo::storage::lmdb_rc {
    struct db_t::impl {
        explicit impl(const std::string_view dir_path, const size_t initial_mapsize):
            _dir_path{dir_path}
        {
            std::filesystem::create_directories(_dir_path);
            _throw_lmdb(mdb_env_create(&_env), "_env_create");
            _throw_lmdb(mdb_env_set_maxdbs(_env, 2), "_env_set_maxdbs");
            _throw_lmdb(mdb_env_set_mapsize(_env, initial_mapsize), "_env_set_mapsize");
            _throw_lmdb(mdb_env_open(_env, _dir_path.c_str(), 0, 0664), "_env_open");
            if (const int rc = mdb_txn_begin(_env, nullptr, 0, &_txn); rc != MDB_SUCCESS) [[unlikely]] {
                _txn = nullptr;
                _throw_lmdb(rc, "txn_begin(open)");
            }
            if (const int rc = mdb_dbi_open(_txn, "file_rc.data", MDB_CREATE, &_dbi_data); rc != MDB_SUCCESS) [[unlikely]]
                _throw_lmdb(rc, "_dbi_open(data)");
            if (const int rc = mdb_dbi_open(_txn, "file_rc.counts", MDB_CREATE, &_dbi_counts); rc != MDB_SUCCESS) [[unlikely]]
                _throw_lmdb(rc, "_dbi_open(counts)");
            MDB_stat st;
            _throw_lmdb(mdb_env_stat(_env, &st), "mdb_env_stat(init)");
            _page_size = st.ms_psize;
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
            std::lock_guard<std::mutex> _g{_mutex};
            _check_txn();
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
            std::lock_guard<std::mutex> _g{_mutex};
            _check_txn();
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
                _throw_lmdb(mdb_put(_txn, _dbi_data, &k, &dv, 0), "mdb_put(data)");
            } else {
                MDB_val existing;
                rc = mdb_get(_txn, _dbi_data, &k, &existing);
                if (rc == MDB_NOTFOUND) [[unlikely]]
                    throw error("lmdb_rc: counts present but data missing (corruption)");
                if (rc != MDB_SUCCESS) [[unlikely]]
                    _throw_lmdb(rc, "mdb_get(data,verify)");
                if (existing.mv_size != val.size() ||
                        (existing.mv_size > 0 && std::memcmp(existing.mv_data, val.data(), existing.mv_size) != 0)) {
                    MDB_val dv = _to_mdb_val(val);
                    _throw_lmdb(mdb_put(_txn, _dbi_data, &k, &dv, 0), "mdb_put(data,update)");
                }
            }

            ++refc;
            MDB_val mv = _to_mdb_val(buffer::from(refc));
            _throw_lmdb(mdb_put(_txn, _dbi_counts, &k, &mv, 0), "mdb_put(counts)");
        }

        void erase(const buffer key) {
            std::lock_guard<std::mutex> _g{_mutex};
            _check_txn();
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
                _throw_lmdb(mdb_put(_txn, _dbi_counts, &k, &mv, 0), "mdb_put(counts,erase)");
            }
        }

        void clear() {
            std::lock_guard<std::mutex> _g{_mutex};
            _check_txn();
            _throw_lmdb(mdb_drop(_txn, _dbi_data, 0), "mdb_drop(data,clear)");
            _throw_lmdb(mdb_drop(_txn, _dbi_counts, 0), "mdb_drop(counts,clear)");
        }

        void foreach(const observer_t& obs) const {
            std::lock_guard<std::mutex> _g{_mutex};
            _check_txn();
            MDB_cursor* cur = nullptr;
            _throw_lmdb(mdb_cursor_open(_txn, _dbi_data, &cur), "cursor_open(data)");
            struct cursor_guard {
                MDB_cursor* c;
                ~cursor_guard() { mdb_cursor_close(c); }
            } guard{cur};
            for (;;) {
                MDB_val k, v;
                const auto rc = mdb_cursor_get(cur, &k, &v, MDB_NEXT);
                if (rc == MDB_NOTFOUND)
                    break;
                if (rc != MDB_SUCCESS) [[unlikely]]
                    _throw_lmdb(rc, "cursor_get(data)");
                obs(_from_mdb_val(k), _from_mdb_val(v));
            }
        }

        size_t size() const {
            std::lock_guard<std::mutex> _g{_mutex};
            _check_txn();
            MDB_stat st;
            if (const auto rc = mdb_stat(_txn, _dbi_data, &st); rc != MDB_SUCCESS) [[unlikely]]
                _throw_lmdb(rc, "mdb_stat(data)");
            return static_cast<size_t>(st.ms_entries);
        }

        map_info_t map_info() const {
            std::lock_guard<std::mutex> _g{_mutex};
            MDB_envinfo info;
            _throw_lmdb(mdb_env_info(_env, &info), "mdb_env_info");
            return { info.me_mapsize, static_cast<size_t>(info.me_last_pgno + 2) * _page_size };
        }

        void commit() {
            std::lock_guard<std::mutex> _g{_mutex};
            _check_txn();
            if (const auto rc = mdb_txn_commit(_txn); rc != MDB_SUCCESS) [[unlikely]] {
                _txn = nullptr;
                _throw_lmdb(rc, "txn_commit");
            }
            _txn = nullptr; // freed by mdb_txn_commit; clear before begin in case it throws
            _grow_map_if_needed();
            if (const int rc = mdb_txn_begin(_env, nullptr, 0, &_txn); rc != MDB_SUCCESS) [[unlikely]]
                _throw_lmdb(rc, "txn_begin");
        }

        void rollback() {
            std::lock_guard<std::mutex> _g{_mutex};
            _check_txn();
            mdb_txn_abort(_txn);
            _txn = nullptr;
            _grow_map_if_needed();
            if (const int rc = mdb_txn_begin(_env, nullptr, 0, &_txn); rc != MDB_SUCCESS) [[unlikely]]
                _throw_lmdb(rc, "txn_begin");
        }
    private:
        std::string _dir_path;
        MDB_env *_env{nullptr};
        MDB_dbi _dbi_data{0};
        MDB_dbi _dbi_counts{0};
        MDB_txn *_txn{nullptr};
        size_t _page_size{0};
        mutable std::mutex _mutex{};

        void _check_txn() const {
            if (!_txn) [[unlikely]]
                throw error("lmdb_rc: operation called with no active transaction");
        }

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

        // Grow the map if more than half of it is already used. Must be called with no
        // active transaction so that mdb_env_set_mapsize is safe to call.
        void _grow_map_if_needed() {
            MDB_envinfo info;
            _throw_lmdb(mdb_env_info(_env, &info), "mdb_env_info");
            const size_t used = static_cast<size_t>(info.me_last_pgno + 2) * _page_size;
            if (used * 2 > info.me_mapsize) {
                const size_t new_size = info.me_mapsize <= SIZE_MAX / 2 ? info.me_mapsize * 2 : SIZE_MAX;
                _throw_lmdb(mdb_env_set_mapsize(_env, new_size), "mdb_env_set_mapsize(grow)");
            }
        }

    };

    db_t::db_t(std::string_view dir_path, size_t initial_mapsize):
        _impl{std::make_unique<impl>(dir_path, initial_mapsize)}
    {}

    db_t::~db_t() = default;

    void db_t::clear() { _impl->clear(); }
    void db_t::erase(buffer key) { _impl->erase(key); }
    void db_t::foreach(const observer_t& obs) const { _impl->foreach(obs); }
    value_t db_t::get(buffer key) const { return _impl->get(key); }
    void db_t::set(buffer key, buffer val) { _impl->set(key, val); }
    size_t db_t::size() const { return _impl->size(); }
    map_info_t db_t::map_info() const { return _impl->map_info(); }
    void db_t::commit() { _impl->commit(); }
    void db_t::rollback() { _impl->rollback(); }
}
