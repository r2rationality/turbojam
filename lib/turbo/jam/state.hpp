#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <numeric>
#include <turbo/container/update-map.hpp>
#include <turbo/storage/update.hpp>
#include <turbo/storage/memory.hpp>
#include "triedb.hpp"
#include "types/header.hpp"
#include "types/mutable-value.hpp"
#include "types/state-dict.hpp"

namespace turbo::jam {
    template<typename T>
    struct persistent_value_t {
        using element_type = T;
        using ptr_type = std::shared_ptr<element_type>;
        using serialize_func_t = std::function<void(const element_type &)>;

        persistent_value_t(storage::db_ptr_t db, const state_key_t &key):
            _db{std::move(db)},
            _key{key}
        {
            if (!_db) [[unlikely]]
                throw error("a persistent value requires an initialized state_dict!");
        }

        persistent_value_t(storage::db_ptr_t db, const uint8_t code):
            persistent_value_t{std::move(db), state_dict_t::make_key(code)}
        {
        }

        persistent_value_t(storage::db_ptr_t db, const state_key_t &key, T val):
            persistent_value_t{std::move(db), key}
        {
            set(std::move(val));
        }

        void serialize(auto &archive) {
            using namespace std::string_view_literals;
            // TODO: can be optimized for the decoding case. That happens only in unit tests though.
            T tmp;
            archive.process(tmp);
            set(std::move(tmp));
        }

        const element_type &get() const {
            if (!_ptr) {
                const auto bytes = _db->get(_key);
                if (!bytes) [[unlikely]]
                    throw error(fmt::format("a required state element is missing: {}", _key));
                _ptr = std::make_shared<element_type>(jam::from_bytes<element_type>(*bytes));
            }
            return *_ptr;
        }

        void set(ptr_type new_ptr) {
            _updated = true;
            _ptr = std::move(new_ptr);
        }

        element_type &update() {
            _updated = true;
            return const_cast<element_type &>(get());
        }

        void reset() {
            _ptr.reset();
            _updated = false;
        }

        void commit() {
            if (_updated) {
                _db->set(_key, _encode(*_ptr));
                _updated = false;
            }
        }

        void rollback() {
            if (_updated)
                reset();
        }

        bool operator==(const persistent_value_t &o) const {
            return *_ptr == *o._ptr;
        }
    private:
        storage::db_ptr_t _db;
        state_key_t _key;
        mutable ptr_type _ptr{};
        bool _updated = false;

        template<typename V>
        static uint8_vector _encode(const V &v)
        {
            encoder enc{v};
            return {std::move(enc.bytes())};
        }
    };

    template<typename CFG>
    struct service_info_t {
        opaque_hash_t code_hash {}; // c
        balance_t balance = 0; // b
        // gas saved in the fixed format form
        gas_t::base_type min_item_gas = 0; // g
        gas_t::base_type min_memo_gas = 0; // m
        uint64_t bytes = 0; // b
        uint64_t deposit_offset = 0; // f
        uint32_t items = 0; // i
        time_slot_t<CFG> creation_slot = 0; // r
        time_slot_t<CFG> last_accumulation_slot = 0; // a
        service_id_t parent_service = 0; // p

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("code_hash"sv, code_hash);
            archive.process("balance"sv, balance);
            archive.process("min_item_gas"sv, min_item_gas);
            archive.process("min_memo_gas"sv, min_memo_gas);
            archive.process("bytes"sv, bytes);
            archive.process("deposit_offset"sv, deposit_offset);
            archive.process("items"sv, items);
            archive.process("creation_slot"sv, creation_slot);
            archive.process("last_accumulation_slot"sv, last_accumulation_slot);
            archive.process("parent_service"sv, parent_service);
        }

        [[nodiscard]] balance_t threshold() const
        {
            const auto t = config_base::BS_min_balance_per_service
                + config_base::BI_min_balance_per_item * items
                + config_base::BL_min_balance_per_octet * bytes;
            return t >= deposit_offset ? t - deposit_offset : 0;
        }

        bool operator==(const service_info_t<CFG> &o) const noexcept = default;
    };

    struct storage_items_config_t {
        std::string key_name = "key";
        std::string val_name = "blob";
    };
    using storage_items_t = map_t<byte_sequence_t, byte_sequence_t, storage_items_config_t>;

    struct preimage_items_config_t {
        std::string key_name = "hash";
        std::string val_name = "blob";
    };
    using preimage_items_t = map_t<opaque_hash_t, byte_sequence_t, preimage_items_config_t>;

    struct lookup_meta_map_key_t {
        opaque_hash_t hash;
        uint32_t length;

        static uint32_t len_from_state_key(const state_key_t &k)
        {
            return decoder::uint_fixed<uint32_t>(byte_array<4> { k[1], k[3], k[5], k[7] });
        }

        void serialize(auto &archive)
        {
            using namespace std::placeholders;
            archive.process("hash", hash);
            archive.process("length", length);
        }

        std::strong_ordering operator<=>(const lookup_meta_map_key_t &o) const noexcept
        {
            const auto cmp = hash <=> o.hash;
            if (cmp != std::strong_ordering::equal)
                return cmp;
            return length <=> o.length;
        }

        bool operator==(const lookup_meta_map_key_t &o) const
        {
            return (*this <=> o) == std::strong_ordering::equal;
        }
    };

    struct lookup_metas_config_t {
        std::string key_name = "key";
        std::string val_name = "value";
    };
    template<typename CFG>
    using lookup_meta_map_val_t = sequence_t<time_slot_t<CFG>, 0, 3>;

    template<typename CFG>
    using lookup_meta_items_t = map_t<lookup_meta_map_key_t, lookup_meta_map_val_t<CFG>, lookup_metas_config_t>;

    struct accounts_config_t {
        std::string key_name = "id";
        std::string val_name = "data";
    };

    template<typename CFG>
    struct account_updates_t;

    template<typename CFG>
    struct accounts_t {
        accounts_t(const accounts_t &o)
        {
            *this = o;
        }

        accounts_t(accounts_t &&o) noexcept:
            _db{std::move(o._db)}
        {
        }

        accounts_t(storage::db_ptr_t db) noexcept:
            _db{std::move(db)}
        {
        }

        std::optional<service_info_t<CFG>> info_get(const service_id_t id) const
        {
            return _get<service_info_t<CFG>>(_info_key(id));
        }

        service_info_t<CFG> info_get_or_throw(const service_id_t id) const
        {
            auto info = info_get(id);
            if (info) [[likely]]
                return *info;
            throw err_bad_service_id_t{};
        }

        void info_erase(const service_id_t id)
        {
            _erase(_info_key(id));
        }

        void info_set(const service_id_t id, service_info_t<CFG> info)
        {
            _set(_info_key(id), std::move(info));
        }

        std::optional<lookup_meta_map_val_t<CFG>> lookup_get(const service_id_t id, const lookup_meta_map_key_t &k) const
        {
            return _get<lookup_meta_map_val_t<CFG>>(_lookup_key(id, k));
        }

        void lookup_erase(const service_id_t id, const lookup_meta_map_key_t &k)
        {
            _erase(_lookup_key(id, k));
        }

        void lookup_set(const service_id_t id, const lookup_meta_map_key_t &k, lookup_meta_map_val_t<CFG> val)
        {
            _set(_lookup_key(id, k), std::move(val));
        }

        std::optional<uint8_vector> preimage_get(const service_id_t id, const opaque_hash_t &k) const
        {
            return _get<uint8_vector>(_preimage_key(id, k));
        }

        void preimage_erase(const service_id_t id, const opaque_hash_t &k)
        {
            _erase(_preimage_key(id, k));
        }

        void preimage_set(const service_id_t id, const opaque_hash_t &k, uint8_vector val)
        {
            _set(_preimage_key(id, k), std::move(val));
        }

        std::optional<uint8_vector> storage_get(const service_id_t id, const buffer &k) const
        {
            return _get<uint8_vector>(_storage_key(id, k));
        }

        void storage_set_raw(const service_id_t id, const buffer &k, uint8_vector val)
        {
            const auto key = _storage_key(id, k);
            _set(key, std::move(val));
        }

        std::optional<uint8_vector> storage_set(const service_id_t id, const buffer &k, uint8_vector val)
        {
            const auto key = _storage_key(id, k);
            auto prev_val = _get<uint8_vector>(key);
            if (!val.empty()) {
                if (val != prev_val) {
                    auto info = info_get_or_throw(id);
                    if (prev_val) {
                        info.bytes -= prev_val->size();
                    } else {
                        info.bytes += 34 + k.size();
                        ++info.items;
                    }
                    info.bytes += val.size();
                    info_set(id, std::move(info));
                    _set(key, std::move(val));
                }
            } else if (prev_val) {
                auto info = info_get_or_throw(id);
                info.bytes -= 34 + k.size() + prev_val->size();
                --info.items;
                info_set(id, std::move(info));
                _erase(key);
            }
            return prev_val;
        }

        accounts_t &operator=(accounts_t &&o) noexcept
        {
            _db = std::move(o._db);
            return *this;
        }

        accounts_t &operator=(const accounts_t &o)
        {
            _db = std::make_shared<storage::memory::db_t>();
            o._db->foreach([&](auto &&k, auto &&v) {
                _db->set(std::move(k), std::move(v));
            });
            return *this;
        }

        bool operator==(const accounts_t &o) const {
            return *_db == *o._db;
        }

        void foreach(const std::function<void(service_id_t, const service_info_t<CFG> &)> &obs) const {
            _db->foreach([&](auto &&k, auto &&v) {
                std::visit([&](const auto &ki) {
                    using T = std::decay_t<decltype(ki)>;
                    if constexpr (std::is_same_v<T, key_service_info_t>) {
                        obs(ki.service_id, jam::from_bytes<service_info_t<CFG>>(v));
                    }
                }, state_dict_t::key_info(k));
            });
        }

        [[nodiscard]] std::string diff(const accounts_t &o) const
        {
            std::set<uint8_vector> seen{};
            std::string diff{};
            auto out_it = std::back_inserter(diff);
            _db->foreach([&](auto &&k, auto &&v) {
                seen.emplace(k);
                const auto ov = o._db->get(k);
                if (!ov) {
                    out_it = fmt::format_to(out_it, "missing key: {}", k);
                } else if (v != ov) {
                    out_it = fmt::format_to(out_it, "key: {} expected: {} got: {}", k, v, *ov);
                }
            });
            o._db->foreach([&](const auto &ok, const auto &) {
                if (!seen.contains(ok)) {
                    out_it = fmt::format_to(out_it, "extra key: {}", ok);
                }
            });
            return diff;
        }
    protected:
        template<typename> friend struct account_updates_t;
        storage::db_ptr_t _db{};

        template<typename V>
        static uint8_vector _encode(V v)
        {
            if constexpr (std::is_same_v<V, uint8_vector>) {
                return std::move(v);
            } else {
                encoder enc { v };
                return { static_cast<buffer>(enc.bytes()) };
            }
        }

        template<typename V>
        static V _decode(uint8_vector bytes)
        {
            if constexpr (std::is_same_v<V, uint8_vector>) {
                return bytes;
            } else {
                decoder dec { bytes };
                V res;
                dec.process(res);
                return res;
            }
        }

        void _erase(const state_key_t &k)
        {
            _db->erase(k);
        }

        template<typename V>
        std::optional<V> _get(const state_key_t &k) const
        {
            if (auto v = _db->get(k); v) {
                return _decode<V>(std::move(*v));
            }
            return {};
        }

        template<typename V>
        void _set(const state_key_t &trie_key, V val)
        {
            _db->set(trie_key, _encode(std::move(val)));
        }

        static state_key_t _info_key(const service_id_t service_id) {
            return state_dict_t::make_key(255U, service_id);
        }

        static state_key_t _lookup_key(const service_id_t service_id, const lookup_meta_map_key_t &k) {
            encoder enc{};
            enc.uint_fixed(4, k.length);
            enc.bytes() << k.hash;
            return state_dict_t::make_key(service_id, enc.bytes());
        }

        static state_key_t _preimage_key(const service_id_t service_id, const opaque_hash_t &k) {
            encoder enc{};
            enc.uint_fixed(4, (1ULL << 32U) - 2ULL);
            enc.bytes() << k;
            return state_dict_t::make_key(service_id, enc.bytes());
        }

        static state_key_t _storage_key(const service_id_t service_id, const buffer &k) {
            encoder enc{};
            enc.uint_fixed(4, (1ULL << 32U) - 1ULL);
            enc.bytes() << k;
            return state_dict_t::make_key(service_id, enc.bytes());
        }
    };

    template<typename CFG>
    struct account_updates_t: accounts_t<CFG> {
        account_updates_t(account_updates_t &&o) noexcept:
            accounts_t<CFG>{std::move(o)}
        {
        }

        account_updates_t(const account_updates_t &o) noexcept:
            accounts_t<CFG>{std::make_shared<storage::update::db_t>(o._updatedb())}
        {
        }

        account_updates_t(const accounts_t<CFG> &base):
            accounts_t<CFG>{std::make_shared<storage::update::db_t>(base._db)}
        {
        }

        account_updates_t &operator=(account_updates_t &&o) noexcept
        {
            accounts_t<CFG>::operator=(std::move(o));
            return *this;
        }

        account_updates_t &operator=(const account_updates_t &o)
        {
            this->_db = std::make_shared<storage::update::db_t>(o._updatedb());
            return *this;
        }

        void consume_from(account_updates_t &&o)
        {
            _updatedb().consume_from(std::move(o._updatedb()));
        }

        void commit()
        {
            _updatedb().commit();
        }
    private:
        storage::update::db_t &_updatedb()
        {
            return const_cast<storage::update::db_t &>(const_cast<const account_updates_t *>(this)->_updatedb());
        }

        const storage::update::db_t &_updatedb() const
        {
            return dynamic_cast<const storage::update::db_t &>(*this->_db);
        }
    };

    template<typename CFG>
    struct auth_queue_updates_t: std::map<core_index_t, auth_queue_t<CFG>> {
        using base_type = std::map<core_index_t, auth_queue_t<CFG>>;
        using base_type::base_type;

        void commit(auth_queues_t<CFG> &dst)
        {
            for (auto &&[c, q]: *this)
                dst[c] = std::move(q);
            this->clear();
        }
    };

    // JAM (12.13)
    template<typename CFG>
    struct mutable_state_t {
        account_updates_t<CFG> services; // d
        mutable_value_t<privileges_t<CFG>> chi; // x -> (m, a, v, z)
        std::shared_ptr<validators_data_t<CFG>> iota{}; // i
        auth_queue_updates_t<CFG> phi{}; // q

        mutable_state_t(const accounts_t<CFG> &base, const privileges_t<CFG> &c):
            services{base},
            chi{c}
        {
        }
        
        void consume_from(mutable_state_t &&o)
        {
            services.consume_from(std::move(o.services));
            chi = std::move(o.chi);
            if (o.iota)
                iota = std::move(o.iota);
            for (auto &[c, q]: o.phi)
                phi[c] = std::move(q);
        }
    };

    template<typename CFG>
    using deferred_transfer_metadata_t = byte_array_t<CFG::WT_transfer_memo_size>;

    // JAM (12.14)
    template<typename CFG>
    struct deferred_transfer_t {
        // JAM: s
        service_id_t source;
        // JAM: d
        service_id_t destination;
        // JAM: a
        balance_t amount;
        // JAM: m
        deferred_transfer_metadata_t<CFG> metadata;
        // JAM: g
        gas_t::base_type gas_limit;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("source"sv, source);
            archive.process("destination"sv, destination);
            archive.process("amount"sv, amount);
            archive.process("metadata"sv, metadata);
            archive.process("gas_limit"sv, gas_limit);
        }
    };
    template<typename CFG>
    using deferred_transfers_t = sequence_t<deferred_transfer_t<CFG>>;

    template<typename CFG>
    using service_code_preimages_t = map_t<service_id_t, byte_sequence_t, CFG>;

    // JAM (B.7)
    template<typename CFG>
    struct accumulate_context_t {
        // JAM: s
        service_id_t service_id;
        // JAM: bold u
        mutable_state_t<CFG> state;
        // JAM: i
        service_id_t new_service_id = 0;
        // JAM: bold t
        deferred_transfers_t<CFG> transfers {};
        // JAM: y
        optional_t<opaque_hash_t> result {};
        // JAM: p
        //service_code_preimages_t<CFG> code {};

        accumulate_context_t(const service_id_t s, const entropy_t &eta0, const time_slot_t<CFG> &blk_slot, mutable_state_t<CFG> &&st):
            service_id{s},
            state{std::move(st)}
        {
            //const encoder{s, e[0], blk_slot};
            encoder enc{};
            enc.uint_varlen(s);
            enc.next_bytes(eta0);
            enc.uint_varlen(blk_slot.slot());
            const auto h = crypto::blake2b::digest(enc.bytes());
            const auto prev_id = decoder::uint_fixed<service_id_t>(h);
            new_service_id = check(gen_new_service_id(prev_id));
        }

        static service_id_t gen_new_service_id(const service_id_t prev_id)
        {
            return prev_id % ((1ULL << 32U) - (1ULL << 9U)) + (1ULL << 8U);
        }

        [[nodiscard]] service_id_t check(service_id_t i) const
        {
            // Due to the limited size of RAM the number of services will always be less than 2^32 - 1
            // Thus, this loop will terminate in all cases.
            while (state.services.info_get(i)) {
                i = gen_new_service_id(i - (1ULL << 8U) + 1U);
            }
            return i;
        }
    };

    // JAM (12.19)
    struct accumulate_operand_t {
        opaque_hash_t work_package_hash;
        opaque_hash_t exports_root;
        opaque_hash_t authorizer_hash;
        opaque_hash_t payload_hash;
        gas_t accumulate_gas;
        work_exec_result_t result;
        byte_sequence_t auth_output;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("work_package_hash"sv, work_package_hash);
            archive.process("exports_root"sv, exports_root);
            archive.process("authorizer_hash"sv, authorizer_hash);
            archive.process("payload_hash"sv, payload_hash);
            archive.process("accumulate_gas"sv, accumulate_gas);
            archive.process("result"sv, result);
            archive.process("auth_output"sv, auth_output);
        }

        bool operator==(const accumulate_operand_t &o) const = default;
    };
    using accumulate_operands_t = sequence_t<accumulate_operand_t>;
    using accumulate_service_operands_t = std::map<service_id_t, accumulate_operands_t>;

    // JAM (B.9)
    template<typename CFG>
    struct accumulate_result_t {
        mutable_state_t<CFG> state;
        deferred_transfers_t<CFG> transfers{};
        std::optional<opaque_hash_t> commitment{};
        gas_t gas{};
        size_t num_reports = 0;
    };
    template<typename CFG>
    using service_results_t = std::map<service_id_t, accumulate_result_t<CFG>>;

    // JAM (12.15): B
    struct service_commitments_config_t {
        std::string key_name = "service_id";
        std::string val_name = "hash";
    };
    using service_commitments_t = map_t<service_id_t, opaque_hash_t, service_commitments_config_t>;
    // JAM (12.15): U + (12.24) num_items
    struct service_work_item_t {
        gas_t gas_used{};
        size_t num_reports = 0;
    };
    using service_work_items_t = std::map<service_id_t, service_work_item_t>;

    // JAM (12.17)
    template<typename CFG>
    struct delta_star_result_t {
        size_t num_accumulated = 0;
        service_results_t<CFG> results{};
    };

    // JAM (12.16)
    template<typename CFG>
    struct delta_plus_result_t {
        mutable_state_t<CFG> state;
        deferred_transfers_t<CFG> transfers{};
        service_commitments_t commitments{};
        service_work_items_t work_items{};
        size_t num_accumulated = 0;

        void consume_from(delta_star_result_t<CFG> &&o)
        {
            num_accumulated += o.num_accumulated;
            for (auto &&[s_id, s_res]: o.results) {
                state.consume_from(std::move(s_res.state));
                transfers.insert(transfers.end(), s_res.transfers.begin(), s_res.transfers.end());
                // o.results is a map, so all s_id are unique. no need to check if try_emplace succeeds
                if (s_res.commitment)
                    commitments.try_emplace(s_id, *s_res.commitment);
                work_items.try_emplace(s_id, s_res.gas, s_res.num_reports);
            }
        }
    };

    template<typename CFG>
    struct accumulate_output_t {
        std::shared_ptr<accumulated_queue_t<CFG>> ksi{};
        std::shared_ptr<ready_queue_t<CFG>> omega{};
        auth_queue_updates_t<CFG> phi{};
        std::shared_ptr<validators_data_t<CFG>> iota{};
        std::shared_ptr<privileges_t<CFG>> chi{};
        service_commitments_t theta{};
        accumulate_root_t root{};
    };

    template<typename CFG=config_prod>
    struct state_base_t {
        using observer_t = storage::observer_t;

        storage::db_ptr_t db;
        persistent_value_t<auth_pools_t<CFG>> alpha{db, 1U}; // authorizations
        persistent_value_t<auth_queues_t<CFG>> phi{db, 2U}; // work authorizer queue
        persistent_value_t<recent_blocks_t<CFG>> beta{db, 3U}; // most recent blocks
        persistent_value_t<safrole_state_t<CFG>> gamma{db, 4U}; // safrole state
        persistent_value_t<disputes_records_t> psi{db, 5U}; // judgements
        persistent_value_t<entropy_buffer_t> eta{db, 6U};
        persistent_value_t<validators_data_t<CFG>> iota{db, 7U};
        persistent_value_t<validators_data_t<CFG>> kappa{db, 8U};
        persistent_value_t<validators_data_t<CFG>> lambda{db, 9U};
        persistent_value_t<availability_assignments_t<CFG>> rho{db, 10U}; // assigned work reports
        persistent_value_t<time_slot_t<CFG>> tau{db, 11U};
        persistent_value_t<privileges_t<CFG>> chi{db, 12U};
        persistent_value_t<statistics_t<CFG>> pi{db, 13U};
        persistent_value_t<ready_queue_t<CFG>> omega{db, 14U}; // JAM (12.3): work reports ready to be accumulated
        persistent_value_t<accumulated_queue_t<CFG>> ksi{db, 15U}; // JAM (12.1): recently accumulated reports
        persistent_value_t<service_commitments_t> theta{db, 16U}; // JAM (7.4): recent service accumulation commitments
        accounts_t<CFG> delta{db}; // services

        template<typename F>
        void visit_simple(F f) {
            f(alpha);
            f(phi);
            f(beta);
            f(gamma);
            f(psi);
            f(eta);
            f(iota);
            f(kappa);
            f(lambda);
            f(rho);
            f(tau);
            f(chi);
            f(pi);
            f(omega);
            f(ksi);
            f(theta);
        }
    };

    // JAM (4.4) - lowercase sigma
    // persistent_value with std::shared_ptr ensures that:
    // 1) the state is cheap to copy
    // 2) automatically searialized into the state_dict on updates
    // TODO: state_dict should use copy_on_write_ptr_t instead of std::shared_ptr
    template<typename CFG>
    struct state_t: state_base_t<CFG> {
        using observer_t = storage::observer_t;

        state_t(triedb::db_ptr_t db): state_base_t<CFG>{std::move(db)} {}
        state_t(const state_t &) = delete;

        static std::string decode_val(buffer key, buffer val);
        header_t<CFG> make_genesis_header() const;
        state_t &operator=(const state_snapshot_t &o);
        state_t &operator=(const state_t &o) = delete;

        void commit();
        void rollback();

        // (4.1): Kapital upsilon
        void apply(const block_t<CFG> &);

        // State transition methods: static to not be explicit about their inputs and outputs
        // (4.5)
        static void tau_prime(time_slot_t<CFG> &tau, const time_slot_t<CFG> &blk_slot);
        // (4.6)
        static void beta_dagger(recent_blocks_t<CFG> &beta, const state_root_t &sr);
        // (4.17)
        static void beta_prime(recent_blocks_t<CFG> &new_beta, const header_hash_t &hh, const std::optional<opaque_hash_t> &ar, const reported_work_seq_t<CFG> &wp);
        // JAM (4.7)
        static void eta_prime(entropy_buffer_t &eta, const time_slot_t<CFG> &prev_tau, const time_slot_t<CFG> &blk_slot, const entropy_t &blk_entropy);
        // JAM (4.8)
        // JAM (4.9)
        // JAM (4.10)
        static safrole_output_data_t<CFG> update_safrole(
            safrole_state_t<CFG> &new_gamma,
            validators_data_t<CFG> &new_kappa,
            validators_data_t<CFG> &new_lambda,
            const entropy_buffer_t &new_eta, const ed25519_keys_set_t &new_offenders,
            const time_slot_t<CFG> &prev_tau, const validators_data_t<CFG> &prev_iota,
            const time_slot_t<CFG> &slot, const tickets_extrinsic_t<CFG> &extrinsic);
        // JAM (4.11)
        static offenders_mark_t psi_prime(disputes_records_t &new_psi, availability_assignments_t<CFG> &new_rho,
            const validators_data_t<CFG> &new_kappa, const validators_data_t<CFG> &new_lambda,
            const time_slot_t<CFG> &prev_tau, const disputes_extrinsic_t<CFG> &disputes
        );
        // JAM (4.19)
        static void alpha_prime(auth_pools_t<CFG> &new_alpha, const time_slot_t<CFG> &slot, const core_authorizers_t &cas,
            const auth_queues_t<CFG> &new_phi);
        // JAM (4.20)
        static void pi_prime(validators_statistics_t<CFG> &new_pi_current, validators_statistics_t<CFG> &new_pi_last,
            const reports_output_data_t &report_res, const validators_data_t<CFG> &new_kappa,
            const time_slot_t<CFG> &prev_tau, const time_slot_t<CFG> &slot, validator_index_t val_idx, const extrinsic_t<CFG> &extrinsic);
        // JAM (4.12)
        // JAM (4.13)
        // JAM (4.14)
        // JAM (4.15)
        static reports_output_data_t update_reports(
            availability_assignments_t<CFG> &tmp_rho,
            cores_statistics_t<CFG> &new_pi_cores,
            services_statistics_t &new_pi_services,
            const blocks_history_t<CFG> &tmp_beta,
            const entropy_buffer_t &new_eta, const ed25519_keys_set_t &new_offenders,
            const validators_data_t<CFG> &new_kappa, const validators_data_t<CFG> &new_lambda,
            const auth_pools_t<CFG> &prev_alpha,
            const accounts_t<CFG> &prev_delta,
            const time_slot_t<CFG> &slot, const guarantees_extrinsic_t<CFG> &guarantees);

        static work_reports_t<CFG> rho_dagger_2(
            availability_assignments_t<CFG> &new_rho, statistics_t<CFG> &tmp_pi,
            const validators_data_t<CFG> &new_kappa,
            const time_slot_t<CFG> &slot, const header_hash_t &parent,
            const assurances_extrinsic_t<CFG> &assurances);

        // JAM (4.18)
        static void provide_preimages(account_updates_t<CFG> &new_delta, services_statistics_t &new_pi_services, const time_slot_t<CFG> &slot, const preimages_extrinsic_t &preimages);
        // JAM (4.16)
        static accumulate_output_t<CFG> accumulate(
            account_updates_t<CFG> &new_delta, services_statistics_t &new_pi_services,
            const entropy_t &new_eta0, const time_slot_t<CFG> &prev_tau,
            const privileges_t<CFG> &prev_chi,
            const ready_queue_t<CFG> &prev_omega, const accumulated_queue_t<CFG> &prev_ksi,
            const time_slot_t<CFG> &slot, const work_reports_t<CFG> &reports);

        [[nodiscard]] state_root_t root() const
        {
            return triedb().root();
        }

        void foreach(const observer_t &) const;
        bool operator==(const state_t &o) const noexcept;
        state_snapshot_t snapshot() const;
    private:
        using guarantor_assignments_t = fixed_sequence_t<core_index_t, CFG::V_validator_count>;
        struct guarantors_t {
            guarantor_assignments_t guarantors;
            validators_data_t<CFG> validators;
        };

        static void _ring_commitment(bandersnatch_ring_commitment_t &res, const validators_data_t<CFG> &);
        static validators_data_t<CFG> _capital_phi(const validators_data_t<CFG> &iota, const offenders_mark_t &psi_o);
        static keys_t<CFG> _fallback_key_sequence(const entropy_t &entropy, const validators_data_t<CFG> &kappa);
        static tickets_t<CFG> _permute_tickets(const tickets_accumulator_t<CFG> &gamma_a);
        static guarantor_assignments_t _guarantor_assignments(const entropy_t &e, const time_slot_t<CFG> &slot);
        static guarantors_t _guarantors(const entropy_buffer_t &eta, const validators_data_t<CFG> &kappa, const validators_data_t<CFG> &lambda,
            const offenders_mark_t &psi_o, const time_slot_t<CFG> &g_slot, const time_slot_t<CFG> &blk_slot);

        static delta_plus_result_t<CFG> accumulate_plus(
            const entropy_t &new_eta0,
            const accounts_t<CFG> &prev_delta, const privileges_t<CFG> &prev_chi,
            const time_slot_t<CFG> &slot, const gas_t gas_limit, const work_reports_t<CFG> &reports
        );
        static delta_star_result_t<CFG> accumulate_star(
            const entropy_t &new_eta0,
            const accounts_t<CFG> &prev_delta, const privileges_t<CFG> &prev_chi,
            const time_slot_t<CFG> &slot, const std::span<const work_report_t<CFG>> reports);
        static accumulate_result_t<CFG> invoke_accumulate(
            const entropy_t &new_eta0,
            const accounts_t<CFG> &prev_delta, const privileges_t<CFG> &prev_chi,
            const time_slot_t<CFG> &slot,
            const service_id_t service_id, const accumulate_operands_t &ops);
        static gas_t invoke_on_transfer(
            const entropy_t &new_eta0, account_updates_t<CFG> &new_delta,
            time_slot_t<CFG> slot, service_id_t service_id, const deferred_transfers_t<CFG> &transfers);

        const triedb::db_t &triedb() const
        {
            return dynamic_cast<const triedb::db_t&>(*this->db);
        }

        triedb::db_t &triedb()
        {
            return const_cast<triedb::db_t&>(const_cast<const state_t *>(this)->triedb());
        }
    };
}
