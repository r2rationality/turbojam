#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/container/update-map.hpp>
#include <turbo/common/logger.hpp>
#include <turbo/storage/file.hpp>

#include "triedb.hpp"
#include "types/header.hpp"
#include "types/state-dict.hpp"

namespace turbo::jam {
    //using kv_store_t = storage::file::client_t;
    //using kv_store_ptr_t = std::shared_ptr<kv_store_t>;

    template<typename T>
    byte_sequence_t encode(const T &v)
    {
        encoder enc { v };
        return { std::move(enc.bytes()) };
    }

    template<typename T>
    struct persistent_value_t {
        using element_type = T;
        using ptr_type = std::shared_ptr<element_type>;
        using serialize_func_t = std::function<void(const element_type &)>;

        persistent_value_t(const triedb::db_ptr_t &db, const uint8_t code):
            persistent_value_t{db, state_dict_t::make_key(code)}
        {
        }

        persistent_value_t(const triedb::db_ptr_t &db, const state_key_t &key):
            _db{db},
            _key{key}
        {
            if (!_db) [[unlikely]]
                throw error("a persistent value requires an initialized state_dict!");
        }

        persistent_value_t(const triedb::db_ptr_t &db, const state_key_t &key, T val):
            _db{db},
            _key{key}
        {
            if (!_db) [[unlikely]]
                throw error("a persistent value requires an initialized state_dict!");
            set(std::move(val));
        }

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            // TODO: can be optimized for the decoding case. That happens only in unit tests though.
            T tmp;
            archive.process(tmp);
            set(std::move(tmp));
        }

        const element_type &get() const
        {
            return *storage();
        }

        const ptr_type &storage() const
        {
            if (!_ptr) {
                const auto bytes = _db->get(_key);
                if (!bytes) [[unlikely]]
                    throw error(fmt::format("a required state element is missing: {}", _key));
                _ptr = std::make_shared<element_type>(jam::from_bytes<element_type>(*bytes));
            }
            return _ptr;
        }

        void set(element_type new_val)
        {
            // allocation of a new shared pointer ensures that other copies are not affected
            _ptr = std::make_shared<element_type>(std::move(new_val));
            _db->set(_key, encode(*_ptr));
        }

        void set(ptr_type new_ptr)
        {
            if (_ptr.get() != new_ptr.get()) {
                _ptr = std::move(new_ptr);
                _db->set(_key, encode(*_ptr));
            }
        }

        void reset()
        {
            _ptr.reset();
        }

        bool operator==(const persistent_value_t &o) const
        {
            return *_ptr == *o._ptr;
        }
    private:
        triedb::db_ptr_t _db;
        state_key_t _key;
        mutable ptr_type _ptr{};
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

        void consume_from(const service_info_t<CFG> &o)
        {
            *this = o;
        }

        void commit(persistent_value_t<service_info_t<CFG>> &target)
        {
            target.set(*this);
        }

        bool operator==(const service_info_t<CFG> &o) const noexcept = default;
    };

    template<typename K, typename V>
    struct state_dict_based_map_t {
        using alt_key_type = K;
        using key_type = state_key_t;
        using mapped_type = V;
        using keys_t = std::set<state_key_t>;
        //using observer_t = std::function<void(const state_key_t &k, mapped_type v)>;
        using trie_key_func_t = std::function<key_type(const alt_key_type &)>;

        state_dict_based_map_t(const storage::db_ptr_t triedb, const trie_key_func_t &try_key_func):
            _triedb{triedb},
            _try_key_func{try_key_func}
        {
        }

        void erase(const alt_key_type &k)
        {
            _erase(make_key(k));
        }

        std::optional<mapped_type> get(const alt_key_type &k) const
        {
            if (auto v = _triedb->get(make_key(k)); v) {
                return _decode(std::move(*v));
            }
            return {};
        }

        void set(const alt_key_type &k, mapped_type val)
        {
            _set(make_key(k), std::move(val));
        }
    private:
        storage::db_ptr_t _triedb;
        trie_key_func_t _try_key_func;

        static uint8_vector _encode(V v)
        {
            if constexpr (std::is_same_v<V, uint8_vector>) {
                return std::move(v);
            } else {
                encoder enc { v };
                return { static_cast<buffer>(enc.bytes()) };
            }
        }

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

        [[nodiscard]] key_type make_key(const alt_key_type &k) const
        {
            return _try_key_func(k);
        }

        void _erase(const state_key_t &k)
        {
            _triedb->erase(k);
        }

        std::optional<mapped_type> _get(const state_key_t &k) const
        {
            if (auto v = _triedb->get(k); v) {
                return _decode(std::move(*v));
            }
            return {};
        }

        void _set(const state_key_t &trie_key, mapped_type val)
        {
            _triedb->set(trie_key, _encode(val));
        }
    };

    struct preimages_t: state_dict_based_map_t<opaque_hash_t, uint8_vector> {
        using base_type = state_dict_based_map_t<opaque_hash_t, uint8_vector>;
        using base_type::base_type;

        static trie_key_func_t make_trie_key_func(const service_id_t service_id)
        {
            return [service_id](const opaque_hash_t &k) {
                encoder enc{};
                enc.uint_fixed(4, (1ULL << 32U) - 2ULL);
                enc.bytes() << k;
                return state_dict_t::make_key(service_id, enc.bytes());
            };
        }
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

    template<typename CFG>
    struct lookup_metas_t: state_dict_based_map_t<lookup_meta_map_key_t, lookup_meta_map_val_t<CFG>> {
        using base_type = state_dict_based_map_t<lookup_meta_map_key_t, lookup_meta_map_val_t<CFG>>;
        using base_type::base_type;

        static typename base_type::trie_key_func_t make_trie_key_func(const service_id_t service_id)
        {
            return [service_id](const lookup_meta_map_key_t &k) {
                encoder enc{};
                enc.uint_fixed(4, k.length);
                enc.bytes() << k.hash;
                return state_dict_t::make_key(service_id, enc.bytes());
            };
        }
    };

    struct service_storage_t: state_dict_based_map_t<uint8_vector, uint8_vector> {
        using base_type = state_dict_based_map_t<uint8_vector, uint8_vector>;
        using base_type::base_type;

        static typename base_type::trie_key_func_t make_trie_key_func(const service_id_t service_id)
        {
            return [service_id](const buffer &k) {
                encoder enc{};
                enc.uint_fixed(4, (1ULL << 32U) - 1ULL);
                enc.bytes() << k;
                return state_dict_t::make_key(service_id, enc.bytes());
            };
        }
    };

    template<typename CFG>
    struct account_t {
        // preimages comes first since it requires an argument to be initialized
        preimages_t preimages;
        lookup_metas_t<CFG> lookup_metas;
        service_storage_t storage;
        persistent_value_t<service_info_t<CFG>> info;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("preimages"sv, preimages);
            archive.process("storage"sv, storage);
            archive.process("lookup_metas"sv, lookup_metas);
            archive.process("info"sv, info);
        }

        //bool operator==(const account_t &o) const = default;
    };

    struct accounts_config_t {
        std::string key_name = "id";
        std::string val_name = "data";
    };

    template<typename CFG>
    struct accounts_t: map_t<service_id_t, account_t<CFG>, accounts_config_t> {
        using base_type = map_t<service_id_t, account_t<CFG>, accounts_config_t>;

        accounts_t(const triedb::db_ptr_t &triedb):
            _triedb{triedb}
        {
        }

        std::pair<typename base_type::iterator, bool> try_create(const typename base_type::key_type &service_id)
        {
            return base_type::try_emplace(
                service_id,
                preimages_t{_triedb, preimages_t::make_trie_key_func(service_id)},
                lookup_metas_t<CFG>{_triedb, lookup_metas_t<CFG>::make_trie_key_func(service_id)},
                service_storage_t{_triedb, service_storage_t::make_trie_key_func(service_id)},
                persistent_value_t<service_info_t<CFG>>{_triedb, state_dict_t::make_key(255U, service_id)}
            );
        }

        accounts_t &operator=(const accounts_t &o)
        {
            if (&o != this) {
                this->clear();
                for (const auto &[s_id, s]: o)
                    try_create(s_id);
            }
            return *this;
        }
    private:
        triedb::db_ptr_t _triedb;
    };

    template<typename CFG>
    struct mutable_service_state_t {
        using update_preimage_base_map_t = container::direct_update_api_t<preimages_t>;
        using update_preimage_map_t = container::update_map_t<update_preimage_base_map_t>;
        using update_lookup_base_map_t = container::direct_update_api_t<lookup_metas_t<CFG>>;
        using update_lookup_map_t = container::update_map_t<update_lookup_base_map_t>;
        using update_storage_base_map_t = container::direct_update_api_t<service_storage_t>;
        using update_storage_map_t = container::update_map_t<update_storage_base_map_t>;

        update_storage_map_t storage;
        update_preimage_map_t preimages;
        update_lookup_map_t lookup_metas;
        service_info_t<CFG> info;

        bool empty() const
        {
            if (!storage.empty())
                return false;
            if (!preimages.empty())
                return false;
            if (!lookup_metas.empty())
                return false;
            return true;
        }

        void consume_from(mutable_service_state_t &&o)
        {
            storage.consume_from(std::move(o.storage));
            preimages.consume_from(std::move(o.preimages));
            lookup_metas.consume_from(std::move(o.lookup_metas));
            info.consume_from(std::move(o.info));
        }

        void commit(account_t<CFG> &target)
        {
            storage.commit(target.storage);
            preimages.commit(target.preimages);
            lookup_metas.commit(target.lookup_metas);
            info.commit(target.info);
        }
    };

    template<typename CFG>
    using mutable_services_base_t = std::map<service_id_t, std::optional<mutable_service_state_t<CFG>>>;

    template<typename CFG>
    struct accounts_update_api_t {
        using base_type = accounts_t<CFG>;
        using key_type = typename accounts_t<CFG>::key_type;
        using mapped_type = mutable_service_state_t<CFG>;
        using observer_key_type = std::function<void(const key_type &)>;

        accounts_update_api_t(const accounts_t<CFG> &base):
            _base{base}
        {
        }

        void consume_from(accounts_update_api_t &&o)
        {
            for (auto &&[k, v]: o._derived) {
                if (v) {
                    const auto v_code_hash = v->info.code_hash;
                    if (auto [it, created] = _derived.try_emplace(k, std::move(v)); !created) {
                        // Appendix B.4 says that if the same service id is assigned to different services, such a block shall be considered invalid
                        // Considering non-matching code-hashes as an indication of differing services here.
                        if (it->second) {
                            it->second->consume_from(std::move(*v));
                            if (it->second->info.code_hash != v_code_hash) [[unlikely]]
                                throw error(fmt::format("service {} accumulation resulted into the same service having different code hashes: {} != {}",
                                    k, it->second->info.code_hash, v_code_hash));
                        } else {
                            it->second = std::move(v);
                        }
                    }
                } else {
                    if (const auto it = _derived.find(k); it != _derived.end())
                        _derived.erase(it);
                }
            }
        }

        mutable_service_state_t<CFG> &emplace(const key_type &k, service_info_t<CFG> info)
        {
            const auto [it, created] = _derived.try_emplace(
                k,
                mutable_service_state_t<CFG> {
                    container::direct_update_api_t<service_storage_t> {},
                    container::direct_update_api_t<preimages_t> {},
                    container::direct_update_api_t<lookup_metas_t<CFG>> {},
                    std::move(info)
                }
            );
            if (!created) [[unlikely]]
                throw error(fmt::format("key {} already exists", k));
            if (_base.get().find(k) != _base.get().end())
                throw error(fmt::format("key {} already exists", k));
            return it->second.value();
        }

        void foreach_key(const observer_key_type &obs)
        {
            for (const auto &[k, v]: _derived) {
                if (v)
                    obs(k);
            }
            for (const auto &[k, v]: _base.get()) {
                if (!_derived.contains(k))
                    obs(k);
            }
        }

        [[nodiscard]] bool contains(const key_type &k) const
        {
            if (const auto d_it = _derived.find(k); d_it != _derived.end())
                return true;
            if (const auto b_it = _base.get().find(k); b_it != _base.get().end())
                return true;
            return false;
        }

        void erase(const key_type &k)
        {
            auto [d_it, created] = _derived.try_emplace(k);
            if (!created)
                d_it->second.reset();
        }

        mapped_type *get_mutable_ptr(const key_type &k)
        {
            if (const auto d_it = _derived.find(k); d_it != _derived.end()) {
                if (d_it->second)
                    return &(*d_it->second);
                return nullptr;
            }
            if (auto b_it = _base.get().find(k); b_it != _base.get().end()) {
                auto [d_it, created] = _derived.try_emplace(
                    k,
                    mapped_type{
                        container::direct_update_api_t<service_storage_t>{b_it->second.storage},
                        container::direct_update_api_t<preimages_t>{b_it->second.preimages},
                        container::direct_update_api_t<lookup_metas_t<CFG>>{b_it->second.lookup_metas},
                        service_info_t<CFG>{b_it->second.info.get()}
                    }
                );
                return &(*d_it->second);
            }
            return nullptr;
        }

        mapped_type &get_mutable(const key_type &k)
        {
            if (auto ptr = get_mutable_ptr(k); ptr)
                return *ptr;
            throw err_bad_service_id_t{};
        }

        void commit(accounts_t<CFG> &target)
        {
            for (auto &&[k, v]: _derived) {
                if (v) {
                    auto [it, created] = target.try_create(k);
                    v->commit(it->second);
                } else {
                    target.erase(k);
                }
            }
            _derived.clear();
        }
    private:
        std::reference_wrapper<const accounts_t<CFG>> _base;
        mutable_services_base_t<CFG> _derived {};
    };

    template<typename CFG>
    using mutable_services_state_t = accounts_update_api_t<CFG>;

    // JAM (12.13)
    template<typename CFG>
    struct mutable_state_t {
        mutable_services_state_t<CFG> services; // d
        privileges_t<CFG> chi; // x -> (m, a, v, z)
        std::optional<validators_data_t<CFG>> iota {}; // i
        std::map<core_index_t, auth_queue_t<CFG>> phi {}; // q

        mutable_state_t(const accounts_t<CFG> &d, const privileges_t<CFG> &c):
            services { d },
            chi { c }
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

        accumulate_context_t(const service_id_t s, const entropy_buffer_t &e, const time_slot_t<CFG> &blk_slot, mutable_state_t<CFG> &&st):
            service_id{s},
            state{std::move(st)}
        {
            //const encoder{s, e[0], blk_slot};
            encoder enc{};
            enc.uint_varlen(s);
            enc.next_bytes(e[0]);
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
            while (state.services.contains(i)) {
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
        std::shared_ptr<accumulated_queue_t<CFG>> new_ksi;
        std::shared_ptr<ready_queue_t<CFG>> new_nu;
        std::shared_ptr<auth_queues_t<CFG>> new_phi;
        std::shared_ptr<validators_data_t<CFG>> new_iota;
        std::shared_ptr<privileges_t<CFG>> new_chi;
        std::optional<mutable_services_state_t<CFG>> service_updates {};
        service_commitments_t new_theta{};
        accumulate_root_t root {};
    };

    template<typename CFG=config_prod>
    struct state_copy_t;

    // JAM (4.4) - lowercase sigma
    // persistent_value with std::shared_ptr ensures that:
    // 1) the state is cheap to copy
    // 2) automatically searialized into the state_dict on updates
    // TODO: state_dict should use copy_on_write_ptr_t instead of std::shared_ptr
    template<typename CFG=config_prod>
    struct state_t {
        using observer_t = storage::observer_t;

        triedb::db_ptr_t triedb;
        persistent_value_t<auth_pools_t<CFG>> alpha{triedb, 1U}; // authorizations
        persistent_value_t<auth_queues_t<CFG>> phi{triedb, 2U}; // work authorizer queue
        persistent_value_t<recent_blocks_t<CFG>> beta{triedb, 3U}; // most recent blocks
        persistent_value_t<safrole_state_t<CFG>> gamma{triedb, 4U}; // safrole state
        persistent_value_t<disputes_records_t> psi{triedb, 5U}; // judgements
        persistent_value_t<entropy_buffer_t> eta{triedb, 6U};
        persistent_value_t<validators_data_t<CFG>> iota{triedb, 7U};
        persistent_value_t<validators_data_t<CFG>> kappa{triedb, 8U};
        persistent_value_t<validators_data_t<CFG>> lambda{triedb, 9U};
        persistent_value_t<availability_assignments_t<CFG>> rho{triedb, 10U}; // assigned work reports
        persistent_value_t<time_slot_t<CFG>> tau{triedb, 11U};
        persistent_value_t<privileges_t<CFG>> chi{triedb, 12U};
        persistent_value_t<statistics_t<CFG>> pi{triedb, 13U};
        persistent_value_t<ready_queue_t<CFG>> omega{triedb, 14U}; // JAM (12.3): work reports ready to be accumulated
        persistent_value_t<accumulated_queue_t<CFG>> ksi{triedb, 15U}; // JAM (12.1): recently accumulated reports
        persistent_value_t<service_commitments_t> theta{triedb, 16U}; // JAM (7.4): recent service accumulation commitments
        accounts_t<CFG> delta{triedb}; // services

        static std::string decode_val(buffer key, buffer val);

        header_t<CFG> make_genesis_header() const;

        state_t &operator=(const state_snapshot_t &o);
        state_t &operator=(const state_t &o) = delete;

        state_copy_t<CFG> working_copy() const;
        void commit(state_copy_t<CFG> &&o);

        // (4.1): Kapital upsilon
        void apply(const block_t<CFG> &);

        // State transition methods: static to not be explicit about their inputs and outputs
        // (4.5)
        static time_slot_t<CFG> tau_prime(const time_slot_t<CFG> &prev_tau, const time_slot_t<CFG> &blk_slot);
        // (4.6)
        static recent_blocks_t<CFG> beta_dagger(const recent_blocks_t<CFG> &prev_beta, const state_root_t &sr);
        // (4.17)
        static recent_blocks_t<CFG> beta_prime(recent_blocks_t<CFG> tmp_beta, const header_hash_t &hh, const std::optional<opaque_hash_t> &ar, const reported_work_seq_t<CFG> &wp);
        // JAM (4.7)
        static entropy_buffer_t eta_prime(const time_slot_t<CFG> &prev_tau, const entropy_buffer_t &prev_eta, const time_slot_t<CFG> &blk_slot, const entropy_t &blk_entropy);
        // JAM (4.8)
        // JAM (4.9)
        // JAM (4.10)
        static safrole_output_data_t<CFG> update_safrole(
            const entropy_buffer_t &new_eta, const disputes_records_t &new_psi,
            const time_slot_t<CFG> &prev_tau, const safrole_state_t<CFG> &prev_gamma,
            const std::shared_ptr<validators_data_t<CFG>> &prev_kappa_ptr,
            const std::shared_ptr<validators_data_t<CFG>> &prev_lambda_ptr, const validators_data_t<CFG> &prev_iota,
            const time_slot_t<CFG> &slot, const tickets_extrinsic_t<CFG> &extrinsic);
        // JAM (4.11)
        static std::shared_ptr<disputes_records_t> psi_prime(offenders_mark_t &new_offenders, availability_assignments_t<CFG> &new_rho,
            const validators_data_t<CFG> &new_kappa, const validators_data_t<CFG> &new_lambda,
            const time_slot_t<CFG> &prev_tau, const std::shared_ptr<disputes_records_t> &prev_psi_ptr,
            const disputes_extrinsic_t<CFG> &disputes
        );
        // JAM (4.19)
        static auth_pools_t<CFG> alpha_prime(const time_slot_t<CFG> &slot, const core_authorizers_t &cas,
            const auth_queues_t<CFG> &new_phi, const auth_pools_t<CFG> &prev_alpha);
        // JAM (4.20)
        static statistics_t<CFG> pi_prime(statistics_t<CFG> &&tmp_pi,
            const reports_output_data_t &report_res, const validators_data_t<CFG> &new_kappa,
            const time_slot_t<CFG> &prev_tau, const time_slot_t<CFG> &slot, validator_index_t val_idx, const extrinsic_t<CFG> &extrinsic);
        // JAM (4.12)
        // JAM (4.13)
        // JAM (4.14)
        // JAM (4.15)
        static reports_output_data_t update_reports(
            availability_assignments_t<CFG> &tmp_rho, statistics_t<CFG> &tmp_pi,
            const blocks_history_t<CFG> &tmp_beta,
            const entropy_buffer_t &new_eta, const disputes_records_t &new_psi,
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
        void provide_preimages(statistics_t<CFG> &new_pi, const time_slot_t<CFG> &slot, const preimages_extrinsic_t &preimages);
        // JAM (4.16)
        static accumulate_output_t<CFG> accumulate(
            statistics_t<CFG> &tmp_pi, const entropy_buffer_t &new_eta,
            const time_slot_t<CFG> &prev_tau,
            const std::shared_ptr<auth_queues_t<CFG>> &prev_phi, const std::shared_ptr<validators_data_t<CFG>> &prev_iota,
            const std::shared_ptr<privileges_t<CFG>> &prev_chi,
            const std::shared_ptr<ready_queue_t<CFG>> &prev_nu, const std::shared_ptr<accumulated_queue_t<CFG>> &prev_ksi,
            const accounts_t<CFG> &prev_delta,
            const time_slot_t<CFG> &slot, const work_reports_t<CFG> &reports);

        [[nodiscard]] state_root_t root() const
        {
            return triedb->trie()->root();
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

        static bandersnatch_ring_commitment_t _ring_commitment(const validators_data_t<CFG> &);
        static validators_data_t<CFG> _capital_phi(const validators_data_t<CFG> &iota, const offenders_mark_t &psi_o);
        static keys_t<CFG> _fallback_key_sequence(const entropy_t &entropy, const validators_data_t<CFG> &kappa);
        static tickets_t<CFG> _permute_tickets(const tickets_accumulator_t<CFG> &gamma_a);
        static guarantor_assignments_t _guarantor_assignments(const entropy_t &e, const time_slot_t<CFG> &slot);
        static guarantors_t _guarantors(const entropy_buffer_t &eta, const validators_data_t<CFG> &kappa, const validators_data_t<CFG> &lambda,
            const offenders_mark_t &psi_o, const time_slot_t<CFG> &g_slot, const time_slot_t<CFG> &blk_slot);

        static delta_plus_result_t<CFG> accumulate_plus(
            statistics_t<CFG> &new_pi, const entropy_buffer_t &new_eta,
            const accounts_t<CFG> &prev_delta, const privileges_t<CFG> &prev_chi,
            const time_slot_t<CFG> &slot, const gas_t gas_limit, const work_reports_t<CFG> &reports
        );
        static delta_star_result_t<CFG> accumulate_star(
            statistics_t<CFG> &new_pi, const entropy_buffer_t &new_eta,
            const accounts_t<CFG> &prev_delta, const privileges_t<CFG> &prev_chi,
            const time_slot_t<CFG> &slot, const std::span<const work_report_t<CFG>> reports);
        static accumulate_result_t<CFG> invoke_accumulate(
            const entropy_buffer_t &new_eta,
            const accounts_t<CFG> &prev_delta, const privileges_t<CFG> &prev_chi,
            const time_slot_t<CFG> &slot,
            const service_id_t service_id, const accumulate_operands_t &ops);
        static gas_t invoke_on_transfer(
            const entropy_buffer_t &new_eta, mutable_services_state_t<CFG> &new_delta,
            time_slot_t<CFG> slot, service_id_t service_id, const deferred_transfers_t<CFG> &transfers);
    };

    template<typename CFG>
    struct state_copy_t: state_t<CFG> {
    };
}
