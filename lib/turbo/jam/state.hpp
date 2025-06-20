#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/container/update-map.hpp>
#include <turbo/common/logger.hpp>
#include <turbo/storage/filedb.hpp>
#include "types/header.hpp"
#include "types/state-dict.hpp"

namespace turbo::jam {
    using kv_store_t = storage::filedb::client_t;
    using kv_store_ptr_t = std::shared_ptr<kv_store_t>;

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

        persistent_value_t(const std::shared_ptr<state_dict_t> &state_dict, const uint8_t code, element_type val={}):
            _state_dict { state_dict },
            _key { state_dict_t::make_key(code) },
            _ptr { std::make_shared<T>(std::move(val)) }
        {
            if (!_state_dict) [[unlikely]]
                throw error("a persistent value requires an initialized state_dict!");
        }

        persistent_value_t(const std::shared_ptr<state_dict_t> &state_dict, const state_key_t &key, element_type val={}):
            _state_dict { state_dict },
            _key { key },
            _ptr { std::make_shared<T>(std::move(val)) }
        {
            if (!_state_dict) [[unlikely]]
                throw error("a persistent value requires an initialized state_dict!");
        }

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            // TODO: can be optimized for the decoding case. That happens only unit tests though.
            auto tmp = get();
            archive.process(tmp);
            set(std::move(tmp));
        }

        const element_type &get() const
        {
            return *_ptr;
        }

        const ptr_type &storage() const
        {
            return _ptr;
        }

        void set(element_type new_val)
        {
            // allocation of a new shared pointer ensures that other copies are not affected
            _ptr = std::make_shared<element_type>(std::move(new_val));
            _state_dict->set(_key, encode(*_ptr));
        }

        void set(ptr_type new_ptr)
        {
            if (_ptr.get() != new_ptr.get()) {
                _ptr = std::move(new_ptr);
                _state_dict->set(_key, encode(*_ptr));
            }
        }

        bool operator==(const persistent_value_t &o) const
        {
            return *_ptr == *o._ptr;
        }
    private:
        std::shared_ptr<state_dict_t> _state_dict;
        state_key_t _key;
        ptr_type _ptr;
    };

    struct service_info_t;

    // This structure captures updates rather than absolute values.
    // For this reason int64_t types are used to track potential decreases of the aboslute values.
    struct service_info_update_t {
        const persistent_value_t<service_info_t> &base;
        std::optional<opaque_hash_t> code_hash {};
        int64_t balance = 0;
        // gas saved in the fixed format form
        std::optional<gas_t::base_type> min_item_gas {};
        std::optional<gas_t::base_type> min_memo_gas {};
        int64_t bytes = 0;
        int32_t items = 0;

        bool empty() const
        {
            if (code_hash)
                return false;
            if (balance)
                return false;
            if (min_item_gas)
                return false;
            if (min_memo_gas)
                return false;
            if (bytes)
                return false;
            if (items)
                return false;
            return true;
        }

        void consume_from(service_info_update_t &&o)
        {
            if (o.code_hash)
                code_hash = o.code_hash;
            balance += o.balance;
            if (o.min_item_gas)
                min_item_gas = o.min_item_gas;
            if (o.min_memo_gas)
                min_memo_gas = o.min_memo_gas;
            bytes += o.bytes;
            items += o.items;
        }

        service_info_t combine() const;
        void commit(persistent_value_t<service_info_t> &);
    };

    struct service_info_t {
        opaque_hash_t code_hash {};
        balance_t balance = 0;
        // gas saved in the fixed format form
        gas_t::base_type min_item_gas = 0;
        gas_t::base_type min_memo_gas = 0;
        uint64_t bytes = 0;
        uint32_t items = 0;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("code_hash"sv, code_hash);
            archive.process("balance"sv, balance);
            archive.process("min_item_gas"sv, min_item_gas);
            archive.process("min_memo_gas"sv, min_memo_gas);
            archive.process("bytes"sv, bytes);
            archive.process("items"sv, items);
        }

        void consume_from(const service_info_update_t &o)
        {
            if (o.code_hash)
                code_hash = *o.code_hash;
            balance += o.balance;
            if (o.min_item_gas)
                min_item_gas = *o.min_item_gas;
            if (o.min_memo_gas)
                min_memo_gas = *o.min_memo_gas;
            bytes += o.bytes;
            items += o.items;
        }

        bool operator==(const service_info_t &o) const noexcept
        {
            if (code_hash != o.code_hash)
                return false;
            if (balance != o.balance)
                return false;
            if (min_item_gas != o.min_item_gas)
                return false;
            if (min_memo_gas != o.min_memo_gas)
                return false;
            if (bytes != o.bytes)
                return false;
            if (items != o.items)
                return false;
            return true;
        }
    };

    inline service_info_t service_info_update_t::combine() const
    {
        auto res = base.get();
        res.consume_from(*this);
        return res;
    }

    inline void service_info_update_t::commit(persistent_value_t<service_info_t> &target)
    {
        target.set(combine());
    }

    template<typename K, typename V>
    struct state_dict_based_map_t {
        using key_type = K;
        using mapped_type = V;
        using keys_t = std::map<key_type, state_key_t>;
        using observer_t = std::function<void(const key_type &k, mapped_type v)>;
        using trie_key_func_t = std::function<state_key_t(const key_type &)>;

        state_dict_based_map_t(const kv_store_ptr_t &kv_store, const state_dict_ptr_t &state_dict, const trie_key_func_t &try_key_func):
            _kv_store { kv_store },
            _state_dict { state_dict },
            _try_key_func { try_key_func }
        {
        }

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process_map(*this, "hash"sv, "blob"sv);
        }

        bool empty() const
        {
            return _keys.empty();
        }

        void erase(const key_type &key)
        {
            if (const auto it = _keys.find(key); it != _keys.end()) {
                const auto &sd_val = _state_dict->get(it->second);
                if (sd_val) {
                    std::visit([&](const auto &sv) {
                        using T = std::decay_t<decltype(sv)>;
                        if constexpr (std::is_same_v<T, state_dict_t::value_hash_t>) {
                            _kv_store->erase(sv);
                        }
                    }, *sd_val);
                    _state_dict->erase(it->second);
                }
                _keys.erase(it);
            }
        }

        void foreach(const observer_t &obs) const
        {
            for (const auto &[k, trie_k]: _keys) {
                const auto &sd_v = _state_dict->get(trie_k);
                if (sd_v) {
                    auto val = std::visit([&](const auto &v) -> std::optional<write_vector> {
                        using T = std::decay_t<decltype(v)>;
                        if constexpr (std::is_same_v<T, state_dict_t::value_hash_t>) {
                            return _kv_store->get(v);
                        } else {
                            return write_vector { buffer { v.data(), v.size() } };
                        }
                    }, *sd_v);
                    if (val)
                        obs(k, _decode(std::move(*val)));
                }
            }
        }

        // preimages for a single service are expected to be called from a single thread at a time
        std::optional<mapped_type> get(const key_type &key) const
        {
            if (const auto k_it = _keys.find(key); k_it != _keys.end()) {
                const auto &sd_v = _state_dict->get(k_it->second);
                auto val = std::visit([&](const auto &v) -> std::optional<write_vector> {
                    using T = std::decay_t<decltype(v)>;
                    if constexpr (std::is_same_v<T, state_dict_t::value_hash_t>) {
                        return _kv_store->get(v);
                    } else {
                        return write_vector { buffer { v.data(), v.size() } };
                    }
                }, *sd_v);
                if (val)
                    return _decode(std::move(*val));
            }
            return {};
        }

        void set(const key_type &key, mapped_type val)
        {
            auto trie_key = _try_key_func(key);
            _keys.try_emplace(key, trie_key);
            // Always update the stored value - necessary for service_storage_t
            auto raw_val = _encode(val);
            const auto &sd_val = _state_dict->emplace(trie_key, raw_val);
            std::visit([&](const auto &sv) {
                using T = std::decay_t<decltype(sv)>;
                if constexpr (std::is_same_v<T, state_dict_t::value_hash_t>) {
                    _kv_store->set(sv, raw_val);
                }
            }, sd_val);
        }

        size_t size() const
        {
            return _keys.size();
        }

        bool operator==(const state_dict_based_map_t &o) const
        {
            size_t num_diff = 0;
            foreach([&](const auto &k, const auto &v) {
                const auto &o_v = o.get(k);
                if (o_v != v)
                    ++num_diff;
            });
            o.foreach([&](const auto &k, const auto &) {
                if (!get(k))
                    ++num_diff;
            });
            return num_diff == 0;
        }
    private:
        kv_store_ptr_t _kv_store;
        state_dict_ptr_t _state_dict;
        trie_key_func_t _try_key_func;
        keys_t _keys {};

        static write_vector _encode(V v)
        {
            if constexpr (std::is_same_v<V, write_vector>) {
                return std::move(v);
            } else {
                encoder enc { v };
                return { static_cast<buffer>(enc.bytes()) };
            }
        }

        static V _decode(write_vector bytes)
        {
            if constexpr (std::is_same_v<V, write_vector>) {
                return bytes;
            } else {
                decoder dec { bytes };
                V res;
                dec.process(res);
                return res;
            }
        }
    };

    struct preimages_t: state_dict_based_map_t<opaque_hash_t, write_vector> {
        using base_type = state_dict_based_map_t<opaque_hash_t, write_vector>;
        using base_type::base_type;

        static trie_key_func_t make_trie_key_func(const service_id_t service_id)
        {
            return [service_id](const key_type &k) {
                state_key_subhash_t kh;
                encoder::uint_fixed(std::span { kh.begin(), kh.begin() + 4 }, 4, (1ULL << 32U) - 2ULL);
                memcpy(kh.data() + 4, k.data() + 1, kh.size() - 4);
                return state_dict_t::make_key(service_id, kh);
            };
        }
    };

    struct storage_items_config_t {
        std::string key_name = "hash";
        std::string val_name = "blob";
    };
    using storage_items_t = map_t<opaque_hash_t, byte_sequence_t, storage_items_config_t>;

    using preimage_items_t = map_t<opaque_hash_t, byte_sequence_t, storage_items_config_t>;

    struct lookup_meta_map_key_t {
        opaque_hash_t hash;
        uint32_t length;

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
    template<typename CONSTANTS>
    using lookup_meta_map_val_t = sequence_t<time_slot_t<CONSTANTS>, 0, 3>;

    template<typename CONSTANTS>
    using lookup_meta_items_t = map_t<lookup_meta_map_key_t, lookup_meta_map_val_t<CONSTANTS>, lookup_metas_config_t>;

    template<typename CFG>
    struct lookup_metas_t: state_dict_based_map_t<lookup_meta_map_key_t, lookup_meta_map_val_t<CFG>> {
        using base_type = state_dict_based_map_t<lookup_meta_map_key_t, lookup_meta_map_val_t<CFG>>;
        using base_type::base_type;

        static typename base_type::trie_key_func_t make_trie_key_func(const service_id_t service_id)
        {
            return [service_id](const typename base_type::key_type &k) {
                state_key_subhash_t kh;
                encoder::uint_fixed(std::span { kh.begin(), kh.begin() + 4 }, 4, k.length);
                const auto hh = crypto::blake2b::digest(k.hash);
                memcpy(kh.data() + 4, hh.data() + 2, kh.size() - 4);
                return state_dict_t::make_key(service_id, kh);
            };
        }
    };

    struct service_storage_t: state_dict_based_map_t<opaque_hash_t, write_vector> {
        using base_type = state_dict_based_map_t<opaque_hash_t, write_vector>;
        using base_type::base_type;

        static typename base_type::trie_key_func_t make_trie_key_func(const service_id_t service_id)
        {
            return [service_id](const typename base_type::key_type &k) {
                state_key_subhash_t kh;
                encoder::uint_fixed(std::span { kh.begin(), kh.begin() + 4 }, 4, (1ULL << 32U) - 1ULL);
                memcpy(kh.data() + 4, k.data(), kh.size() - 4);
                return state_dict_t::make_key(service_id, kh);
            };
        }
    };

    // (9.8)
    template<typename L, typename S>
    balance_t account_balance_threshold(const L &l, const S &s)
    {
        size_t a_i = 0;
        size_t a_o = 0;
        l.foreach([&](const auto &k, const auto &) {
            a_i += 2;
            a_o += 81 + k.length;
        });
        s.foreach([&](const auto &, const auto &v) {
            a_i += 1;
            a_o += 32 + v.size();
        });
        return config_base::min_balance_per_service
            + config_base::min_balance_per_item * a_i
            + config_base::min_balance_per_octet * a_o;
    }

    template<typename CFG>
    struct account_t {
        // preimages comes first since it requires an argument to be initialized
        preimages_t preimages;
        lookup_metas_t<CFG> lookup_metas;
        service_storage_t storage;
        persistent_value_t<service_info_t> info;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("preimages"sv, preimages);
            archive.process("storage"sv, storage);
            archive.process("lookup_metas"sv, lookup_metas);
            archive.process("info"sv, info);
        }

        bool operator==(const account_t &o) const
        {
            if (storage != o.storage)
                return false;
            if (preimages != o.preimages)
                return false;
            if (lookup_metas != o.lookup_metas)
                return false;
            if (info != o.info)
                return false;
            return true;
        }
    };

    struct accounts_config_t {
        std::string key_name = "id";
        std::string val_name = "data";
    };

    template<typename CONSTANTS>
    using accounts_t = map_t<service_id_t, account_t<CONSTANTS>, accounts_config_t>;

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
        service_info_update_t info;

        bool empty() const
        {
            if (!storage.empty())
                return false;
            if (!preimages.empty())
                return false;
            if (!lookup_metas.empty())
                return false;
            if (!info.empty())
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
    using mutable_services_base_t = std::map<service_id_t, mutable_service_state_t<CFG>>;

    template<typename CFG>
    struct accounts_update_api_t {
        using base_type = accounts_t<CFG>;
        using key_type = typename accounts_t<CFG>::key_type;
        using mapped_type = mutable_service_state_t<CFG>;

        accounts_update_api_t(const accounts_t<CFG> &base):
            _base { base }
        {
        }

        void consume_from(accounts_update_api_t &&o)
        {
            for (auto &&[k, v]: o._derived) {
                if (auto [it, created] = _derived.try_emplace(k, std::move(v)); !created)
                    it->second.consume_from(std::move(v));
            }
        }

        mapped_type *get_mutable_ptr(const key_type &k)
        {
            if (const auto d_it = _derived.find(k); d_it != _derived.end())
                return &d_it->second;
            if (auto b_it = _base.find(k); b_it != _base.end()) {
                const auto [d_it, created] = _derived.try_emplace(
                    k,
                    container::direct_update_api_t<service_storage_t> { b_it->second.storage },
                    container::direct_update_api_t<preimages_t> { b_it->second.preimages },
                    container::direct_update_api_t<lookup_metas_t<CFG>> { b_it->second.lookup_metas },
                    service_info_update_t { b_it->second.info }
                );
                return &d_it->second;
            }
            return nullptr;
        }

        mapped_type &get_mutable(const key_type &k)
        {
            if (auto ptr = get_mutable_ptr(k); ptr)
                return *ptr;
            throw err_bad_service_id_t {};
        }

        void commit(accounts_t<CFG> &target)
        {
            for (auto &[k, v]: _derived)
                v.commit(target.at(k));
            _derived.clear();
        }
    private:
        const accounts_t<CFG> &_base;
        mutable_services_base_t<CFG> _derived {};
    };

    template<typename CFG>
    using mutable_services_state_t = accounts_update_api_t<CFG>;

    // JAM (12.13)
    template<typename CFG>
    struct mutable_state_t {
        // JAM: bold d
        mutable_services_state_t<CFG> services;
        // JAM: bold i
        std::optional<validators_data_t<CFG>> iota {};
        // JAM: bold q
        std::optional<auth_queues_t<CFG>> queue {};
        // JAM: bold x
        std::optional<privileges_t> privileges {};

        void consume_from(mutable_state_t &&o)
        {
            services.consume_from(std::move(o.services));
            if (o.iota)
                iota = std::move(o.iota);
            if (o.queue)
                queue = std::move(o.queue);
            if (o.privileges)
                privileges = std::move(o.privileges);
        }
    };

    using deferred_transfer_metadata_t = byte_array_t<128>;

    // JAM (12.14)
    struct deferred_transfer_t {
        // JAM: s
        service_id_t source;
        // JAM: d
        service_id_t destination;
        // JAM: a
        balance_t amount;
        // JAM: m
        deferred_transfer_metadata_t metadata;
        // JAM: g
        gas_t gas_limit;
    };
    using deferred_transfers_t = sequence_t<deferred_transfer_t>;
    using deferred_transfer_ptrs_t = std::vector<const deferred_transfer_t *>;

    template<typename CONSTANTS>
    using service_code_preimages_t = map_t<service_id_t, byte_sequence_t, CONSTANTS>;

    // JAM (B.7)
    template<typename CONSTANTS>
    struct accumulate_context_t {
        // JAM: s
        service_id_t service_id = 0;
        // JAM: bold u
        mutable_state_t<CONSTANTS> state;
        // JAM: i
        service_id_t new_service_id = 0;
        // JAM: bold t
        deferred_transfers_t transfers {};
        // JAM: y
        optional_t<opaque_hash_t> result {};
        // JAM: p
        //service_code_preimages_t<CONSTANTS> code {};
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

        bool operator==(const accumulate_operand_t &o) const
        {
            if (work_package_hash != o.work_package_hash)
                return false;
            if (exports_root != o.exports_root)
                return false;
            if (authorizer_hash != o.authorizer_hash)
                return false;
            if (auth_output != o.auth_output)
                return false;
            if (payload_hash != o.payload_hash)
                return false;
            if (accumulate_gas != o.accumulate_gas)
                return false;
            if (result != o.result)
                return false;
            return true;
        }
    };
    using accumulate_operands_t = sequence_t<accumulate_operand_t>;
    using accumulate_service_operands_t = std::map<service_id_t, accumulate_operands_t>;

    // JAM (B.9)
    template<typename CFG>
    struct accumulate_result_t {
        mutable_state_t<CFG> state;
        deferred_transfers_t transfers {};
        std::optional<opaque_hash_t> commitment {};
        gas_t gas {};
        size_t num_reports = 0;
    };
    template<typename CFG>
    using service_results_t = std::map<service_id_t, accumulate_result_t<CFG>>;

    // JAM (12.15): B
    using service_commitments_t = std::map<service_id_t, opaque_hash_t>;
    // JAM (12.15): U + (12.24) num_items
    struct service_work_item_t {
        gas_t gas_used {};
        size_t num_reports = 0;
    };
    using service_work_items_t = std::map<service_id_t, service_work_item_t>;

    // JAM (12.17)
    template<typename CFG>
    struct delta_star_result_t {
        size_t num_accumulated = 0;
        service_results_t<CFG> results {};
    };

    // JAM (12.16)
    template<typename CFG>
    struct delta_plus_result_t {
        mutable_state_t<CFG> state;
        deferred_transfers_t transfers {};
        service_commitments_t commitments {};
        service_work_items_t work_items {};
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
        std::shared_ptr<privileges_t> new_chi;
        std::optional<mutable_services_state_t<CFG>> service_updates;
        accumulate_root_t root {};
    };

    // JAM (4.4) - lowercase sigma
    // persistent_value with std::shared_ptr ensures that:
    // 1) the state is cheap to copy
    // 2) automatically searialized into the state_dict on updates
    // TODO: state_dict should use copy_on_write_ptr_t instead of std::shared_ptr
    template<typename CFG=config_prod>
    struct state_t {
        kv_store_ptr_t kv_store;
        state_dict_ptr_t state_dict = std::make_shared<state_dict_ptr_t::element_type>();
        persistent_value_t<auth_pools_t<CFG>> alpha { state_dict, 1U }; // authorizations
        persistent_value_t<auth_queues_t<CFG>> phi {  state_dict, 2U }; // work authorizer queue
        persistent_value_t<blocks_history_t<CFG>> beta { state_dict, 3U }; // most recent blocks
        persistent_value_t<safrole_state_t<CFG>> gamma { state_dict, 4U }; // safrole state
        persistent_value_t<disputes_records_t> psi { state_dict, 5U }; // judgements
        persistent_value_t<entropy_buffer_t> eta { state_dict, 6U };
        persistent_value_t<validators_data_t<CFG>> iota { state_dict, 7U };
        persistent_value_t<validators_data_t<CFG>> kappa { state_dict, 8U };
        persistent_value_t<validators_data_t<CFG>> lambda { state_dict, 9U };
        persistent_value_t<availability_assignments_t<CFG>> rho { state_dict, 10U }; // assigned work reports
        persistent_value_t<time_slot_t<CFG>> tau { state_dict, 11U };
        persistent_value_t<privileges_t> chi { state_dict, 12U };
        persistent_value_t<statistics_t<CFG>> pi { state_dict, 13U };
        persistent_value_t<ready_queue_t<CFG>> nu { state_dict, 14U }; // JAM (12.3): work reports ready to be accumulated
        persistent_value_t<accumulated_queue_t<CFG>> ksi { state_dict, 15U }; // JAM (12.1): recently accumulated reports
        accounts_t<CFG> delta {}; // services

        [[nodiscard]] std::optional<std::string> diff(const state_t &o) const;
        state_t &operator=(const state_snapshot_t &o);

        // (4.1): Kapital upsilon
        void apply(const block_t<CFG> &);

        std::optional<write_vector> state_get(const state_key_t &k) const;

        // State transition methods: static to not be explicit about their inputs and outputs

        // (4.5)
        static time_slot_t<CFG> tau_prime(const time_slot_t<CFG> &prev_tau, const time_slot_t<CFG> &blk_slot);
        // (4.6)
        static blocks_history_t<CFG> beta_dagger(const blocks_history_t<CFG> &prev_beta, const state_root_t &sr);
        // (4.17)
        static blocks_history_t<CFG> beta_prime(blocks_history_t<CFG> tmp_beta, const header_hash_t &hh, const std::optional<opaque_hash_t> &ar, const reported_work_seq_t &wp);
        // JAM (4.7)
        static entropy_buffer_t eta_prime(const time_slot_t<CFG> &prev_tau, const entropy_buffer_t &prev_eta, const time_slot_t<CFG> &blk_slot, const entropy_t &blk_entropy);
        // JAM (4.8)
        // JAM (4.9)
        // JAM (4.10)
        static safrole_output_data_t<CFG> update_safrole(
            const time_slot_t<CFG> &prev_tau, const safrole_state_t<CFG> &prev_gamma,
            const entropy_buffer_t &new_eta,
            const std::shared_ptr<validators_data_t<CFG>> &prev_kappa_ptr, const std::shared_ptr<validators_data_t<CFG>> &prev_lambda_ptr,
            const validators_data_t<CFG> &prev_iota, const disputes_records_t &prev_psi,
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
        static statistics_t<CFG> pi_prime(statistics_t<CFG> &&tmp_pi, const time_slot_t<CFG> &prev_tau, const time_slot_t<CFG> &slot, validator_index_t val_idx, const extrinsic_t<CFG> &extrinsic);
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
            statistics_t<CFG> &tmp_pi,
            const time_slot_t<CFG> &prev_tau,
            const std::shared_ptr<auth_queues_t<CFG>> &prev_phi, const std::shared_ptr<validators_data_t<CFG>> &prev_iota,
            const std::shared_ptr<privileges_t> &prev_chi,
            const std::shared_ptr<ready_queue_t<CFG>> &prev_nu, const std::shared_ptr<accumulated_queue_t<CFG>> &prev_ksi,
            const accounts_t<CFG> &prev_delta,
            const time_slot_t<CFG> &slot, const work_reports_t<CFG> &reports);
        bool operator==(const state_t &o) const noexcept;
    private:
        using guarantor_assignments_t = fixed_sequence_t<core_index_t, CFG::validator_count>;

        static bandersnatch_ring_commitment_t _ring_commitment(const validators_data_t<CFG> &);
        static validators_data_t<CFG> _capital_phi(const validators_data_t<CFG> &iota, const offenders_mark_t &psi_o);
        static keys_t<CFG> _fallback_key_sequence(const entropy_t &entropy, const validators_data_t<CFG> &kappa);
        static tickets_t<CFG> _permute_tickets(const tickets_accumulator_t<CFG> &gamma_a);
        static guarantor_assignments_t _guarantor_assignments(const entropy_t &e, const time_slot_t<CFG> &slot);

        static delta_plus_result_t<CFG> accumulate_plus(statistics_t<CFG> &new_pi, const time_slot_t<CFG> &slot, const gas_t gas_limit, const work_reports_t<CFG> &reports, const accounts_t<CFG> &prev_delta, const free_services_t &prev_free_services);
        static delta_star_result_t<CFG> accumulate_star(statistics_t<CFG> &new_pi, const time_slot_t<CFG> &slot, std::span<const work_report_t<CFG>> reports,
            const accounts_t<CFG> &prev_delta, const free_services_t &prev_free_services);
        static accumulate_result_t<CFG> invoke_accumulate(time_slot_t<CFG> slot, service_id_t service_id,
            const accumulate_operands_t &ops,
            const accounts_t<CFG> &prev_delta, const free_services_t &prev_free_services);
        static gas_t invoke_on_transfer(time_slot_t<CFG> slot, service_id_t service_id,
            const accounts_t<CFG> &prev_delta, const deferred_transfer_ptrs_t &transfers);
    };
}
