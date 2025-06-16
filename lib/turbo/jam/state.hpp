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

    struct preimages_t {
        using keys_t = std::set<opaque_hash_t>;
        using key_type = opaque_hash_t;
        using mapped_type = write_vector;
        using observer_t = std::function<void(const opaque_hash_t &k, mapped_type v)>;

        preimages_t(const kv_store_ptr_t &kv_store):
            _kv_store { kv_store }
        {
        }

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process_map(*this, "hash"sv, "blob"sv);
        }

        std::pair<keys_t::const_iterator, bool> try_emplace(const opaque_hash_t &key, const buffer &val)
        {
            auto [it, created] = _keys.emplace(key);
            if (created)
                _kv_store->set(key, val);
            return std::make_pair(it, created);
        }

        bool empty() const
        {
            return _keys.empty();
        }

        void erase(const opaque_hash_t &key)
        {
            if (const auto it = _keys.find(key); it != _keys.end()) {
                _kv_store->erase(key);
                _keys.erase(it);
            }
        }

        void foreach(const observer_t &obs) const
        {
            for (const auto &k: _keys) {
                auto val = _kv_store->get(k);
                //logger::info("preimages_t::foreach k: {} v: {}", k, val);
                if (!val) [[unlikely]]
                    throw error(fmt::format("internal error: a missing preimage value for hash: {}", k));
                obs(k, std::move(*val));
            }
        }

        // preimages for a single service are expected to be called from a single thread at a time
        mapped_type get(const opaque_hash_t &hash) const
        {
            if (_keys.contains(hash)) {
                if (auto val = _kv_store->get(hash); val)
                    return std::move(*val);
            }
            return write_vector(0);
        }

        void set(const buffer &key, const buffer &val)
        {
            _keys.emplace(key);
            _kv_store->set(key, val);
        }

        void set(const opaque_hash_t &key, const mapped_type val)
        {
            if (val.empty()) [[unlikely]]
                throw error("preimages_t::set expects only non-null values!");
            set(static_cast<buffer>(key), static_cast<buffer>(val));
        }

        size_t size() const
        {
            return _keys.size();
        }

        bool operator==(const preimages_t &o) const
        {
            size_t num_diff = 0;
            foreach([&](const auto &k, const auto &v) {
                const auto &o_v = o.get(k);
                if (o_v != v)
                    ++num_diff;
            });
            o.foreach([&](const auto &k, const auto &v) {
                if (!container::has_value(get(k)))
                    ++num_diff;
            });
            return num_diff == 0;
        }
    private:
        kv_store_ptr_t _kv_store;
        keys_t _keys {};
    };
    static_assert(codec::has_foreach_c<preimages_t>);

    struct storage_items_config_t {
        std::string key_name = "hash";
        std::string val_name = "blob";
    };
    using storage_items_t = map_t<opaque_hash_t, byte_sequence_t, storage_items_config_t>;

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
    using lookup_metas_t = map_t<lookup_meta_map_key_t, lookup_meta_map_val_t<CONSTANTS>, lookup_metas_config_t>;

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

    template<typename CONSTANTS>
    struct account_t {
        // preimages comes first since it requires an argument to be initialized
        preimages_t preimages;
        storage_items_t storage {};
        lookup_metas_t<CONSTANTS> lookup_metas {};
        service_info_t info {};

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("storage", storage);
            archive.process("preimages", preimages);
            archive.process("lookup_metas", lookup_metas);
            archive.process("info", info);
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

    template<typename CONFIG>
    struct mutable_service_state_t {
        using update_preimage_map_t = container::update_map_t<container::direct_update_api_t<preimages_t>>;
        using update_storage_map_t = container::update_map_t<container::std_map_update_api_t<storage_items_t>>;
        using update_lookup_map_t = container::update_map_t<container::std_map_update_api_t<lookup_metas_t<CONFIG>>>;

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

        void commit()
        {
            storage.commit();
            preimages.commit();
            lookup_metas.commit();
            info.commit();
        }
    };

    template<typename CONFIG>
    using mutable_services_base_t = std::map<service_id_t, mutable_service_state_t<CONFIG>>;

    template<typename CONFIG>
    struct accounts_update_api_t {
        using base_type = accounts_t<CONFIG>;
        using key_type = typename accounts_t<CONFIG>::key_type;
        using mapped_type = mutable_service_state_t<CONFIG>;

        accounts_update_api_t(accounts_t<CONFIG> &base):
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

        mapped_type &get_mutable(const key_type &k)
        {
            if (const auto d_it = _derived.find(k); d_it != _derived.end())
                return d_it->second;
            if (const auto b_it = _base.find(k); b_it != _base.end()) {
                const auto [d_it, created] = _derived.try_emplace(
                    k,
                    container::std_map_update_api_t { b_it->second.storage },
                    container::direct_update_api_t { b_it->second.preimages },
                    container::std_map_update_api_t { b_it->second.lookup_metas },
                    service_info_update_t { b_it->second.info }
                );
                return d_it->second;
            }
            throw err_bad_service_id_t {};
        }

        void commit()
        {
            for (auto &[k, v]: _derived)
                v.commit();
            _derived.clear();
        }
    private:
        accounts_t<CONFIG> &_base;
        mutable_services_base_t<CONFIG> _derived {};
    };

    template<typename CONFIG>
    using mutable_services_state_t = accounts_update_api_t<CONFIG>;

    // JAM (12.13)
    template<typename CONFIG>
    struct mutable_state_t {
        // JAM: bold d
        mutable_services_state_t<CONFIG> services;
        // JAM: bold i
        std::optional<validators_data_t<CONFIG>> iota;
        // JAM: bold q
        std::optional<auth_queues_t<CONFIG>> queue;
        // JAM: bold x
        std::optional<privileges_t> privileges;

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
        byte_sequence_t auth_output;
        opaque_hash_t payload_hash;
        gas_t accumulate_gas;
        work_exec_result_t result;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("work_package_hash"sv, work_package_hash);
            archive.process("exports_root"sv, exports_root);
            archive.process("authorizer_hash"sv, authorizer_hash);
            archive.process("auth_output"sv, auth_output);
            archive.process("payload_hash"sv, payload_hash);
            archive.process("accumulate_gas"sv, accumulate_gas);
            archive.process("result"sv, result);
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
    template<typename CONFIG>
    struct accumulate_result_t {
        mutable_state_t<CONFIG> state;
        deferred_transfers_t transfers {};
        std::optional<opaque_hash_t> commitment {};
        gas_t gas {};
        size_t num_reports = 0;
    };
    template<typename CONFIG>
    using service_results_t = std::map<service_id_t, accumulate_result_t<CONFIG>>;

    // JAM (12.15): B
    using service_commitments_t = std::map<service_id_t, opaque_hash_t>;
    // JAM (12.15): U + (12.24) num_items
    struct service_work_item_t {
        gas_t gas_used {};
        size_t num_reports = 0;
    };
    using service_work_items_t = std::map<service_id_t, service_work_item_t>;

    // JAM (12.17)
    template<typename CONFIG>
    struct delta_star_result_t {
        size_t num_accumulated = 0;
        service_results_t<CONFIG> results {};
    };

    // JAM (12.16)
    template<typename CONFIG>
    struct delta_plus_result_t {
        mutable_state_t<CONFIG> state;
        deferred_transfers_t transfers {};
        service_commitments_t commitments {};
        service_work_items_t work_items {};
        size_t num_accumulated = 0;

        void consume_from(delta_star_result_t<CONFIG> &&o)
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
            _code { code },
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
            _state_dict->set(state_dict_t::make_key(_code), encode(*_ptr));
        }

        void set(ptr_type new_ptr)
        {
            _ptr = std::move(new_ptr);
            _state_dict->set(state_dict_t::make_key(_code), encode(*_ptr));
        }
    private:
        std::shared_ptr<state_dict_t> _state_dict;
        uint8_t _code;
        ptr_type _ptr;
    };

    // JAM (4.4) - lowercase sigma
    // persistent_value with std::shared_ptr ensures that:
    // 1) the state is cheap to copy
    // 2) automatically searialized into the state_dict on updates
    template<typename CONFIG=config_prod>
    class state_t {
        kv_store_ptr_t _kv_store;
        std::shared_ptr<state_dict_t> _state_dict = std::make_shared<state_dict_t>();
    public:
        // authorizations
        persistent_value_t<auth_pools_t<CONFIG>> alpha { _state_dict, 1U };
        // most recent blocks
        persistent_value_t<blocks_history_t<CONFIG>> beta { _state_dict, 3U };
        // safrole state
        persistent_value_t<safrole_state_t<CONFIG>> gamma { _state_dict, 4U };
        accounts_t<CONFIG> delta {}; // services
        persistent_value_t<entropy_buffer_t> eta { _state_dict, 6U };
        persistent_value_t<validators_data_t<CONFIG>> iota { _state_dict, 7U };
        persistent_value_t<validators_data_t<CONFIG>> kappa { _state_dict, 8U };
        persistent_value_t<validators_data_t<CONFIG>> lambda { _state_dict, 9U };
        availability_assignments_t<CONFIG> rho {}; // assigned work reports

        persistent_value_t<time_slot_t<CONFIG>> tau { _state_dict, 11U };

        auth_queues_t<CONFIG> phi {}; // work authorizer queue
        privileges_t chi {};
        // judgements
        persistent_value_t<disputes_records_t> psi { _state_dict, 5U };
        statistics_t<CONFIG> pi {};
        ready_queue_t<CONFIG> nu {}; // JAM (12.3): work reports ready to be accumulated
        accumulated_queue_t<CONFIG> ksi {}; // JAM (12.1): recently accumulated reports

        state_t(kv_store_ptr_t kv_store):
            _kv_store { std::move(kv_store) }
        {
            if (!_kv_store) [[unlikely]]
                throw error("a state requires a non-null kv_store!");
        }

        [[nodiscard]] std::optional<std::string> diff(const state_t &o) const;

        // export & import
        state_dict_t state_dict() const;
        state_t &operator=(const state_snapshot_t &o);

        // (4.1): Kapital upsilon
        void apply(const block_t<CONFIG> &);
        std::exception_ptr try_apply(const block_t<CONFIG> &) noexcept;

        // Methods internally used by the apply and in unit tests
        // Todo: make them protected and the respective unit test classes friends?

        // (4.5)
        static time_slot_t<CONFIG> tau_prime(const time_slot_t<CONFIG> &prev_tau, const time_slot_t<CONFIG> &blk_slot);
        // (4.6)
        static blocks_history_t<CONFIG> beta_dagger(const blocks_history_t<CONFIG> &prev_beta, const state_root_t &sr);
        // (4.17)
        static blocks_history_t<CONFIG> beta_prime(blocks_history_t<CONFIG> tmp_beta, const header_hash_t &hh, const std::optional<opaque_hash_t> &ar, const reported_work_seq_t &wp);
        // JAM (4.7)
        static entropy_buffer_t eta_prime(const time_slot_t<CONFIG> &prev_tau, const entropy_buffer_t &prev_eta, const time_slot_t<CONFIG> &blk_slot, const entropy_t &blk_entropy);
        // JAM (4.8)
        // JAM (4.9)
        // JAM (4.10)
        static safrole_output_data_t<CONFIG> update_safrole(
            const time_slot_t<CONFIG> &prev_tau, const safrole_state_t<CONFIG> &prev_gamma,
            const entropy_buffer_t &new_eta,
            const std::shared_ptr<validators_data_t<CONFIG>> &prev_kappa_ptr, const std::shared_ptr<validators_data_t<CONFIG>> &prev_lambda_ptr,
            const validators_data_t<CONFIG> &prev_iota, const disputes_records_t &prev_psi,
            const time_slot_t<CONFIG> &slot, const tickets_extrinsic_t<CONFIG> &extrinsic);
        // JAM (4.12)
        // JAM (4.13)
        // JAM (4.14)
        // JAM (4.15)
        reports_output_data_t update_reports(const time_slot_t<CONFIG> &slot, const guarantees_extrinsic_t<CONFIG> &guarantees,
            const auth_pools_t<CONFIG> &prev_alpha, const blocks_history_t<CONFIG> &prev_beta);
        // JAM (4.11)
        offenders_mark_t update_disputes(const time_slot_t<CONFIG> &prev_tau, const disputes_extrinsic_t<CONFIG> &disputes);
        // JAM (4.18)
        void provide_preimages(const time_slot_t<CONFIG> &slot, const preimages_extrinsic_t &preimages);
        // JAM (4.20)
        void update_statistics(const time_slot_t<CONFIG> &prev_tau, const time_slot_t<CONFIG> &slot, validator_index_t val_idx, const extrinsic_t<CONFIG> &extrinsic);
        // JAM (4.16)
        accumulate_root_t accumulate(const time_slot_t<CONFIG> &prev_tau, const time_slot_t<CONFIG> &slot, const work_reports_t<CONFIG> &reports);
        // JAM (4.19)
        static auth_pools_t<CONFIG> alpha_prime(const time_slot_t<CONFIG> &slot, const core_authorizers_t &cas,
            const auth_queues_t<CONFIG> &new_phi, const auth_pools_t<CONFIG> &prev_alpha);
        bool operator==(const state_t &o) const noexcept;
    private:
        using guarantor_assignments_t = fixed_sequence_t<core_index_t, CONFIG::validator_count>;

        static bandersnatch_ring_commitment_t _ring_commitment(const validators_data_t<CONFIG> &);
        static validators_data_t<CONFIG> _capital_phi(const validators_data_t<CONFIG> &iota, const offenders_mark_t &psi_o);
        static keys_t<CONFIG> _fallback_key_sequence(const entropy_t &entropy, const validators_data_t<CONFIG> &kappa);
        static tickets_t<CONFIG> _permute_tickets(const tickets_accumulator_t<CONFIG> &gamma_a);
        static guarantor_assignments_t _guarantor_assignments(const entropy_t &e, const time_slot_t<CONFIG> &slot);

        delta_plus_result_t<CONFIG> accumulate_plus(time_slot_t<CONFIG> slot, gas_t gas_limit, const work_reports_t<CONFIG> &reports);
        delta_star_result_t<CONFIG> accumulate_star(time_slot_t<CONFIG> slot, std::span<const work_report_t<CONFIG>> reports);
        accumulate_result_t<CONFIG> invoke_accumulate(time_slot_t<CONFIG> slot, service_id_t service_id, const accumulate_operands_t &ops);
        gas_t invoke_on_transfer(time_slot_t<CONFIG> slot, service_id_t service_id, const deferred_transfer_ptrs_t &transfers);
    };
}
