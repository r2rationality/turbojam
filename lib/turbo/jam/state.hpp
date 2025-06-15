#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/container/update-map.hpp>
#include <turbo/storage/filedb.hpp>
#include "types/header.hpp"
#include "types/state-dict.hpp"

namespace turbo::jam {
    using kv_store_t = storage::filedb::client_t;
    using kv_store_ptr_t = std::shared_ptr<kv_store_t>;

    template<typename CONFIG>
    struct mutable_service_state_t {
        using update_value_map_t = container::update_map_t<container::std_map_update_api_t<preimages_t>>;
        using update_lookup_map_t = container::update_map_t<container::std_map_update_api_t<lookup_metas_t<CONFIG>>>;

        update_value_map_t storage;
        update_value_map_t preimages;
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
                    container::std_map_update_api_t { b_it->second.preimages },
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

    // A smart_pointer-compatible API for pure value storage
    template<typename T>
    struct value_ptr {
        using element_type = T;

        value_ptr() = default;
        value_ptr(const T& v) : _val { v } {}
        value_ptr(T&& v) : _val { std::move(v) } {}

        value_ptr(const value_ptr &o) = default;
        value_ptr(value_ptr &&o) = default;
        value_ptr& operator=(const value_ptr &o) = default;
        value_ptr& operator=(value_ptr &&o) = default;

        T& operator*() { return _val; }
        const T& operator*() const { return _val; }
        T* operator->() { return &_val; }
        const T* operator->() const { return &_val; }
    private:
        T _val {};
    };

    template<typename S>
    struct persistent_value_t {
        using element_type = typename S::element_type;
        using serialize_func_t = std::function<void(const element_type &)>;

        persistent_value_t(S storage, serialize_func_t serialize):
            _storage { std::move(storage) },
            _serialize { std::move(serialize) }
        {
        }

        const element_type &get() const
        {
            return *_storage;
        }

        void set(element_type new_val)
        {
            *_storage = std::move(new_val);
            _serialize(*_storage);
        }
    private:
        S _storage;
        serialize_func_t _serialize;
    };

    template<typename CFG>
    using block_history_val_t = persistent_value_t<std::shared_ptr<blocks_history_t<CFG>>>;

    // JAM (4.4) - lowercase sigma
    // objects that are expensive to copy are represented with std::shared_ptr
    template<typename CONFIG=config_prod>
    class state_t {
        kv_store_ptr_t _kv_store {};
        state_dict_t _state_dict {};
    public:
        auth_pools_t<CONFIG> alpha {}; // authorizations
        block_history_val_t<CONFIG> beta { // most recent blocks
            std::make_shared<blocks_history_t<CONFIG>>(),
            [this](const typename block_history_val_t<CONFIG>::element_type &new_val) {
                _state_dict.set(state_dict_t::make_key(3), encode(new_val));
            }
        };
        safrole_state_t<CONFIG> gamma {};
        accounts_t<CONFIG> delta {}; // services
        entropy_buffer_t eta {}; // JAM (6.21)
        validators_data_t<CONFIG> iota {}; // next validators JAM (6.7)
        validators_data_t<CONFIG> kappa {}; // active validators JAM (6.7)
        validators_data_t<CONFIG> lambda {}; // prev validators JAM (6.7)
        availability_assignments_t<CONFIG> rho {}; // assigned work reports
        time_slot_t<CONFIG> tau {};
        auth_queues_t<CONFIG> phi {}; // work authorizer queue
        privileges_t chi {};
        disputes_records_t psi {}; // judgements
        statistics_t<CONFIG> pi {};
        ready_queue_t<CONFIG> nu {}; // JAM (12.3): work reports ready to be accumulated
        accumulated_queue_t<CONFIG> ksi {}; // JAM (12.1): recently accumulated reports

        template<typename T>
        static byte_sequence_t encode(const T &v);

        [[nodiscard]] std::optional<std::string> diff(const state_t &o) const;

        // export & import
        state_dict_t state_dict() const;
        state_t &operator=(const state_snapshot_t &o);

        void kv_store(kv_store_ptr_t kv_store)
        {
            _kv_store = std::move(kv_store);
        }

        kv_store_t &kv_store()
        {
            if (!_kv_store) [[unlikely]]
                throw error("state_t::kv_store has not been yet configured!");
            return *_kv_store;
        }

        // (4.1): Kapital upsilon
        void apply(const block_t<CONFIG> &);
        std::exception_ptr try_apply(const block_t<CONFIG> &) noexcept;

        // Methods internally used by the apply and in unit tests
        // Todo: make them protected and the respective unit test classes friends?

        // (4.5)
        static void tau_prime(time_slot_t<CONFIG> &new_tau, const time_slot_t<CONFIG> &prev_tau, const time_slot_t<CONFIG> &blk_slot);
        // (4.6)
        static blocks_history_t<CONFIG> beta_dagger(const blocks_history_t<CONFIG> &prev_beta, const state_root_t &sr);
        // (4.17)
        static blocks_history_t<CONFIG> beta_prime(blocks_history_t<CONFIG> tmp_beta, const header_hash_t &hh, const std::optional<opaque_hash_t> &ar, const reported_work_seq_t &wp);
        // JAM (4.7)
        // JAM (4.8)
        // JAM (4.9)
        // JAM (4.10)
        safrole_output_data_t<CONFIG> update_safrole(const time_slot_t<CONFIG> &slot, const entropy_t &entropy, const tickets_extrinsic_t<CONFIG> &extrinsic);
        // JAM (4.12)
        // JAM (4.13)
        // JAM (4.14)
        // JAM (4.15)
        reports_output_data_t update_reports(const time_slot_t<CONFIG> &slot, const guarantees_extrinsic_t<CONFIG> &guarantees, const blocks_history_t<CONFIG> &prev_beta);
        // JAM (4.11)
        offenders_mark_t update_disputes(const disputes_extrinsic_t<CONFIG> &disputes);
        // JAM (4.18)
        void provide_preimages(const time_slot_t<CONFIG> &slot, const preimages_extrinsic_t &preimages);
        // JAM (4.20)
        void update_statistics(const time_slot_t<CONFIG> &slot, validator_index_t val_idx, const extrinsic_t<CONFIG> &extrinsic);
        // JAM (4.16)
        accumulate_root_t accumulate(const time_slot_t<CONFIG> &slot, const work_reports_t<CONFIG> &reports);
        // JAM (4.19)
        void update_auth_pools(const time_slot_t<CONFIG> &slot, const core_authorizers_t &cas);
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
