#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/jam/accumulate.hpp>
#include <turbo/storage/filedb.hpp>
#include "header.hpp"
#include "state-dict.hpp"

namespace turbo::jam {
    using kv_store_t = storage::filedb::client_t;
    using kv_store_ptr_t = std::shared_ptr<kv_store_t>;

    // JAM (4.4) - lowercase sigma
    template<typename CONFIG=config_prod>
    struct state_t {
        auth_pools_t<CONFIG> alpha {}; // authorizations
        blocks_history_t<CONFIG> beta {}; // most recent blocks
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

        [[nodiscard]] std::optional<std::string> diff(const state_t &o) const;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("alpha"sv, alpha);
            archive.process("beta"sv, beta);
            archive.process("gamma"sv, gamma);
            archive.process("delta"sv, delta);
            archive.process("eta"sv, eta);
            archive.process("kappa"sv, kappa);
            archive.process("lambda"sv, lambda);
            archive.process("rho"sv, rho);
            archive.process("tau"sv, tau);
            archive.process("chi"sv, chi);
            archive.process("psi"sv, psi);
            archive.process("pi"sv, pi);
            archive.process("nu"sv, nu);
            archive.process("ksi"sv, ksi);
        }

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

        // JAM (4.1): Kapital upsilon
        void apply(const block_t<CONFIG> &);
        std::exception_ptr try_apply(const block_t<CONFIG> &) noexcept;

        // Methods internally used by the apply and in unit tests
        // Todo: make them protected and the respective unit test classes friends?

        // JAM (4.5)
        void update_time(const time_slot_t<CONFIG> &slot);
        // JAM (4.6)
        void update_history_1(const state_root_t &sr);
        void update_history_2(const header_hash_t &hh, const std::optional<opaque_hash_t> &ar, const reported_work_seq_t &wp);
        // JAM (4.7)
        // JAM (4.8)
        // JAM (4.9)
        // JAM (4.10)
        safrole_output_data_t<CONFIG> update_safrole(const time_slot_t<CONFIG> &slot, const entropy_t &entropy, const tickets_extrinsic_t<CONFIG> &extrinsic);
        // JAM (4.12)
        // JAM (4.13)
        // JAM (4.14)
        // JAM (4.15)
        reports_output_data_t update_reports(const time_slot_t<CONFIG> &slot, const guarantees_extrinsic_t<CONFIG> &guarantees);
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

        kv_store_ptr_t _kv_store {};

        static bandersnatch_ring_commitment_t _ring_commitment(const validators_data_t<CONFIG> &);
        static validators_data_t<CONFIG> _capital_phi(const validators_data_t<CONFIG> &iota, const offenders_mark_t &psi_o);
        static keys_t<CONFIG> _fallback_key_sequence(const entropy_t &entropy, const validators_data_t<CONFIG> &kappa);
        static tickets_t<CONFIG> _permute_tickets(const tickets_accumulator_t<CONFIG> &gamma_a);
        static guarantor_assignments_t _guarantor_assignments(const entropy_t &e, const time_slot_t<CONFIG> &slot);

        accumulate::delta_plus_result_t<CONFIG> accumulate_plus(time_slot_t<CONFIG> slot, gas_t gas_limit, const work_reports_t<CONFIG> &reports);
        accumulate::delta_star_result_t<CONFIG> accumulate_star(time_slot_t<CONFIG> slot, std::span<const work_report_t<CONFIG>> reports);
        accumulate::result_t<CONFIG> invoke_accumulate(time_slot_t<CONFIG> slot, service_id_t service_id, const accumulate::operands_t &ops);
        gas_t invoke_on_transfer(time_slot_t<CONFIG> slot, service_id_t service_id, const accumulate::deferred_transfer_ptrs_t &transfers);
    };
}
