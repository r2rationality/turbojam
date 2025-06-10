#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/container/update-map.hpp>
#include "types/common.hpp"

namespace turbo::jam::accumulate {
    using container::update_map_t;

    template<typename CONFIG>
    struct mutable_service_state_t {
        update_map_t<preimages_t> storage;
        update_map_t<preimages_t> preimages;
        update_map_t<lookup_metas_t<CONFIG>> lookup_metas;

        void merge_from(mutable_service_state_t &&o)
        {
            storage.merge_from(std::move(o.storage));
            preimages.merge_from(std::move(o.preimages));
            lookup_metas.merge_from(std::move(o.lookup_metas));
        }

        void commit()
        {
            storage.merge();
            preimages.merge();
            lookup_metas.merge();
        }
    };

    template<typename CONFIG>
    using mutable_services_state_t = std::map<service_id_t, mutable_service_state_t<CONFIG>>;

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

        void merge_from(mutable_state_t &&o)
        {
            for (auto &&[s_id, s_state]: o.services) {
                if (auto [it, created] = services.try_emplace(s_id, std::move(s_state)); !created)
                    it->second.merge_from(std::move(s_state));
            }
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

    template<typename CONSTANTS>
    using service_code_preimages_t = map_t<service_id_t, byte_sequence_t, CONSTANTS>;

    // JAM (B.7)
    template<typename CONSTANTS>
    struct context_t {
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
    struct operand_t {
        opaque_hash_t work_package_hash;
        opaque_hash_t exports_root;
        opaque_hash_t authorizer_hash;
        byte_sequence_t auth_output;
        opaque_hash_t payload_hash;
        // gas_t accumulate_gas; gas_t is variable length, but currently the value is fixed length
        gas_t::base_type accumulate_gas;
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

        bool operator==(const operand_t &o) const
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
    using operands_t = sequence_t<operand_t>;
    using service_operands_t = std::map<service_id_t, operands_t>;

    // JAM (B.9)
    template<typename CONFIG>
    struct result_t {
        mutable_state_t<CONFIG> state;
        deferred_transfers_t transfers {};
        std::optional<opaque_hash_t> commitment {};
        gas_t gas {};
        size_t num_reports = 0;
    };
    template<typename CONFIG>
    using service_results_t = std::map<service_id_t, result_t<CONFIG>>;

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
        size_t num_accumulated = 0;
        mutable_state_t<CONFIG> state;
        deferred_transfers_t transfers {};
        service_commitments_t commitments {};
        service_work_items_t work_items {};

        void merge_from(delta_star_result_t<CONFIG> &&o)
        {
            num_accumulated += o.num_accumulated;
            for (auto &&[s_id, s_res]: o.results) {
                state.merge_from(std::move(s_res.state));
                transfers.insert(transfers.end(), s_res.transfers.begin(), s_res.transfers.end());
                // o.results is a map, so all s_id are unique. no need to check if try_emplace succeeds
                if (s_res.commitment)
                    commitments.try_emplace(s_id, *s_res.commitment);
                work_items.try_emplace(s_id, s_res.gas, s_res.num_reports);
            }
        }
    };
}
