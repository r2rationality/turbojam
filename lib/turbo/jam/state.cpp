/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <algorithm>
#include <ark-vrf.hpp>
#include <numeric>
#include <turbo/crypto/blake2b.hpp>
#include <turbo/crypto/ed25519.hpp>
#include <turbo/crypto/keccak.hpp>
#include <turbo/jam/shuffle.hpp>
#include <turbo/jam/host-service.hpp>
#include "types/errors.hpp"
#include "state.hpp"

namespace turbo::jam {
    template<typename CFG>
    header_t<CFG> state_t<CFG>::make_genesis_header() const
    {
        // Genesis Block Header expectations from here: https://docs.jamcha.in/basics/genesis-config
        header_t<CFG> h {};
        h.epoch_mark.emplace(
            this->eta.get()[1],
            this->eta.get()[2],
            this->gamma.get().k
        );
        h.author_index = 0xFFFFU;
        return h;
    }

    // Safrole-related state methods
    struct ark_vrf_initialier_t {
        explicit ark_vrf_initialier_t() {
            if (ark_vrf::init(file::install_path("data/zcash-srs-2-11-uncompressed.bin")) != 0) [[unlikely]]
                throw error("ark_vrf_cpp::init() failed");;
        }

        static void init()
        {
            static ark_vrf_initialier_t initializer{};
        }
    };

    template<typename CFG>
    bandersnatch_ring_commitment_t state_t<CFG>::_ring_commitment(const validators_data_t<CFG> &gamma_k)
    {
        ark_vrf_initialier_t::init();
        std::array<bandersnatch_public_t, CFG::V_validator_count> vkeys;
        for (size_t i = 0; i < vkeys.size(); ++i) {
            vkeys[i] = gamma_k[i].bandersnatch;
        }
        bandersnatch_ring_commitment_t res;
        if (ark_vrf::ring_commitment(res, buffer { reinterpret_cast<const uint8_t *>(vkeys.data()), sizeof(vkeys) }) != 0) [[unlikely]]
            throw error("failed to generate a ring commitment!");
        return res;
    }

    // (6.26)
    template<typename CFG>
    keys_t<CFG> state_t<CFG>::_fallback_key_sequence(const entropy_t &entropy, const validators_data_t<CFG> &kappa)
    {
        static_assert(std::endian::native == std::endian::little);
        keys_t<CFG> res;
        byte_array<sizeof(entropy) + sizeof(uint32_t)> preimage;
        memcpy(preimage.data(), entropy.data(), entropy.size());
        uint32_t &i = *reinterpret_cast<uint32_t *>(preimage.data() + entropy.size());
        for (i = 0; i < res.size(); ++i) {
            const auto h = crypto::blake2b::digest(preimage);
            const auto next_k = *reinterpret_cast<const uint32_t *>(h.data()) % kappa.size();
            res[i] = kappa[next_k].bandersnatch;
        }
        return res;
    }

    // (6.25): Z
    template<typename CFG>
    tickets_t<CFG> state_t<CFG>::_permute_tickets(const tickets_accumulator_t<CFG> &gamma_a)
    {
        tickets_t<CFG> tickets;
        if (gamma_a.empty() || gamma_a.size() % 2) [[unlikely]]
            throw error(fmt::format("gamma.a size cannot be 0 or odd but got: {}", gamma_a.size()));
        if (gamma_a.size() != tickets.size()) [[unlikely]]
            throw error(fmt::format("unexpected size of gamma.a: got: {} expected: {}", gamma_a.size(), tickets.size()));
        auto left = gamma_a.begin();
        auto right = std::prev(gamma_a.end());
        for (size_t i = 0; i < tickets.size(); ++i) {
            tickets[i] = i & 1U ? *right-- : *left++;
        }
        return tickets;
    }

    // (6.14)
    template<typename CFG>
    validators_data_t<CFG> state_t<CFG>::_capital_phi(const validators_data_t<CFG> &iota, const offenders_mark_t &psi_o)
    {
        validators_data_t<CFG> res;
        for (size_t i = 0; i < iota.size(); ++i) {
            const auto &v = iota[i];
            res[i] = psi_o.contains(v.ed25519) ? validator_data_t{} : v;
        }
        return res;
    }

    template<typename CFG>
    safrole_output_data_t<CFG> state_t<CFG>::update_safrole(
        const entropy_buffer_t &new_eta, const ed25519_keys_set_t &new_offenders,
        const time_slot_t<CFG> &prev_tau, const safrole_state_t<CFG> &prev_gamma,
        const std::shared_ptr<validators_data_t<CFG>> &prev_kappa_ptr, const std::shared_ptr<validators_data_t<CFG>> &prev_lambda_ptr,
        const validators_data_t<CFG> &prev_iota,
        const time_slot_t<CFG> &slot, const tickets_extrinsic_t<CFG> &extrinsic)
    {
        if (slot.epoch_slot() >= CFG::Y_ticket_submission_end && !extrinsic.empty()) [[unlikely]]
            throw err_unexpected_ticket_t {};

        safrole_output_data_t<CFG> res {
            std::make_shared<safrole_state_t<CFG>>(prev_gamma)
        };

        // Epoch transition
        if (slot.epoch() > prev_tau.epoch()) [[unlikely]] {
            // JAM Paper (6.13)
            res.lambda_ptr = std::make_shared<validators_data_t<CFG>>(*prev_kappa_ptr);
            res.kappa_ptr = std::make_shared<validators_data_t<CFG>>(res.gamma_ptr->k);
            res.gamma_ptr->k = _capital_phi(prev_iota, new_offenders);
            if (!std::holds_alternative<tickets_t<CFG>>(prev_gamma.s) || res.gamma_ptr->k != prev_gamma.k)
                res.gamma_ptr->z = _ring_commitment(res.gamma_ptr->k);
            // JAM Paper (6.27) - epoch marker
            res.epoch_mark.emplace(new_eta[1], new_eta[2]);
            for (size_t ki = 0; ki < res.gamma_ptr->k.size(); ++ki) {
                res.epoch_mark->validators[ki].bandersnatch = res.gamma_ptr->k[ki].bandersnatch;
                res.epoch_mark->validators[ki].ed25519 = res.gamma_ptr->k[ki].ed25519;
            }
        } else {
            res.kappa_ptr = prev_kappa_ptr;
            res.lambda_ptr = prev_lambda_ptr;
        }

        // JAM (6.24)
        if (slot.epoch() == prev_tau.epoch() + 1
                && prev_tau.epoch_slot() >= CFG::Y_ticket_submission_end
                && res.gamma_ptr->a.size() == CFG::E_epoch_length) {
            res.gamma_ptr->s = _permute_tickets(res.gamma_ptr->a);
        } else if (slot.epoch() != prev_tau.epoch()) {
            // since the update operates on a copy of the state
            // eta[2] and kappa are the updated "prime" values
            res.gamma_ptr->s = _fallback_key_sequence(new_eta[2], *res.kappa_ptr);
        }

        if (slot.epoch() > prev_tau.epoch()) [[unlikely]] {
            // JAM Paper (6.34)
            res.gamma_ptr->a.clear();
        }

        // JAM Paper (6.28) - winning-tickets marker
        if (slot.epoch() == prev_tau.epoch()
                && prev_tau.epoch_slot() < CFG::Y_ticket_submission_end
                && slot.epoch_slot() >= CFG::Y_ticket_submission_end && res.gamma_ptr->a.size() == CFG::E_epoch_length) {
            res.tickets_mark.emplace(_permute_tickets(res.gamma_ptr->a));
        }

        std::optional<ticket_body_t> prev_ticket {};

        if (!extrinsic.empty()) {
            // (6.34)
            for (const auto &t: extrinsic) {
                if (t.attempt >= CFG::N_ticket_attempts) [[unlikely]]
                    throw err_bad_ticket_attempt_t {};
            }

            static const uint8_vector aux{};
            static constexpr std::string_view input_prefix{"jam_ticket_seal"};
            static constexpr size_t input_size = input_prefix.size() + sizeof(new_eta[2]) + 1U;
            static_assert(input_size == 48U);
            byte_array<input_size> input;
            memcpy(input.data(), input_prefix.data(), input_prefix.size());
            for (const auto &t: extrinsic) {
                memcpy(input.data() + input_prefix.size(), new_eta[2].data(), new_eta[2].size());
                input[input_prefix.size() + new_eta[2].size()] = t.attempt;

                ticket_body_t tb;
                tb.attempt = t.attempt;
                if (ark_vrf::ring_vrf_output(tb.id, t.signature) != 0) [[unlikely]]
                    throw err_bad_ticket_proof_t {};
                if (prev_ticket && *prev_ticket >= tb) [[unlikely]]
                    throw err_bad_ticket_order_t {};
                prev_ticket = tb;
                const auto it = std::lower_bound(res.gamma_ptr->a.begin(), res.gamma_ptr->a.end(), tb);
                if (it != res.gamma_ptr->a.end() && *it == tb) [[unlikely]]
                    throw err_duplicate_ticket_t {};
                if (ark_vrf::ring_vrf_verify(CFG::V_validator_count, res.gamma_ptr->z, t.signature, input, aux) != 0) [[unlikely]]
                    throw err_bad_ticket_proof_t {};
                res.gamma_ptr->a.insert(it, std::move(tb));
            }
        }
        if (res.gamma_ptr->a.size() > res.gamma_ptr->a.max_size)
            res.gamma_ptr->a.resize(res.gamma_ptr->a.max_size);

        return res;
    }

    // End of Safrole-related state methods

    template<typename CFG>
    account_updates_t<CFG> state_t<CFG>::provide_preimages(services_statistics_t &new_pi_services,
        const accounts_t<CFG> &new_delta, const time_slot_t<CFG> &slot, const preimages_extrinsic_t &preimages)
    {
        account_updates_t<CFG> accs{new_delta};
        const preimage_t *prev = nullptr;
        for (const auto &p: preimages) {
            if (prev && *prev >= p) [[unlikely]]
                throw err_preimages_not_sorted_or_unique_t {};
            prev = &p;
            const auto info = accs.info_get(p.requester);
            if (!info) [[unlikely]]
                throw err_bad_service_id_t{};
            const lookup_meta_map_key_t key{crypto::blake2b::digest<opaque_hash_t>(p.blob), static_cast<uint32_t>(p.blob.size())};
            auto l_val = accs.lookup_get(p.requester, key);
            if (!l_val) [[unlikely]]
                throw err_preimage_unneeded_t {};
            if (accs.preimage_get(p.requester, key.hash)) [[unlikely]]
                throw err_preimage_unneeded_t {};
            accs.preimage_set(p.requester, key.hash, uint8_vector{p.blob});
            l_val->emplace_back(slot);
            accs.lookup_set(p.requester, key, std::move(*l_val));
            auto &service_stats = new_pi_services[p.requester];
            ++service_stats.provided_count;
            service_stats.provided_size += p.blob.size();
        }
        return accs;
    }

    template<typename CFG>
    entropy_buffer_t state_t<CFG>::eta_prime(const time_slot_t<CFG> &prev_tau, const entropy_buffer_t &prev_eta,
        const time_slot_t<CFG> &blk_slot, const entropy_t &blk_entropy)
    {
        auto new_eta = prev_eta;
        if (blk_slot.epoch() > prev_tau.epoch()) [[unlikely]] {
            // JAM Paper (6.23)
            new_eta[3] = prev_eta[2];
            new_eta[2] = prev_eta[1];
            new_eta[1] = prev_eta[0];
        }
        byte_array<sizeof(prev_eta[0]) + sizeof(blk_entropy)> eta_preimage;
        memcpy(eta_preimage.data(), prev_eta[0].data(), prev_eta[0].size());
        memcpy(eta_preimage.data() + prev_eta[0].size(), blk_entropy.data(), blk_entropy.size());
        crypto::blake2b::digest(new_eta[0], eta_preimage);
        return new_eta;
    }

    template<typename CFG>
    void state_t<CFG>::pi_prime(validators_statistics_t<CFG> &new_pi_current, validators_statistics_t<CFG> &new_pi_last,
        const reports_output_data_t &reports_res, const validators_data_t<CFG> &new_kappa, const time_slot_t<CFG> &prev_tau,
        const time_slot_t<CFG> &slot, validator_index_t val_idx, const extrinsic_t<CFG> &extrinsic)
    {
        if (slot.epoch() > prev_tau.epoch()) {
            new_pi_last = new_pi_current;
            new_pi_current = {};
        }
        if (val_idx >= CFG::V_validator_count) [[unlikely]]
            throw err_bad_validator_index_t{};
        auto &stats = new_pi_current.at(val_idx);
        ++stats.blocks;
        stats.tickets += extrinsic.tickets.size();
        stats.pre_images += extrinsic.preimages.size();
        for (const auto &p: extrinsic.preimages) {
            stats.pre_images_size += p.blob.size();
        }
        for (size_t vi = 0; vi < new_pi_current.size(); ++vi) {
            if (reports_res.reporters.contains(new_kappa[vi].ed25519))
                ++new_pi_current[vi].guarantees;
        }
        for (const auto &a: extrinsic.assurances) {
            ++new_pi_current.at(a.validator_index).assurances;
        }
    }

    template<typename CFG>
    state_t<CFG>::guarantor_assignments_t state_t<CFG>::_guarantor_assignments(const entropy_t &e, const time_slot_t<CFG> &slot)
    {
        guarantor_assignments_t in;
        for (size_t vi = 0; vi < in.size(); ++vi) {
            in[vi] = CFG::C_core_count * vi / CFG::V_validator_count;
        }
        auto res = shuffle::with_entropy(in, e);
        const auto shift = slot.epoch_slot() / CFG::R_core_assignment_rotation_period;
        for (size_t vi = 0; vi < res.size(); ++vi) {
            res[vi] = (res[vi] + shift) % CFG::C_core_count;
        }
        return res;
    }

    template<typename CFG>
    state_t<CFG>::guarantors_t state_t<CFG>::_guarantors(const entropy_buffer_t &eta,
        const validators_data_t<CFG> &kappa, const validators_data_t<CFG> &lambda,
        const offenders_mark_t &psi, const time_slot_t<CFG> &g_slot, const time_slot_t<CFG> &blk_slot)
    {
        const auto same_rotation = g_slot.slot() / CFG::R_core_assignment_rotation_period == blk_slot.slot() / CFG::R_core_assignment_rotation_period;
        if (same_rotation)
            return {_guarantor_assignments(eta[2], blk_slot), _capital_phi(kappa, psi)};
        const auto base_slot = blk_slot.slot() - CFG::R_core_assignment_rotation_period;
        const auto same_epoch = base_slot / CFG::E_epoch_length == blk_slot.slot() / CFG::E_epoch_length;
        const auto &e = same_epoch ? eta[2] : eta[3];
        const auto &k = same_epoch ? kappa : lambda;
        return {_guarantor_assignments(e, base_slot), _capital_phi(k, psi)};
    }

    // JAM (12.7) - E: remove packages and update dependencies
    template<typename CFG>
    static void accumulate_update_deps(ready_queue_item_t<CFG> &queue, const set_t<work_package_hash_t> &known_reports, const std::optional<std::function<void(const work_report_t<CFG> &)>> &on_empty_deps={})
    {
        set_t<work_package_hash_t> ready {};
        for (auto q_it = queue.begin(); q_it != queue.end();) {
            if (!known_reports.contains(q_it->report.package_spec.hash)) {
                for (auto d_it = q_it->dependencies.begin(); d_it != q_it->dependencies.end();) {
                    if (known_reports.contains(*d_it)) {
                        d_it = q_it->dependencies.erase(d_it);
                    } else {
                        ++d_it;
                    }
                }
                if (q_it->dependencies.empty() && on_empty_deps) {
                    ready.emplace(q_it->report.package_spec.hash);
                    (*on_empty_deps)(q_it->report);
                }
                ++q_it;
            } else {
                q_it = queue.erase(q_it);
            }
        }
        if (!ready.empty())
            accumulate_update_deps<CFG>(queue, ready, on_empty_deps);
    }

    // JAM (12.16)
    template<typename CFG>
    delta_plus_result_t<CFG> state_t<CFG>::accumulate_plus(
        const entropy_t &new_eta0,
        const accounts_t<CFG> &prev_delta, const privileges_t<CFG> &prev_chi,
        const time_slot_t<CFG> &slot, const gas_t gas_limit, const work_reports_t<CFG> &reports)
    {
        delta_plus_result_t<CFG> res{{prev_delta, prev_chi}};

        if (!reports.empty()) {
            size_t num_ok = 0;
            gas_t total_gas = 0;
            for (const auto &r: reports) {
                for (const auto &rr: r.results)
                    total_gas += rr.accumulate_gas;
                if (total_gas > gas_limit)
                    break;
                ++num_ok;
            }

            res.consume_from(accumulate_star(new_eta0, prev_delta, prev_chi, slot, std::span { reports.data(), num_ok }));
        }
        return res;
    }

    // JAM (12.17)
    template<typename CFG>
    delta_star_result_t<CFG> state_t<CFG>::accumulate_star(
        const entropy_t &new_eta0,
        const accounts_t<CFG> &prev_delta, const privileges_t<CFG> &prev_chi,
        const time_slot_t<CFG> &slot, const std::span<const work_report_t<CFG>> reports)
    {
        accumulate_service_operands_t service_ops {};
        for (const auto &r: reports) {
            for (const auto &r_res: r.results) {
                service_ops[r_res.service_id].emplace_back(
                    accumulate_operand_t {
                        .work_package_hash=r.package_spec.hash,
                        .exports_root=r.package_spec.exports_root,
                        .authorizer_hash=r.authorizer_hash,
                        .payload_hash=r_res.payload_hash,
                        .accumulate_gas=r_res.accumulate_gas,
                        .result=r_res.result,
                        .auth_output=r.auth_output
                    }
                );
            }
        }

        // JAM (12.17) - Ensure that free services are always accumulated
        for (const auto &fs: prev_chi.always_acc)
            service_ops.try_emplace(fs.id);

        delta_star_result_t<CFG> res {};
        for (const auto &[service_id, ops]: service_ops) {
            auto acc_res = invoke_accumulate(new_eta0, prev_delta, prev_chi, slot, service_id, ops);
            if (acc_res.num_reports) {
                res.num_accumulated += acc_res.num_reports;
                res.results.try_emplace(service_id, std::move(acc_res));
            }
        }

        return res;
    }

    template<typename CFG>
    accumulate_result_t<CFG> state_t<CFG>::invoke_accumulate(
        const entropy_t &new_eta0,
        const accounts_t<CFG> &prev_delta, const privileges_t<CFG> &prev_chi,
        const time_slot_t<CFG> &slot,
        const service_id_t service_id, const accumulate_operands_t &ops)
    {
        encoder arg_enc {};
        arg_enc.uint_varlen(slot.slot());
        arg_enc.uint_varlen(service_id);
        arg_enc.process(ops);

        accumulate_context_t<CFG> ctx_err {
            service_id, new_eta0, slot,
            { prev_delta, prev_chi },
        };
        auto ctx_ok = ctx_err;

        const auto prev_service_info = prev_delta.info_get_or_throw(service_id);
        const auto code = prev_delta.preimage_get(service_id, prev_service_info.code_hash);
        if (!code) [[unlikely]] {
            logger::warn("service {} accumulate: preimage for code hash {} is not available!", service_id, prev_service_info.code_hash);
        } else if (code->size() > CFG::WC_max_service_code_size) [[unlikely]] {
            logger::warn("service {} accumulate: preimage for code hash {} is too large!", service_id, prev_service_info.code_hash);
        } else [[likely]] {
            const auto code_hash = crypto::blake2b::digest(*code);
            if (code_hash != prev_service_info.code_hash) [[unlikely]]
                throw error(fmt::format("the blob registered for code hash {} has hash {}", prev_service_info.code_hash, code_hash));
            gas_t::base_type gas_limit = 0;
            for (const auto &fs: prev_chi.always_acc) {
                if (fs.id == service_id)
                    gas_limit += fs.gas;
            }
            for (const auto &op: ops)
                gas_limit += op.accumulate_gas;

            std::optional<host_service_accumulate_t<CFG>> host_service{};
            // JAM (B.9): bold psi_a
            const auto inv_res = machine::invoke(
                static_cast<buffer>(*code), 5U, gas_limit, arg_enc.bytes(),
                [&](machine::machine_t &m) {
                    host_service.emplace(
                        host_service_params_t<CFG>{
                            .m=m,
                            .services=ctx_ok.state.services,
                            .service_id=service_id,
                            .slot=slot,
                            .fetch={
                                .nonce=&new_eta0,
                                .operands=&ops
                            }
                        },
                        ctx_ok,
                        ctx_err
                    );
                },
                [&](const machine::register_val_t id) -> machine::host_call_res_t {
                    if (!host_service) [[unlikely]]
                        return machine::exit_panic_t{};
                    return host_service->call(id);
                }
            );
            // (B.13)
            auto &ctx = std::holds_alternative<uint8_vector>(inv_res.result) ? ctx_ok : ctx_err;
            auto res = ctx.result;
            if (std::holds_alternative<uint8_vector>(inv_res.result)) {
                const auto &res_bytes = std::get<uint8_vector>(inv_res.result);
                if (res_bytes.size() == sizeof(opaque_hash_t))
                    res.emplace(res_bytes);
            }
            return {
                std::move(ctx.state),
                std::move(ctx.transfers),
                res,
                inv_res.gas_used,
                ops.size()
            };
        }
        return {
            std::move(ctx_err.state),
            std::move(ctx_err.transfers),
            ctx_err.result,
            0,
            ops.size()
        };
    }

    template<typename CFG>
    gas_t state_t<CFG>::invoke_on_transfer(
        const entropy_t &new_eta0, account_updates_t<CFG> &new_delta,
        time_slot_t<CFG> slot, service_id_t service_id, const deferred_transfers_t<CFG> &transfers)
    {
        auto service_info = new_delta.info_get_or_throw(service_id);
        const auto amount = std::ranges::fold_left(
            transfers | std::views::transform(&deferred_transfer_t<CFG>::amount),
            balance_t{0},
            std::plus()
        );
        service_info.balance += amount;
        auto code = new_delta.preimage_get(service_id, service_info.code_hash);
        if (!code) [[unlikely]] {
            logger::warn("service {} on_transfer: preimage for code hash {} is not available!", service_id, service_info.code_hash);
        } else if (code->size() > CFG::WC_max_service_code_size) [[unlikely]] {
            logger::warn("service {} on_transfer: preimage for code hash {} is too large!", service_id, service_info.code_hash);
        } else [[likely]] {
            if (const auto code_hash = crypto::blake2b::digest(*code); code_hash != service_info.code_hash) [[unlikely]]
            throw error(fmt::format("the blob registered for code hash {} has hash {}", service_info.code_hash, code_hash));
            gas_t::base_type gas_limit = 0;
            std::optional<host_service_on_transfer_t<CFG>> host_service{};
            const auto inv_res = machine::invoke(
                static_cast<buffer>(*code), 10U, gas_limit, buffer{},
                [&](machine::machine_t &m) {
                    host_service.emplace(
                        host_service_params_t<CFG>{
                            .m=m,
                            .services=new_delta,
                            .service_id=service_id,
                            .slot=slot,
                            .fetch={
                                .nonce=&new_eta0,
                                .transfers=&transfers
                            }
                        }
                    );
                },
                [&](const machine::register_val_t id) -> machine::host_call_res_t {
                    if (!host_service) [[unlikely]]
                        return machine::exit_panic_t{};
                    return host_service->call(id);
                }
            );
            return inv_res.gas_used;
        }
        new_delta.info_set(service_id, std::move(service_info));
        return {};
    }

    // produces: accumulate_root, iota', psi' and chi'
    template<typename CFG>
    accumulate_output_t<CFG> state_t<CFG>::accumulate(
        services_statistics_t &new_pi_services, const entropy_t &new_eta0,
        const time_slot_t<CFG> &prev_tau,
        const privileges_t<CFG> &prev_chi,
        const ready_queue_t<CFG> &prev_omega, const accumulated_queue_t<CFG> &prev_ksi,
        const accounts_t<CFG> &prev_delta,
        const time_slot_t<CFG> &slot, const work_reports_t<CFG> &reports)
    {
        accumulate_output_t<CFG> res{};

        // JAM Paper (12.2)
        set_t<work_package_hash_t> known_reports {};
        for (const auto &er: prev_ksi) {
            known_reports.reserve(known_reports.size() + er.size());
            known_reports.insert_unique(er.begin(), er.end());
        }

        work_reports_t<CFG> work_immediate {}; // JAM (12.4) W^!
        ready_queue_item_t<CFG> work_queued {}; // JAM (12.5) W^Q
        work_queued.reserve(reports.size());

        for (const auto &r: reports) {
            report_deps_t deps {};
            for (const auto &h: r.context.prerequisites)
                deps.emplace_hint(deps.end(), h);
            for (const auto &l: r.segment_root_lookup)
                deps.emplace_hint(deps.end(), l.work_package_hash);
            if (deps.empty())
                work_immediate.emplace_back(r);
            else
                work_queued.emplace_back(r, std::move(deps));
        }
        accumulate_update_deps<CFG>(work_queued, known_reports);

        set_t<work_package_hash_t> immediate_hashes {};
        for (const auto &r: work_immediate)
            immediate_hashes.emplace(r.package_spec.hash);

        // JAM (12.10)
        const auto m = slot.epoch_slot();

        // (12.11) - work immediate is w_star after this point

        ready_queue_item_t<CFG> all_queued {};
        for (size_t i = 0; i < prev_omega.size(); ++i) {
            const auto nu_i = (m + i) % prev_omega.size();
            for (const auto &rr: prev_omega[nu_i])
                all_queued.emplace_back(rr);
        }
        for (const auto &rr: work_queued)
            all_queued.emplace_back(rr);
        accumulate_update_deps<CFG>(all_queued, immediate_hashes, [&](const auto &wr) {
            work_immediate.emplace_back(wr);
        });

        // (12.21)
        boost::container::flat_set<service_id_t> free_services {};
        gas_t::base_type gas_limit = CFG::GA_max_accumulate_gas * CFG::C_core_count;

        free_services.reserve(prev_chi.always_acc.size());
        for (auto &fs: prev_chi.always_acc)
            free_services.emplace_hint(free_services.end(), fs.id);

        for (const auto &re: prev_omega) {
            for (const auto &ri: re) {
                for (const auto &rr: ri.report.results) {
                    if (free_services.contains(rr.service_id))
                        gas_limit += rr.accumulate_gas;
                }
            }
        }
        if (gas_limit < CFG::GT_max_total_accumulation_gas)
            gas_limit = CFG::GT_max_total_accumulation_gas;

        // (12.22)
        auto plus_res = accumulate_plus(new_eta0, prev_delta, prev_chi, slot, gas_limit, work_immediate);

        // (12.28)
        {
            std::map<service_id_t, deferred_transfers_t<CFG>> dst_transfers{};
            for (auto &t: plus_res.transfers) {
                auto [it, created] = dst_transfers.try_emplace(t.destination);
                it->second.emplace_back(t);
            }
            for (const auto &[service_id, transfers]: dst_transfers) {
                const auto gas_used = invoke_on_transfer(new_eta0, plus_res.state.services, slot, service_id, transfers);
                auto &stats = new_pi_services[service_id];
                stats.on_transfers_count += transfers.size();
                stats.on_transfers_gas_used += gas_used;
            }
        }

        // (12.23)
        res.service_updates.emplace(std::move(plus_res.state.services));
        if (plus_res.state.chi.updated())
            plus_res.state.chi.commit(res.chi);
        if (plus_res.state.iota)
            res.iota = std::move(plus_res.state.iota);
        res.phi = std::move(plus_res.state.phi);

        // (12.24) (12.25) (12.26)
        for (const auto &[s_id, work_info]: plus_res.work_items) {
            auto &s_stats = new_pi_services[s_id];
            s_stats.accumulate_count = work_info.num_reports;
            s_stats.accumulate_gas_used = work_info.gas_used;
            auto info = res.service_updates->info_get_or_throw(s_id);
            info.last_accumulation_slot = slot;
            res.service_updates->info_set(s_id, std::move(info));
        }

        // (12.33)
        res.ksi = std::make_shared<accumulated_queue_t<CFG>>(prev_ksi);
        for (size_t i = 0; i < res.ksi->size() - 1; ++i)
            (*res.ksi)[i] = std::move((*res.ksi)[i + 1]);
        // (12.32)
        const auto work_immediate_hashes = work_immediate
            | std::views::take(plus_res.num_accumulated)
            | std::views::transform([](const auto &wr) { return wr.package_spec.hash; });
        const std::vector<work_package_hash_t> accumulated_report_hashes { work_immediate_hashes.begin(), work_immediate_hashes.end() };
        res.ksi->back().clear();
        res.ksi->back().reserve(accumulated_report_hashes.size());
        for (const auto &wrh: accumulated_report_hashes)
            res.ksi->back().emplace(wrh);

        // The actually accumulated report set can be a subset of the reports ready for accumulation due to the gas limit.
        // Therefore, the omega must be updated given the list of actually accumulated reports

        // (12.34)
        res.omega = std::make_shared<ready_queue_t<CFG>>(prev_omega);
        accumulate_update_deps((*res.omega)[m], res.ksi->back());
        const auto time_step = slot.slot() - prev_tau.slot();
        for (size_t i = 0; i < res.omega->size(); ++i) {
            const auto nu_i = (m + res.omega->size() - i) % res.omega->size();
            if (i == 0) {
                (*res.omega)[nu_i] = std::move(work_queued);
            } else if (i >= 1 && i < time_step) {
                (*res.omega)[nu_i].clear();
            }
            accumulate_update_deps((*res.omega)[nu_i], res.ksi->back());
        }

        // (7.3)
        logger::trace("accumulate commitments: {}", plus_res.commitments);
        if (!plus_res.commitments.empty()) {
            std::vector<merkle::hash_t> nodes {};
            nodes.reserve(plus_res.commitments.size());
            for (const auto &[s_id, s_hash]: plus_res.commitments) {
                encoder enc {};
                enc.uint_fixed(4, s_id);
                enc.next_bytes(s_hash);
                nodes.emplace_back(crypto::keccak::digest(enc.bytes()));
            }
            res.root = merkle::binary::encode_keccak(nodes);
            res.theta = std::move(plus_res.commitments);
        }
        return res;
    }

    template<typename CFG>
    time_slot_t<CFG> state_t<CFG>::tau_prime(const time_slot_t<CFG> &prev_tau, const time_slot_t<CFG> &blk_slot)
    {
        if (blk_slot <= prev_tau || blk_slot > time_slot_t<CFG>::current()) [[unlikely]]
            throw err_bad_slot_t {};
        // JAM (6.1)
        return blk_slot;
    }

    template<typename CFG>
    reports_output_data_t state_t<CFG>::update_reports(
        availability_assignments_t<CFG> &tmp_rho,
        cores_statistics_t<CFG> &new_pi_cores,
        services_statistics_t &new_pi_services,
        const blocks_history_t<CFG> &tmp_beta,
        const entropy_buffer_t &new_eta, const ed25519_keys_set_t &new_offenders,
        const validators_data_t<CFG> &new_kappa, const validators_data_t<CFG> &new_lambda,
        const auth_pools_t<CFG> &prev_alpha,
        const accounts_t<CFG> &prev_delta,
        const time_slot_t<CFG> &slot, const guarantees_extrinsic_t<CFG> &guarantees)
    {
        reports_output_data_t res {};

        if (!guarantees.empty()) {
            std::set<opaque_hash_t> known_packages {};
            std::set<opaque_hash_t> known_segment_roots {};
            for (const auto &blk: tmp_beta) {
                for (const auto &wr: blk.reported) {
                    known_packages.insert(wr.hash);
                    known_segment_roots.insert(wr.exports_root);
                }
            }

            std::set<opaque_hash_t> wp_hashes {};
            for (const auto &g: guarantees) {
                wp_hashes.emplace(g.report.package_spec.hash);
                known_segment_roots.insert(g.report.package_spec.exports_root);
            }

            std::optional<core_index_t> prev_core {};

            for (const auto &g: guarantees) {
                // JAM Paper (11.33)
                const auto blk_it = std::find_if(tmp_beta.begin(), tmp_beta.end(), [&g](const auto &blk) {
                    return blk.header_hash == g.report.context.anchor;
                });
                if (blk_it == tmp_beta.end()) [[unlikely]]
                    throw err_anchor_not_recent_t {};
                if (blk_it->state_root != g.report.context.state_root) [[unlikely]]
                    throw err_bad_state_root_t {};
                if (blk_it->beefy_root != g.report.context.beefy_root) [[unlikely]]
                    throw err_bad_beefy_mmr_root_t {};
                if (g.report.core_index >= tmp_rho.size()) [[unlikely]]
                    throw err_bad_core_index_t {};
                // (11.24)
                if (prev_core && *prev_core >= g.report.core_index) [[unlikely]]
                    throw err_out_of_order_guarantee_t {};
                // JAM (11.3)
                if (g.report.segment_root_lookup.size() + g.report.context.prerequisites.size() > CFG::J_max_report_dependencies) [[unlikely]]
                    throw err_too_many_dependencies_t {};
                prev_core = g.report.core_index;
                if (g.slot > slot) [[unlikely]]
                    throw err_future_report_slot_t {};
                {
                    static_assert(CFG::E_epoch_length % CFG::R_core_assignment_rotation_period == 0);
                    const auto current_rotation = slot.slot() / CFG::R_core_assignment_rotation_period;
                    const auto report_rotation = g.slot.slot() / CFG::R_core_assignment_rotation_period;
                    if (current_rotation - report_rotation >= 2) [[unlikely]]
                        throw err_report_epoch_before_last_t {};
                }

                const auto guarantors = _guarantors(new_eta, new_kappa, new_lambda, new_offenders, g.slot, slot);

                // JAM Paper (11.34)
                if (g.report.context.lookup_anchor_slot.slot() + CFG::L_max_lookup_anchor_age < slot) [[unlikely]]
                    throw err_segment_root_lookup_invalid_t {};

                // JAM Paper (11.35)
                /*const auto lblk_it = std::find_if(tmp_beta.begin(), tmp_beta.end(), [&g](const auto &blk) {
                    return blk.header_hash == g.report.context.lookup_anchor;
                });
                if (lblk_it == tmp_beta.end()) [[unlikely]]
                    throw err_segment_root_lookup_invalid_t {};*/

                // JAM Paper (11.38)
                if (known_packages.contains(g.report.package_spec.hash)) [[unlikely]]
                    throw err_duplicate_package_t {};
                // + add a check that the package is not in the accumulation queue
                // + add a check that the package is not in the accumulation history

                // JAM Paper (11.3)
                if (g.report.context.prerequisites.size() + g.report.segment_root_lookup.size() > CFG::J_max_report_dependencies) [[unlikely]]
                    throw err_too_many_dependencies_t {};

                // circular dependencies are allowed
                for (const auto &pr: g.report.context.prerequisites) {
                    if (!known_packages.contains(pr) && !wp_hashes.contains(pr)) [[unlikely]]
                        throw err_dependency_missing_t {};
                }

                for (const auto &s: g.report.segment_root_lookup) {
                    if (!known_packages.contains(s.work_package_hash) && !wp_hashes.contains(s.work_package_hash)) [[unlikely]]
                        throw err_segment_root_lookup_invalid_t {};
                    if (!known_segment_roots.contains(s.segment_tree_root)) [[unlikely]]
                        throw err_segment_root_lookup_invalid_t {};
                }

                // JAM Paper: (11.29)
                {
                    if (tmp_rho[g.report.core_index])
                        throw err_core_engaged_t {};
                    const auto &auth_pool = prev_alpha[g.report.core_index];
                    const auto auth_it = std::find(auth_pool.begin(), auth_pool.end(), g.report.authorizer_hash);
                    if (auth_it == auth_pool.end()) [[unlikely]]
                        throw err_core_unauthorized_t {};
                }

                tmp_rho[g.report.core_index] = availability_assignment_t<CFG> {
                    .report=g.report, .timeout=slot.slot()
                };
                res.reported.emplace_back(g.report.package_spec.hash, g.report.package_spec.exports_root);

                uint8_vector msg{CFG::jam_guarantee};
                {
                    encoder enc{g.report};
                    msg << crypto::blake2b::digest(enc.bytes());
                }
                std::optional<validator_index_t> prev_validator {};
                for (const auto &s: g.signatures) {
                    if (s.validator_index >= new_kappa.size()) [[unlikely]]
                        throw err_bad_validator_index_t {};

                    // JAM Paper (11.25)
                    if (prev_validator && *prev_validator >= s.validator_index) [[unlikely]]
                        throw err_not_sorted_or_unique_guarantors_t {};
                    prev_validator = s.validator_index;

                    if (guarantors.guarantors[s.validator_index] != g.report.core_index) [[unlikely]]
                        throw err_wrong_assignment_t {};

                    const auto &vk = guarantors.validators[s.validator_index].ed25519;
                    static const ed25519_public_t offender_vk{};
                    if (vk == offender_vk) [[unlikely]]
                        throw err_banned_validator_t{};

                    if (!crypto::ed25519::verify(s.signature, msg, vk)) [[unlikely]]
                        throw err_bad_signature_t {};
                    res.reporters.emplace(vk);
                }

                // (11.23)
                // No need to check for g.signatures.size() > validators per core
                // since core assignment check won't pass in that case
                if (g.signatures.size() < CFG::min_guarantors) [[unlikely]]
                    throw err_insufficient_guarantees_t {};

                size_t blobs_size = g.report.auth_output.size();
                gas_t total_accumulate_gas = 0;
                auto &core_stats = new_pi_cores[g.report.core_index];
                core_stats.bundle_size += g.report.package_spec.length;

                for (const auto &r: g.report.results) {
                    if (std::holds_alternative<work_result_ok_t>(r.result)) {
                        blobs_size += std::get<work_result_ok_t>(r.result).data.size();
                    }
                    const auto s_info = prev_delta.info_get(r.service_id);
                    if (!s_info) [[unlikely]]
                        throw err_bad_service_id_t {};
                    if (s_info->code_hash != r.code_hash) [[unlikely]]
                        throw err_bad_code_hash_t {};

                    // JAM (11.30) part 1
                    if (r.accumulate_gas < s_info->min_item_gas) [[unlikely]]
                        throw err_service_item_gas_too_low_t {};
                    total_accumulate_gas += r.accumulate_gas;

                    core_stats.gas_used += r.refine_load.gas_used;
                    core_stats.imports += r.refine_load.imports;
                    core_stats.extrinsic_count += r.refine_load.extrinsic_count;
                    core_stats.extrinsic_size += r.refine_load.extrinsic_size;
                    core_stats.exports += r.refine_load.exports;

                    auto &service_stats = new_pi_services[r.service_id];
                    ++service_stats.refinement_count;
                    service_stats.refinement_gas_used += r.refine_load.gas_used;
                    service_stats.imports += r.refine_load.imports;
                    service_stats.exports += r.refine_load.exports;
                    service_stats.extrinsic_size += r.refine_load.extrinsic_size;
                    service_stats.extrinsic_count += r.refine_load.extrinsic_count;
                }
                // JAM (11.30) part 2
                if (total_accumulate_gas > CFG::GA_max_accumulate_gas) [[unlikely]]
                    throw err_work_report_gas_too_high_t {};

                // JAM Paper (11.8)
                if (blobs_size > CFG::WR_max_blobs_size) [[unlikely]]
                    throw err_work_report_too_big_t {};
            }
            // Jam Paper (11.32)
            if (guarantees.size() != wp_hashes.size()) [[unlikely]]
                throw err_duplicate_package_t {};
            std::sort(res.reported.begin(), res.reported.end());
            std::sort(res.reporters.begin(), res.reporters.end());
        }
        return res;
    }

    template<typename CFG>
    std::shared_ptr<disputes_records_t> state_t<CFG>::psi_prime(
        offenders_mark_t &new_offenders, availability_assignments_t<CFG> &new_rho,
        const validators_data_t<CFG> &new_kappa, const validators_data_t<CFG> &new_lambda,
        const time_slot_t<CFG> &prev_tau, const std::shared_ptr<disputes_records_t> &prev_psi_ptr,
        const disputes_extrinsic_t<CFG> &disputes)
    {
        auto new_psi_ptr = prev_psi_ptr;
        new_offenders.clear();
        if (!disputes.empty()) {
            new_psi_ptr = std::make_shared<disputes_records_t>(*new_psi_ptr);
            auto &new_psi = *new_psi_ptr;
            set_t<ed25519_public_t> known_vkeys {};
            known_vkeys.reserve(new_kappa.size() + new_lambda.size());
            for (const auto &validator_set: { new_kappa, new_lambda }) {
                for (const auto &v: validator_set)
                    known_vkeys.emplace_hint_unique(known_vkeys.end(), v.ed25519);
            }

            set_t<work_report_hash_t> known_reports {};
            known_reports.reserve(new_psi.bad.size() + new_psi.good.size() + new_psi.wonky.size());
            for (const auto &report_set: { new_psi.good, new_psi.bad, new_psi.wonky }) {
                for (const auto &rh: report_set)
                    known_reports.emplace_hint_unique(known_reports.end(), rh);
            }

            uint8_vector msg {};

            // JAM (10.3)
            const auto cur_epoch = prev_tau.epoch();
            const verdict_t<CFG> *prev_verdict = nullptr;
            std::map<work_report_hash_t, size_t> report_oks {};
            for (const auto &v: disputes.verdicts) {
                if (known_reports.contains(v.target)) [[unlikely]]
                    throw err_already_judged_t {};
                if (prev_verdict && *prev_verdict >= v) [[unlikely]]
                    throw err_verdicts_not_sorted_unique_t {};
                prev_verdict = &v;
                const judgement_t *prev_judgement = nullptr;
                auto &ok_cnt = report_oks[v.target];
                for (const auto &j: v.votes) {
                    if (prev_judgement && *prev_judgement >= j) [[unlikely]]
                        throw err_judgements_not_sorted_unique_t {};
                    prev_judgement = &j;
                    msg.clear();
                    msg.reserve(v.target.size() + std::max(CFG::jam_valid.size(), CFG::jam_invalid.size()));
                    msg << static_cast<buffer>(j.vote ? CFG::jam_valid : CFG::jam_invalid);
                    msg << v.target;
                    if (v.age > cur_epoch || v.age + 1 < cur_epoch) [[unlikely]]
                        throw err_bad_judgement_age_t {};
                    const auto &validators = v.age == cur_epoch ? new_kappa : new_lambda;
                    if (j.index >= validators.size()) [[unlikely]]
                        throw err_bad_validator_index_t {};
                    const auto &val = validators[j.index];
                    if (!crypto::ed25519::verify(j.signature, msg, val.ed25519)) [[unlikely]]
                        throw err_bad_signature_t {};
                    if (j.vote)
                        ++ok_cnt;
                }
            }

            // JAM (10.5)
            std::map<work_report_hash_t, size_t> new_culprits {};
            const culprit_t *prev_culprit = nullptr;
            for (const auto &c: disputes.culprits) {
                if (known_reports.contains(c.target)) [[unlikely]]
                    throw err_already_judged_t {};
                if (!known_vkeys.contains(c.key)) [[unlikely]]
                    throw err_bad_guarantor_key_t {};
                if (prev_culprit && *prev_culprit >= c) [[unlikely]]
                    throw err_culprits_not_sorted_unique_t {};
                prev_culprit = &c;
                msg.clear();
                msg.reserve(c.target.size() + CFG::jam_guarantee.size());
                msg << static_cast<buffer>(CFG::jam_guarantee);
                msg << c.target;
                if (!crypto::ed25519::verify(c.signature, msg, c.key)) [[unlikely]]
                    throw err_bad_signature_t {};
                ++new_culprits[c.target];
                new_offenders.emplace(c.key);
            }

            // JAM (10.6)
            std::set<work_report_hash_t> new_fault_reports {};
            const fault_t *prev_fault = nullptr;
            for (const auto &f: disputes.faults) {
                if (known_reports.contains(f.target)) [[unlikely]]
                    throw err_already_judged_t {};
                if (!known_vkeys.contains(f.key)) [[unlikely]]
                    throw err_bad_auditor_key_t {};
                if (prev_fault && *prev_fault >= f) [[unlikely]]
                    throw err_faults_not_sorted_unique_t {};
                prev_fault = &f;
                msg.clear();
                const auto &verdict_prefix = f.vote ? CFG::jam_valid : CFG::jam_invalid;
                msg.reserve(f.target.size() + verdict_prefix.size());
                msg << static_cast<buffer>(verdict_prefix);
                msg << f.target;
                if (!crypto::ed25519::verify(f.signature, msg, f.key)) [[unlikely]]
                    throw err_bad_signature_t {};
                new_fault_reports.emplace(f.target);
                new_offenders.emplace(f.key);
            }

            for (const auto &[report_hash, ok_cnt]: report_oks) {
                switch (ok_cnt) {
                    case CFG::validator_super_majority:
                        // JAM (10.13)
                        if (!new_fault_reports.contains(report_hash)) [[unlikely]]
                            throw err_not_enough_faults_t {};
                        // JAM (10.16)
                        new_psi.good.emplace(report_hash);
                        continue;
                    case CFG::V_validator_count / 3:
                        // JAM (10.18)
                        new_psi.wonky.emplace(report_hash);
                        break;
                    case 0:
                        // JAM (10.14)
                        if (const auto c_it = new_culprits.find(report_hash); c_it == new_culprits.end() || c_it->second < 2)
                            throw err_not_enough_culprits_t {};
                        // JAM (10.17)
                        new_psi.bad.emplace(report_hash);
                        break;
                    [[unlikely]] default:
                        throw err_bad_vote_split_t {};
                }
            }

            for (const auto &f: disputes.faults) {
                if (new_psi.bad.contains(f.target)) {
                    if (!f.vote) [[unlikely]]
                        throw err_fault_verdict_wrong_t {};
                }
                if (new_psi.good.contains(f.target)) {
                    if (f.vote) [[unlikely]]
                        throw err_fault_verdict_wrong_t {};
                }
            }

            for (const auto &c: disputes.culprits) {
                if (!new_psi.bad.contains(c.target)) [[unlikely]]
                    throw err_culprits_verdict_not_bad_t {};
            }

            // JAM (10.15)
            for (auto &ra: new_rho) {
                if (ra) {
                    encoder enc { ra->report };
                    work_report_hash_t report_hash;
                    crypto::blake2b::digest(report_hash, enc.bytes());
                    if (const auto ok_it = report_oks.find(report_hash); ok_it != report_oks.end() && ok_it->second < CFG::validator_super_majority) [[unlikely]]
                        ra.reset();
                }
            }

            // JAM (10.19)
            for (const auto &k: new_offenders) {
                if (const auto [it, created] = new_psi.offenders.emplace_unique(k); !created) [[unlikely]]
                    throw err_offender_already_reported_t {};
            }
        }
        return new_psi_ptr;
    }

    template<typename CFG>
    recent_blocks_t<CFG> state_t<CFG>::beta_dagger(const recent_blocks_t<CFG> &prev_beta, const state_root_t &sr)
    {
        recent_blocks_t<CFG> new_beta = prev_beta;
        if (!new_beta.history.empty())
            new_beta.history.back().state_root = sr;
        return new_beta;
    }

    template<typename CFG>
    recent_blocks_t<CFG> state_t<CFG>::beta_prime(recent_blocks_t<CFG> tmp_beta, const header_hash_t &hh,
        const std::optional<opaque_hash_t> &accumulation_result, const reported_work_seq_t<CFG> &wp)
    {
        recent_blocks_t<CFG> new_beta = std::move(tmp_beta);
        if (accumulation_result)
            new_beta.mmr = new_beta.mmr.append(*accumulation_result);
        block_info_t<CFG> bi {
            .header_hash=hh,
            .beefy_root=new_beta.mmr.root(),
            .reported=wp
        };
        if (new_beta.history.size() == new_beta.history.max_size) [[likely]]
            new_beta.history.erase(new_beta.history.begin());
        new_beta.history.emplace_back(std::move(bi));
        return new_beta;
    }

    template<typename CFG>
    auth_pools_t<CFG> state_t<CFG>::alpha_prime(const time_slot_t<CFG> &slot, const core_authorizers_t &cas,
        const auth_queues_t<CFG> &new_phi, const auth_pools_t<CFG> &prev_alpha)
    {
        auth_pools_t<CFG> new_alpha = prev_alpha;
        for (const auto &ca: cas) {
            auto &pool = new_alpha.at(ca.core);
            auto pool_it = std::find(pool.begin(), pool.end(), ca.auth_hash);
            if (pool_it == pool.end()) [[unlikely]]
                throw error(fmt::format("a work report for core {} mentions an unknown auth_hash: {}", ca.core, ca.auth_hash));
            // remove the element and shift all elements after to make the final slot free
            pool.erase(pool_it);
        }

        // JAM (8.2)
        for (size_t core = 0; core < new_alpha.size(); ++core) {
            auto &pool = new_alpha.at(core);
            if (pool.size() == pool.max_size)
                pool.erase(pool.begin());
            const auto &queue = new_phi.at(core);
            pool.emplace_back(queue.at(slot.slot() % queue.size()));
        }
        return new_alpha;
    }

    // JAM (4.1): Kapital upsilon
    template<typename CFG>
    void state_t<CFG>::apply(const block_t<CFG> &blk)
    {
        // Work on a copy so that in case of errors the original state remains intact
        auto new_st = working_copy();
        // JAM (4.5) update tau
        new_st.tau.set(state_t::tau_prime(this->tau.get(), blk.header.slot));

        // core and service statistics are tracked per-block only! (13.11)
        statistics_t<CFG> new_pi{this->pi.get().current, this->pi.get().last};

        // (4.6) beta_dagger - deps match GP
        auto new_beta = beta_dagger(this->beta.get(), blk.header.parent_state_root);

        // (4.8) eta_prime - deps match GP
        new_st.eta.set(eta_prime(this->tau.get(), this->eta.get(), blk.header.slot, blk.header.entropy()));

        // (4.11) -> psi_prime - additional deps: relies on kappa', lambda' and updates_rho
        auto new_rho = this->rho.get();
        offenders_mark_t new_offenders {};
        new_st.psi.set(
            psi_prime(
                new_offenders, new_rho,
                new_st.kappa.get(), new_st.lambda.get(),
                this->tau.get(), this->psi.storage(),
                blk.extrinsic.disputes
            )
        );

        // (4.7) gamma_prime + (4.9) kappa_prime + (4.10) lambda_prime - deps match GP
        {
            const auto safrole_res = update_safrole(
                new_st.eta.get(), new_st.psi.get().offenders,
                this->tau.get(), this->gamma.get(),
                this->kappa.storage(), this->lambda.storage(),
                this->iota.get(),
                blk.header.slot, blk.extrinsic.tickets
            );
            if (safrole_res.epoch_mark != blk.header.epoch_mark) [[unlikely]]
                throw error("supplied epoch_mark does not match the computed one!");
            if (safrole_res.tickets_mark != blk.header.tickets_mark) [[unlikely]]
                throw error("supplied tickets_mark does not match the computed one!");
            new_st.gamma.set(std::move(safrole_res.gamma_ptr));
            new_st.kappa.set(std::move(safrole_res.kappa_ptr));
            new_st.lambda.set(std::move(safrole_res.lambda_ptr));
        }

        // signature verification depends on updated kappa, gamma.s and eta, so happens after update_safrole
        {
            blk.header.verify_signatures(
                new_st.kappa.get().at(blk.header.author_index).bandersnatch,
                new_st.gamma.get().s,
                new_st.eta.get()[3]
            );
        }

        // (4.13) (4.14) (4.15) - extra deps:
        // - updates pi';
        // - uses: beta_dagger, eta', psi', kappa', lambda', alpha, delta
        auto ready_reports = rho_dagger_2(
            new_rho, new_pi,
            this->tau.get().epoch() == new_st.tau.get().epoch() ? new_st.kappa.get() : new_st.lambda.get(),
            blk.header.slot, blk.header.parent, blk.extrinsic.assurances);
        // JAM (4.12)
        const auto report_res = update_reports(
            new_rho, new_pi.cores, new_pi.services,
            new_beta.history,
            new_st.eta.get(), new_st.psi.get().offenders,
            new_st.kappa.get(), new_st.lambda.get(),
            this->alpha.get(), this->delta,
            blk.header.slot, blk.extrinsic.guarantees
        );
        new_st.rho.set(std::move(new_rho));

        // (4.16) - extra deps: updates: pi
        auto accumulate_res = accumulate(
            new_pi.services,
            new_st.eta.get()[0],
            this->tau.get(),
            this->chi.get(), this->omega.get(), this->ksi.get(),
            this->delta,
            blk.header.slot, ready_reports
        );
        if (accumulate_res.ksi)
            new_st.ksi.set(std::move(accumulate_res.ksi));
        if (accumulate_res.omega)
            new_st.omega.set(std::move(accumulate_res.omega));
        if (!accumulate_res.phi.empty()) {
            auto new_phi = new_st.phi.get();
            accumulate_res.phi.commit(new_phi);
            new_st.phi.set(std::move(new_phi));
        }
        if (accumulate_res.iota)
            new_st.iota.set(std::move(accumulate_res.iota));
        if (accumulate_res.chi)
            new_st.chi.set(std::move(accumulate_res.chi));

        // (4.17)
        {
            reported_work_seq_t<CFG> reported_work {};
            reported_work.reserve(ready_reports.size());
            for (const auto &g: blk.extrinsic.guarantees) {
                reported_work.emplace_hint(reported_work.end(), g.report.package_spec.hash, g.report.package_spec.exports_root);
            }
            new_st.beta.set(state_t::beta_prime(std::move(new_beta), blk.header.hash(), accumulate_res.root, reported_work));
            new_st.theta.set(std::move(accumulate_res.theta));
        }

        // (4.18)
        {
            auto account_updates = provide_preimages(new_pi.services, new_st.delta, blk.header.slot, blk.extrinsic.preimages);
            account_updates.commit();
        }

        // (4.19): alpha' <- (H, E_G, psi', and alpha)
        {
            core_authorizers_t cas {};
            for (const auto &g: blk.extrinsic.guarantees) {
                cas.emplace_back(g.report.core_index, g.report.authorizer_hash);
            }
            new_st.alpha.set(state_t::alpha_prime(blk.header.slot, cas, new_st.phi.get(), this->alpha.get()));
        }

        // (4.20) but most updates are applied when the respective extrinsics are processed
        pi_prime(new_pi.current, new_pi.last, report_res, new_st.kappa.get(),this->tau.get(), blk.header.slot, blk.header.author_index, blk.extrinsic);
        new_st.pi.set(std::move(new_pi));

        // commit the service updates to the global key-value store only once everything else has succeeded
        if (accumulate_res.service_updates)
            accumulate_res.service_updates->commit();

        new_st.commit();
    }

    template<typename CFG>
    work_reports_t<CFG> state_t<CFG>::rho_dagger_2(
        availability_assignments_t<CFG> &new_rho, statistics_t<CFG> &tmp_pi,
        const validators_data_t<CFG> &validators,
        const time_slot_t<CFG> &slot, const header_hash_t &parent, const assurances_extrinsic_t<CFG> &assurances)
    {
        std::optional<validator_index_t> prev_validator {};
        for (const auto &a: assurances) {
            if (a.validator_index >= CFG::V_validator_count) [[unlikely]]
                throw err_bad_validator_index_t {};
            if (a.anchor != parent) [[unlikely]]
                throw err_bad_attestation_parent_t {};
            if (prev_validator && a.validator_index <= *prev_validator) [[unlikely]]
                throw err_not_sorted_or_unique_assurers {};
            prev_validator = a.validator_index;
            uint8_vector msg {};
            msg << std::string_view { "jam_available" };
            {
                encoder enc {};
                enc.bytes();
                enc.process(parent);
                enc.process(a.bitfield);
                msg << crypto::blake2b::digest(enc.bytes());
            }
            const auto &vk = validators[a.validator_index].ed25519;
            if (!crypto::ed25519::verify(a.signature, msg, vk)) [[unlikely]]
                throw err_bad_signature_t {};
            for (size_t ci = 0; ci < CFG::C_core_count; ++ci) {
                if (a.bitfield.test(ci)) {
                    if (!new_rho.at(ci)) [[unlikely]]
                        throw err_core_not_engaged_t {};
                    ++tmp_pi.cores[ci].popularity;
                }
            }
        }
        work_reports_t<CFG> res {};
        for (size_t ci = 0; ci < CFG::C_core_count; ++ci) {
            if (new_rho[ci]) {
                if (tmp_pi.cores[ci].popularity >= CFG::validator_super_majority) {
                    tmp_pi.cores[ci].da_load += new_rho[ci]->report.package_spec.length;
                    res.emplace_back(std::move(new_rho[ci]->report));
                    new_rho[ci].reset();
                } else if (slot >= new_rho[ci]->timeout + CFG::U_reported_work_timeout) {
                    new_rho[ci].reset();
                }
            }
        }
        return res;
    }

    template<typename CFG>
    void state_t<CFG>::foreach(const observer_t &obs) const
    {
        triedb().foreach([&](const auto &k, const auto &v) {
            obs(k, v);
        });
    }

    template<typename CFG>
    state_snapshot_t state_t<CFG>::snapshot() const
    {
        state_snapshot_t snap {};
        triedb().foreach([&](const auto &k, const auto &v) {
            snap.emplace(k, v);
        });
        return snap;
    }

    template<typename CFG>
    state_copy_t<CFG>::state_copy_t(state_base_t<CFG> &base_):
        state_base_t<CFG>{std::make_shared<storage::update::db_t>(base_.db)},
        base{base_}
    {
    }

    template<typename CFG>
    state_copy_t<CFG> state_t<CFG>::working_copy()
    {
        return {*this};
    }

    template<typename CFG>
    void state_copy_t<CFG>::commit()
    {
        auto &src_db = dynamic_cast<storage::update::db_t &>(*this->db);
        src_db.commit();
        base.alpha.reset();
        base.phi.reset();
        base.beta.reset();
        base.gamma.reset();
        base.psi.reset();
        base.eta.reset();
        base.iota.reset();
        base.kappa.reset();
        base.lambda.reset();
        base.rho.reset();
        base.tau.reset();
        base.chi.reset();
        base.pi.reset();
        base.omega.reset();
        base.ksi.reset();
    }

    template<typename CFG>
    bool state_t<CFG>::operator==(const state_t &o) const noexcept
    {
        return dynamic_cast<triedb::db_t &>(*this->db).root() == dynamic_cast<triedb::db_t &>(*o.db).root();
    }

    template<typename CFG>
    state_t<CFG> &state_t<CFG>::operator=(const state_snapshot_t &st)
    {
        this->db->clear();
        this->alpha.reset();
        this->phi.reset();
        this->beta.reset();
        this->gamma.reset();
        this->psi.reset();
        this->eta.reset();
        this->iota.reset();
        this->kappa.reset();
        this->lambda.reset();
        this->rho.reset();
        this->tau.reset();
        this->chi.reset();
        this->pi.reset();
        this->omega.reset();
        this->ksi.reset();
        for (const auto &[key, bytes]: st) {
            this->db->set(key, bytes);
        }
        return *this;
    }

    template<typename CFG>
    std::string state_t<CFG>::decode_val(const buffer key, const buffer val)
    {
        if (key.size() != sizeof(merkle::key_t)) [[unlikely]]
            throw error(fmt::format("Invalid key size: {} bytes while expecting {}", key.size(), sizeof(merkle::key_t)));
        const auto key_info = state_dict_t::key_info(key);
        return std::visit([&](const auto &ki) {
            using T = std::decay_t<decltype(ki)>;
            if constexpr (std::is_same_v<T, key_service_info_t>) {
                const auto info = jam::from_bytes<service_info_t<CFG>>(val);
                return fmt::format("service {} info: {}", ki.service_id, info);
            } else if constexpr (std::is_same_v<T, key_service_data_t>) {
                return fmt::format("service {} data: {} bytes", ki.service_id, val.size());
            } else if constexpr (std::is_same_v<T, key_state_var_t>) {
                switch (ki.id) {
                    case 1: return fmt::format("alpha: {}", jam::from_bytes<typename decltype(state_t::alpha)::element_type>(val));
                    case 2: return fmt::format("phi: {}", jam::from_bytes<typename decltype(state_t::phi)::element_type>(val));
                    case 3: return fmt::format("beta: {}", jam::from_bytes<typename decltype(state_t::beta)::element_type>(val));
                    case 4: return fmt::format("gamma: {}", jam::from_bytes<typename decltype(state_t::gamma)::element_type>(val));
                    case 5: return fmt::format("psi: {}", jam::from_bytes<typename decltype(state_t::psi)::element_type>(val));
                    case 6: return fmt::format("eta: {}", jam::from_bytes<typename decltype(state_t::eta)::element_type>(val));
                    case 7: return fmt::format("iota: {}", jam::from_bytes<typename decltype(state_t::iota)::element_type>(val));
                    case 8: return fmt::format("kappa: {}", jam::from_bytes<typename decltype(state_t::kappa)::element_type>(val));
                    case 9: return fmt::format("lambda: {}", jam::from_bytes<typename decltype(state_t::lambda)::element_type>(val));
                    case 10: return fmt::format("rho: {}", jam::from_bytes<typename decltype(state_t::rho)::element_type>(val));
                    case 11: return fmt::format("tau: {}", jam::from_bytes<typename decltype(state_t::tau)::element_type>(val));
                    case 12: return fmt::format("chi: {}", jam::from_bytes<typename decltype(state_t::chi)::element_type>(val));
                    case 13: return fmt::format("pi: {}", jam::from_bytes<typename decltype(state_t::pi)::element_type>(val));
                    case 14: return fmt::format("omega: {}", jam::from_bytes<typename decltype(state_t::omega)::element_type>(val));
                    case 15: return fmt::format("ksi: {}", jam::from_bytes<typename decltype(state_t::ksi)::element_type>(val));
                    case 16: return fmt::format("theta: {}", jam::from_bytes<typename decltype(state_t::theta)::element_type>(val));
                    [[unlikely]] default: return fmt::format("unknown state variable with id: {}", ki.id);
                }
            } else {
                return fmt::format("state key {} has unsupported type: {}", key, typeid(T).name());
            }
        }, key_info);
    }

    template struct state_t<config_prod>;
    template struct state_t<config_tiny>;

    template struct state_copy_t<config_prod>;
    template struct state_copy_t<config_tiny>;
}
