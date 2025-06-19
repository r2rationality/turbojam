/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <algorithm>
#include <iostream>
#include <ark-vrf-cpp.hpp>
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
    bool safrole_state_t<CFG>::operator==(const safrole_state_t &o) const noexcept
    {
        if (a != o.a)
            return false;
        if (k != o.k)
            return false;
        if (s != o.s)
            return false;
        if (z != o.z)
            return false;
        return true;
    }

    template struct safrole_state_t<config_prod>;
    template struct safrole_state_t<config_tiny>;

    template<typename CFG>
    bool state_t<CFG>::operator==(const state_t &o) const noexcept
    {
        if (alpha.get() != o.alpha.get())
            return false;
        if (beta.get() != o.beta.get())
            return false;
        if (gamma.get() != o.gamma.get())
            return false;
        if (delta != o.delta)
            return false;
        if (eta.get() != o.eta.get())
            return false;
        if (iota.get() != o.iota.get())
            return false;
        if (kappa.get() != o.kappa.get())
            return false;
        if (lambda.get() != o.lambda.get())
            return false;
        if (nu.get() != o.nu.get())
            return false;
        if (ksi.get() != o.ksi.get())
            return false;
        if (pi.get() != o.pi.get())
            return false;
        if (rho.get() != o.rho.get())
            return false;
        if (tau.get() != o.tau.get())
            return false;
        if (phi.get() != o.phi.get())
            return false;
        if (chi.get() != o.chi.get())
            return false;
        if (psi.get() != o.psi.get())
            return false;
        return true;
    }

    template<typename CFG>
    std::optional<std::string> state_t<CFG>::diff(const state_t &o) const
    {
        using namespace std::string_view_literals;
        std::string diff_text {};
        auto oit = std::back_inserter(diff_text);
        const auto compare_item = [&](const std::string_view &name, const auto &a, const auto &b) {
            if (a != b)
                oit = fmt::format_to(oit, "{} left: {}\n{} right {}\n", name, a, name, b);
        };
        compare_item("alpha"sv, alpha.get(), o.alpha.get());
        compare_item("beta"sv, beta.get(), o.beta.get());
        compare_item("gamma"sv, gamma.get(), o.gamma.get());
        compare_item("delta"sv, delta, o.delta);
        compare_item("eta"sv, eta.get(), o.eta.get());
        compare_item("iota"sv, iota.get(), o.iota.get());
        compare_item("kappa"sv, kappa.get(), o.kappa.get());
        compare_item("lambda"sv, lambda.get(), o.lambda.get());
        compare_item("nu"sv, nu.get(), o.nu.get());
        compare_item("ksi"sv, ksi.get(), o.ksi.get());
        compare_item("pi"sv, pi.get(), o.pi.get());
        compare_item("rho"sv, rho.get(), o.rho.get());
        compare_item("tau"sv, tau.get(), o.tau.get());
        compare_item("phi"sv, phi.get(), o.phi.get());
        compare_item("chi"sv, chi.get(), o.chi.get());
        compare_item("psi"sv, psi.get(), o.psi.get());
        std::optional<std::string> res {};
        if (!diff_text.empty())
            res.emplace(std::move(diff_text));
        return res;
    }

    // JAM paper (6.14)
    template<typename CFG>
    validators_data_t<CFG> state_t<CFG>::_capital_phi(const validators_data_t<CFG> &iota, const offenders_mark_t &psi_o)
    {
        validators_data_t<CFG> res;
        for (size_t i = 0; i < iota.size(); ++i) {
            const auto &v = iota[i];
            if (const auto it = std::find(psi_o.begin(), psi_o.end(), v.ed25519); it != psi_o.end()) [[unlikely]] {
                res[i] = {};
            } else {
                res[i] = v;
            }
        }
        return res;
    }

    template<typename CFG>
    bandersnatch_ring_commitment_t state_t<CFG>::_ring_commitment(const validators_data_t<CFG> &gamma_k)
    {
        static auto params_path = file::install_path("data/zcash-srs-2-11-uncompressed.bin");
        if (ark_vrf_cpp::init(params_path.data(), params_path.size()) != 0) [[unlikely]]
            throw error("ark_vrf_cpp::init() failed");
        std::array<bandersnatch_public_t, CFG::validator_count> vkeys;
        for (size_t i = 0; i < vkeys.size(); ++i) {
            vkeys[i] = gamma_k[i].bandersnatch;
        }
        bandersnatch_ring_commitment_t res;
        if (ark_vrf_cpp::ring_commitment(res.data(), res.size(), vkeys.data(), sizeof(vkeys)) != 0) [[unlikely]]
            throw error("failed to generate a ring commitment!");
        return res;
    }

    // JAM paper (6.26)
    template<typename CFG>
    keys_t<CFG> state_t<CFG>::_fallback_key_sequence(const entropy_t &entropy, const validators_data_t<CFG> &kappa)
    {
        keys_t<CFG> res;
        for (uint32_t i = 0; i < res.size(); ++i) {
            static_assert(std::endian::native == std::endian::little);
            static_assert(sizeof(i) == sizeof(uint32_t));
            byte_array<sizeof(entropy) + sizeof(uint32_t)> preimage;
            memcpy(preimage.data(), entropy.data(), entropy.size());
            memcpy(preimage.data() + entropy.size(), &i, sizeof(uint32_t));
            const auto h = crypto::blake2b::digest(preimage);
            const auto next_k = *reinterpret_cast<const uint32_t *>(h.data()) % kappa.size();
            res[i] = kappa[next_k].bandersnatch;
        }
        return res;
    }

    // JAM Paper (6.25): Z
    template<typename CFG>
    tickets_t<CFG> state_t<CFG>::_permute_tickets(const tickets_accumulator_t<CFG> &gamma_a)
    {
        tickets_t<CFG> tickets;
        for (size_t i = 0; i < tickets.size(); ++i) {
            const auto j = i / 2;
            if (i % 2 == 0) {
                tickets[i] = gamma_a[j];
            } else {
                tickets[i] = gamma_a[gamma_a.size() - (j + 1)];
            }
        }
        return tickets;
    }

    template<typename CFG>
    void state_t<CFG>::provide_preimages(statistics_t<CFG> &new_pi, const time_slot_t<CFG> &slot, const preimages_extrinsic_t &preimages)
    {
        mutable_services_state_t<CFG> mutable_services { delta };
        const preimage_t *prev = nullptr;
        for (const auto &p: preimages) {
            if (prev && *prev >= p) [[unlikely]]
                throw err_preimages_not_sorted_or_unique_t {};
            prev = &p;
            auto &service = mutable_services.get_mutable(p.requester);
            lookup_meta_map_key_t key;
            static_assert(sizeof(key.hash) == sizeof(crypto::blake2b::hash_t));
            key.length = numeric_cast<decltype(lookup_meta_map_key_t::length)>(p.blob.size());
            crypto::blake2b::digest(*reinterpret_cast<crypto::blake2b::hash_t *>(&key.hash), p.blob);
            auto l_val = service.lookup_metas.get(key);
            if (!l_val) [[unlikely]]
                throw err_preimage_unneeded_t {};
            if (service.preimages.get(key.hash)) [[unlikely]]
                throw err_preimage_unneeded_t {};
            service.preimages.set(key.hash, write_vector { p.blob });
            l_val->emplace_back(slot);
            service.lookup_metas.set(key, std::move(*l_val));
            auto &service_stats = new_pi.services[p.requester];
            ++service_stats.provided_count;
            service_stats.provided_size += p.blob.size();
        }
        mutable_services.commit(delta);
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
    safrole_output_data_t<CFG> state_t<CFG>::update_safrole(
        const time_slot_t<CFG> &prev_tau, const safrole_state_t<CFG> &prev_gamma,
        const entropy_buffer_t &new_eta,
        const std::shared_ptr<validators_data_t<CFG>> &prev_kappa_ptr, const std::shared_ptr<validators_data_t<CFG>> &prev_lambda_ptr,
        const validators_data_t<CFG> &prev_iota, const disputes_records_t &prev_psi,
        const time_slot_t<CFG> &slot, const tickets_extrinsic_t<CFG> &extrinsic)
    {
        if (slot.epoch_slot() >= CFG::ticket_submission_end && !extrinsic.empty()) [[unlikely]]
            throw err_unexpected_ticket_t {};

        safrole_output_data_t<CFG> res {
            std::make_shared<safrole_state_t<CFG>>(prev_gamma)
        };

        // Epoch transition
        if (slot.epoch() > prev_tau.epoch()) [[unlikely]] {
            // JAM Paper (6.13)
            res.lambda_ptr = std::make_shared<validators_data_t<CFG>>(*prev_kappa_ptr);
            res.kappa_ptr = std::make_shared<validators_data_t<CFG>>(res.gamma_ptr->k);
            res.gamma_ptr->k = _capital_phi(prev_iota, prev_psi.offenders);
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
        if (slot.epoch() == prev_tau.epoch() + 1 && prev_tau.epoch_slot() >= CFG::ticket_submission_end && res.gamma_ptr->a.size() == CFG::epoch_length) {
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
        if (slot.epoch() == prev_tau.epoch() && prev_tau.epoch_slot() < CFG::ticket_submission_end
                && slot.epoch_slot() >= CFG::ticket_submission_end && res.gamma_ptr->a.size() == CFG::epoch_length) {
            res.tickets_mark.emplace(_permute_tickets(res.gamma_ptr->a));
        }

        std::optional<ticket_body_t> prev_ticket {};
        // JAM Paper (6.34)
        for (const auto &t: extrinsic) {
            if (t.attempt >= CFG::ticket_attempts) [[unlikely]]
                throw err_bad_ticket_attempt_t {};

            uint8_vector aux {};

            uint8_vector input {};
            input<< std::string_view { "jam_ticket_seal" };
            input << new_eta[2];
            input << t.attempt;

            ticket_body_t tb;
            tb.attempt = t.attempt;
            if (ark_vrf_cpp::ring_vrf_output(tb.id.data(), tb.id.size(), t.signature.data(), t.signature.size()) != 0) [[unlikely]]
                throw err_bad_ticket_proof_t {};
            if (prev_ticket && *prev_ticket >= tb)
                throw err_bad_ticket_order_t {};
            prev_ticket = tb;
            const auto it = std::lower_bound(res.gamma_ptr->a.begin(), res.gamma_ptr->a.end(), tb);
            if (it != res.gamma_ptr->a.end() && *it == tb) [[unlikely]]
                throw err_duplicate_ticket_t {};
            if (ark_vrf_cpp::ring_vrf_verify(CFG::validator_count, res.gamma_ptr->z.data(), res.gamma_ptr->z.size(),
                    t.signature.data(), t.signature.size(),
                    input.data(), input.size(), aux.data(), aux.size()) != 0) [[unlikely]]
                throw err_bad_ticket_proof_t {};
            res.gamma_ptr->a.insert(it, std::move(tb));
        }
        if (res.gamma_ptr->a.size() > res.gamma_ptr->a.max_size)
            res.gamma_ptr->a.resize(res.gamma_ptr->a.max_size);

        return res;
    }

    template<typename CFG>
    statistics_t<CFG> state_t<CFG>::pi_prime(statistics_t<CFG> &&tmp_pi, const time_slot_t<CFG> &prev_tau, const time_slot_t<CFG> &slot, validator_index_t val_idx, const extrinsic_t<CFG> &extrinsic)
    {
        auto new_pi = std::move(tmp_pi);
        if (slot.epoch() > prev_tau.epoch()) {
            new_pi.last = new_pi.current;
            new_pi.current = decltype(new_pi.current) {};
        }
        if (val_idx >= CFG::validator_count) [[unlikely]]
            throw err_bad_validator_index_t {};
        auto &stats = new_pi.current.at(val_idx);
        ++stats.blocks;
        stats.tickets += extrinsic.tickets.size();
        stats.pre_images += extrinsic.preimages.size();
        for (const auto &p: extrinsic.preimages) {
            stats.pre_images_size += p.blob.size();
        }
        for (const auto &g: extrinsic.guarantees) {
            for (const auto &s: g.signatures) {
                ++new_pi.current.at(s.validator_index).guarantees;
            }
        }
        for (const auto &a: extrinsic.assurances) {
            ++new_pi.current.at(a.validator_index).assurances;
        }
        return new_pi;
    }

    template<typename CFG>
    state_t<CFG>::guarantor_assignments_t state_t<CFG>::_guarantor_assignments(const entropy_t &e, const time_slot_t<CFG> &slot)
    {
        guarantor_assignments_t in;
        for (size_t vi = 0; vi < in.size(); ++vi) {
            in[vi] = CFG::core_count * vi / CFG::validator_count;
        }
        auto res = shuffle::with_entropy(in, e);
        const auto shift = slot.epoch_slot() / CFG::core_assignment_rotation_period;
        for (size_t vi = 0; vi < res.size(); ++vi) {
            res[vi] = (res[vi] + shift) % CFG::core_count;
        }
        return res;
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
    delta_plus_result_t<CFG> state_t<CFG>::accumulate_plus(const time_slot_t<CFG> slot, const gas_t gas_limit, const work_reports_t<CFG> &reports,
        const accounts_t<CFG> &prev_delta, const free_services_t &prev_free_services)
    {
        delta_plus_result_t<CFG> res { { prev_delta } };

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

            res.consume_from(accumulate_star(slot, std::span { reports.data(), num_ok }, prev_delta, prev_free_services));
        }
        return res;
    }

    // JAM (12.17)
    template<typename CFG>
    delta_star_result_t<CFG> state_t<CFG>::accumulate_star(const time_slot_t<CFG> slot, const std::span<const work_report_t<CFG>> reports,
        const accounts_t<CFG> &prev_delta, const free_services_t &prev_free_services)
    {
        accumulate_service_operands_t service_ops {};
        for (const auto &r: reports) {
            for (const auto &r_res: r.results) {
                service_ops[r_res.service_id].emplace_back(
                    accumulate_operand_t {
                        .work_package_hash=r.package_spec.hash,
                        .exports_root=r.package_spec.exports_root,
                        .authorizer_hash=r.authorizer_hash,
                        .auth_output=r.auth_output,
                        .payload_hash=r_res.payload_hash,
                        .accumulate_gas=r_res.accumulate_gas,
                        .result=r_res.result
                    }
                );
            }
        }

        // JAM (12.17) - Ensure that free services are always accumulated
        for (const auto &fs: prev_free_services)
            service_ops.try_emplace(fs.id);

        delta_star_result_t<CFG> res {};
        for (const auto &[service_id, ops]: service_ops) {
            auto acc_res = invoke_accumulate(slot, service_id, ops, prev_delta, prev_free_services);
            if (acc_res.num_reports) {
                res.num_accumulated += acc_res.num_reports;
                res.results.try_emplace(service_id, std::move(acc_res));
            }
        }
        return res;
    }

    template<typename CFG>
    accumulate_result_t<CFG> state_t<CFG>::invoke_accumulate(const time_slot_t<CFG> slot, const service_id_t service_id,
        const accumulate_operands_t &ops, const accounts_t<CFG> &prev_delta, const free_services_t &prev_free_services)
    {
        auto &service = prev_delta.at(service_id);
        encoder arg_enc {};
        arg_enc.uint_varlen(slot.slot());
        arg_enc.uint_varlen(service_id);
        arg_enc.process(ops);

        accumulate_context_t<CFG> ctx_ok {
            service_id,
            { prev_delta }
        };
        auto ctx_err = ctx_ok;

        const auto &prev_service_info = service.info.get();
        if (const auto code = service.preimages.get(prev_service_info.code_hash); code) {
            const auto code_hash = crypto::blake2b::digest(*code);
            if (code_hash != prev_service_info.code_hash) [[unlikely]]
                throw error(fmt::format("the blob registered for code hash {} has hash {}", prev_service_info.code_hash, code_hash));

            gas_t::base_type gas_limit = 0;
            for (const auto &fs: prev_free_services) {
                if (fs.id == service_id)
                    gas_limit += fs.gas;
            }
            for (const auto &op: ops)
                gas_limit += op.accumulate_gas;

            // JAM (B.9): bold psi_a
            const auto inv_res = machine::invoke(
                static_cast<buffer>(*code), 5U, gas_limit, arg_enc.bytes(),
                [&](const machine::register_val_t id, machine::machine_t &m) -> machine::host_call_res_t {
                    host_service_accumulate_t<CFG> host_service { m, service_id, slot, ctx_ok, ctx_err };
                    return host_service.call(id);
                }
            );
            auto &ctx = std::holds_alternative<uint8_vector>(inv_res.result) ? ctx_ok : ctx_err;
            return {
                std::move(ctx.state),
                std::move(ctx.transfers),
                ctx.result,
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
    gas_t state_t<CFG>::invoke_on_transfer(const time_slot_t<CFG> slot, const service_id_t service_id,
        const accounts_t<CFG> &prev_delta, const deferred_transfer_ptrs_t &transfers)
    {
        auto &service = prev_delta.at(service_id);
        const auto &prev_service_info = service.info.get();
        const auto code = service.preimages.get(prev_service_info.code_hash);
        if (!code)
            return {};
        if (const auto code_hash = crypto::blake2b::digest(*code); code_hash != prev_service_info.code_hash) [[unlikely]]
            throw error(fmt::format("the blob registered for code hash {} has hash {}", prev_service_info.code_hash, code_hash));
        gas_t::base_type gas_limit = 0;
        encoder arg_enc {};
        arg_enc.uint_varlen(slot.slot());
        arg_enc.uint_varlen(service_id);
        arg_enc.uint_varlen(transfers.size());
        for (const auto &t: transfers) {
            gas_limit += t->gas_limit;
            arg_enc.process(*t);
        }
        mutable_services_state_t<CFG> services_state { prev_delta };
        const auto inv_res = machine::invoke(
            static_cast<buffer>(*code), 10U, gas_limit, arg_enc.bytes(),
            [&](const machine::register_val_t id, machine::machine_t &m) -> machine::host_call_res_t {
                host_service_on_transfer_t<CFG> host_service { m, services_state, service_id, slot };
                return host_service.call(id);
            }
        );
        return inv_res.gas_used;
    }

    // produces: accumulate_root, iota', psi' and chi'
    template<typename CFG>
    accumulate_output_t<CFG> state_t<CFG>::accumulate(
        statistics_t<CFG> &tmp_pi,
        const time_slot_t<CFG> &prev_tau,
        const std::shared_ptr<auth_queues_t<CFG>> &prev_phi, const std::shared_ptr<validators_data_t<CFG>> &prev_iota,
        const std::shared_ptr<privileges_t> &prev_chi,
        const std::shared_ptr<ready_queue_t<CFG>> &prev_nu, const std::shared_ptr<accumulated_queue_t<CFG>> &prev_ksi,
        const accounts_t<CFG> &prev_delta,
        const time_slot_t<CFG> &slot, const work_reports_t<CFG> &reports)
    {
        accumulate_output_t<CFG> res {
            prev_ksi, prev_nu, prev_phi, prev_iota, prev_chi
        };
        // JAM Paper (12.2)
        set_t<work_package_hash_t> known_reports {};
        for (const auto &er: *prev_ksi) {
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

        set_t<work_package_hash_t> immediate_hashes {};
        for (const auto &r: work_immediate)
            immediate_hashes.emplace(r.package_spec.hash);

        // JAM (12.10)
        const auto m = slot.epoch_slot();

        // (12.11) - work immediate is w_star after this point

        ready_queue_item_t<CFG> all_queued {};
        for (size_t i = 0; i < prev_nu->size(); ++i) {
            const auto nu_i = (m + i) % prev_nu->size();
            for (const auto &rr: (*prev_nu)[nu_i])
                all_queued.emplace_back(rr);
        }
        for (const auto &rr: work_queued)
            all_queued.emplace_back(rr);
        accumulate_update_deps<CFG>(all_queued, immediate_hashes, [&](const auto &wr) {
            work_immediate.emplace_back(wr);
        });

        // (12.21)
        boost::container::flat_set<service_id_t> free_services {};
        gas_t::base_type gas_limit = CFG::max_work_report_accumulate_gas * CFG::core_count;

        free_services.reserve(prev_chi->always_acc.size());
        for (auto &fs: prev_chi->always_acc)
            free_services.emplace_hint(free_services.end(), fs.id);

        for (const auto &re: *prev_nu) {
            for (const auto &ri: re) {
                for (const auto &rr: ri.report.results) {
                    if (free_services.contains(rr.service_id))
                        gas_limit += rr.accumulate_gas;
                }
            }
        }
        if (gas_limit < CFG::max_total_accumulation_gas)
            gas_limit = CFG::max_total_accumulation_gas;

        // (12.22)
        auto plus_res = accumulate_plus(slot, gas_limit, work_immediate, prev_delta, prev_chi->always_acc);
        // (12.23)
        res.service_updates.emplace(std::move(plus_res.state.services));
        if (plus_res.state.privileges)
            res.new_chi = std::make_shared<privileges_t>(std::move(*plus_res.state.privileges));
        if (plus_res.state.iota)
            res.new_iota = std::make_shared<validators_data_t<CFG>>(std::move(*plus_res.state.iota));
        if (plus_res.state.queue)
            res.new_phi = std::make_shared<auth_queues_t<CFG>>(std::move(*plus_res.state.queue));

        // core and service statistics are tracked per-block only! (13.11)
        tmp_pi.services.clear();

        // (12.24) (12.25) (12.26)
        for (const auto &[s_id, work_info]: plus_res.work_items) {
            auto &s_stats = tmp_pi.services[s_id];
            s_stats.accumulate_count = work_info.num_reports;
            s_stats.accumulate_gas_used = work_info.gas_used;
        }

        // (12.27)
        std::map<service_id_t, deferred_transfer_ptrs_t> dst_transfers {};
        for (const auto &t: plus_res.transfers) {
            dst_transfers[t.destination].emplace_back(&t);
        }

        // (12.28) (12.29) (12.30) (12.31)
        for (const auto &[s_id, s_transfers]: dst_transfers) {
            const auto gas_used = invoke_on_transfer(slot, s_id, prev_delta, s_transfers);
            auto &stats = tmp_pi.services[s_id];
            stats.on_transfers_count += s_transfers.size();
            stats.on_transfers_gas_used += gas_used;
        }

        // (12.33)
        res.new_ksi = std::make_shared<accumulated_queue_t<CFG>>(*prev_ksi);
        for (size_t i = 0; i < res.new_ksi->size() - 1; ++i)
            (*res.new_ksi)[i] = std::move((*res.new_ksi)[i + 1]);
        // (12.32)
        const auto work_immediate_hashes = work_immediate
            | std::views::take(plus_res.num_accumulated)
            | std::views::transform([](const auto &wr) { return wr.package_spec.hash; });
        const std::vector<work_package_hash_t> accumulated_report_hashes { work_immediate_hashes.begin(), work_immediate_hashes.end() };
        res.new_ksi->back().clear();
        res.new_ksi->back().reserve(accumulated_report_hashes.size());
        for (const auto &wrh: accumulated_report_hashes)
            res.new_ksi->back().emplace(wrh);

        // The actually accumulated report set can be a subset of the reports ready for accumulation due to the gas limit.
        // Therefore, the nu must be updated given the list of actually accumulated reports

        // (12.34)
        res.new_nu = std::make_shared<ready_queue_t<CFG>>(*prev_nu);
        accumulate_update_deps((*res.new_nu)[m], res.new_ksi->back());
        const auto time_step = slot.slot() - prev_tau.slot();
        for (size_t i = 0; i < res.new_nu->size(); ++i) {
            const auto nu_i = (m + res.new_nu->size() - i) % res.new_nu->size();
            if (i == 0) {
                (*res.new_nu)[nu_i] = std::move(work_queued);
            } else if (i >= 1 && i < time_step) {
                (*res.new_nu)[nu_i].clear();
            }
            accumulate_update_deps((*res.new_nu)[nu_i], res.new_ksi->back());
        }

        // (7.3)
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
        availability_assignments_t<CFG> &tmp_rho, statistics_t<CFG> &tmp_pi,
        const entropy_buffer_t &new_eta, const disputes_records_t &new_psi,
        const validators_data_t<CFG> &new_kappa, const validators_data_t<CFG> &new_lambda,
        const auth_pools_t<CFG> &prev_alpha, const blocks_history_t<CFG> &prev_beta,
        const accounts_t<CFG> &prev_delta,
        const time_slot_t<CFG> &slot, const guarantees_extrinsic_t<CFG> &guarantees)
    {
        reports_output_data_t res {};

        if (!guarantees.empty()) {
            std::set<opaque_hash_t> known_packages {};
            std::set<opaque_hash_t> known_segment_roots {};
            for (const auto &blk: prev_beta) {
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
            const auto current_guarantors = _guarantor_assignments(new_eta[2], slot);
            const auto current_guarantor_sigs = _capital_phi(new_kappa, new_psi.offenders);
            const auto prev_guarantors = _guarantor_assignments(new_eta[3], slot.slot() - CFG::core_assignment_rotation_period);
            const auto prev_guarantor_sigs = _capital_phi(new_lambda, new_psi.offenders);
            for (const auto &g: guarantees) {
                // JAM Paper (11.33)
                const auto blk_it = std::find_if(prev_beta.begin(), prev_beta.end(), [&g](const auto &blk) {
                    return blk.header_hash == g.report.context.anchor;
                });
                if (blk_it == prev_beta.end()) [[unlikely]]
                    throw err_anchor_not_recent_t {};
                if (blk_it->state_root != g.report.context.state_root) [[unlikely]]
                    throw err_bad_state_root_t {};
                if (blk_it->mmr.root() != g.report.context.beefy_root) [[unlikely]]
                    throw err_bad_beefy_mmr_root_t {};
                if (g.report.core_index >= tmp_rho.size()) [[unlikely]]
                    throw err_bad_core_index_t {};
                if (prev_core && *prev_core >= g.report.core_index) [[unlikely]]
                    throw err_out_of_order_guarantee_t {};
                // JAM (11.3)
                if (g.report.segment_root_lookup.size() + g.report.context.prerequisites.size() > CFG::max_report_dependencies) [[unlikely]]
                    throw err_too_many_dependencies_t {};
                prev_core = g.report.core_index;
                if (g.slot > slot) [[unlikely]]
                    throw err_future_report_slot_t {};
                {
                    static_assert(CFG::epoch_length % CFG::core_assignment_rotation_period == 0);
                    const auto current_rotation = slot.slot() / CFG::core_assignment_rotation_period;
                    const auto report_rotation = g.slot.slot() / CFG::core_assignment_rotation_period;
                    if (current_rotation - report_rotation >= 2) [[unlikely]]
                        throw err_report_epoch_before_last_t {};
                }
                const auto same_rotation = g.slot.epoch_slot() / CFG::core_assignment_rotation_period == slot.epoch_slot() / CFG::core_assignment_rotation_period;
                const auto &guarantors = same_rotation ? current_guarantors : prev_guarantors;
                const auto &guarantor_sigs = same_rotation ? current_guarantor_sigs : prev_guarantor_sigs;

                // JAM Paper (11.34)
                if (g.report.context.lookup_anchor_slot.slot() + CFG::max_lookup_anchor_age < slot) [[unlikely]]
                    throw err_segment_root_lookup_invalid_t {};

                // JAM Paper (11.35)
                const auto lblk_it = std::find_if(prev_beta.begin(), prev_beta.end(), [&g](const auto &blk) {
                    return blk.header_hash == g.report.context.lookup_anchor;
                });
                if (lblk_it == prev_beta.end()) [[unlikely]]
                    throw err_segment_root_lookup_invalid_t {};

                // JAM Paper (11.38)
                if (known_packages.contains(g.report.package_spec.hash)) [[unlikely]]
                    throw err_duplicate_package_t {};
                // + add a check that the package is not in the accumulation queue
                // + add a check that the package is not in the accumulation history

                // JAM Paper (11.3)
                if (g.report.context.prerequisites.size() + g.report.segment_root_lookup.size() > CFG::max_report_dependencies) [[unlikely]]
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

                uint8_vector msg {};
                msg << std::string_view { "jam_guarantee" };
                {
                    encoder enc { g.report };
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

                    if (guarantors[s.validator_index] != g.report.core_index) [[unlikely]]
                        throw err_wrong_assignment_t {};

                    const auto &vk = guarantor_sigs[s.validator_index].ed25519;
                    if (!crypto::ed25519::verify(s.signature, msg, vk)) [[unlikely]]
                        throw err_bad_signature_t {};
                    res.reporters.emplace_back(vk);
                }
                if (g.signatures.size() < CFG::min_guarantors) [[unlikely]]
                    throw err_insufficient_guarantees_t {};

                tmp_pi.cores[g.report.core_index].bundle_size += g.report.package_spec.length;
                size_t blobs_size = g.report.auth_output.size();
                gas_t total_accumulate_gas = 0;
                auto &core_stats = tmp_pi.cores[g.report.core_index];

                for (const auto &r: g.report.results) {
                    if (std::holds_alternative<work_result_ok_t>(r.result)) {
                        blobs_size += std::get<work_result_ok_t>(r.result).data.size();
                    }
                    const auto s_it = prev_delta.find(r.service_id);
                    if (s_it == prev_delta.end()) [[unlikely]]
                        throw err_bad_service_id_t {};
                    if (s_it->second.info.get().code_hash != r.code_hash) [[unlikely]]
                        throw err_bad_code_hash_t {};

                    // JAM (11.30) part 1
                    if (r.accumulate_gas < s_it->second.info.get().min_item_gas) [[unlikely]]
                        throw err_service_item_gas_too_low_t {};
                    total_accumulate_gas += r.accumulate_gas;

                    core_stats.gas_used += r.refine_load.gas_used;
                    core_stats.imports += r.refine_load.imports;
                    core_stats.extrinsic_count += r.refine_load.extrinsic_count;
                    core_stats.extrinsic_size += r.refine_load.extrinsic_size;
                    core_stats.exports += r.refine_load.exports;

                    auto &service_stats = tmp_pi.services[r.service_id];
                    ++service_stats.refinement_count;
                    service_stats.refinement_gas_used += r.refine_load.gas_used;
                    service_stats.imports += r.refine_load.imports;
                    service_stats.exports += r.refine_load.exports;
                    service_stats.extrinsic_size += r.refine_load.extrinsic_size;
                    service_stats.extrinsic_count += r.refine_load.extrinsic_count;
                }
                // JAM (11.30) part 2
                if (total_accumulate_gas > CFG::max_work_report_accumulate_gas) [[unlikely]]
                    throw err_work_report_gas_too_high_t {};

                // JAM Paper (11.8)
                if (blobs_size > CFG::max_blobs_size) [[unlikely]]
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
                    case CFG::validator_count / 3:
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
    blocks_history_t<CFG> state_t<CFG>::beta_dagger(const blocks_history_t<CFG> &prev_beta, const state_root_t &sr)
    {
        blocks_history_t<CFG> new_beta = prev_beta;
        if (!new_beta.empty())
            new_beta.back().state_root = sr;
        return new_beta;
    }

    template<typename CFG>
    blocks_history_t<CFG> state_t<CFG>::beta_prime(blocks_history_t<CFG> tmp_beta, const header_hash_t &hh, const std::optional<opaque_hash_t> &accumulation_result, const reported_work_seq_t &wp)
    {
        blocks_history_t<CFG> new_beta = std::move(tmp_beta);
        static mmr_t empty_mmr {};
        const mmr_t &prev_mmr = new_beta.empty() ? empty_mmr : new_beta.back().mmr;
        block_info_t bi {
            .header_hash=hh,
            .mmr=accumulation_result ? prev_mmr.append(*accumulation_result) : prev_mmr,
            .reported=wp
        };
        if (new_beta.size() == new_beta.max_size) [[likely]]
            new_beta.erase(new_beta.begin());
        new_beta.emplace_back(std::move(bi));
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
        // In addition, this makes it easier to differentiate between the original and intermediate state values
        auto new_st = *this;
        auto new_pi = new_st.pi.get();

        // JAM (4.6)
        auto tmp_beta = new_st.beta_dagger(beta.get(), blk.header.parent_state_root);

        // JAM (4.7) update gamma
        // JAM (4.8) update eta
        // JAM (4.9) update kappa
        // JAM (4.10) update lambda

        entropy_t entropy_vrf_output;
        if (ark_vrf_cpp::ietf_vrf_output(entropy_vrf_output, blk.header.entropy_source) != 0) [[unlikely]]
            throw err_bad_signature_t {};
        new_st.eta.set(new_st.eta_prime(tau.get(), eta.get(), blk.header.slot, entropy_vrf_output));
        const auto safrole_res = new_st.update_safrole(
            tau.get(), gamma.get(), new_st.eta.get(),
            kappa.storage(), lambda.storage(),
            iota.get(), psi.get(),
            blk.header.slot, blk.extrinsic.tickets
        );
        new_st.gamma.set(std::move(safrole_res.gamma_ptr));
        new_st.kappa.set(std::move(safrole_res.kappa_ptr));
        new_st.lambda.set(std::move(safrole_res.lambda_ptr));
        if (safrole_res.epoch_mark != blk.header.epoch_mark) [[unlikely]]
            throw error("supplied epoch_mark does not match the computed one!");
        if (safrole_res.tickets_mark != blk.header.tickets_mark) [[unlikely]]
            throw error("supplied tickets_mark does not match the computed one!");

        // signature verification depends on updated kappa, gamma.s and eta, so happens after update_safrole
        blk.header.verify_signatures(
            new_st.kappa.get().at(blk.header.author_index).bandersnatch,
            new_st.gamma.get().s,
            new_st.eta.get()[3]
        );

        // JAM (4.11) -> psi'
        auto tmp_rho = rho.get();
        offenders_mark_t new_offenders {};
        new_st.psi.set(
            new_st.psi_prime(
                new_offenders, tmp_rho,
                new_st.kappa.get(), new_st.lambda.get(),
                tau.get(), psi.storage(),
                blk.extrinsic.disputes
            )
        );

        // JAM (4.12)
        new_st.update_reports(
            tmp_rho, new_pi,
            new_st.eta.get(), new_st.psi.get(),
            new_st.kappa.get(), new_st.lambda.get(),
            alpha.get(), beta.get(), delta,
            blk.header.slot, blk.extrinsic.guarantees
        );
        // JAM (4.13)
        // JAM (4.14)
        // JAM (4.15)
        work_reports_t<CFG> ready_reports {};
        new_st.rho.set(tmp_rho.apply(ready_reports, new_st.kappa.get(), blk.header.slot, blk.header.parent, blk.extrinsic.assurances));

        auto accumulate_res = new_st.accumulate(
            new_pi,
            tau.get(),
            phi.storage(), iota.storage(), chi.storage(),
            nu.storage(), ksi.storage(),
            delta,
            blk.header.slot, ready_reports
        );
        new_st.ksi.set(std::move(accumulate_res.new_ksi));
        new_st.nu.set(std::move(accumulate_res.new_nu));
        new_st.phi.set(std::move(accumulate_res.new_phi));
        new_st.iota.set(std::move(accumulate_res.new_iota));
        new_st.chi.set(std::move(accumulate_res.new_chi));

        // JAM (4.18)
        new_st.provide_preimages(new_pi, blk.header.slot, blk.extrinsic.preimages);

        // JAM (4.6)
        // JAM (4.16)
        reported_work_seq_t reported_work {};
        for (const auto &g: blk.extrinsic.guarantees) {
            reported_work.emplace_back(g.report.package_spec.hash, g.report.package_spec.exports_root);
        }

        // JAM (4.17)
        new_st.beta.set(state_t::beta_prime(std::move(tmp_beta), blk.header.hash(), accumulate_res.root, reported_work));

        // (4.19): alpha' <- (H, E_G, psi', and alpha)
        {
            core_authorizers_t cas {};
            for (const auto &g: blk.extrinsic.guarantees) {
                cas.emplace_back(g.report.core_index, g.report.authorizer_hash);
            }
            new_st.alpha.set(state_t::alpha_prime(blk.header.slot, cas, new_st.phi.get(), alpha.get()));
        }

        // JAM (4.20): pi' <- (E_G, E_P, E_A, E_T, taz, kappa', pi, H)
        new_st.pi.set(pi_prime(std::move(new_pi), tau.get(), blk.header.slot, blk.header.author_index, blk.extrinsic));

        // JAM (4.5) update tau
        new_st.tau.set(state_t::tau_prime(tau.get(), blk.header.slot));

        // commit the service updates to the global key-value store only once everything else has succeeded
        if (accumulate_res.service_updates)
            accumulate_res.service_updates->commit(new_st.delta);

        *this = std::move(new_st);
    }

    template<typename CFG>
    state_t<CFG> &state_t<CFG>::operator=(const state_snapshot_t &st)
    {
        using preimage_hh_t = byte_array_t<23>;
        struct lookup_request_t {
            uint32_t l;
            lookup_meta_map_val_t<CFG> meta;
        };

        std::map<service_id_t, std::map<preimage_hh_t, lookup_request_t>> lookup_requests {};
        const auto decode_service_info = [&](const state_key_t &key, decoder &dec) {
            const auto service_id = decoder::uint_fixed<service_id_t>(byte_array<4> { key[1], key[3], key[5], key[7] });
            const auto [it, created] = delta.try_emplace(
                service_id,
                preimages_t { kv_store, state_dict, preimages_t::make_trie_key_func(service_id) },
                lookup_metas_t<CFG> { kv_store, state_dict, lookup_metas_t<CFG>::make_trie_key_func(service_id) },
                service_storage_t { kv_store, state_dict, service_storage_t::make_trie_key_func(service_id) },
                persistent_value_t<service_info_t> { state_dict, state_dict_t::make_key(255U, service_id) }
            );
            dec.process(it->second.info);
        };
        const auto decode_service_data = [&](const state_key_t &key, decoder &dec) {
            const auto service_id = decoder::uint_fixed<service_id_t>(byte_array<4> { key[0], key[2], key[4], key[6] });
            const auto [s_it, created] = delta.try_emplace(
                service_id,
                preimages_t { kv_store, state_dict, preimages_t::make_trie_key_func(service_id) },
                lookup_metas_t<CFG> { kv_store, state_dict, lookup_metas_t<CFG>::make_trie_key_func(service_id) },
                service_storage_t { kv_store, state_dict, service_storage_t::make_trie_key_func(service_id) },
                persistent_value_t<service_info_t> { state_dict, state_dict_t::make_key(255U, service_id) }
            );
            auto &service = s_it->second;
            const auto typ = decoder::uint_fixed<service_id_t>(byte_array<4> { key[1], key[3], key[5], key[7] });
            switch (typ) {
                case 0xFFFFFFFFU: {
                    const auto data = dec.next_bytes(dec.size());
                    service.storage.set(crypto::blake2b::digest<opaque_hash_t>(data), std::move(data));
                    break;
                }
                case 0xFFFFFFFEU: {
                    const auto data= dec.next_bytes(dec.size());
                    const auto h = crypto::blake2b::digest<opaque_hash_t>(data);
                    service.preimages.set(static_cast<buffer>(h), data);
                    break;
                }
                default: {
                    const buffer meta_hh { key.data() + 8, key.size() - 8 };
                    lookup_meta_map_val_t<CFG> meta;
                    dec.process(meta);
                    lookup_requests[service_id].try_emplace(meta_hh, typ, std::move(meta));
                    break;
                }
            }
        };
        state_dict->clear();
        const auto decode_state_item_or_service_data = [&](const state_key_t &key, decoder &dec, const size_t ksum, auto &item) {
            if (ksum == 0)
                dec.process(item);
            else
                decode_service_data(key, dec);
        };
        // TODO: verify that deserialization always clears the previous state!
        using namespace std::string_view_literals;
        for (const auto &[key, bytes]: st) {
            decoder dec { bytes };
            const auto ksum = std::accumulate(key.begin() + 1, key.end(), size_t { 0 });
            const auto k2sum = key[2] + key[4] + key[6] + std::accumulate(key.begin() + 8, key.end(), size_t { 0 });
            switch (const auto typ = key[0]; typ) {
                case 1: decode_state_item_or_service_data(key, dec, ksum, alpha); break;
                case 2: decode_state_item_or_service_data(key, dec, ksum, phi); break;
                case 3: decode_state_item_or_service_data(key, dec, ksum, beta); break;
                case 4: decode_state_item_or_service_data(key, dec, ksum, gamma); break;
                case 5: decode_state_item_or_service_data(key, dec, ksum, psi); break;
                case 6: decode_state_item_or_service_data(key, dec, ksum, eta); break;
                case 7: decode_state_item_or_service_data(key, dec, ksum, iota); break;
                case 8: decode_state_item_or_service_data(key, dec, ksum, kappa); break;
                case 9: decode_state_item_or_service_data(key, dec, ksum, lambda); break;
                case 10: decode_state_item_or_service_data(key, dec, ksum, rho); break;
                case 11: decode_state_item_or_service_data(key, dec, ksum, tau); break;
                case 12: decode_state_item_or_service_data(key, dec, ksum, chi); break;
                case 13: decode_state_item_or_service_data(key, dec, ksum, pi); break;
                case 14: decode_state_item_or_service_data(key, dec, ksum, nu); break;
                case 15: decode_state_item_or_service_data(key, dec, ksum, ksi); break;
                case 255:
                    if (k2sum == 0)
                        decode_service_info(key, dec);
                    else
                        decode_service_data(key, dec);
                    break;
                default:
                    decode_service_data(key, dec);
                    break;
            }
        }
        // ensure each preimage has a corresponding lookup
        size_t unresolved = 0;
        for (auto &[service_id, requests]: lookup_requests) {
            auto s_it = delta.find(service_id);
            if (s_it == delta.end()) [[unlikely]]
                throw error(fmt::format("lookup request for unknown service: {}", service_id));
            auto &service = s_it->second;
            service.preimages.foreach([&](const auto &h, const auto &) {
                const auto hh = crypto::blake2b::digest<opaque_hash_t>(h);
                const auto meta_hh = buffer { hh }.subbuf(2, 23);
                auto r_it = requests.find(meta_hh);
                if (r_it == requests.end()) [[unlikely]]
                    throw error(fmt::format("preimage without a lookup: {}", h));
                lookup_meta_map_key_t meta_key { h, r_it->second.l };
                service.lookup_metas.set(std::move(meta_key), std::move(r_it->second.meta));
                requests.erase(r_it);
            });
            unresolved += requests.size();
        }
        if (unresolved) [[unlikely]]
            throw error(fmt::format("state snapshot contains metadata without preimages: {} items", unresolved));
        return *this;
    }

    template<typename CFG>
    std::optional<write_vector> state_t<CFG>::state_get(const state_key_t &k) const
    {
        const auto &sd_val = state_dict->get(k);
        if (sd_val) {
            return std::visit([&](const auto &sv) -> std::optional<write_vector> {
                using T = std::decay_t<decltype(sv)>;
                if constexpr (std::is_same_v<T, state_dict_t::value_hash_t>) {
                    return kv_store->get(sv);
                } else {
                    return write_vector { buffer { sv.data(), sv.size() } };
                }
            }, *sd_val);
        }
        return {};
    }

    template struct state_t<config_prod>;
    template struct state_t<config_tiny>;
}
