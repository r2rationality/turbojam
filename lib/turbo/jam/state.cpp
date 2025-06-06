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
#include "types/errors.hpp"
#include "accumulate.hpp"
#include "host-service.hpp"
#include "machine.hpp"
#include "merkle.hpp"
#include "shuffle.hpp"

namespace turbo::jam {
    template<typename CONSTANTS>
    bool safrole_state_t<CONSTANTS>::operator==(const safrole_state_t &o) const noexcept
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

    template<typename CONSTANTS>
    bool state_t<CONSTANTS>::operator==(const state_t &o) const noexcept
    {
        if (alpha != o.alpha)
            return false;
        if (beta != o.beta)
            return false;
        if (gamma != o.gamma)
            return false;
        if (delta != o.delta)
            return false;
        if (eta != o.eta)
            return false;
        if (iota != o.iota)
            return false;
        if (kappa != o.kappa)
            return false;
        if (lambda != o.lambda)
            return false;
        if (nu != o.nu)
            return false;
        if (ksi != o.ksi)
            return false;
        if (pi != o.pi)
            return false;
        if (rho != o.rho)
            return false;
        if (tau != o.tau)
            return false;
        if (phi != o.phi)
            return false;
        if (chi != o.chi)
            return false;
        if (psi != o.psi)
            return false;
        return true;
    }

    template<typename CONSTANTS>
    std::optional<std::string> state_t<CONSTANTS>::diff(const state_t &o) const
    {
        using namespace std::string_view_literals;
        std::string diff_text {};
        auto oit = std::back_inserter(diff_text);
        const auto compare_item = [&](const std::string_view &name, const auto &a, const auto &b) {
            if (a != b)
                oit = fmt::format_to(oit, "{} left: {}\n{} right {}\n", name, a, name, b);
        };
        compare_item("alpha"sv, alpha, o.alpha);
        compare_item("beta"sv, beta, o.beta);
        compare_item("gamma"sv, gamma, o.gamma);
        compare_item("delta"sv, delta, o.delta);
        compare_item("eta"sv, eta, o.eta);
        compare_item("iota"sv, iota, o.iota);
        compare_item("kappa"sv, kappa, o.kappa);
        compare_item("lambda"sv, lambda, o.lambda);
        compare_item("nu"sv, nu, o.nu);
        compare_item("ksi"sv, ksi, o.ksi);
        compare_item("pi"sv, pi, o.pi);
        compare_item("rho"sv, rho, o.rho);
        compare_item("tau"sv, tau, o.tau);
        compare_item("phi"sv, phi, o.phi);
        compare_item("chi"sv, chi, o.chi);
        compare_item("psi"sv, psi, o.psi);
        std::optional<std::string> res {};
        if (!diff_text.empty())
            res.emplace(std::move(diff_text));
        return res;
    }

    // JAM paper (6.14)
    template<typename CONSTANTS>
    validators_data_t<CONSTANTS> state_t<CONSTANTS>::_capital_phi(const validators_data_t<CONSTANTS> &iota, const offenders_mark_t &psi_o)
    {
        validators_data_t<CONSTANTS> res;
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

    template<typename CONSTANTS>
    bandersnatch_ring_commitment_t state_t<CONSTANTS>::_ring_commitment(const validators_data_t<CONSTANTS> &gamma_k)
    {
        static auto params_path = file::install_path("data/zcash-srs-2-11-uncompressed.bin");
        if (ark_vrf_cpp::init(params_path.data(), params_path.size()) != 0) [[unlikely]]
            throw error("ark_vrf_cpp::init() failed");
        std::array<bandersnatch_public_t, CONSTANTS::validator_count> vkeys;
        for (size_t i = 0; i < vkeys.size(); ++i) {
            vkeys[i] = gamma_k[i].bandersnatch;
        }
        bandersnatch_ring_commitment_t res;
        if (ark_vrf_cpp::ring_commitment(res.data(), res.size(), vkeys.data(), sizeof(vkeys)) != 0) [[unlikely]]
            throw error("failed to generate a ring commitment!");
        return res;
    }

    // JAM paper (6.26)
    template<typename CONSTANTS>
    keys_t<CONSTANTS> state_t<CONSTANTS>::_fallback_key_sequence(const entropy_t &entropy, const validators_data_t<CONSTANTS> &kappa)
    {
        keys_t<CONSTANTS> res;
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
    template<typename CONSTANTS>
    tickets_t<CONSTANTS> state_t<CONSTANTS>::_permute_tickets(const tickets_accumulator_t<CONSTANTS> &gamma_a)
    {
        tickets_t<CONSTANTS> tickets;
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

    template<typename CONSTANTS>
    void state_t<CONSTANTS>::provide_preimages(const time_slot_t<CONSTANTS> &slot, const preimages_extrinsic_t &preimages)
    {
        const preimage_t *prev = nullptr;
        for (const auto &p: preimages) {
            if (prev && *prev >= p) [[unlikely]]
                throw err_preimages_not_sorted_or_unique_t {};
            prev = &p;
            auto &service = delta.at(p.requester);
            lookup_meta_map_key_t key;
            static_assert(sizeof(key.hash) == sizeof(crypto::blake2b::hash_t));
            key.length = numeric_cast<decltype(lookup_meta_map_key_t::length)>(p.blob.size());
            crypto::blake2b::digest(*reinterpret_cast<crypto::blake2b::hash_t *>(&key.hash), p.blob);
            const auto meta_it = service.lookup_metas.find(key);
            if (meta_it == service.lookup_metas.end()) [[unlikely]]
                throw err_preimage_unneeded_t {};
            const auto [it, created] = service.preimages.try_emplace(key.hash, p.blob);
            if (!created) [[unlikely]]
                throw err_preimage_unneeded_t {};
            meta_it->second.emplace_back(slot);
            auto &service_stats = pi.services[p.requester];
            ++service_stats.provided_count;
            service_stats.provided_size += p.blob.size();
        }
    }

    template<typename CONSTANTS>
    safrole_output_data_t<CONSTANTS> state_t<CONSTANTS>::update_safrole(const time_slot_t<CONSTANTS> &slot, const entropy_t &entropy, const tickets_extrinsic_t<CONSTANTS> &extrinsic)
    {
        if (slot.epoch_slot() >= CONSTANTS::ticket_submission_end && !extrinsic.empty()) [[unlikely]]
            throw err_unexpected_ticket_t {};
        safrole_output_data_t<CONSTANTS> res {};

        // Epoch transition
        if (slot.epoch() > tau.epoch()) [[unlikely]] {
            // JAM Paper (6.13)
            lambda = kappa;
            kappa = gamma.k;
            gamma.k = _capital_phi(iota, psi.offenders);
            gamma.z = _ring_commitment(gamma.k);

            // JAM Paper (6.23)
            eta[3] = eta[2];
            eta[2] = eta[1];
            eta[1] = eta[0];



            // JAM Paper (6.27) - epoch marker
            res.epoch_mark.emplace();
            res.epoch_mark->entropy = eta[0];
            res.epoch_mark->tickets_entropy = eta[2];
            for (size_t ki = 0; ki < gamma.k.size(); ++ki) {
                res.epoch_mark->validators[ki].bandersnatch = gamma.k[ki].bandersnatch;
                res.epoch_mark->validators[ki].ed25519 = gamma.k[ki].ed25519;
            }
        }

        // JAM (6.24)
        if (slot.epoch() == tau.epoch() + 1 && tau.epoch_slot() >= CONSTANTS::ticket_submission_end && gamma.a.size() == CONSTANTS::epoch_length) {
            gamma.s = _permute_tickets(gamma.a);
        } else if (slot.epoch() != tau.epoch()) {
            // since the update operates on a copy of the state
            // eta[2] and kappa are the updated "prime" values
            gamma.s = _fallback_key_sequence(eta[2], kappa);
        }

        if (slot.epoch() > tau.epoch()) [[unlikely]] {
        // JAM Paper (6.34)
            gamma.a.clear();
        }

        // JAM Paper (6.28) - winning-tickets marker
        if (slot.epoch() == tau.epoch() && tau.epoch_slot() < CONSTANTS::ticket_submission_end
                && slot.epoch_slot() >= CONSTANTS::ticket_submission_end && gamma.a.size() == CONSTANTS::epoch_length) {
            res.tickets_mark.emplace(_permute_tickets(gamma.a));
        }

        // JAM Paper (6.22)
        {
            byte_array<sizeof(eta[0]) + sizeof(entropy)> eta_preimage;
            memcpy(eta_preimage.data(), eta[0].data(), eta[0].size());
            memcpy(eta_preimage.data() + eta[0].size(), entropy.data(), entropy.size());
            crypto::blake2b::digest(eta[0], eta_preimage);
        }

        std::optional<ticket_body_t> prev_ticket {};
        // JAM Paper (6.34)
        for (const auto &t: extrinsic) {
            if (t.attempt >= CONSTANTS::ticket_attempts) [[unlikely]]
                throw err_bad_ticket_attempt_t {};

            uint8_vector aux {};

            uint8_vector input {};
            input<< std::string_view { "jam_ticket_seal" };
            input << eta[2];
            input << t.attempt;

            ticket_body_t tb;
            tb.attempt = t.attempt;
            if (ark_vrf_cpp::ring_vrf_output(tb.id.data(), tb.id.size(), t.signature.data(), t.signature.size()) != 0) [[unlikely]]
                throw err_bad_ticket_proof_t {};
            if (prev_ticket && *prev_ticket >= tb)
                throw err_bad_ticket_order_t {};
            prev_ticket = tb;
            const auto it = std::lower_bound(gamma.a.begin(), gamma.a.end(), tb);
            if (it != gamma.a.end() && *it == tb) [[unlikely]]
                throw err_duplicate_ticket_t {};
            if (ark_vrf_cpp::ring_vrf_verify(CONSTANTS::validator_count, gamma.z.data(), gamma.z.size(),
                    t.signature.data(), t.signature.size(),
                    input.data(), input.size(), aux.data(), aux.size()) != 0) [[unlikely]]
                throw err_bad_ticket_proof_t {};
            gamma.a.insert(it, std::move(tb));
        }
        if (gamma.a.size() > gamma.a.max_size)
            gamma.a.resize(gamma.a.max_size);

        return res;
    }

    template<typename CONSTANTS>
    void state_t<CONSTANTS>::update_statistics(const time_slot_t<CONSTANTS> &slot, validator_index_t val_idx, const extrinsic_t<CONSTANTS> &extrinsic)
    {
        if (slot.epoch() > tau.epoch()) {
            pi.last = pi.current;
            pi.current = decltype(pi.current) {};
        }
        if (val_idx >= CONSTANTS::validator_count) [[unlikely]]
            throw err_bad_validator_index_t {};
        auto &stats = pi.current.at(val_idx);
        ++stats.blocks;
        stats.tickets += extrinsic.tickets.size();
        stats.pre_images += extrinsic.preimages.size();
        for (const auto &p: extrinsic.preimages) {
            stats.pre_images_size += p.blob.size();
        }
        for (const auto &g: extrinsic.guarantees) {
            for (const auto &s: g.signatures) {
                ++pi.current.at(s.validator_index).guarantees;
            }
        }
        for (const auto &a: extrinsic.assurances) {
            ++pi.current.at(a.validator_index).assurances;
        }
    }

    template<typename CONSTANTS>
    state_t<CONSTANTS>::guarantor_assignments_t state_t<CONSTANTS>::_guarantor_assignments(const entropy_t &e, const time_slot_t<CONSTANTS> &slot)
    {
        guarantor_assignments_t in;
        for (size_t vi = 0; vi < in.size(); ++vi) {
            in[vi] = CONSTANTS::core_count * vi / CONSTANTS::validator_count;
        }
        auto res = shuffle::with_entropy(in, e);
        const auto shift = slot.epoch_slot() / CONSTANTS::core_assignment_rotation_period;
        for (size_t vi = 0; vi < res.size(); ++vi) {
            res[vi] = (res[vi] + shift) % CONSTANTS::core_count;
        }
        return res;
    }

    // JAM (12.7)
    template<typename CONSTANTS>
    static void accumulate_update_deps(ready_queue_item_t<CONSTANTS> &queue, const set_t<work_package_hash_t> &known_reports)
    {
        for (auto &rq: queue) {
            for (auto d_it = rq.dependencies.begin(); d_it != rq.dependencies.end();) {
                if (known_reports.contains(*d_it)) {
                    d_it = rq.dependencies.erase(d_it);
                } else {
                    ++d_it;
                }
            }
        }
    }

    // JAM (12.8)
    template<typename CONSTANTS>
    static void accumulate_q(std::vector<ready_queue_item_t<CONSTANTS> *>work_waiting, const work_report_t<CONSTANTS> &work_queued)
    {

    }

    // produces: accumulate_root, iota', psi' and chi'
    template<typename CONSTANTS>
    accumulate_root_t state_t<CONSTANTS>::accumulate(const time_slot_t<CONSTANTS> &slot, const work_reports_t<CONSTANTS> &reports)
    {
        accumulate_root_t res {};
        // JAM Paper (12.2)
        set_t<work_package_hash_t> known_reports {};
        for (const auto &er: ksi) {
            known_reports.reserve(known_reports.size() + er.size());
            known_reports.insert_unique(er.begin(), er.end());
        }

        work_reports_t<CONSTANTS> work_immediate {}; // JAM (12.4) W^!
        ready_queue_item_t<CONSTANTS> work_queued {}; // JAM (12.5) W^Q
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

        accumulate_update_deps(work_queued, known_reports);
        for (auto &q: nu)
            accumulate_update_deps(q, immediate_hashes);
        accumulate_update_deps(work_queued, immediate_hashes);
        for (;;) {
            set_t<work_package_hash_t> new_hashes {};
            for (size_t i = 0; i < nu.size(); ++i) {
                for (const auto &rq: nu[(m + i) % nu.size()]) {
                    if (rq.dependencies.empty()) {
                        work_immediate.emplace_back(rq.report);
                        new_hashes.emplace(rq.report.package_spec.hash);
                    }
                }
            }
            if (new_hashes.empty())
                break;
            for (auto &q: nu)
                accumulate_update_deps(q, new_hashes);
            accumulate_update_deps(work_queued, new_hashes);
        }

        std::map<service_id_t, sequence_t<accumulate_operand_t>> service_ops {};
        std::map<service_id_t, gas_t> service_gas {};

        for (const auto &r: work_immediate) {
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
                service_gas[r_res.service_id] += r_res.accumulate_gas;
            }
        }

        // transfers
        struct transfer_info_t {
            balance_t amount;
            gas_t gas;
        };
        struct service_context_t {
            service_id_t service_id;
            // new_service_id is updated by the new host call
            service_id_t new_service_id;
            // transfers are updated with the transfer host call
            std::vector<transfer_info_t> transfers {};
            // commitment is updated by the yield host call
            std::optional<opaque_hash_t> commitment {};
            // preimages are updated by the provide host call
            std::map<service_id_t, uint8_vector> preimages {};
        };
        std::map<service_id_t, service_context_t> service_ctxs {};

        for (const auto &[service_id, ops]: service_ops) {
            auto &service = delta.at(service_id);
            const auto &code = service.preimages.at(service.info.code_hash);
            const auto code_hash = crypto::blake2b::digest(code);
            if (code_hash != service.info.code_hash) [[unlikely]]
                throw error(fmt::format("the blob registered for code hash {} has hash {}", service.info.code_hash, code_hash));
            encoder arg_enc { slot, service_id, ops };

            // JAM (B.9): bold psi_a
            const auto inv_res = machine::invoke(
                static_cast<buffer>(code), 5U, 100ULL, arg_enc.bytes(),
                [&](const machine::register_val_t id, machine::machine_t &m) -> machine::host_call_res_t {
                    static std::set<machine::register_val_t> allowed_calls {
                        0, 1, 2, 3, 4, // general
                        5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 // accumulate-specific
                    };
                    if (allowed_calls.contains(id)) {
                        host_service_t<CONSTANTS> host_service { m, *this, service_id, slot };
                        return host_service.call(id);
                    }
                    m.consume_gas(10);
                    m.set_reg(7, machine::host_call_res_t::what);
                    return std::monostate {};
                }
            );

            if (!std::holds_alternative<uint8_vector>(inv_res.result)) [[unlikely]]
                throw error(fmt::format("accumulation for service {} has failed", service_id));

            // JAM (12.2)
            for (const auto &o: ops)
                ksi[slot.slot()].emplace(o.work_package_hash);
        }
        return res;
    }

    template<typename CONSTANTS>
    void state_t<CONSTANTS>::update_time(const time_slot_t<CONSTANTS> &slot)
    {
        // JAM (5.7)
        // Bootstrapping: allow slot 0 when the history is empty
        if (slot <= tau || slot > time_slot_t<CONSTANTS>::current()) [[unlikely]]
            throw err_bad_slot_t {};
        // JAM (6.1)
        tau = slot;
    }

    template<typename CONSTANTS>
    reports_output_data_t state_t<CONSTANTS>::update_reports(const time_slot_t<CONSTANTS> &slot, const guarantees_extrinsic_t<CONSTANTS> &guarantees)
    {
        reports_output_data_t res {};

        std::set<opaque_hash_t> known_packages {};
        std::set<opaque_hash_t> known_segment_roots {};
        for (const auto &blk: beta) {
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
        const auto current_guarantors = _guarantor_assignments(eta[2], slot);
        const auto current_guarantor_sigs = _capital_phi(kappa, psi.offenders);
        const auto prev_guarantors = _guarantor_assignments(eta[3], slot.slot() - CONSTANTS::core_assignment_rotation_period);
        const auto prev_guarantor_sigs = _capital_phi(lambda, psi.offenders);
        for (const auto &g: guarantees) {
            // JAM Paper (11.33)
            const auto blk_it = std::find_if(beta.begin(), beta.end(), [&g](const auto &blk) {
                return blk.header_hash == g.report.context.anchor;
            });
            if (blk_it == beta.end()) [[unlikely]]
                throw err_anchor_not_recent_t {};
            if (blk_it->state_root != g.report.context.state_root) [[unlikely]]
                throw err_bad_state_root_t {};
            if (blk_it->mmr.root() != g.report.context.beefy_root) [[unlikely]]
                throw err_bad_beefy_mmr_root_t {};
            if (g.report.core_index >= rho.size()) [[unlikely]]
                throw err_bad_core_index_t {};
            if (prev_core && *prev_core >= g.report.core_index) [[unlikely]]
                throw err_out_of_order_guarantee_t {};
            // JAM (11.3)
            if (g.report.segment_root_lookup.size() + g.report.context.prerequisites.size() > CONSTANTS::max_report_dependencies) [[unlikely]]
                throw err_too_many_dependencies_t {};
            prev_core = g.report.core_index;
            if (g.slot > slot) [[unlikely]]
                throw err_future_report_slot_t {};
            {
                static_assert(CONSTANTS::epoch_length % CONSTANTS::core_assignment_rotation_period == 0);
                const auto current_rotation = slot.slot() / CONSTANTS::core_assignment_rotation_period;
                const auto report_rotation = g.slot.slot() / CONSTANTS::core_assignment_rotation_period;
                if (current_rotation - report_rotation >= 2) [[unlikely]]
                    throw err_report_epoch_before_last_t {};
            }
            const auto same_rotation = g.slot.epoch_slot() / CONSTANTS::core_assignment_rotation_period == slot.epoch_slot() / CONSTANTS::core_assignment_rotation_period;
            const auto &guarantors = same_rotation ? current_guarantors : prev_guarantors;
            const auto &guarantor_sigs = same_rotation ? current_guarantor_sigs : prev_guarantor_sigs;

            // JAM Paper (11.34)
            if (g.report.context.lookup_anchor_slot.slot() + CONSTANTS::max_lookup_anchor_age < slot) [[unlikely]]
                throw err_segment_root_lookup_invalid_t {};

            // JAM Paper (11.35)
            const auto lblk_it = std::find_if(beta.begin(), beta.end(), [&g](const auto &blk) {
                return blk.header_hash == g.report.context.lookup_anchor;
            });
            if (lblk_it == beta.end()) [[unlikely]]
                throw err_segment_root_lookup_invalid_t {};

            // JAM Paper (11.38)
            if (known_packages.contains(g.report.package_spec.hash)) [[unlikely]]
                throw err_duplicate_package_t {};
            // + add a check that the package is not in the accumulation queue
            // + add a check that the package is not in the accumulation history

            // JAM Paper (11.3)
            if (g.report.context.prerequisites.size() + g.report.segment_root_lookup.size() > CONSTANTS::max_report_dependencies) [[unlikely]]
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
                if (rho[g.report.core_index])
                    throw err_core_engaged_t {};
                const auto &auth_pool = alpha[g.report.core_index];
                const auto auth_it = std::find(auth_pool.begin(), auth_pool.end(), g.report.authorizer_hash);
                if (auth_it == auth_pool.end()) [[unlikely]]
                    throw err_core_unauthorized_t {};
            }

            rho[g.report.core_index] = availability_assignment_t<CONSTANTS> {
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
                if (s.validator_index >= kappa.size()) [[unlikely]]
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
            if (g.signatures.size() < CONSTANTS::min_guarantors) [[unlikely]]
                throw err_insufficient_guarantees_t {};

            pi.cores[g.report.core_index].bundle_size += g.report.package_spec.length;
            size_t blobs_size = g.report.auth_output.size();
            gas_t total_accumulate_gas = 0;
            auto &core_stats = pi.cores[g.report.core_index];

            for (const auto &r: g.report.results) {
                if (std::holds_alternative<work_result_ok_t>(r.result)) {
                    blobs_size += std::get<work_result_ok_t>(r.result).data.size();
                }
                const auto s_it = delta.find(r.service_id);
                if (s_it == delta.end()) [[unlikely]]
                    throw err_bad_service_id_t {};
                if (s_it->second.info.code_hash != r.code_hash) [[unlikely]]
                    throw err_bad_code_hash_t {};

                // JAM (11.30) part 1
                if (r.accumulate_gas < s_it->second.info.min_item_gas) [[unlikely]]
                    throw err_service_item_gas_too_low_t {};
                total_accumulate_gas += r.accumulate_gas;

                core_stats.gas_used += r.refine_load.gas_used;
                core_stats.imports += r.refine_load.imports;
                core_stats.extrinsic_count += r.refine_load.extrinsic_count;
                core_stats.extrinsic_size += r.refine_load.extrinsic_size;
                core_stats.exports += r.refine_load.exports;

                auto &service_stats = pi.services[r.service_id];
                ++service_stats.refinement_count;
                service_stats.refinement_gas_used += r.refine_load.gas_used;
                service_stats.imports += r.refine_load.imports;
                service_stats.exports += r.refine_load.exports;
                service_stats.extrinsic_size += r.refine_load.extrinsic_size;
                service_stats.extrinsic_count += r.refine_load.extrinsic_count;
            }
            // JAM (11.30) part 2
            if (total_accumulate_gas > CONSTANTS::max_accumulate_gas) [[unlikely]]
                throw err_work_report_gas_too_high_t {};

            // JAM Paper (11.8)
            if (blobs_size > CONSTANTS::max_blobs_size) [[unlikely]]
                throw err_work_report_too_big_t {};
        }
        // Jam Paper (11.32)
        if (guarantees.size() != wp_hashes.size()) [[unlikely]]
            throw err_duplicate_package_t {};
        std::sort(res.reported.begin(), res.reported.end());
        std::sort(res.reporters.begin(), res.reporters.end());
        return res;
    }

    template<typename CONSTANTS>
    offenders_mark_t state_t<CONSTANTS>::update_disputes(const disputes_extrinsic_t<CONSTANTS> &disputes)
    {
        set_t<ed25519_public_t> known_vkeys {};
        known_vkeys.reserve(kappa.size() + lambda.size());
        for (const auto &validator_set: { kappa, lambda }) {
            for (const auto &v: validator_set)
                known_vkeys.emplace_hint_unique(known_vkeys.end(), v.ed25519);
        }

        set_t<work_report_hash_t> known_reports {};
        known_reports.reserve(psi.bad.size() + psi.good.size() + psi.wonky.size());
        for (const auto &report_set: { psi.good, psi.bad, psi.wonky }) {
            for (const auto &rh: report_set)
                known_reports.emplace_hint_unique(known_reports.end(), rh);
        }

        offenders_mark_t new_offenders {};
        uint8_vector msg {};

        // JAM (10.3)
        const auto cur_epoch = tau.epoch();
        const verdict_t<CONSTANTS> *prev_verdict = nullptr;
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
                msg.reserve(v.target.size() + std::max(CONSTANTS::jam_valid.size(), CONSTANTS::jam_invalid.size()));
                msg << static_cast<buffer>(j.vote ? CONSTANTS::jam_valid : CONSTANTS::jam_invalid);
                msg << v.target;
                if (v.age > cur_epoch || v.age + 1 < cur_epoch) [[unlikely]]
                    throw err_bad_judgement_age_t {};
                const auto &validators = v.age == cur_epoch ? kappa : lambda;
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
            msg.reserve(c.target.size() + CONSTANTS::jam_guarantee.size());
            msg << static_cast<buffer>(CONSTANTS::jam_guarantee);
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
            const auto &verdict_prefix = f.vote ? CONSTANTS::jam_valid : CONSTANTS::jam_invalid;
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
                case CONSTANTS::validator_super_majority:
                    // JAM (10.13)
                    if (!new_fault_reports.contains(report_hash)) [[unlikely]]
                        throw err_not_enough_faults_t {};
                    // JAM (10.16)
                    psi.good.emplace(report_hash);
                    continue;
                case CONSTANTS::validator_count / 3:
                    // JAM (10.18)
                    psi.wonky.emplace(report_hash);
                    break;
                case 0:
                    // JAM (10.14)
                    if (const auto c_it = new_culprits.find(report_hash); c_it == new_culprits.end() || c_it->second < 2)
                        throw err_not_enough_culprits_t {};
                    // JAM (10.17)
                    psi.bad.emplace(report_hash);
                    break;
                [[unlikely]] default:
                    throw err_bad_vote_split_t {};
            }
        }

        for (const auto &f: disputes.faults) {
            if (psi.bad.contains(f.target)) {
                if (!f.vote) [[unlikely]]
                    throw err_fault_verdict_wrong_t {};
            }
            if (psi.good.contains(f.target)) {
                if (f.vote) [[unlikely]]
                    throw err_fault_verdict_wrong_t {};
            }
        }

        for (const auto &c: disputes.culprits) {
            if (!psi.bad.contains(c.target)) [[unlikely]]
                throw err_culprits_verdict_not_bad_t {};
        }

        // JAM (10.15)
        for (auto &ra: rho) {
            if (ra) {
                encoder enc { ra->report };
                work_report_hash_t report_hash;
                crypto::blake2b::digest(report_hash, enc.bytes());
                if (const auto ok_it = report_oks.find(report_hash); ok_it != report_oks.end() && ok_it->second < CONSTANTS::validator_super_majority) [[unlikely]]
                    ra.reset();
            }
        }

        // JAM (10.19)
        for (const auto &k: new_offenders) {
            const auto [it, created] = psi.offenders.emplace_unique(k);
            if (!created) [[unlikely]]
                throw err_offender_already_reported_t {};
        }

        return new_offenders;
    }

    template<typename CONSTANTS>
    void state_t<CONSTANTS>::update_history_1(const state_root_t &state_root)
    {
        if (!beta.empty()) [[likely]]
            beta.back().state_root = state_root;
    }

    template<typename CONSTANTS>
    void state_t<CONSTANTS>::update_history_2(const header_hash_t &hh, const std::optional<opaque_hash_t> &accumulation_result, const reported_work_seq_t &wp)
    {
        static mmr_t empty_mmr {};
        const mmr_t &prev_mmr = beta.empty() ? empty_mmr : beta.at(beta.size() - 1).mmr;
        block_info_t bi {
            .header_hash=hh,
            .mmr=accumulation_result ? prev_mmr.append(*accumulation_result) : prev_mmr,
            .reported=wp
        };
        if (beta.size() == beta.max_size) [[likely]]
            beta.erase(beta.begin());
        beta.emplace_back(std::move(bi));
    }

    template<typename CONSTANTS>
    void state_t<CONSTANTS>::update_auth_pools(const time_slot_t<CONSTANTS> &slot, const core_authorizers_t &cas)
    {
        for (const auto &ca: cas) {
            auto &pool = alpha.at(ca.core);
            auto pool_it = std::find(pool.begin(), pool.end(), ca.auth_hash);
            if (pool_it == pool.end()) [[unlikely]]
                throw error(fmt::format("a work report for core {} mentions an unknown auth_hash: {}", ca.core, ca.auth_hash));
            // remove the element and shift all elements after to make the final slot free
            pool.erase(pool_it);
        }

        // JAM (8.2)
        for (size_t core = 0; core < alpha.size(); ++core) {
            auto &pool = alpha.at(core);
            if (pool.size() == pool.max_size)
                pool.erase(pool.begin());
            const auto &queue = phi.at(core);
            pool.emplace_back(queue.at(slot.slot() % queue.size()));
        }
    }

    // JAM (4.1): Kapital upsilon
    template<typename CONSTANTS>
    void state_t<CONSTANTS>::apply(const block_t<CONSTANTS> &blk)
    {
        using namespace std::string_view_literals;
        // Work on a copy so that in case of exceptions the original state remains intact
        // In addition, this makes it easier to differentiate between the original and intermediate state values
        auto new_st = *this;

        // JAM (4.6)
        new_st.update_history_1(blk.header.parent_state_root);

        // JAM (4.7) update gamma
        // JAM (4.8) update eta
        // JAM (4.9) update kappa
        // JAM (4.10) update lambda

        entropy_t entropy_vrf_output;
        if (ark_vrf_cpp::ietf_vrf_output(entropy_vrf_output, blk.header.entropy_source) != 0) [[unlikely]]
            throw err_bad_signature_t {};
        const auto safrole_res = new_st.update_safrole(blk.header.slot, entropy_vrf_output, blk.extrinsic.tickets);
        if (safrole_res.epoch_mark != blk.header.epoch_mark) [[unlikely]]
            throw error("supplied epoch_mark does not match the computed one!");
        if (safrole_res.tickets_mark != blk.header.tickets_mark) [[unlikely]]
            throw error("supplied tickets_mark does not match the computed one!");

        // signature verification depends on updated kappa, gamma.s and eta, so happens after update_safrole
        blk.header.verify_signatures(
            new_st.kappa.at(blk.header.author_index).bandersnatch,
            new_st.gamma.s,
            new_st.eta[3]
        );

        // JAM (4.11) -> psi'
        new_st.update_disputes(blk.extrinsic.disputes);

        // JAM (4.12)
        new_st.update_reports(blk.header.slot, blk.extrinsic.guarantees);
        // JAM (4.13)
        // JAM (4.14)
        // JAM (4.15)
        work_reports_t<CONSTANTS> ready_reports {};
        new_st.rho = new_st.rho.apply(ready_reports, new_st.kappa, blk.header.slot, blk.header.parent, blk.extrinsic.assurances);

        // accumulate
        accumulate_root_t accumulate_res = new_st.accumulate(blk.header.slot, ready_reports);

        // JAM (4.18)
        new_st.provide_preimages(blk.header.slot, blk.extrinsic.preimages);

        // JAM (4.6)
        // JAM (4.16)
        reported_work_seq_t reported_work {};
        for (const auto &g: blk.extrinsic.guarantees) {
            reported_work.emplace_back(g.report.package_spec.hash, g.report.package_spec.exports_root);
        }

        // JAM (4.17)
        new_st.update_history_2(blk.header.hash(), accumulate_res, reported_work);

        // (4.19): alpha' <- (H, E_G, psi', and alpha)
        {
            core_authorizers_t cas {};
            for (const auto &g: blk.extrinsic.guarantees) {
                cas.emplace_back(g.report.core_index, g.report.authorizer_hash);
            }
            new_st.update_auth_pools(blk.header.slot, cas);
        }

        // JAM (4.20): pi' <- (E_G, E_P, E_A, E_T, taz, kappa', pi, H)
        new_st.update_statistics(blk.header.slot, blk.header.author_index, blk.extrinsic);

        // JAM (4.5) update tau
        new_st.update_time(blk.header.slot);

        *this = std::move(new_st);
    }

    template<typename CONSTANTS>
    std::exception_ptr state_t<CONSTANTS>::try_apply(const block_t<CONSTANTS> &blk) noexcept
    {
        try {
            apply(blk);
            return nullptr;
        } catch (const std::exception &ex) {
            std::cerr << fmt::format("state_t::try_apply failed: {}\n", ex.what());
            return std::current_exception();
        } catch (...) {
            std::cerr << fmt::format("state_t::try_apply failed: unknown exception\n");
            return std::current_exception();
        }
    }

    template<typename T>
    static byte_sequence_t encode(const T &v)
    {
        encoder enc { v };
        return { std::move(enc.bytes()) };
    }

    template<typename CONSTANTS>
    state_dict_t state_t<CONSTANTS>::state_dict() const
    {
        state_dict_t st {};
        st.emplace(state_dict_t::make_key(1), encode(alpha));
        st.emplace(state_dict_t::make_key(2), encode(phi));
        st.emplace(state_dict_t::make_key(3), encode(beta));
        st.emplace(state_dict_t::make_key(4), encode(gamma));
        st.emplace(state_dict_t::make_key(5), encode(psi));
        st.emplace(state_dict_t::make_key(6), encode(eta));
        st.emplace(state_dict_t::make_key(7), encode(iota));
        st.emplace(state_dict_t::make_key(8), encode(kappa));
        st.emplace(state_dict_t::make_key(9), encode(lambda));
        st.emplace(state_dict_t::make_key(10), encode(rho));
        st.emplace(state_dict_t::make_key(11), encode(tau));
        st.emplace(state_dict_t::make_key(12), encode(chi));
        st.emplace(state_dict_t::make_key(13), encode(pi));
        st.emplace(state_dict_t::make_key(14), encode(nu));
        st.emplace(state_dict_t::make_key(15), encode(ksi));
        for (const auto &[s_id, s]: delta) {
            st.emplace(state_dict_t::make_key(255, s_id), encode(s.info));
            for (const auto &[k, v]: s.storage) {
                state_key_subhash_t kh;
                encoder::uint_fixed(std::span { kh.begin(), kh.begin() + 4 }, 4, (1ULL << 32U) - 1ULL);
                memcpy(kh.data() + 4, k.data(), kh.size() - 4);
                st.emplace(state_dict_t::make_key(s_id, kh), v);
            }
            for (const auto &[k, v]: s.preimages) {
                state_key_subhash_t kh;
                encoder::uint_fixed(std::span { kh.begin(), kh.begin() + 4 }, 4, (1ULL << 32U) - 2ULL);
                memcpy(kh.data() + 4, k.data() + 1, kh.size() - 4);
                st.emplace(state_dict_t::make_key(s_id, kh), v);
            }
            for (const auto &[k, v]: s.lookup_metas) {
                state_key_subhash_t kh;
                encoder::uint_fixed(std::span { kh.begin(), kh.begin() + 4 }, 4, k.length);
                const auto hh = crypto::blake2b::digest(k.hash);
                memcpy(kh.data() + 4, hh.data() + 2, kh.size() - 4);
                st.emplace(state_dict_t::make_key(s_id, kh), encode(v));
            }
        }
        return st;
    }

    template<typename CONSTANTS>
    state_t<CONSTANTS> &state_t<CONSTANTS>::operator=(const state_dict_t &st)
    {
        using preimage_hh_t = byte_array_t<23>;
        struct lookup_request_t {
            service_id_t service_id;
            preimage_hh_t hh;
            uint32_t l;
            lookup_meta_map_val_t<CONSTANTS> meta;
        };

        std::vector<lookup_request_t> lookup_requests {};
        const auto decode_service_info = [&](const state_key_t &key, decoder &dec) {
            const auto service_id = decoder::uint_fixed<service_id_t>(byte_array<4> { key[1], key[3], key[5], key[7] });
            dec.process(delta[service_id].info);
        };
        const auto decode_service_data = [&](const state_key_t &key, decoder &dec) {
            const auto service_id = decoder::uint_fixed<service_id_t>(byte_array<4> { key[0], key[2], key[4], key[6] });
            auto &service = delta[service_id];
            const auto typ = decoder::uint_fixed<service_id_t>(byte_array<4> { key[1], key[3], key[5], key[7] });
            switch (typ) {
                case 0xFFFFFFFFU: {
                    byte_sequence_t data { dec.next_bytes(dec.size()) };
                    service.storage[crypto::blake2b::digest<opaque_hash_t>(data)] = std::move(data);
                    break;
                }
                case 0xFFFFFFFEU: {
                    byte_sequence_t data { dec.next_bytes(dec.size()) };
                    const auto h = crypto::blake2b::digest<opaque_hash_t>(data);
                    service.preimages[h] = std::move(data);
                    break;
                }
                default: {
                    const buffer meta_hh { key.data() + 8, key.size() - 8 };
                    lookup_meta_map_val_t<CONSTANTS> meta;
                    dec.process(meta);
                    lookup_requests.emplace_back(service_id, meta_hh, typ, std::move(meta));
                    break;
                }
            }
        };
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
        // Resolve metadata hashes
        // Slow!!! But this is OK for genesis_state decoding
        for (auto &&lr: lookup_requests) {
            auto &service = delta[lr.service_id];
            std::optional<opaque_hash_t> meta_hash {};
            for (const auto &[h, p]: service.preimages) {
                const auto hh = crypto::blake2b::digest<opaque_hash_t>(h);
                if (buffer { hh }.subbuf(2, 23) == lr.hh) {
                    meta_hash.emplace(h);
                    break;
                }
            }
            if (!meta_hash) [[unlikely]]
                throw error(fmt::format("failed to recover preimage with its hash's hash: {}", lr.hh));
            lookup_meta_map_key_t meta_key { *meta_hash, lr.l };
            service.lookup_metas[std::move(meta_key)] = std::move(lr.meta);
        }
        return *this;
    }

    template struct state_t<config_prod>;
    template struct state_t<config_tiny>;
}
