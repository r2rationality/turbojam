/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <ark-vrf-cpp.hpp>
#include <turbo/crypto/blake2b.hpp>
#include <turbo/crypto/ed25519.hpp>
#include "errors.hpp"
#include "merkle.hpp"
#include "state.hpp"
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
    state_t<CONSTANTS> state_t<CONSTANTS>::apply(const block_info_t &) const
    {
        state_t new_st = *this;
        // assurances must be processed before guarantees

        // new_st.beta = this->beta.apply(blk.header_hash, blk.state_root)

        // alpha is processed after phi
        return new_st;
    }

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
        if (ro != o.ro)
            return false;
        if (tau != o.tau)
            return false;
        if (phi != o.phi)
            return false;
        if (chi != o.chi)
            return false;
        if (psi_o_post != o.psi_o_post)
            return false;
        return true;
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
    safrole_output_data_t<CONSTANTS> state_t<CONSTANTS>::update_safrole(const time_slot_t<CONSTANTS> &slot, const entropy_t &entropy, const tickets_extrinsic_t<CONSTANTS> &extrinsic)
    {
        if (slot <= tau) [[unlikely]]
            throw err_bad_slot_t {};
        if (slot.epoch_slot() >= CONSTANTS::ticket_submission_end && !extrinsic.empty()) [[unlikely]]
            throw err_unexpected_ticket_t {};
        safrole_output_data_t<CONSTANTS> res {};
        if (slot.epoch() > tau.epoch()) {
            // JAM Paper (6.13)
            lambda = kappa;
            kappa = gamma.k;
            gamma.k = _capital_phi(iota, psi_o_post);
            gamma.z = _ring_commitment(gamma.k);

            // JAM Paper (6.23)
            eta[3] = eta[2];
            eta[2] = eta[1];
            eta[1] = eta[0];

            // JAM Paper (6.24)
            if (slot.epoch() == tau.epoch() + 1 && tau.epoch_slot() >= CONSTANTS::ticket_submission_end && gamma.a.size() == CONSTANTS::epoch_length) {
                gamma.s = _permute_tickets(gamma.a);
            } else {
                // JAM Paper (6.26)
                // since the update operates on a copy of the state
                // eta[2] and kappa are the updated "prime" values
                gamma.s = _fallback_key_sequence(eta[2], kappa);
            }

            // JAM Paper (6.34)
            gamma.a.clear();

            // JAM Paper (6.27) - epoch marker
            res.epoch_mark.emplace();
            res.epoch_mark->entropy = eta[0];
            res.epoch_mark->tickets_entropy = eta[2];
            for (size_t ki = 0; ki < gamma.k.size(); ++ki) {
                res.epoch_mark->validators[ki].bandersnatch = gamma.k[ki].bandersnatch;
                res.epoch_mark->validators[ki].ed25519 = gamma.k[ki].ed25519;
            }
        }

        // JAM Paper (6.28) - winning-tickets marker
        if (slot.epoch() == tau.epoch() &&  tau.epoch_slot() < CONSTANTS::ticket_submission_end
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
            if (ark_vrf_cpp::vrf_output(tb.id.data(), tb.id.size(), t.signature.data(), t.signature.size()) != 0) [[unlikely]]
                throw err_bad_ticket_proof_t {};
            if (prev_ticket && *prev_ticket >= tb)
                throw err_bad_ticket_order_t {};
            prev_ticket = tb;
            const auto it = std::lower_bound(gamma.a.begin(), gamma.a.end(), tb);
            if (it != gamma.a.end() && *it == tb) [[unlikely]]
                throw err_duplicate_ticket_t {};
            if (ark_vrf_cpp::vrf_verify(CONSTANTS::validator_count, gamma.z.data(), gamma.z.size(),
                    t.signature.data(), t.signature.size(),
                    input.data(), input.size(), aux.data(), aux.size()) != 0) [[unlikely]]
                throw err_bad_ticket_proof_t {};
            gamma.a.insert(it, std::move(tb));
        }
        if (gamma.a.size() > gamma.a.max_size)
            gamma.a.resize(gamma.a.max_size);

        tau = slot;
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
            throw error(fmt::format("validator index too large: {}", val_idx));
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
        work_reports_t<CONSTANTS> work_immediate {}; // JAM Paper (12.4) W^!
        work_reports_t<CONSTANTS> work_queued {};    // JAM Paper (12.5) W^Q
        std::map<work_package_hash_t, set_t<work_package_hash_t>> dependencies {};  // JAM Paper (12.6) D(w)
        for (const auto &r: reports) {
            auto &deps = dependencies[r.package_spec.hash];
            deps.reserve(deps.size() + r.context.prerequisites.size() + r.segment_root_lookup.size());
            for (const auto &h: r.context.prerequisites) {
                deps.emplace_hint(deps.end(), h);
            }
            for (const auto &l: r.segment_root_lookup) {
                deps.emplace_hint(deps.end(), l.work_package_hash);
            }
            auto &queue = static_cast<int>(r.context.prerequisites.empty()) & static_cast<int>(r.segment_root_lookup.empty())
                ? work_immediate
                : work_queued;
            queue.emplace_back(r);
        }
        return res;
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
        const auto current_guarantor_sigs = _capital_phi(kappa, psi_o_post);
        const auto prev_guarantors = _guarantor_assignments(eta[3], slot.slot() - CONSTANTS::core_assignment_rotation_period);
        const auto prev_guarantor_sigs = _capital_phi(lambda, psi_o_post);
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
            if (g.report.core_index >= ro.size()) [[unlikely]]
                throw err_bad_core_index_t {};
            if (prev_core && *prev_core >= g.report.core_index) [[unlikely]]
                throw err_out_of_order_guarantee_t {};
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
                if (ro[g.report.core_index])
                    throw err_core_engaged_t {};
                const auto &auth_pool = alpha[g.report.core_index];
                const auto auth_it = std::find(auth_pool.begin(), auth_pool.end(), g.report.authorizer_hash);
                if (auth_it == auth_pool.end()) [[unlikely]]
                    throw err_core_unauthorized_t {};
            }

            ro[g.report.core_index] = availability_assignment_t<CONSTANTS> {
                .report=g.report, .timeout=slot.slot()
            };
            res.reported.emplace_back(reported_work_package_t {
                .hash=g.report.package_spec.hash, .exports_root=g.report.package_spec.exports_root
            });

            uint8_vector msg {};
            msg << std::string_view { "jam_guarantee" };
            {
                encoder enc {};
                enc.process(g.report);
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

                ++pi.services[r.service_id].refinement_count;
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

    template struct state_t<config_prod>;
    template struct state_t<config_tiny>;
}
