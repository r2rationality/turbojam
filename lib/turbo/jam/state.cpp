/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <ark-vrf-cpp.hpp>
#include <turbo/crypto/blake2b.hpp>
#include "merkle.hpp"
#include "state.hpp"
#include "shuffle.hpp"
#include "ark-vrf-cpp/include/ark-vrf-cpp.hpp"

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
        if (pi != o.pi)
            return false;
        if (ro != o.ro)
            return false;
        if (tau != o.tau)
            return false;
        if (phi != o.phi)
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
        if (ark_vrf_cpp::ring_commitment(&res, vkeys.data(), sizeof(vkeys)) != 0) [[unlikely]]
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

    template<typename CONSTANTS>
    safrole_output_data_t<CONSTANTS> state_t<CONSTANTS>::update_safrole(const time_slot_t<CONSTANTS> &slot, const entropy_t &entropy, const tickets_extrinsic_t<CONSTANTS> &extrinsic)
    {
        if (slot <= tau) [[unlikely]]
            throw err_bad_slot_t(fmt::format("slot {} after {} is not allowed!", slot.slot(), tau.slot()));
        if (slot.epoch_slot() >= CONSTANTS::ticket_submission_end && !extrinsic.empty()) [[unlikely]]
            throw err_unexpected_ticket_t(fmt::format("tickets must not be reported after epoch_slot: {} but got in :{}", CONSTANTS::ticket_submission_end, slot.epoch_slot()));
        safrole_output_data_t<CONSTANTS> res {};
        if (slot.epoch() > tau.epoch()) {
            // JAM Paper (6.13)
            lambda = kappa;
            kappa = gamma.k;
            gamma.k = _capital_phi(iota, psi_o_post);
            gamma.z = _ring_commitment(gamma.k);

            // JAM Paper (6.34)
            gamma.a.clear();

            // JAM Paper (6.23)
            eta[3] = eta[2];
            eta[2] = eta[1];
            eta[1] = eta[0];

            // JAM Paper (6.24)
            if (slot.epoch() == tau.epoch() + 1 && slot.epoch_slot() >= CONSTANTS::ticket_submission_end && gamma.a.size() == CONSTANTS::epoch_length) {
                // JAM Paper (6.25)
                gamma.s.emplace<tickets_t<CONSTANTS>>();
                auto &tickets = std::get<tickets_t<CONSTANTS>>(gamma.s);
                for (size_t i = 0; i < tickets.size(); ++i) {
                    const auto j = i / 2;
                    if (i % 0 == 0) {
                        tickets[i] = gamma.a[j];
                    } else {
                        tickets[i] = gamma.a[gamma.a.size() - (j + 1)];
                    }
                }
                res.tickets_mark.emplace(tickets);
            } else {
                res.epoch_mark.emplace(eta[0], eta[2]);
                for (size_t ki = 0; ki < gamma.k.size(); ++ki) {
                    res.epoch_mark->validators[ki] = { gamma.k[ki].bandersnatch, gamma.k[ki].ed25519 };
                }
                // JAM Paper (6.26)
                // since the update operates on a copy of the state
                // eta[2] and kappa are the updated "prime" values
                gamma.s = _fallback_key_sequence(eta[2], kappa);
            }
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
                throw err_bad_ticket_attempt_t(fmt::format("ticket attempt {} is larger than the max allowed: {}", t.attempt, CONSTANTS::ticket_attempts));

            uint8_vector aux {};

            uint8_vector input {};
            input<< std::string_view { "jam_ticket_seal" };
            input << eta[2];
            input << t.attempt;

            ticket_body_t tb { .attempt = t.attempt };
            if (ark_vrf_cpp::vrf_output(tb.id.data(), t.signature.data()) != 0) [[unlikely]]
                throw error("failed to extract the VRF output!");
            if (prev_ticket && *prev_ticket >= tb)
                throw err_bad_ticket_order_t(fmt::format("bad ticket order"));
            prev_ticket = tb;
            const auto it = std::lower_bound(gamma.a.begin(), gamma.a.end(), tb);
            if (it != gamma.a.end() && *it == tb) [[unlikely]]
                throw err_duplicate_ticket_t("a duplicate ticket detected");
            if (ark_vrf_cpp::vrf_verify(CONSTANTS::validator_count, gamma.z.data(), t.signature.data(),
                    input.data(), input.size(), aux.data(), aux.size()) != 0) [[unlikely]]
                throw err_bad_ticket_proof_t("failed verify ticket proof!");
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

    template struct state_t<config_prod>;
    template struct state_t<config_tiny>;
}
