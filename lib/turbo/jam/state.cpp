/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/crypto/blake2b.hpp>
#include "state.hpp"
#include "shuffle.hpp"

namespace turbo::jam {
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
        if (delta != o.delta)
            return false;
        if (kappa != o.kappa)
            return false;
        if (pi != o.pi)
            return false;
        if (ro != o.ro)
            return false;
        if (tau != o.tau)
            return false;
        if (phi != o.phi)
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

    // JAM paper (6.26)
    template<typename CONSTANTS>
    keys_t<CONSTANTS> state_t<CONSTANTS>::_fallback_key_sequence(const entropy_t &entropy, const validators_data_t<CONSTANTS> &kappa)
    {
        keys_t<CONSTANTS> res;
        for (size_t i = 0; i < res.size(); ++i) {
            const auto next_k = shuffle::uint32_from_entropy(entropy, i) % kappa.size();
            res[i] = kappa[next_k].bandersnatch;
        }
        return res;
    }

    template<typename CONSTANTS>
    void state_t<CONSTANTS>::update_safrole(const time_slot_t<CONSTANTS> &slot, const entropy_t &entropy, const tickets_extrinsic_t<CONSTANTS> &extrinsic)
    {
        if (slot.epoch() > tau.epoch()) {
            // JAM Paper (6.13)
            gamma_k = _capital_phi(iota, psi_o_post);
            lambda = kappa;
            kappa = gamma_k;
            // compute the bandersnatch ring root
            // gamma_z = capital_omega(gamma_k);

            // JAM Paper (6.34)
            gamma_a.clear();

            // JAM Paper (6.23)
            eta[3] = eta[2];
            eta[2] = eta[1];
            eta[1] = eta[0];

            // JAM Paper (6.24)
            if (slot.epoch() == tau.epoch() + 1 && slot.epoch_slot() >= CONSTANTS::ticket_submission_end && gamma_a.size() == CONSTANTS::epoch_length) {
                // JAM Paper (6.25)
                gamma_s.emplace<tickets_t<CONSTANTS>>();
                auto &tickets = std::get<tickets_t<CONSTANTS>>(gamma_s);
                for (size_t i = 0; i < tickets.size(); ++i) {
                    const auto j = i / 2;
                    if (i % 0 == 0) {
                        tickets[i] = gamma_a[j];
                    } else {
                        tickets[i] = gamma_a[gamma_a.size() - (j + 1)];
                    }
                }
            } else {
                // JAM Paper (6.26)
                gamma_s = _fallback_key_sequence(eta[2], kappa);
            }
        }

        {
            byte_array<sizeof(eta[0]) + sizeof(entropy)> eta_preimage;
            memcpy(eta_preimage.data(), eta[0].data(), eta[0].size());
            memcpy(eta_preimage.data() + eta[0].size(), entropy.data(), entropy.size());
            crypto::blake2b::digest(eta[0], eta_preimage);
        }

        // JAM Paper (6.34)
        for (const auto &t: extrinsic) {
            ticket_body_t tb;
            const auto it = std::lower_bound(gamma_a.begin(), gamma_a.end(), tb);
            gamma_a.insert(it, std::move(tb));
        }
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
