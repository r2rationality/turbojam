/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/crypto/blake2b.hpp>
#include <turbo/crypto/ed25519.hpp>
#include "errors.hpp"
#include "types.hpp"

namespace turbo::jam {
    template<typename CONSTANTS>
    availability_assignments_t<CONSTANTS> availability_assignments_t<CONSTANTS>::apply(work_reports_t<CONSTANTS> &out, const validators_data_t<CONSTANTS> &kappa,
            const time_slot_t<CONSTANTS> &slot, const header_hash_t parent, const assurances_extrinsic_t<CONSTANTS> &assurances) const
    {
        std::optional<validator_index_t> prev_validator {};
        std::array<size_t, CONSTANTS::core_count> cnts {};
        for (const auto &a: assurances) {
            if (a.validator_index >= CONSTANTS::validator_count) [[unlikely]]
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
                parent.serialize(enc);
                a.bitfield.serialize(enc);
                msg << crypto::blake2b::digest(enc.bytes());
            }
            const auto &vk = kappa[a.validator_index].ed25519;
            if (!crypto::ed25519::verify(a.signature, msg, vk)) [[unlikely]]
                throw err_bad_signature_t {};
            for (size_t ci = 0; ci < CONSTANTS::core_count; ++ci) {
                if (a.bitfield.test(ci)) {
                    if (!this->at(ci)) [[unlikely]]
                        throw err_core_not_engaged_t {};
                    ++cnts[ci];
                }
            }
        }
        auto new_avail = *this;
        for (size_t ci = 0; ci < CONSTANTS::core_count; ++ci) {
            if (new_avail[ci]) {
                if (cnts[ci] >= CONSTANTS::validator_super_majority) {
                    out.emplace_back(std::move(new_avail[ci]->report));
                    new_avail[ci].reset();
                } else if (slot >= new_avail[ci]->timeout + CONSTANTS::reported_work_timeout) {
                    new_avail[ci].reset();
                }
            }
        }
        return new_avail;
    }

    template struct availability_assignments_t<config_prod>;
    template struct availability_assignments_t<config_tiny>;
}
