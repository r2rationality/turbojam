/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <ark-vrf.hpp>
#include "header.hpp"

namespace turbo::jam {
    template<typename CONSTANTS>
    void header_t<CONSTANTS>::verify_signatures(const bandersnatch_public_t &vkey, const tickets_or_keys_t<CONSTANTS> &gamma_s, const entropy_t &eta3) const
    {
        using namespace std::string_view_literals;
        entropy_t seal_vrf_output;
        if (ark_vrf::ietf_vrf_output(seal_vrf_output, seal) != 0) [[unlikely]]
            throw err_bad_signature_t {};
        {
            uint8_vector seal_input {};
            std::visit([&](const auto &s) {
                using T = std::decay_t<decltype(s)>;
                if constexpr (std::is_same_v<T, tickets_t<CONSTANTS>>) {
                    auto &i = s[slot.slot() % s.size()];
                    if (i.id != seal_vrf_output) [[unlikely]]
                        throw err_bad_signature_t {};
                    seal_input << "jam_ticket_seal"sv;
                    seal_input << eta3;
                    seal_input << i.attempt;
                } else if constexpr (std::is_same_v<T, keys_t<CONSTANTS>>) {
                    auto &i = s[slot.slot() % s.size()];
                    if (i != vkey) [[unlikely]]
                        throw err_bad_signature_t {};
                    seal_input << "jam_fallback_seal"sv;
                    seal_input << eta3;
                } else {
                    throw error(fmt::format("unsupported type for tickets_or_keys: {}", typeid(T).name()));
                }
            }, gamma_s);
            if (ark_vrf::ietf_vrf_verify(vkey, seal, seal_input, unsigned_bytes()) != 0) [[unlikely]]
                throw err_bad_signature_t {};
        }

        {
            uint8_vector entropy_input {};
            entropy_input << "jam_entropy"sv;
            entropy_input << seal_vrf_output;
            if (ark_vrf::ietf_vrf_verify(vkey, entropy_source, entropy_input, uint8_vector {}) != 0) [[unlikely]]
                throw err_bad_signature_t {};
        }
    }

    template struct header_t<config_tiny>;
    template struct header_t<config_prod>;
}