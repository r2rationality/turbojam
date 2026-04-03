/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <ark-vrf.hpp>
#include <boost/container/static_vector.hpp>
#include "header.hpp"

namespace turbo::jam {
    template<typename CFG>
    header_t<CFG>::prepared_signatures_t header_t<CFG>::prepare_signatures() const
    {
        prepared_signatures_t prepared{};
        prepared.unsigned_header = unsigned_bytes();
        if (ark_vrf::ietf_vrf_output(prepared.entropy_output, entropy_source) != 0) [[unlikely]]
            throw err_bad_signature_t{};
        if (ark_vrf::ietf_vrf_output(prepared.seal_output, seal) != 0) [[unlikely]]
            throw err_bad_signature_t{};
        return prepared;
    }

    template<typename CFG>
    void header_t<CFG>::verify_signatures(const bandersnatch_public_t &vkey, const tickets_or_keys_t<CFG> &gamma_s,
        const entropy_t &eta3, const prepared_signatures_t &prepared) const
    {
        using namespace std::string_view_literals;
        static constexpr size_t ticket_seal_input_size = CFG::jam_ticket_seal.size() + sizeof(entropy_t) + 1U;
        static constexpr size_t fallback_seal_input_size = CFG::jam_fallback_seal.size() + sizeof(entropy_t);
        static constexpr size_t seal_input_capacity = ticket_seal_input_size > fallback_seal_input_size
            ? ticket_seal_input_size
            : fallback_seal_input_size;
        static constexpr size_t entropy_input_size = CFG::jam_entropy.size() + sizeof(entropy_t);
        const auto &seal_vrf_output = prepared.seal_output;
        boost::container::static_vector<uint8_t, seal_input_capacity> seal_input {};
        std::visit([&](const auto &s) {
            using T = std::decay_t<decltype(s)>;
            if constexpr (std::is_same_v<T, tickets_t<CFG>>) {
                auto &i = s[slot.slot() % s.size()];
                if (i.id != seal_vrf_output) [[unlikely]]
                    throw err_bad_signature_t {};
                seal_input << CFG::jam_ticket_seal << eta3 << static_cast<uint8_t>(i.attempt);
            } else if constexpr (std::is_same_v<T, keys_t<CFG>>) {
                auto &i = s[slot.slot() % s.size()];
                if (i != vkey) [[unlikely]]
                    throw err_bad_signature_t {};
                seal_input << CFG::jam_fallback_seal << eta3;
            } else {
                throw error(fmt::format("unsupported type for tickets_or_keys: {}", typeid(T).name()));
            }
        }, gamma_s);
        if (ark_vrf::ietf_vrf_verify(vkey, seal, buffer{seal_input.data(), seal_input.size()}, prepared.unsigned_header) != 0) [[unlikely]]
            throw err_bad_signature_t {};
        {
            boost::container::static_vector<uint8_t, entropy_input_size> entropy_input {};
            entropy_input << CFG::jam_entropy << seal_vrf_output;
            if (ark_vrf::ietf_vrf_verify(vkey, entropy_source, buffer{entropy_input.data(), entropy_input.size()}, buffer{}) != 0) [[unlikely]]
                throw err_bad_signature_t {};
        }
    }

    template struct header_t<config_tiny>;
    template struct header_t<config_prod>;
}
