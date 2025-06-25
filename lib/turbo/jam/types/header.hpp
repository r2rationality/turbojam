#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <ark-vrf.hpp>
#include "common.hpp"

namespace turbo::jam {
    // JAM (4.3)
    template<typename CONSTANTS>
    struct extrinsic_t {
        tickets_extrinsic_t<CONSTANTS> tickets;
        preimages_extrinsic_t preimages;
        guarantees_extrinsic_t<CONSTANTS> guarantees;
        assurances_extrinsic_t<CONSTANTS> assurances;
        disputes_extrinsic_t<CONSTANTS> disputes;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("tickets"sv, tickets);
            archive.process("preimages"sv, preimages);
            archive.process("guarantees"sv, guarantees);
            archive.process("assurances"sv, assurances);
            archive.process("disputes"sv, disputes);
        }

        bool empty() const
        {
            if (!tickets.empty())
                return false;
            if (!preimages.empty())
                return false;
            if (!guarantees.empty())
                return false;
            if (!assurances.empty())
                return false;
            if (!disputes.empty())
                return false;
            return true;
        }

        bool operator==(const extrinsic_t &o) const
        {
            if (tickets != o.tickets)
                return false;
            if (preimages != o.preimages)
                return false;
            if (guarantees != o.guarantees)
                return false;
            if (assurances != o.assurances)
                return false;
            if (disputes != o.disputes)
                return false;
            return true;
        }
    };

    // JAM (5.1)

    template<typename CONSTANTS>
    struct header_t {
        // H_p
        header_hash_t parent {};
        // H_r - ancestors need to be stored only for previous 24-hours of any block to be validated
        state_root_t parent_state_root {};
        // H_x - merkle commitment (H^#) to the block's external data
        opaque_hash_t extrinsic_hash {};
        // H_t
        time_slot_t<CONSTANTS> slot {};
        // H_e
        optional_t<epoch_mark_t<CONSTANTS>> epoch_mark {};
        // H_w
        optional_t<tickets_mark_t<CONSTANTS>> tickets_mark {};
        // H_o
        offenders_mark_t offenders_mark {};
        // H_i
        validator_index_t author_index {};
        // H_v
        bandersnatch_vrf_signature_t entropy_source {};
        // H_s
        bandersnatch_vrf_signature_t seal {};

        [[nodiscard]] uint8_vector unsigned_bytes() const
        {
            encoder enc {};
            const_cast<header_t &>(*this).serialize_unsigned(enc);
            return std::move(enc.bytes());
        }

        [[nodiscard]] header_hash_t hash() const
        {
            header_hash_t res;
            encoder enc {};
            enc.process(*this);
            crypto::blake2b::digest(res, enc.bytes());
            return res;
        }

        [[nodiscard]] entropy_t entropy() const
        {
            entropy_t res;
            if (ark_vrf::ietf_vrf_output(res, entropy_source) != 0) [[unlikely]]
                throw err_bad_signature_t {};
            return res;
        }

        void verify_signatures(const bandersnatch_public_t &vkey, const tickets_or_keys_t<CONSTANTS> &gamma_s, const entropy_t &eta3) const;

        void serialize_unsigned(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("parent"sv, parent);
            archive.process("parent_state_root"sv, parent_state_root);
            archive.process("extrinsic_hash"sv, extrinsic_hash);
            archive.process("slot"sv, slot);
            archive.process("epoch_mark"sv, epoch_mark);
            archive.process("tickets_mark"sv, tickets_mark);
            archive.process("offenders_mark"sv, offenders_mark);
            archive.process("author_index"sv, author_index);
            archive.process("entropy_source"sv, entropy_source);
        }

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            serialize_unsigned(archive);
            archive.process("seal"sv, seal);
        }

        bool operator==(const header_t &o) const
        {
            if (parent != o.parent)
                return false;
            if (parent_state_root != o.parent_state_root)
                return false;
            if (extrinsic_hash != o.extrinsic_hash)
                return false;
            if (slot != o.slot)
                return false;
            if (epoch_mark != o.epoch_mark)
                return false;
            if (tickets_mark != o.tickets_mark)
                return false;
            if (offenders_mark != o.offenders_mark)
                return false;
            if (author_index != o.author_index)
                return false;
            if (entropy_source != o.entropy_source)
                return false;
            if (seal != o.seal)
                return false;
            return true;
        }
    };

    // JAM (4.2)
    template<typename CONSTANTS>
        struct block_t {
        header_t<CONSTANTS> header;
        extrinsic_t<CONSTANTS> extrinsic;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("header"sv, header);
            archive.process("extrinsic"sv, extrinsic);
        }

        bool operator==(const block_t &o) const
        {
            if (header != o.header)
                return false;
            if (extrinsic != o.extrinsic)
                return false;
            return true;
        }
    };

    // JAM (6.3) - Changed: new order k, y_z, y_s, y_a but not reflected in the tests yet
    template<typename CONSTANTS=config_prod>
    struct safrole_state_t {
        validators_data_t<CONSTANTS> k {}; // prior next epoch validator keys and metadata
        bandersnatch_ring_commitment_t z {}; // prior bandersnatch ring commitment
        tickets_or_keys_t<CONSTANTS> s; // prior sealing key series
        tickets_accumulator_t<CONSTANTS> a {}; // prior sealing key ticket accumulator

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("k"sv, k);
            archive.process("z"sv, z);
            archive.process("s"sv, s);
            archive.process("a"sv, a);
        }

        bool operator==(const safrole_state_t &o) const noexcept;
    };

    template<typename CFG>
    struct safrole_output_data_t {
        std::shared_ptr<safrole_state_t<CFG>> gamma_ptr {};
        std::shared_ptr<validators_data_t<CFG>> kappa_ptr {};
        std::shared_ptr<validators_data_t<CFG>> lambda_ptr {};
        optional_t<epoch_mark_t<CFG>> epoch_mark {};
        optional_t<tickets_mark_t<CFG>> tickets_mark {};
    };

    // This data structure is need only because the json names in reports_output_items_t
    // differ from what's encoded in the conformance tests
    struct reports_output_item_t {
        work_report_hash_t work_package_hash;
        exports_root_t segment_tree_root;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("work_package_hash"sv, work_package_hash);
            archive.process("segment_tree_root"sv, segment_tree_root);
        }

        std::strong_ordering operator<=>(const reports_output_item_t &o) const
        {
            if (const auto cmp = work_package_hash <=> o.work_package_hash; cmp == std::weak_ordering::less || cmp == std::weak_ordering::greater)
                return cmp;
            if (const auto cmp = segment_tree_root <=> o.segment_tree_root; cmp == std::weak_ordering::less || cmp == std::weak_ordering::greater)
                return cmp;
            return std::strong_ordering::equal;
        }

        bool operator==(const reports_output_item_t &o) const noexcept
        {
            return work_package_hash <=> o.work_package_hash == std::strong_ordering::equal;
        }
    };
    using reports_output_items_t = sequence_t<reports_output_item_t>;

    struct reports_output_data_t {
        reports_output_items_t reported {};
        sequence_t<ed25519_public_t> reporters {};

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("reported"sv, reported);
            archive.process("reporters"sv, reporters);
        }

        bool operator==(const reports_output_data_t &o) const
        {
            if (reported != o.reported)
                return false;
            if (reporters != o.reporters)
                return false;
            return true;
        }
    };
}
