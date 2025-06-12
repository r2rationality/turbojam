#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

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

    template<typename CONSTANTS>
    struct safrole_output_data_t {
        optional_t<epoch_mark_t<CONSTANTS>> epoch_mark;
        optional_t<tickets_mark_t<CONSTANTS>> tickets_mark;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("epoch_mark"sv, epoch_mark);
            archive.process("tickets_mark"sv, tickets_mark);
        }

        bool operator==(const safrole_output_data_t &o) const
        {
            if (epoch_mark != o.epoch_mark)
                return false;
            if (tickets_mark != o.tickets_mark)
                return false;
            return true;
        }
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
        reports_output_items_t reported;
        sequence_t<ed25519_public_t> reporters;

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
