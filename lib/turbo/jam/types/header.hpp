#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <ark-vrf.hpp>
#include <turbo/storage/update.hpp>
#include "ancestry.hpp"

namespace turbo::jam {
    // JAM (4.3)
    template<typename CFG>
    struct extrinsic_t {
        tickets_extrinsic_t<CFG> tickets;
        preimages_extrinsic_t preimages;
        guarantees_extrinsic_t<CFG> guarantees;
        assurances_extrinsic_t<CFG> assurances;
        disputes_extrinsic_t<CFG> disputes;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("tickets"sv, tickets);
            archive.process("preimages"sv, preimages);
            archive.process("guarantees"sv, guarantees);
            archive.process("assurances"sv, assurances);
            archive.process("disputes"sv, disputes);
        }

        bool operator==(const extrinsic_t &o) const = default;
    };

    // JAM (5.1)

    template<typename CFG>
    struct header_t {
        struct prepared_signatures_t {
            entropy_t seal_output{};
            entropy_t entropy_output{};
            uint8_vector unsigned_header{};
        };

        header_hash_t parent{}; // p
        state_root_t parent_state_root{}; // r
        opaque_hash_t extrinsic_hash{}; // x
        time_slot_t<CFG> slot{}; // t
        optional_t<epoch_mark_t<CFG>> epoch_mark{}; // e
        optional_t<tickets_mark_t<CFG>> tickets_mark{}; // w
        validator_index_t author_index{}; // i
        bandersnatch_vrf_signature_t entropy_source{}; // v
        offenders_mark_t offenders_mark{}; // o
        bandersnatch_vrf_signature_t seal{}; // s

        [[nodiscard]] prepared_signatures_t prepare_signatures() const;

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
                throw err_bad_signature_t{};
            return res;
        }

        void verify_signatures(const bandersnatch_public_t &vkey, const tickets_or_keys_t<CFG> &gamma_s,
            const entropy_t &eta3, const prepared_signatures_t &prepared) const;

        void serialize_unsigned(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("parent"sv, parent);
            archive.process("parent_state_root"sv, parent_state_root);
            archive.process("extrinsic_hash"sv, extrinsic_hash);
            archive.process("slot"sv, slot);
            archive.process("epoch_mark"sv, epoch_mark);
            archive.process("tickets_mark"sv, tickets_mark);
            archive.process("author_index"sv, author_index);
            archive.process("entropy_source"sv, entropy_source);
            archive.process("offenders_mark"sv, offenders_mark);
        }

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            serialize_unsigned(archive);
            archive.process("seal"sv, seal);
        }

        bool operator==(const header_t &o) const = default;
    };

    struct preimage_proof_t {
        service_id_t service_id;
        opaque_hash_t hash;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("service_id"sv, service_id);
            archive.process("hash"sv, hash);
        }
    };
    using preimage_proofs_t = sequence_t<preimage_proof_t>;

    // JAM (4.2)
    template<typename CFG>
    struct block_t {
        header_t<CFG> header;
        extrinsic_t<CFG> extrinsic;

        // (5.4), (5.5), (5.6) can be run in parallel
        void verify_extrinsic_hash() const {
            uint8_vector leafs{};
            {
                encoder enc{extrinsic.tickets};
                leafs << crypto::blake2b::digest<opaque_hash_t>(enc.bytes());
            }
            {
                preimage_proofs_t proofs{};
                proofs.reserve(extrinsic.preimages.size());
                for (const auto &p: extrinsic.preimages) {
                    proofs.emplace_back(p.requester, crypto::blake2b::digest<opaque_hash_t>(p.blob));
                }
                encoder enc{proofs};
                leafs << crypto::blake2b::digest<opaque_hash_t>(enc.bytes());
            }
            {
                report_guarantee_infos_t<CFG> g_infos{};
                g_infos.reserve(extrinsic.guarantees.size());
                for (const auto &g: extrinsic.guarantees) {
                    const encoder r_enc{g.report};
                    g_infos.emplace_back(
                        crypto::blake2b::digest<opaque_hash_t>(r_enc.bytes()),
                        g.slot,
                        g.signatures
                    );
                }
                encoder enc{g_infos};
                leafs << crypto::blake2b::digest<opaque_hash_t>(enc.bytes());
            }
            {
                encoder enc{extrinsic.assurances};
                leafs << crypto::blake2b::digest<opaque_hash_t>(enc.bytes());
            }
            {
                encoder enc{extrinsic.disputes};
                leafs << crypto::blake2b::digest<opaque_hash_t>(enc.bytes());
            }
            const auto ex_hash = crypto::blake2b::digest<opaque_hash_t>(leafs);
            if (ex_hash != header.extrinsic_hash) [[unlikely]]
                throw err_bad_extrinsic_hash_t{};
        }

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("header"sv, header);
            archive.process("extrinsic"sv, extrinsic);
        }

        bool operator==(const block_t &o) const = default;
    };

    // JAM (6.3) - Changed: new order k, y_z, y_s, y_a but not reflected in the tests yet
    template<typename CFG=config_prod>
    struct safrole_state_t {
        validators_data_t<CFG> p{}; // pending keys
        bandersnatch_ring_commitment_t z{}; // bandersnatch ring commitment
        tickets_or_keys_t<CFG> s; // sealing key series
        tickets_accumulator_t<CFG> a{}; // sealing key ticket accumulator

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("p"sv, p);
            archive.process("z"sv, z);
            archive.process("s"sv, s);
            archive.process("a"sv, a);
        }

        bool operator==(const safrole_state_t &o) const noexcept = default;
    };

    template<typename CFG>
    struct safrole_output_data_t {
        optional_t<epoch_mark_t<CFG>> epoch_mark{};
        optional_t<tickets_mark_t<CFG>> tickets_mark{};
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
        set_t<ed25519_public_t> reporters {};

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("reported"sv, reported);
            archive.process("reporters"sv, reporters);
        }

        bool operator==(const reports_output_data_t &o) const = default;
    };
}
