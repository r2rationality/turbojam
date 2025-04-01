/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <iostream>
#include "types.hpp"
#include "turbo/codec/json.hpp"

namespace turbo::jam {
    always_accumulate_map_item_t always_accumulate_map_item_t::from_bytes(codec::decoder &dec)
    {
        return {
            dec.decode<decltype(id)>(),
            dec.decode<decltype(gas)>()
        };
    }

    activity_record_t activity_record_t::from_bytes(codec::decoder &dec) {
        return {
            dec.decode<decltype(blocks)>(),
            dec.decode<decltype(tickets)>(),
            dec.decode<decltype(pre_images)>(),
            dec.decode<decltype(pre_images_size)>(),
            dec.decode<decltype(guarantees)>(),
            dec.decode<decltype(assurances)>()
        };
    }

    bool activity_record_t::operator==(const activity_record_t &o) const
    {
        return blocks == o.blocks
            && tickets == o.tickets
            && pre_images == o.pre_images
            && pre_images_size == o.pre_images_size
            && guarantees == o.guarantees
            && assurances == o.assurances;
    }

    authorizer_t authorizer_t::from_bytes(codec::decoder &dec)
    {
        return {
            dec.decode<decltype(code_hash)>(),
            dec.decode<decltype(params)>()
        };
    }

    authorizer_t authorizer_t::from_json(const boost::json::value &j)
    {
        return {
            decltype(code_hash)::from_json(j.at("code_hash")),
            decltype(params)::from_json(j.at("params"))
        };
    }

    availability_assignment_t availability_assignment_t::from_bytes(codec::decoder &dec)
    {
        return {
            dec.decode<decltype(report)>(),
            dec.decode<decltype(timeout)>()
        };
    }

    availability_assignment_t availability_assignment_t::from_json(const boost::json::value &j)
    {
        return {
            decltype(report)::from_json(j.at("report")),
            boost::json::value_to<decltype(timeout)>(j.at("timeout"))
        };
    }

    block_info_t block_info_t::from_bytes(codec::decoder &dec)
    {
        return {
            dec.decode<decltype(header_hash)>(),
            dec.decode<decltype(mmr)>(),
            dec.decode<decltype(state_root)>(),
            dec.decode<decltype(reported)>()
        };
    }

    block_info_t block_info_t::from_json(const boost::json::value &j)
    {
        return {
            decltype(header_hash)::from_json(j.at("header_hash")),
            decltype(mmr)::from_json(j.at("mmr")),
            decltype(state_root)::from_json(j.at("state_root")),
            decltype(reported)::from_json(j.at("reported"))
        };
    }

    byte_sequence_t byte_sequence_t::from_bytes(codec::decoder &dec)
    {
        const auto sz = dec.uint_general();
        return { dec.next_bytes(sz) };
    }

    byte_sequence_t byte_sequence_t::from_json(const boost::json::value &j)
    {
        const auto hex = boost::json::value_to<std::string_view>(j);
        if (!hex.starts_with("0x")) [[unlikely]]
            throw error(fmt::format("expected a string begining with 0x but got: {}", hex));
        return from_hex<byte_sequence_t>(hex.substr(2));
    }

    core_authorizer_t core_authorizer_t::from_bytes(codec::decoder &dec)
    {
        return {
            dec.decode<decltype(core)>(),
            dec.decode<decltype(auth_hash)>()
        };
    }

    core_authorizer_t core_authorizer_t::from_json(const boost::json::value &j)
    {
        return {
            boost::json::value_to<decltype(core)>(j.at("core")),
            decltype(auth_hash)::from_json(j.at("auth_hash"))
        };
    }

    culprit_t culprit_t::from_bytes(codec::decoder &dec)
    {
        return {
            dec.decode<decltype(target)>(),
            dec.decode<decltype(key)>(),
            dec.decode<decltype(signature)>()
        };
    }

    culprit_t culprit_t::from_json(const boost::json::value &j)
    {
        return {
            decltype(target)::from_json(j.at("target")),
            decltype(key)::from_json(j.at("key")),
            decltype(signature)::from_json(j.at("signature"))
        };
    }

    epoch_mark_validator_keys_t epoch_mark_validator_keys_t::from_bytes(codec::decoder &dec)
    {
        return {
            dec.decode<decltype(bandersnatch)>(),
            dec.decode<decltype(ed25519)>()
        };
    }

    epoch_mark_validator_keys_t epoch_mark_validator_keys_t::from_json(const boost::json::value &j)
    {
        return {
            decltype(bandersnatch)::from_json(j.at("bandersnatch")),
            decltype(ed25519)::from_json(j.at("ed25519"))
        };
    }

    fault_t fault_t::from_bytes(codec::decoder &dec)
    {
        return {
            dec.decode<decltype(target)>(),
            dec.decode<decltype(vote)>(),
            dec.decode<decltype(key)>(),
            dec.decode<decltype(signature)>()
        };
    }

    fault_t fault_t::from_json(const boost::json::value &j)
    {
        return {
            decltype(target)::from_json(j.at("target")),
            boost::json::value_to<decltype(vote)>(j.at("vote")),
            decltype(key)::from_json(j.at("key")),
            decltype(signature)::from_json(j.at("signature"))
        };
    }

    judgement_t judgement_t::from_bytes(codec::decoder &dec)
    {
        return {
            dec.decode<decltype(vote)>(),
            dec.decode<decltype(index)>(),
            dec.decode<decltype(signature)>()
        };
    }

    judgement_t judgement_t::from_json(const boost::json::value &j)
    {
        return {
            boost::json::value_to<decltype(vote)>(j.at("vote")),
            boost::json::value_to<decltype(index)>(j.at("index")),
            decltype(signature)::from_json(j.at("signature"))
        };
    }

    import_spec_t import_spec_t::from_bytes(codec::decoder &dec)
    {
        return {
            dec.decode<decltype(tree_root)>(),
            dec.decode<decltype(index)>()
        };
    }

    import_spec_t import_spec_t::from_json(const boost::json::value &j)
    {
        return {
            decltype(tree_root)::from_json(j.at("tree_root")),
            boost::json::value_to<decltype(index)>(j.at("index"))
        };
    }

    extrinsic_spec_t extrinsic_spec_t::from_bytes(codec::decoder &dec)
    {
        return {
            dec.decode<decltype(hash)>(),
            dec.decode<decltype(len)>()
        };
    }

    extrinsic_spec_t extrinsic_spec_t::from_json(const boost::json::value &json)
    {
        return {
            decltype(hash)::from_json(json.at("hash")),
            boost::json::value_to<decltype(len)>(json.at("len"))
        };
    }

    lookup_met_map_key_t lookup_met_map_key_t::from_bytes(codec::decoder &dec)
    {
        return {
            dec.decode<decltype(hash)>(),
            dec.decode<decltype(length)>()
        };
    }

    lookup_met_map_key_t lookup_met_map_key_t::from_json(const boost::json::value &j)
    {
        return {
            decltype(hash)::from_json(j.at("hash")),
            boost::json::value_to<decltype(length)>(j.at("length"))
        };
    }

    preimage_t preimage_t::from_bytes(codec::decoder &dec)
    {
        return {
            dec.decode<decltype(requester)>(),
            dec.decode<decltype(blob)>()
        };
    }

    preimage_t preimage_t::from_json(const boost::json::value &j)
    {
        return {
            boost::json::value_to<decltype(requester)>(j.at("requester")),
            decltype(blob)::from_json(j.at("blob"))
        };
    }

    ready_record_t ready_record_t::from_bytes(codec::decoder &dec)
    {
        return {
            dec.decode<decltype(report)>(),
            dec.decode<decltype(dependencies)>()
        };
    }

    refine_context_t refine_context_t::from_bytes(codec::decoder &dec)
    {
        return {
            dec.decode<decltype(anchor)>(),
            dec.decode<decltype(state_root)>(),
            dec.decode<decltype(beefy_root)>(),
            dec.decode<decltype(lookup_anchor)>(),
            dec.decode<decltype(lookup_anchor_slot)>(),
            dec.decode<decltype(prerequisites)>()
        };
    }

    refine_context_t refine_context_t::from_json(const boost::json::value &j)
    {
        return {
            decltype(anchor)::from_json(j.at("anchor")),
            decltype(state_root)::from_json(j.at("state_root")),
            decltype(beefy_root)::from_json(j.at("beefy_root")),
            decltype(lookup_anchor)::from_json(j.at("lookup_anchor")),
            boost::json::value_to<decltype(lookup_anchor_slot)>(j.at("lookup_anchor_slot")),
            decltype(prerequisites)::from_json(j.at("prerequisites"))
        };
    }

    bool refine_context_t::operator==(const refine_context_t &o) const
    {
        return anchor == o.anchor && state_root == o.state_root && beefy_root == o.beefy_root
            && lookup_anchor == o.lookup_anchor && lookup_anchor_slot == o.lookup_anchor_slot
            && prerequisites == o.prerequisites;
    }

    refine_load_t refine_load_t::from_bytes(codec::decoder &dec)
    {
        return {
            dec.uint_general<decltype(gas_used)>(),
            dec.uint_general<decltype(imports)>(),
            dec.uint_general<decltype(extrinsic_count)>(),
            dec.uint_general<decltype(extrinsic_size)>(),
            dec.uint_general<decltype(exports)>()
        };
    }

    refine_load_t refine_load_t::from_json(const boost::json::value &j)
    {
        return {
            boost::json::value_to<decltype(gas_used)>(j.at("gas_used")),
            boost::json::value_to<decltype(imports)>(j.at("imports")),
            boost::json::value_to<decltype(extrinsic_count)>(j.at("extrinsic_count")),
            boost::json::value_to<decltype(extrinsic_size)>(j.at("extrinsic_size")),
            boost::json::value_to<decltype(exports)>(j.at("exports"))
        };
    }

    report_guarantee_t report_guarantee_t::from_bytes(codec::decoder &dec)
    {
        return {
            dec.decode<decltype(report)>(),
            dec.decode<decltype(slot)>(),
            dec.decode<decltype(signatures)>()
        };
    }

    report_guarantee_t report_guarantee_t::from_json(const boost::json::value &j)
    {
        return {
            decltype(report)::from_json(j.at("report")),
            boost::json::value_to<decltype(slot)>(j.at("slot")),
            decltype(signatures)::from_json(j.at("signatures"))
        };
    }

    reported_work_package_t reported_work_package_t::from_bytes(codec::decoder &dec)
    {
        return {
            dec.decode<decltype(hash)>(),
            dec.decode<decltype(exports_root)>()
        };
    }

    reported_work_package_t reported_work_package_t::from_json(const boost::json::value &j)
    {
        return {
            decltype(hash)::from_json(j.at("hash")),
            decltype(exports_root)::from_json(j.at("exports_root"))
        };
    }

    segment_root_lookup_item segment_root_lookup_item::from_bytes(codec::decoder &dec)
    {
        return {
            dec.decode<decltype(work_package_hash)>(),
            dec.decode<decltype(segment_tree_root)>()
        };
    }

    segment_root_lookup_item segment_root_lookup_item::from_json(const boost::json::value &j)
    {
        return {
            decltype(work_package_hash)::from_json(j.at("work_package_hash")),
            decltype(segment_tree_root)::from_json(j.at("segment_tree_root"))
        };
    }

    ticket_body_t ticket_body_t::from_bytes(codec::decoder &dec)
    {
        return {
            dec.decode<decltype(id)>(),
            dec.decode<decltype(attempt)>()
        };
    }

    ticket_body_t ticket_body_t::from_json(const boost::json::value &j)
    {
        return {
            decltype(id)::from_json(j.at("id")),
            boost::json::value_to<decltype(attempt)>(j.at("attempt"))
        };
    }

    ticket_envelope_t ticket_envelope_t::from_bytes(codec::decoder &dec)
    {
        return {
            dec.decode<decltype(attempt)>(),
            dec.decode<decltype(signature)>()
        };
    }

    ticket_envelope_t ticket_envelope_t::from_json(const boost::json::value &j)
    {
        return {
            boost::json::value_to<decltype(attempt)>(j.at("attempt")),
            decltype(signature)::from_json(j.at("signature"))
        };
    }

    validator_data_t validator_data_t::from_bytes(codec::decoder &dec)
    {
        return {
            dec.decode<decltype(bandersnatch)>(),
            dec.decode<decltype(ed25519)>(),
            dec.decode<decltype(bls)>(),
            dec.decode<decltype(metadata)>()
        };
    }

    validator_signature_t validator_signature_t::from_bytes(codec::decoder &dec)
    {
        return {
            dec.decode<decltype(validator_index)>(),
            dec.decode<decltype(signature)>()
        };
    }

    validator_signature_t validator_signature_t::from_json(const boost::json::value &j)
    {
        return {
            boost::json::value_to<decltype(validator_index)>(j.at("validator_index")),
            decltype(signature)::from_json(j.at("signature"))
        };
    }

    work_result_ok_t work_result_ok_t::from_bytes(codec::decoder &dec)
    {
        return {
            dec.decode<decltype(data)>()
        };
    }

    work_result_ok_t work_result_ok_t::from_json(const boost::json::value &j)
    {
        return { decltype(data)::from_json(j) };
    }

    work_exec_result_t work_exec_result_t::from_bytes(codec::decoder &dec)
    {
        const auto typ = dec.decode<uint8_t>();
        switch (typ) {
            case 0: return { work_result_ok_t::from_bytes(dec) };
            case 1: return { work_result_out_of_gas_t {} };
            case 2: return { work_result_panic_t {} };
            case 3: return { work_result_bad_exports_t {} };
            case 4: return { work_result_bad_code_t {} };
            case 5: return { work_result_code_oversize_t {} };
            [[unlikely]] default: throw error(fmt::format("unsupported work_exec_result_t type: {}", typ));
        }
    }

    work_exec_result_t work_exec_result_t::from_json(const boost::json::value &j)
    {
        const auto &jobj = j.as_object();
        if (jobj.size() != 1) [[unlikely]]
            throw error(fmt::format("expected the map to have just one element but got: {}", boost::json::serialize(j)));
        const auto name = jobj.begin()->key();
        if (name == "ok")
            return { work_result_ok_t::from_json(jobj.begin()->value()) };
        if (name == "out_of_gas")
            return { work_result_out_of_gas_t {} };
        if (name == "panic")
            return { work_result_panic_t {} };
        if (name == "bad_exports")
            return { work_result_bad_exports_t {} };
        if (name == "bad_code")
            return { work_result_bad_code_t {} };
        if (name == "code_oversize")
            return { work_result_code_oversize_t {} };
        throw error(fmt::format("unexpected work_exec_result_t key {}", name));
    }

    work_item_t work_item_t::from_bytes(codec::decoder &dec)
    {
        return {
            dec.decode<decltype(service)>(),
            dec.decode<decltype(code_hash)>(),
            dec.decode<decltype(payload)>(),
            dec.decode<decltype(refine_gas_limit)>(),
            dec.decode<decltype(accumulate_gas_limit)>(),
            dec.decode<decltype(import_segments)>(),
            dec.decode<decltype(extrinsic)>(),
            dec.decode<decltype(export_count)>()
        };
    }

    work_item_t work_item_t::from_json(const boost::json::value &j)
    {
        return {
            boost::json::value_to<decltype(service)>(j.at("service")),
            decltype(code_hash)::from_json(j.at("code_hash")),
            decltype(payload)::from_json(j.at("payload")),
            boost::json::value_to<decltype(refine_gas_limit)>(j.at("refine_gas_limit")),
            boost::json::value_to<decltype(accumulate_gas_limit)>(j.at("accumulate_gas_limit")),
            decltype(import_segments)::from_json(j.at("import_segments")),
            decltype(extrinsic)::from_json(j.at("extrinsic")),
            boost::json::value_to<decltype(export_count)>(j.at("export_count"))
        };
    }

    work_package_t work_package_t::from_bytes(codec::decoder &dec)
    {
        return {
            dec.decode<decltype(authorization)>(),
            dec.decode<decltype(auth_code_host)>(),
            dec.decode<decltype(authorizer)>(),
            dec.decode<decltype(context)>(),
            dec.decode<decltype(items)>()
        };
    }

    work_package_t work_package_t::from_json(const boost::json::value &j)
    {
        return {
            decltype(authorization)::from_json(j.at("authorization")),
            boost::json::value_to<decltype(auth_code_host)>(j.at("auth_code_host")),
            decltype(authorizer)::from_json(j.at("authorizer")),
            decltype(context)::from_json(j.at("context")),
            decltype(items)::from_json(j.at("items"))
        };
    }

    work_package_spec_t work_package_spec_t::from_bytes(codec::decoder &dec)
    {
        return {
            dec.decode<decltype(hash)>(),
            dec.decode<decltype(length)>(),
            dec.decode<decltype(erasure_root)>(),
            dec.decode<decltype(exports_root)>(),
            dec.decode<decltype(exports_count)>()
        };
    }

    work_package_spec_t work_package_spec_t::from_json(const boost::json::value &j)
    {
        return {
            decltype(hash)::from_json(j.at("hash")),
            boost::json::value_to<decltype(length)>(j.at("length")),
            decltype(erasure_root)::from_json(j.at("erasure_root")),
            decltype(exports_root)::from_json(j.at("exports_root")),
            boost::json::value_to<decltype(exports_count)>(j.at("exports_count"))
        };
    }

    work_report_t work_report_t::from_bytes(codec::decoder &dec)
    {
        return {
            dec.decode<decltype(package_spec)>(),
            dec.decode<decltype(context)>(),
            dec.decode<decltype(core_index)>(),
            dec.decode<decltype(authorizer_hash)>(),
            dec.decode<decltype(auth_output)>(),
            dec.decode<decltype(segment_root_lookup)>(),
            dec.decode<decltype(results)>(),
            dec.uint_general<decltype(auth_gas_used)>()
        };
    }

    work_report_t work_report_t::from_json(const boost::json::value &json)
    {
        return {
            decltype(package_spec)::from_json(json.at("package_spec")),
            decltype(context)::from_json(json.at("context")),
            boost::json::value_to<decltype(core_index)>(json.at("core_index")),
            decltype(authorizer_hash)::from_json(json.at("authorizer_hash")),
            decltype(auth_output)::from_json(json.at("auth_output")),
            decltype(segment_root_lookup)::from_json(json.at("segment_root_lookup")),
            decltype(results)::from_json(json.at("results")),
            boost::json::value_to<decltype(auth_gas_used)>(json.at("auth_gas_used"))
        };
    }

    work_result_t work_result_t::from_bytes(codec::decoder &dec)
    {
        return {
            dec.decode<decltype(service_id)>(),
            dec.decode<decltype(code_hash)>(),
            dec.decode<decltype(payload_hash)>(),
            dec.decode<decltype(accumulate_gas)>(),
            dec.decode<decltype(result)>(),
            dec.decode<decltype(refine_load)>()
        };
    }

    work_result_t work_result_t::from_json(const boost::json::value &j)
    {
        return {
            boost::json::value_to<decltype(service_id)>(j.at("service_id")),
            decltype(code_hash)::from_json(j.at("code_hash")),
            decltype(payload_hash)::from_json(j.at("payload_hash")),
            boost::json::value_to<decltype(accumulate_gas)>(j.at("accumulate_gas")),
            decltype(result)::from_json(j.at("result")),
            decltype(refine_load)::from_json(j.at("refine_load"))
        };
    }
}
