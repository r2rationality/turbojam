/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include "types.hpp"

namespace turbo::jam {
    authorizer_t authorizer_t::from_bytes(codec::decoder &dec)
    {
        return {
            dec.decode<decltype(code_hash)>(),
            dec.decode<decltype(params)>()
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

    fault_t fault_t::from_bytes(codec::decoder &dec)
    {
        return {
            dec.decode<decltype(target)>(),
            dec.decode<decltype(vote)>(),
            dec.decode<decltype(key)>(),
            dec.decode<decltype(signature)>()
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

    import_spec_t import_spec_t::from_bytes(codec::decoder &dec)
    {
        return {
            dec.decode<decltype(tree_root)>(),
            dec.decode<decltype(index)>()
        };
    }

    extrinsic_spec_t extrinsic_spec_t::from_bytes(codec::decoder &dec)
    {
        return {
            dec.decode<decltype(hash)>(),
            dec.decode<decltype(len)>()
        };
    }

    preimage_t preimage_t::from_bytes(codec::decoder &dec)
    {
        return {
            dec.decode<decltype(requester)>(),
            dec.decode<decltype(blob)>()
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

    report_guarantee_t report_guarantee_t::from_bytes(codec::decoder &dec)
    {
        return {
            dec.decode<decltype(report)>(),
            dec.decode<decltype(slot)>(),
            dec.decode<decltype(signatures)>()
        };
    }

    segment_root_lookup_item segment_root_lookup_item::from_bytes(codec::decoder &dec)
    {
        return {
            dec.decode<decltype(work_package_hash)>(),
            dec.decode<decltype(segment_tree_root)>()
        };
    }

    ticket_body_t ticket_body_t::from_bytes(codec::decoder &dec)
    {
        return {
            dec.decode<decltype(id)>(),
            dec.decode<decltype(attempt)>()
        };
    }

    ticket_envelope_t ticket_envelope_t::from_bytes(codec::decoder &dec)
    {
        return {
            dec.decode<decltype(attempt)>(),
            dec.decode<decltype(signature)>()
        };
    }

    validator_signature_t validator_signature_t::from_bytes(codec::decoder &dec)
    {
        return {
            dec.decode<decltype(validator_index)>(),
            dec.decode<decltype(signature)>()
        };
    }

    work_result_ok_t work_result_ok_t::from_bytes(codec::decoder &dec)
    {
        return {
            dec.decode<decltype(data)>()
        };
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

    work_item_t work_item_t::from_bytes(codec::decoder &dec)
    {
        return {
            dec.decode<decltype(service)>(),
            dec.decode<decltype(code_hash)>(),
            dec.decode<decltype(payload)>(),
            dec.decode<decltype(refine_gas_limit)>(),
            dec.decode<decltype(accumulate_gas_limit)>(),
            dec.decode<decltype(import_specs)>(),
            dec.decode<decltype(extrinsic_specs)>(),
            dec.decode<decltype(export_count)>()
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

    work_report_t work_report_t::from_bytes(codec::decoder &dec)
    {
        return {
            dec.decode<decltype(package_spec)>(),
            dec.decode<decltype(context)>(),
            dec.decode<decltype(core_index)>(),
            dec.decode<decltype(authorizer_hash)>(),
            dec.decode<decltype(auth_output)>(),
            dec.decode<decltype(segment_root_lookup)>(),
            dec.decode<decltype(results)>()
        };
    }

    work_result_t work_result_t::from_bytes(codec::decoder &dec)
    {
        return {
            dec.decode<decltype(service_id)>(),
            dec.decode<decltype(code_hash)>(),
            dec.decode<decltype(payload_hash)>(),
            dec.decode<decltype(accumulate_gas)>(),
            dec.decode<decltype(result)>()
        };
    }
}
