/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include "types.hpp"
#include "turbo/codec/json.hpp"

namespace turbo::jam {
    always_accumulate_map_item_t always_accumulate_map_item_t::from_bytes(decoder &dec)
    {
        return {
            dec.decode<decltype(id)>(),
            dec.decode<decltype(gas)>()
        };
    }

    activity_record_t activity_record_t::from_bytes(decoder &dec) {
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

    authorizer_t authorizer_t::from_bytes(decoder &dec)
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

    template<typename CONSTANTS>
    availability_assignment_t<CONSTANTS> availability_assignment_t<CONSTANTS>::from_bytes(decoder &dec)
    {
        return {
            dec.decode<decltype(report)>(),
            dec.decode<decltype(timeout)>()
        };
    }

    template<typename CONSTANTS>
    availability_assignment_t<CONSTANTS> availability_assignment_t<CONSTANTS>::from_json(const boost::json::value &j)
    {
        codec::json::decoder report_dec { j.at("report") };
        return {
            decltype(report)::from(report_dec),
            boost::json::value_to<decltype(timeout)>(j.at("timeout"))
        };
    }

    template struct availability_assignment_t<config_prod>;
    template struct availability_assignment_t<config_tiny>;

    block_info_t block_info_t::from_bytes(decoder &dec)
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

    core_authorizer_t core_authorizer_t::from_bytes(decoder &dec)
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

    lookup_met_map_key_t lookup_met_map_key_t::from_bytes(decoder &dec)
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

    privileges_t privileges_t::from_bytes(decoder &dec)
    {
        return {
            dec.decode<decltype(bless)>(),
            dec.decode<decltype(assign)>(),
            dec.decode<decltype(designate)>(),
            dec.decode<decltype(always_acc)>()
        };
    }

    bool privileges_t::operator==(const privileges_t &o) const
    {
        if (bless != o.bless)
            return false;
        if (assign != o.assign)
            return false;
        if (designate != o.designate)
            return false;
        if (always_acc != o.always_acc)
            return false;
        return true;
    }

    template<typename CONSTANTS>
    ready_record_t<CONSTANTS> ready_record_t<CONSTANTS>::from_bytes(decoder &dec)
    {
        return {
            dec.decode<decltype(report)>(),
            dec.decode<decltype(dependencies)>()
        };
    }

    template<typename CONSTANTS>
    ready_record_t<CONSTANTS> ready_record_t<CONSTANTS>::from_json(const boost::json::value &j)
    {
        codec::json::decoder report_dec { j.at("report") };
        return {
            decltype(report)::from(report_dec),
            decltype(dependencies)::from_json(j.at("dependencies"))
        };
    }

    template struct ready_record_t<config_prod>;
    template struct ready_record_t<config_tiny>;

    template<typename CONSTANTS>
    refine_context_t<CONSTANTS> refine_context_t<CONSTANTS>::from_bytes(decoder &dec)
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

    template<typename CONSTANTS>
    refine_context_t<CONSTANTS> refine_context_t<CONSTANTS>::from_json(const boost::json::value &j)
    {
        codec::json::decoder lookup_anchor_slot_dec { j.at("lookup_anchor_slot") };
        return {
            decltype(anchor)::from_json(j.at("anchor")),
            decltype(state_root)::from_json(j.at("state_root")),
            decltype(beefy_root)::from_json(j.at("beefy_root")),
            decltype(lookup_anchor)::from_json(j.at("lookup_anchor")),
            decltype(lookup_anchor_slot)::from(lookup_anchor_slot_dec),
            decltype(prerequisites)::from_json(j.at("prerequisites"))
        };
    }

    template<typename CONSTANTS>
    void refine_context_t<CONSTANTS>::to_bytes(encoder &enc) const
    {
        anchor.to_bytes(enc);
        state_root.to_bytes(enc);
        beefy_root.to_bytes(enc);
        lookup_anchor.to_bytes(enc);
        lookup_anchor_slot.serialize(enc);
        prerequisites.to_bytes(enc);
    }

    template<typename CONSTANTS>
    bool refine_context_t<CONSTANTS>::operator==(const refine_context_t &o) const
    {
        return anchor == o.anchor && state_root == o.state_root && beefy_root == o.beefy_root
            && lookup_anchor == o.lookup_anchor && lookup_anchor_slot == o.lookup_anchor_slot
            && prerequisites == o.prerequisites;
    }

    template struct refine_context_t<config_prod>;
    template struct refine_context_t<config_tiny>;

    reported_work_package_t reported_work_package_t::from_bytes(decoder &dec)
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

    segment_root_lookup_item segment_root_lookup_item::from_bytes(decoder &dec)
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

    void segment_root_lookup_item::to_bytes(encoder &enc) const
    {
        work_package_hash.to_bytes(enc);
        segment_tree_root.to_bytes(enc);
    }

    service_info_t service_info_t::from_bytes(decoder &dec)
    {
        return {
            dec.decode<decltype(code_hash)>(),
            dec.decode<decltype(balance)>(),
            dec.decode<decltype(min_item_gas)>(),
            dec.decode<decltype(min_memo_gas)>(),
            dec.decode<decltype(bytes)>(),
            dec.decode<decltype(items)>(),
        };
    }

    bool service_info_t::operator==(const service_info_t &o) const noexcept
    {
        if (code_hash != o.code_hash)
            return false;
        if (balance != o.balance)
            return false;
        if (min_item_gas != o.min_item_gas)
            return false;
        if (min_memo_gas != o.min_memo_gas)
            return false;
        if (bytes != o.bytes)
            return false;
        if (items != o.items)
            return false;
        return true;
    }

    template<typename CONSTANTS>
    tickets_or_keys_t<CONSTANTS> tickets_or_keys_t<CONSTANTS>::from_bytes(decoder &dec)
    {
        switch (const auto typ = dec.decode<uint8_t>(); typ) {
            case 0: return { tickets_t<CONSTANTS>::from(dec) };
            case 1: return { keys_t<CONSTANTS>::from(dec) };
            [[unlikely]] default: throw error(fmt::format("unsupported tickets_or_keys_t type: {}", typ));
        }
    }

    template struct tickets_or_keys_t<config_prod>;
    template struct tickets_or_keys_t<config_tiny>;

    template struct time_slot_t<config_prod>;
    template struct time_slot_t<config_tiny>;

    validator_data_t validator_data_t::from_bytes(decoder &dec)
    {
        return {
            dec.decode<decltype(bandersnatch)>(),
            dec.decode<decltype(ed25519)>(),
            dec.decode<decltype(bls)>(),
            dec.decode<decltype(metadata)>()
        };
    }

    work_result_ok_t work_result_ok_t::from_bytes(decoder &dec)
    {
        return {
            dec.decode<decltype(data)>()
        };
    }

    work_result_ok_t work_result_ok_t::from_json(const boost::json::value &j)
    {
        return { decltype(data)::from_json(j) };
    }

    void work_result_ok_t::to_bytes(encoder &enc) const
    {
        data.to_bytes(enc);
    }

    work_exec_result_t work_exec_result_t::from_bytes(decoder &dec)
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

    void work_exec_result_t::to_bytes(encoder &enc) const
    {
        std::visit([&](const auto &cv) {
            using T = std::decay_t<decltype(cv)>;
            if constexpr (std::is_same_v<T, work_result_ok_t>) {
                enc.process_uint<uint8_t>(0);
                cv.to_bytes(enc);
            } else if constexpr (std::is_same_v<T, work_result_out_of_gas_t>) {
                enc.process_uint<uint8_t>(1);
            } else if constexpr (std::is_same_v<T, work_result_panic_t>) {
                enc.process_uint<uint8_t>(2);
            } else if constexpr (std::is_same_v<T, work_result_bad_exports_t>) {
                enc.process_uint<uint8_t>(3);
            } else if constexpr (std::is_same_v<T, work_result_bad_code_t>) {
                enc.process_uint<uint8_t>(4);
            } else if constexpr (std::is_same_v<T, work_result_code_oversize_t>) {
                enc.process_uint<uint8_t>(5);
            } else {
                throw error(fmt::format("unsupported work_exec_result_t type: {}", typeid(T).name()));
            }
        }, *this);
    }

    template<typename CONSTANTS>
    work_package_t<CONSTANTS> work_package_t<CONSTANTS>::from_bytes(decoder &dec)
    {
        return {
            dec.decode<decltype(authorization)>(),
            dec.decode<decltype(auth_code_host)>(),
            dec.decode<decltype(authorizer)>(),
            dec.decode<decltype(context)>(),
            dec.decode<decltype(items)>()
        };
    }

    template<typename CONSTANTS>
    work_package_t<CONSTANTS> work_package_t<CONSTANTS>::from_json(const boost::json::value &j)
    {
        return {
            decltype(authorization)::from_json(j.at("authorization")),
            boost::json::value_to<decltype(auth_code_host)>(j.at("auth_code_host")),
            decltype(authorizer)::from_json(j.at("authorizer")),
            decltype(context)::from_json(j.at("context")),
            decltype(items)::from_json(j.at("items"))
        };
    }

    template struct work_package_t<config_prod>;
    template struct work_package_t<config_tiny>;

    work_package_spec_t work_package_spec_t::from_bytes(decoder &dec)
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

    void work_package_spec_t::to_bytes(encoder &enc) const
    {
        hash.to_bytes(enc);
        enc.uint_fixed(sizeof(length), length);
        erasure_root.to_bytes(enc);
        exports_root.to_bytes(enc);
        enc.uint_fixed(sizeof(exports_count), exports_count);
    }

    template struct work_report_t<config_prod>;
    template struct work_report_t<config_tiny>;
}
