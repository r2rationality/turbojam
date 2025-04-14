/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include "types.hpp"
#include "turbo/codec/json.hpp"

namespace turbo::jam {
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

    work_exec_result_t work_exec_result_t::from_bytes(decoder &dec)
    {
        const auto typ = dec.decode<uint8_t>();
        switch (typ) {
            case 0: return { work_result_ok_t::from(dec) };
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
        if (name == "ok") {
            codec::json::decoder j_dec { jobj.begin()->value() };
            return { work_result_ok_t::from(j_dec) };
        }
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
                enc.process(cv);
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
}
