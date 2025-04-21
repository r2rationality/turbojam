/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/test.hpp>
#include "errors.hpp"
#include "types.hpp"
#include "state.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jam;

    template<typename CONSTANTS>
    struct input_t {
        assurances_extrinsic_t<CONSTANTS> assurances;
        time_slot_t<CONSTANTS> slot;
        header_hash_t parent;

        static input_t from_bytes(decoder &dec)
        {
            return {
                dec.decode<decltype(assurances)>(),
                dec.decode<decltype(slot)>(),
                dec.decode<decltype(parent)>()
            };
        }
    };

    template<typename CONSTANTS>
    struct output_data_t {
        work_reports_t<CONSTANTS> reported;

        static output_data_t from_bytes(decoder &dec)
        {
            return {
                dec.decode<decltype(reported)>()
            };
        }

        bool operator==(const output_data_t &o) const
        {
            return reported == o.reported;
        }
    };

    struct err_code_t: err_any_t {
        using base_type = err_any_t;
        using base_type::base_type;

        static err_code_t from_bytes(decoder &dec)
        {
            const auto typ = dec.decode<uint8_t>();
            switch (typ) {
                case 0: return { err_bad_attestation_parent_t {} };
                case 1: return { err_bad_validator_index_t {} };
                case 2: return { err_core_not_engaged_t {} };
                case 3: return { err_bad_signature_t {} };
                case 4: return { err_not_sorted_or_unique_assurers {} };
                [[unlikely]] default: throw error(fmt::format("unsupported err_code_t type: {}", typ));
            }
        }
    };

    template<typename CONSTANTS>
    struct output_t: std::variant<output_data_t<CONSTANTS>, err_code_t> {
        using base_type = std::variant<output_data_t<CONSTANTS>, err_code_t>;

        static output_t from_bytes(decoder &dec)
        {
            const auto typ = dec.decode<uint8_t>();
            switch (typ) {
                case 0: return { output_data_t<CONSTANTS>::from_bytes(dec) };
                case 1: return { err_code_t::from_bytes(dec) };
                [[unlikely]] default: throw error(fmt::format("unsupported output_t type: {}", typ));
            }
        }
    };

    template<typename CONSTANTS>
    struct test_case_t {
        input_t<CONSTANTS> input;
        state_t<CONSTANTS> pre_state;
        output_t<CONSTANTS> output;
        state_t<CONSTANTS> post_state;

        static state_t<CONSTANTS> decode_state(decoder &dec)
        {
            // the order of the fields in the test state is different that the one in the regular state
            auto rho = dec.decode<decltype(pre_state.rho)>();
            auto kappa = dec.decode<decltype(pre_state.kappa)>();
            return {
                .kappa=std::move(kappa),
                .rho=std::move(rho)
            };
        }

        static test_case_t from_bytes(decoder &dec)
        {
            return {
                dec.decode<decltype(input)>(),
                decode_state(dec),
                dec.decode<decltype(output)>(),
                decode_state(dec)
            };
        }
    };

    template<typename CFG>
    void test_file(const std::string &path)
    {
        const auto tc = jam::load<test_case_t<CFG>>(path);
        auto new_st = tc.pre_state;
        std::optional<output_t<CFG>> out {};
        err_any_t::catch_into(
            [&] {
                output_data_t<CFG> res {};
                new_st.rho = tc.pre_state.rho.apply(res.reported, tc.pre_state.kappa, tc.input.slot, tc.input.parent, tc.input.assurances);
                out.emplace(std::move(res));
            },
            [&](err_any_t err) {
                std::visit([&](auto &&e) {
                    out.emplace(std::move(e));
                }, std::move(err));
            }
        );
        expect(fatal(out.has_value())) << path;
        expect(out == tc.output) << path;
        expect(new_st == tc.post_state) << path;
    }
}

suite turbo_jam_assurances_suite = [] {
    "turbo::jam::assurances"_test = [] {
        test_file<config_prod>(file::install_path("test/jam-test-vectors/assurances/full/no_assurances_with_stale_report-1.bin"));
        "tiny"_test = [] {
            for (const auto &path: file::files_with_ext(file::install_path("test/jam-test-vectors/assurances/tiny"), ".bin")) {
                test_file<config_tiny>(path);
            }
        };
        "full"_test = [] {
            for (const auto &path: file::files_with_ext(file::install_path("test/jam-test-vectors/assurances/full"), ".bin")) {
                test_file<config_prod>(path);
            }
        };
    };
};
