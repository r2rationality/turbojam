/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/test.hpp>
#include "types.hpp"
#include "state.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jam;

    template<typename CONSTANTS>
    struct input_t {
        assurances_extrinsic_t<CONSTANTS> assurances;
        time_slot_t slot;
        header_hash_t parent;

        static input_t from_bytes(codec::decoder &dec)
        {
            return {
                dec.decode<decltype(assurances)>(),
                dec.decode<decltype(slot)>(),
                dec.decode<decltype(parent)>()
            };
        }
    };

    struct output_data_t {
        work_reports_t reported;

        static output_data_t from_bytes(codec::decoder &dec)
        {
            return {
                dec.decode<decltype(reported)>()
            };
        }
    };

    struct err_bad_attestation_parent_t {};
    struct err_bad_validator_index_t {};
    struct err_core_not_engaged_t {};
    struct err_bad_signature_t {};
    struct err_not_sorted_or_unique_assurers {};

    struct err_code_t: std::variant<err_bad_attestation_parent_t, err_bad_validator_index_t, err_core_not_engaged_t, err_bad_signature_t, err_not_sorted_or_unique_assurers> {
        using base_type = std::variant<err_bad_attestation_parent_t, err_bad_validator_index_t, err_core_not_engaged_t, err_bad_signature_t, err_not_sorted_or_unique_assurers>;
        using base_type::base_type;

        static err_code_t from_bytes(codec::decoder &dec)
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

    struct output_t: std::variant<output_data_t, err_code_t> {
        using base_type = std::variant<output_data_t, err_code_t>;

        static output_t from_bytes(codec::decoder &dec)
        {
            const auto typ = dec.decode<uint8_t>();
            switch (typ) {
                case 0: return { output_data_t::from_bytes(dec) };
                case 1: return { err_code_t::from_bytes(dec) };
                [[unlikely]] default: throw error(fmt::format("unsupported output_t type: {}", typ));
            }
        }
    };

    template<typename CONSTANTS>
    struct test_case_t {
        input_t<CONSTANTS> input;
        state_t<CONSTANTS> pre_state;
        output_t output;
        state_t<CONSTANTS> post_state;

        static state_t<CONSTANTS> decode_state(codec::decoder &dec)
        {
            // the order of the fields in the test state is different that the one in the regular state
            auto ro = dec.decode<decltype(pre_state.ro)>();
            auto kappa = dec.decode<decltype(pre_state.kappa)>();
            return {
                .kappa=std::move(kappa),
                .ro=std::move(ro)
            };
        }

        static test_case_t from_bytes(codec::decoder &dec)
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
    void test_file(const std::string &path, const std::source_location &loc=std::source_location::current())
    {
        const auto tc = codec::load<test_case_t<CFG>>(path);
        //const auto new_alpha = tc.pre_state.alpha.apply(tc.input.slot, tc.input.auths, tc.pre_state.phi);
        //expect(new_alpha == tc.post_state.alpha) << path;
        expect(false);
    }
}

suite turbo_jam_assurances_suite = [] {
    "turbo::jam::assurances"_test = [] {
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
