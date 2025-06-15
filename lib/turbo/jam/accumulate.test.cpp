/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <turbo/common/test.hpp>
#include "types/errors.hpp"
#include "state.hpp"

namespace {
    using namespace turbo;
    using namespace turbo::jam;
    using namespace std::string_view_literals;

    struct stored_items_config_t {
        std::string key_name = "key";
        std::string val_name = "value";
    };
    using stored_items_t = map_t<byte_sequence_t, byte_sequence_t, stored_items_config_t>;

    struct tmp_account_t {
        service_info_t service;
        stored_items_t storage;
        preimages_t preimages;

        void serialize(auto &archive)
        {
            archive.process("service"sv, service);
            archive.process("storage"sv, storage);
            archive.process("preimages"sv, preimages);
        }
    };

    using tmp_accounts_t = map_t<service_id_t, tmp_account_t, accounts_config_t>;

    template<typename CONSTANTS>
    struct input_t {
        time_slot_t<CONSTANTS> slot;
        work_reports_t<CONSTANTS> reports;

        void serialize(auto &archive)
        {
            archive.process("slot"sv, slot);
            archive.process("reports"sv, reports);
        }

        bool operator==(const input_t &o) const
        {
            if (slot != o.slot)
                return false;
            if (reports != o.reports)
                return false;
            return true;
        }
    };

    struct err_code_t {
        void serialize(auto &)
        {
        }

        bool operator==(const err_code_t &) const
        {
            return true;
        }
    };

    using output_base_t = std::variant<accumulate_root_t, err_code_t>;
    struct output_t: output_base_t {
        using base_type = output_base_t;
        using base_type::base_type;

        void serialize(auto &archive)
        {
            static codec::variant_names_t<base_type> names {
                "ok"sv,
                "err"sv
            };
            archive.template process_variant<base_type>(*this, names);
        }
    };

    template<typename CONSTANTS>
    struct test_case_t {
        input_t<CONSTANTS> in;
        state_t<CONSTANTS> pre;
        output_t out;
        state_t<CONSTANTS> post;

        static void serialize_accounts(auto &archive, const std::string_view name, accounts_t<CONSTANTS> &accs)
        {
            tmp_accounts_t taccs;
            archive.process(name, taccs);
            accs.clear();
            for (auto &&[id, tacc]: taccs) {
                preimages_t storage {};
                for (auto &&[k, v]: tacc.storage) {
                    encoder enc {};
                    enc.uint_fixed(4, id);
                    enc.next_bytes(k);
                    storage[crypto::blake2b::digest<opaque_hash_t>(enc.bytes())] = std::move(v);
                }
                account_t<CONSTANTS> acc {
                    .storage=std::move(storage),
                    .preimages=std::move(tacc.preimages),
                    .info=std::move(tacc.service)
                };
                const auto [it, created] = accs.try_emplace(std::move(id), std::move(acc));
                if (!created) [[unlikely]]
                    throw error(fmt::format("a duplicate account in the service map!"));
            }
        }

        static void serialize_state(const std::string_view name, auto &archive, state_t<CONSTANTS> &st)
        {
            archive.push(name);
            archive.process("slot"sv, st.tau);
            archive.process("entropy"sv, st.eta[0]);
            archive.process("ready_queue"sv, st.nu);
            archive.process("accumulated"sv, st.ksi);
            archive.process("privileges"sv, st.chi);
            archive.process("statistics"sv, st.pi.services);
            serialize_accounts(archive, "accounts"sv, st.delta);
            archive.pop();
        }

        void serialize(auto &archive)
        {
            archive.process("input"sv, in);
            serialize_state("pre_state"sv, archive, pre);
            archive.process("output"sv, out);
            serialize_state("post_state"sv, archive, post);
        }

        bool operator==(const test_case_t &o) const
        {
            if (in != o.in)
                return false;
            if (pre != o.pre)
                return false;
            if (out != o.out)
                return false;
            if (post != o.post)
                return false;
            return true;
        }
    };

    template<typename CFG>
    void test_file(const std::string &path)
    {
        const auto tc = jam::load_obj<test_case_t<CFG>>(path + ".bin");
        {
            const auto j_tc = codec::json::load_obj<test_case_t<CFG>>(path + ".json");
            expect(tc == j_tc) << "the json test case does not match the binary one" << path;
        }
        std::optional<output_t> out {};
        state_t<CFG> res_st = tc.pre;
        try {
            auto tmp_st = tc.pre;
            out.emplace(tmp_st.accumulate(tc.in.slot, tc.in.reports));
            state_t<CFG>::tau_prime(tmp_st.tau, tc.pre.tau, tc.in.slot);
            res_st = std::move(tmp_st);
        } catch (const error &) {
            out.emplace(err_code_t {});
        } catch (const std::exception &ex) {
            expect(false) << ex.what() << path;
        } catch (...) {
            expect(false) << "An unknown error occurred" << path;
        }
        if (out.has_value()) {
            expect(out == tc.out) << path;
            const auto same_state = res_st == tc.post;
            expect(same_state) << path;
            //if (!same_state)
            //    std::cout << fmt::format("{} state diff: {}\n", path, res_st.diff(tc.post));
        } else {
            expect(false) << path;
        }
    }
}

suite turbo_jam_accumulate_suite = [] {
    "turbo::jam::accumulate"_test = [] {
        //test_file<config_tiny>(file::install_path("test/jam-test-vectors/stf/accumulate/tiny/accumulate_ready_queued_reports-1"));
        "tiny test vectors"_test = [] {
            for (const auto &path: file::files_with_ext(file::install_path("test/jam-test-vectors/stf/accumulate/tiny"), ".bin")) {
                test_file<config_tiny>(path.substr(0, path.size() - 4));
            }
        };
        "full test vectors"_test = [] {
            for (const auto &path: file::files_with_ext(file::install_path("test/jam-test-vectors/stf/accumulate/full"), ".bin")) {
                test_file<config_prod>(path.substr(0, path.size() - 4));
            }
        };
    };
};
