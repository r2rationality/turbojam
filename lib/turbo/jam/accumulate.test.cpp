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

    struct preimage_items_config_t {
        std::string key_name = "hash";
        std::string val_name = "blob";
    };
    using preimage_items_t = map_t<opaque_hash_t, byte_sequence_t, preimage_items_config_t>;

    template<typename CFG>
    struct tmp_account_t {
        service_info_t<CFG> service;
        stored_items_t storage;
        preimage_items_t preimages;

        void serialize(auto &archive)
        {
            archive.process("service"sv, service);
            archive.process("storage"sv, storage);
            archive.process("preimages"sv, preimages);
        }
    };

    template<typename CFG>
    using tmp_accounts_t = map_t<service_id_t, tmp_account_t<CFG>, accounts_config_t>;

    template<typename CFG>
    struct input_t {
        time_slot_t<CFG> slot;
        work_reports_t<CFG> reports;

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

    template<typename CFG>
    struct test_case_t {
        file::tmp_directory tmp_dir_pre { fmt::format("test-jam-accumulate-{}-pre", static_cast<void *>(this)) };
        file::tmp_directory tmp_dir_post { fmt::format("test-jam-accumulate-{}-post", static_cast<void *>(this)) };
        input_t<CFG> in;
        state_t<CFG> pre { std::make_shared<triedb::db_t>(tmp_dir_pre.path()) };
        output_t out;
        state_t<CFG> post { std::make_shared<triedb::db_t>(tmp_dir_post.path()) };

        void serialize_accounts(auto &archive, const std::string_view name, state_t<CFG> &st)
        {
            tmp_accounts_t<CFG> taccs;
            archive.process(name, taccs);
            st.delta.clear();
            for (auto &&[id, tacc]: taccs) {
                auto [it, created] = st.delta.try_create(id);
                for (auto &&[k, v]: tacc.storage) {
                    it->second.storage.set(k, static_cast<buffer>(v));
                }
                for (auto &&[k, v]: tacc.preimages) {
                    it->second.preimages.set(k, uint8_vector{v});
                }
                it->second.info.set(std::move(tacc.service));
                if (!created) [[unlikely]]
                    throw error(fmt::format("a duplicate account in the service map!"));
            }
        }

        void serialize_state(const std::string_view name, auto &archive, state_t<CFG> &st)
        {
            archive.push(name);
            archive.process("slot"sv, st.tau);
            {
                std::decay_t<decltype(st.eta.get())> new_eta{};
                archive.process("entropy"sv, new_eta[0]);
                st.eta.set(std::move(new_eta));
            }
            archive.process("ready_queue"sv, st.nu);
            archive.process("accumulated"sv, st.ksi);
            archive.process("privileges"sv, st.chi);
            {
                std::decay_t<decltype(st.pi.get())> new_pi{};
                archive.process("statistics"sv, new_pi.services);
                st.pi.set(std::move(new_pi));
            }
            serialize_accounts(archive, "accounts"sv, st);
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
        state_t<CFG> new_st = tc.pre.working_copy();
        try {
            auto tmp_st = new_st.working_copy();
            auto new_pi = tmp_st.pi.get();
            new_pi.services.clear();
            auto res = tmp_st.accumulate(
                new_pi, tc.pre.eta.get(),
                tc.pre.tau.get(),
                std::make_shared<typename decltype(tc.pre.phi)::element_type>(),
                std::make_shared<typename decltype(tc.pre.iota)::element_type>(),
                tc.pre.chi.storage(),
                tc.pre.nu.storage(), tc.pre.ksi.storage(),
                tc.pre.delta,
                tc.in.slot, tc.in.reports
            );
            // accumulate updates da_load statistics
            new_pi.cores = {};
            out.emplace(res.root);
            tmp_st.nu.set(std::move(res.new_nu));
            tmp_st.ksi.set(std::move(res.new_ksi));
            tmp_st.phi.set(std::move(res.new_phi));
            // Do not update iota since the test cases do not provide such values
            //tmp_st.iota.set(std::move(res.new_iota));
            tmp_st.chi.set(std::move(res.new_chi));
            if (res.service_updates)
                res.service_updates->commit(tmp_st.delta);
            tmp_st.pi.set(std::move(new_pi));
            tmp_st.tau.set(state_t<CFG>::tau_prime(tc.pre.tau.get(), tc.in.slot));
            new_st.commit(std::move(tmp_st));
        } catch (const error &) {
            out.emplace(err_code_t {});
        } catch (const std::exception &ex) {
            expect(false) << ex.what() << path;
        } catch (...) {
            expect(false) << "An unknown error occurred" << path;
        }
        if (out.has_value()) {
            expect(out == tc.out) << path;
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
