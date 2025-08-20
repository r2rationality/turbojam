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

    template<typename CONSTANTS>
    struct tmp_account_t {
        preimage_items_t preimages;
        lookup_meta_items_t<CONSTANTS> lookup_metas;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("preimages"sv, preimages);
            archive.process("lookup_meta"sv, lookup_metas);
        }
    };
    template<typename CONSTANTS>
    using tmp_accounts_t = map_t<service_id_t, tmp_account_t<CONSTANTS>, accounts_config_t>;

    template<typename CONSTANTS>
    struct input_t {
        preimages_extrinsic_t preimages;
        time_slot_t<CONSTANTS> slot;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("preimages"sv, preimages);
            archive.process("slot"sv, slot);
        }

        bool operator==(const input_t &o) const
        {
            if (preimages != o.preimages)
                return false;
            if (slot != o.slot)
                return false;
            return true;
        }
    };

    struct ok_t {
        void serialize(auto &)
        {
            // do nothing
        }

        bool operator==(const ok_t &) const
        {
            return true;
        }
    };

    using err_code_base_t = std::variant<
        err_preimage_unneeded_t,
        err_preimages_not_sorted_or_unique_t
    >;

    struct err_code_t: err_group_t<err_code_t, err_code_base_t> {
        using base_type = err_group_t;
        using base_type::base_type;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            static_assert(std::variant_size_v<err_code_base_t> > 0);
            static codec::variant_names_t<err_code_base_t> names {
                "preimage_unneeded"sv,
                "preimages_not_sorted_unique"sv
            };
            archive.template process_variant<err_code_base_t>(*this, names);
        }
    };

    struct output_t: std::variant<ok_t, err_code_t> {
        using base_type = std::variant<ok_t, err_code_t>;
        using base_type::base_type;

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            static_assert(std::variant_size_v<base_type> > 0);
            static codec::variant_names_t<base_type> names {
                "ok"sv,
                "err"sv
            };
            archive.template process_variant<base_type>(*this, names);
        }
    };

    template<typename CONSTANTS>
    struct test_case_t {
        file::tmp_directory tmp_dir_pre { fmt::format("test-jam-preimages-{}-pre", static_cast<void *>(this)) };
        file::tmp_directory tmp_dir_post { fmt::format("test-jam-preimages-{}-post", static_cast<void *>(this)) };
        input_t<CONSTANTS> in;
        state_t<CONSTANTS> pre { std::make_shared<triedb::db_t>(tmp_dir_pre.path()) };
        output_t out;
        state_t<CONSTANTS> post { std::make_shared<triedb::db_t>(tmp_dir_post.path()) };

        void serialize_state(auto &archive, const std::string_view name, state_t<CONSTANTS> &st)
        {
            using namespace std::string_view_literals;
            archive.push(name);
            tmp_accounts_t<CONSTANTS> taccs;
            archive.process("accounts"sv, taccs);
            for (auto &&[id, tacc]: taccs) {
                preimages_t preimages{st.triedb, preimages_t::make_trie_key_func(id)};
                for (auto &&[k, v]: tacc.preimages) {
                    preimages.set(k, uint8_vector { static_cast<buffer>(v) });
                }
                lookup_metas_t<CONSTANTS> lookup_metas{st.triedb, lookup_metas_t<CONSTANTS>::make_trie_key_func(id)};
                for (auto &&[k, v]: tacc.lookup_metas) {
                    lookup_metas.set(k, std::move(v));
                }
                st.delta.try_emplace(std::move(id), account_t<CONSTANTS> {
                    .preimages=std::move(preimages),
                    .lookup_metas=std::move(lookup_metas),
                    .storage=service_storage_t { st.triedb, service_storage_t::make_trie_key_func(id) },
                    .info={st.triedb, state_dict_t::make_key(255U, id), {}}
                });
            }
            {
                std::decay_t<typename decltype(st.pi)::element_type> new_pi{};
                archive.process("statistics"sv, new_pi.services);
                st.pi.set(std::move(new_pi));
            }
            archive.pop();
        }

        void serialize(auto &archive)
        {
            using namespace std::string_view_literals;
            archive.process("input"sv, in);
            serialize_state(archive, "pre_state"sv, pre);
            archive.process("output"sv, out);
            serialize_state(archive, "post_state"sv, post);
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
            expect(tc == j_tc) << "json test case does not match the binary one" << path;
        }
        std::optional<output_t> out {};
        auto new_st = tc.pre.working_copy();
        err_code_t::catch_into(
            [&] {
                auto tmp_st = new_st.working_copy();
                auto new_pi = tmp_st.pi.get();
                tmp_st.provide_preimages(new_pi, tc.in.slot, tc.in.preimages);
                tmp_st.pi.set(std::move(new_pi));
                out.emplace(ok_t {});
                new_st.commit(std::move(tmp_st));
            },
            [&](err_code_t err) {
                out.emplace(std::move(err));
            }
        );
        if (out.has_value()) {
            expect(out == tc.out) << path;
            expect(new_st == tc.post) << path;
        } else {
            expect(false) << path;
        }
    }
}

suite turbo_jam_preimages_suite = [] {
    "turbo::jam::preimages"_test = [] {
        //test_file<config_tiny>(file::install_path("test/jam-test-vectors/stf/preimages/data/preimage_not_needed-2"));
        "tiny"_test = [] {
            for (const auto &path: file::files_with_ext(file::install_path("test/jam-test-vectors/stf/preimages/tiny"), ".bin")) {
                test_file<config_tiny>(path.substr(0, path.size() - 4));
            }
        };
        "full"_test = [] {
            for (const auto &path: file::files_with_ext(file::install_path("test/jam-test-vectors/stf/preimages/full"), ".bin")) {
                test_file<config_prod>(path.substr(0, path.size() - 4));
            }
        };
    };
};
