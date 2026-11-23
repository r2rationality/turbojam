#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <boost/circular_buffer.hpp>
#include <turbo/storage/update.hpp>
#include "common.hpp"

namespace turbo::jam {
    template<typename CFG>
    struct ancestry_item_pair_t {
        time_slot_t<CFG> slot{};
        header_hash_t header_hash{};

        void serialize(auto &archive) {
            using namespace std::string_view_literals;
            archive.process("slot"sv, slot);
            archive.process("header_hash"sv, header_hash);
        }

        [[nodiscard]] bool operator==(const ancestry_item_pair_t &o) const =default;
    };

    template<typename CFG>
    using partial_ancestry_t = sequence_t<ancestry_item_pair_t<CFG>, 0, CFG::L_max_lookup_anchor_age>;

    template<typename CFG>
        struct ancestry_item_triplet_t: ancestry_item_pair_t<CFG> {
        std::optional<state_root_t> state_root{};

        void serialize(auto &archive) {
            using namespace std::string_view_literals;
            archive.process(static_cast<ancestry_item_pair_t<CFG> &>(*this));
            archive.process("state_root"sv, state_root);
        }

        [[nodiscard]] bool operator==(const ancestry_item_triplet_t &o) const =default;
    };

    template<typename CFG>
    struct ancestry_item_t: ancestry_item_triplet_t<CFG> {
        std::optional<storage::update::undo_list_t> undo{};

        void serialize(auto &archive) {
            using namespace std::string_view_literals;
            archive.process(static_cast<ancestry_item_triplet_t<CFG> &>(*this));
            archive.process("undo"sv, undo);
        }

        [[nodiscard]] bool operator==(const ancestry_item_t &o) const {
            return static_cast<const ancestry_item_triplet_t<CFG> &>(*this) == static_cast<const ancestry_item_triplet_t<CFG> &>(o);
        }
    };

    // A compatibility class to enable serialization
    template<typename T, size_t MAX>
    struct ring_buffer_t: boost::circular_buffer<T> {
        using base_type = boost::circular_buffer<T>;

        static constexpr size_t min_size = 0;
        static constexpr size_t max_size = MAX;

        ring_buffer_t(): base_type(MAX) {}

        void emplace_back(T value) {
            base_type::push_back(std::move(value));
        }
    };

    template<typename CFG>
    struct ancestry_t {
        using item_t = ancestry_item_t<CFG>;
        using value_type = item_t;
        using storage_t = ring_buffer_t<item_t, CFG::L_max_lookup_anchor_age>;
        using const_iterator = typename storage_t::const_iterator;
        using range_t = std::ranges::subrange<const_iterator>;

        static constexpr size_t max_undo_history = CFG::H_max_blocks_history * 4U;
        static_assert(storage_t::max_size > 0 && max_undo_history > 0, "mac_size and max_undo_history must be greater than zero");

        ancestry_t() =default;

        ancestry_t(const partial_ancestry_t<CFG> &o): ancestry_t{} {
            *this = o;
        }

        void serialize(auto &archive) {
            using namespace std::string_view_literals;
            archive.process("data", _data);
            archive.process("checks_enabled", _checks_enabled);
        }

        const_iterator begin() const { return _data.begin(); }
        const_iterator end() const { return _data.end(); }

        [[nodiscard]] bool empty() const { return size() == 0; }
        [[nodiscard]] size_t size() const { return _data.size(); }
        [[nodiscard]] range_t view() const { return {_data.begin(), _data.end()}; }

        const item_t &back() const {
            return _data.back();
        }

        void clear() { _data.clear(); }

        void truncate(const size_t retained) {
            if (retained > _data.size()) [[unlikely]]
                throw error("ancestry truncation exceeds its size");
            _data.erase_end(_data.size() - retained);
        }

        bool operator==(const ancestry_t &o) const {
            return std::ranges::equal(range_t{_data.begin(), _data.end()}, range_t{o._data.begin(), o._data.end()});
        }

        ancestry_t &operator=(const partial_ancestry_t<CFG> &o) {
            _data.clear();
            for (const auto &item: o)
                add(item.slot, item.header_hash);
            return *this;
        }

        void add(const time_slot_t<CFG> &slot, const header_hash_t &hash,
                 std::optional<state_root_t> sr={}, std::optional<storage::update::undo_list_t> undo={}) {
            _add(item_t{slot, hash, std::move(sr), std::move(undo)});
        }

        const_iterator known(const header_hash_t &parent_hash, const state_root_t &parent_state_root) const {
            const auto parent_it = std::find_if(_data.begin(), _data.end(), [&](const auto &a) {
                return a.header_hash == parent_hash;
            });
            if (parent_it == _data.end()) [[unlikely]]
                throw err_unknown_parent_t{};
            if (parent_it->state_root && *parent_it->state_root != parent_state_root) [[unlikely]]
                throw err_bad_state_root_t{};
            return std::next(parent_it);
        }

        void checks_enabled(const bool new_val) noexcept {
            _checks_enabled = new_val;
        }

        [[nodiscard]] bool checks_enabled() const noexcept {
            return _checks_enabled;
        }
    private:
        storage_t _data{};
        bool _checks_enabled = true;

        void _add(item_t item) {
            if (!_data.empty() && _data.back().slot >= item.slot) [[unlikely]]
                throw error{"ancestry: an attempt to add a block with slot {} after one with slot {}", item.slot, _data.back().slot};
            _data.push_back(std::move(item));
            if (_data.size() > max_undo_history)
                _data[_data.size() - max_undo_history - 1].undo.reset();
        }
    };

    template<typename CFG>
    using ancestry_range_t = typename ancestry_t<CFG>::range_t;
}
