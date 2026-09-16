#pragma once
/* This file is part of TurboJam project: https://github.com/r2rationality/turbojam/
 * Copyright (c) 2026 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/r2rationality/turbojam/blob/main/LICENSE */

#include <initializer_list>
#include <utility>
#include <turbo/jam/host-call.hpp>
#include <turbo/jam/machine.hpp>

namespace turbo::jam::machine {
    struct program_builder_t {
        void set_metadata(uint8_vector metadata) {
            _metadata = std::move(metadata);
        }

        void set_heap_pages(const uint16_t pages) {
            _heap_pages = pages;
        }

        void set_stack_size(const uint32_t size) {
            _stack_size = size;
        }

        void emit(const buffer instruction) {
            static constexpr size_t max_instr_size = max_skip_len + 1U;
            if (instruction.empty() || instruction.size() > max_instr_size) [[unlikely]]
                throw error(fmt::format(
                    "an instruction must contain between 1 and {} bytes but got {}",
                    max_instr_size, instruction.size()
                ));
            const auto offset = _instrs.size();
            _instrs.insert(_instrs.end(), instruction.begin(), instruction.end());
            _mask.resize((_instrs.size() + 7) / 8, 0);
            _mask[offset / 8] |= uint8_t{1} << (offset % 8);
        }

        void emit(const std::initializer_list<uint8_t> instruction) {
            emit(buffer{instruction.begin(), instruction.size()});
        }

        void load(const size_t reg, const register_val_t value) {
            _check_reg(reg);
            const auto low = static_cast<uint32_t>(value);
            const bool short_form = sign_extend(4, low) == value;
            encoder enc{};
            enc.uint_fixed(1, short_form ? 51 : 20); // load_imm / load_imm_64
            enc.uint_fixed(1, reg);
            enc.uint_fixed(short_form ? 4 : 8, short_form ? low : value);
            emit(enc.bytes());
        }

        void move(const size_t dst, const size_t src) {
            _check_reg(dst);
            _check_reg(src);
            emit({100, static_cast<uint8_t>(dst | (src << 4))}); // move_reg
        }

        void ecalli(const int32_t id) {
            encoder enc{};
            enc.uint_fixed(1, 10);
            enc.uint_fixed(4, static_cast<uint32_t>(id));
            emit(enc.bytes());
        }

        void host_call(const host_call_t id, const std::initializer_list<register_val_t> args={}, const register_idx_t base_reg=7U) {
            if (args.size() > registers_t::fixed_size - 7) [[unlikely]]
                throw error("a JAM host call accepts at most six register arguments");
            uint8_t reg = base_reg;
            for (const auto arg: args)
                load(reg++, arg);
            ecalli(std::to_underlying(id));
        }

        void trap() {
            emit({0});
        }

        void loop_forever() {
            emit({40, 0}); // jump to self
        }

        void return_bytes(const address_val_t address, const uint32_t length) {
            load(7, address);
            load(8, length);
            emit({50, 0, 0}); // jump_ind r0, 0
        }

        void pad_code(const address_val_t pc) {
            if (pc < _instrs.size()) [[unlikely]]
                throw error("cannot pad a program backwards");
            while (_instrs.size() < pc)
                trap();
        }

        [[nodiscard]] address_val_t append_readonly(const buffer data) {
            _check_readonly_mutable();
            const auto address = numeric_cast<address_val_t>(config_prod::ZZ_pvm_init_zone_size + _readonly.size());
            _readonly.insert(_readonly.end(), data.begin(), data.end());
            return address;
        }

        [[nodiscard]] address_val_t append_writeable(const buffer data) {
            const auto address = numeric_cast<address_val_t>(2 * config_prod::ZZ_pvm_init_zone_size
                + config_prod::pvm_z_size(_readonly.size()) + numeric_cast<uint32_t>(_writeable.size()));
            _readonly_frozen = true;
            _writeable.insert(_writeable.end(), data.begin(), data.end());
            return address;
        }

        // Pad the code-and-data image, excluding metadata, by extending read-only data.
        void pad_image(const size_t target_size) {
            const auto current_size = data_bytes().size();
            if (current_size > target_size) [[unlikely]]
                throw error("cannot pad an image backwards");
            if (target_size > current_size) {
                _check_readonly_mutable();
                _readonly.resize(_readonly.size() + (target_size - current_size), 0);
            }
        }

        [[nodiscard]] uint8_vector code_bytes() const {
            encoder enc{};
            _encode_code(enc);
            return std::move(enc.bytes());
        }

        [[nodiscard]] uint8_vector data_bytes() const {
            encoder enc{};
            _encode_data(enc);
            return std::move(enc.bytes());
        }

        [[nodiscard]] uint8_vector program_bytes() const {
            encoder enc{};
            _encode_program(enc);
            return std::move(enc.bytes());
        }

        [[nodiscard]] code_t build_code() const {
            return code_t::from_bytes(code_bytes());
        }
    private:
        uint8_vector _metadata{};
        uint8_vector _writeable{};
        uint16_t _heap_pages = 0;
        uint32_t _stack_size = 0;
        uint8_vector _instrs{};
        uint8_vector _mask{};
        uint8_vector _readonly{};
        bool _readonly_frozen = false;

        void _encode_code(encoder &enc) const {
            enc.uint_varlen(0); // jump-table entries
            enc.uint_fixed(1, 0); // jump-table entry width
            enc.uint_varlen(_instrs.size() + 1);
            enc.next_bytes(_instrs);
            enc.uint_fixed(1, 0); // Delimiter trap
            enc.next_bytes(_mask);
            const auto delimiter_bit = _instrs.size() % 8;
            if (delimiter_bit == 0)
                enc.uint_fixed(1, 1); // The delimiter starts a new mask byte.
            else
                enc.bytes().back() |= uint8_t{1} << delimiter_bit;
        }

        void _encode_data(encoder &enc) const {
            enc.uint_fixed(3, _readonly.size());
            enc.uint_fixed(3, _writeable.size());
            enc.uint_fixed(2, _heap_pages);
            enc.uint_fixed(3, _stack_size);
            enc.next_bytes(_readonly);
            enc.next_bytes(_writeable);
            constexpr size_t length_width = 4;
            const auto length_offset = enc.bytes().size();
            enc.uint_fixed(length_width, 0);
            const auto code_offset = enc.bytes().size();
            _encode_code(enc);
            // Encoding may reallocate the buffer, so calculate the address only after it finishes.
            encoder::uint_fixed(
                std::span<uint8_t>{enc.bytes()}.subspan(length_offset, length_width),
                length_width, enc.bytes().size() - code_offset
            );
        }

        void _encode_program(encoder &enc) const {
            enc.uint_varlen(_metadata.size());
            enc.next_bytes(_metadata);
            _encode_data(enc);
        }

        static void _check_reg(const size_t reg) {
            if (reg >= registers_t::fixed_size) [[unlikely]]
                throw error(fmt::format("invalid program register index: {}", reg));
        }

        void _check_readonly_mutable() const {
            if (_readonly_frozen) [[unlikely]]
                throw error("read-only layout is frozen after taking a writable address");
        }
    };
}
