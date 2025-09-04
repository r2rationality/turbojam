namespace turbo::jam {
    struct ark_vrf_initialier_t {
        explicit ark_vrf_initialier_t() {
            if (ark_vrf::init(file::install_path("data/zcash-srs-2-11-uncompressed.bin")) != 0) [[unlikely]]
                throw error("ark_vrf_cpp::init() failed");;
        }

        static void init()
        {
            static ark_vrf_initialier_t initializer{};
        }
    };

    template<typename CFG>
    bandersnatch_ring_commitment_t state_t<CFG>::_ring_commitment(const validators_data_t<CFG> &gamma_k)
    {
        using bandesnatch_vkeys_t = std::array<bandersnatch_public_t, CFG::V_validator_count>;
        struct commitment_t {
            bandesnatch_vkeys_t vkeys;
            bandersnatch_ring_commitment_t commitment;
        };
        ark_vrf_initialier_t::init();
        bandesnatch_vkeys_t vkeys;
        for (size_t i = 0; i < CFG::V_validator_count; ++i)
            vkeys[i] = gamma_k[i].bandersnatch;
        static std::optional<commitment_t> prev_commitment{};
        if (!prev_commitment || prev_commitment->vkeys != vkeys) {
            if (!prev_commitment)
                prev_commitment.emplace();
            prev_commitment->vkeys = vkeys;
            if (ark_vrf::ring_commitment(prev_commitment->commitment, buffer{reinterpret_cast<const uint8_t *>(vkeys.data()), sizeof(vkeys)}) != 0) [[unlikely]]
                throw error("failed to generate a ring commitment!");
        }
        return prev_commitment->commitment;
    }

    // (6.26)
    template<typename CFG>
    keys_t<CFG> state_t<CFG>::_fallback_key_sequence(const entropy_t &entropy, const validators_data_t<CFG> &kappa)
    {
        static_assert(std::endian::native == std::endian::little);
        keys_t<CFG> res;
        byte_array<sizeof(entropy) + sizeof(uint32_t)> preimage;
        memcpy(preimage.data(), entropy.data(), entropy.size());
        uint32_t &i = *reinterpret_cast<uint32_t *>(preimage.data() + entropy.size());
        for (i = 0; i < res.size(); ++i) {
            const auto h = crypto::blake2b::digest(preimage);
            const auto next_k = *reinterpret_cast<const uint32_t *>(h.data()) % kappa.size();
            res[i] = kappa[next_k].bandersnatch;
        }
        return res;
    }

    // (6.25): Z
    template<typename CFG>
    tickets_t<CFG> state_t<CFG>::_permute_tickets(const tickets_accumulator_t<CFG> &gamma_a)
    {
        tickets_t<CFG> tickets;
        if (gamma_a.empty() || gamma_a.size() % 2) [[unlikely]]
            throw error(fmt::format("gamma.a size cannot be 0 or odd but got: {}", gamma_a.size()));
        if (gamma_a.size() != tickets.size()) [[unlikely]]
            throw error(fmt::format("unexpected size of gamma.a: got: {} expected: {}", gamma_a.size(), tickets.size()));
        auto left = gamma_a.begin();
        auto right = std::prev(gamma_a.end());
        for (size_t i = 0; i < tickets.size(); ++i) {
            tickets[i] = i & 1U ? *right-- : *left++;
        }
        return tickets;
    }

    // (6.14)
    template<typename CFG>
    validators_data_t<CFG> state_t<CFG>::_capital_phi(const validators_data_t<CFG> &iota, const offenders_mark_t &psi_o)
    {
        validators_data_t<CFG> res;
        for (size_t i = 0; i < iota.size(); ++i) {
            const auto &v = iota[i];
            res[i] = psi_o.contains(v.ed25519) ? validator_data_t{} : v;
        }
        return res;
    }

    template<typename CFG>
    safrole_output_data_t<CFG> state_t<CFG>::update_safrole(
        const entropy_buffer_t &new_eta, const ed25519_keys_set_t &new_offenders,
        const time_slot_t<CFG> &prev_tau, const safrole_state_t<CFG> &prev_gamma,
        const std::shared_ptr<validators_data_t<CFG>> &prev_kappa_ptr, const std::shared_ptr<validators_data_t<CFG>> &prev_lambda_ptr,
        const validators_data_t<CFG> &prev_iota,
        const time_slot_t<CFG> &slot, const tickets_extrinsic_t<CFG> &extrinsic)
    {
        if (slot.epoch_slot() >= CFG::Y_ticket_submission_end && !extrinsic.empty()) [[unlikely]]
            throw err_unexpected_ticket_t {};

        safrole_output_data_t<CFG> res {
            std::make_shared<safrole_state_t<CFG>>(prev_gamma)
        };

        // Epoch transition
        if (slot.epoch() > prev_tau.epoch()) [[unlikely]] {
            // JAM Paper (6.13)
            res.lambda_ptr = std::make_shared<validators_data_t<CFG>>(*prev_kappa_ptr);
            res.kappa_ptr = std::make_shared<validators_data_t<CFG>>(res.gamma_ptr->k);
            res.gamma_ptr->k = _capital_phi(prev_iota, new_offenders);
            res.gamma_ptr->z = _ring_commitment(res.gamma_ptr->k);
            // JAM Paper (6.27) - epoch marker
            res.epoch_mark.emplace(new_eta[1], new_eta[2]);
            for (size_t ki = 0; ki < res.gamma_ptr->k.size(); ++ki) {
                res.epoch_mark->validators[ki].bandersnatch = res.gamma_ptr->k[ki].bandersnatch;
                res.epoch_mark->validators[ki].ed25519 = res.gamma_ptr->k[ki].ed25519;
            }
        } else {
            res.kappa_ptr = prev_kappa_ptr;
            res.lambda_ptr = prev_lambda_ptr;
        }

        // JAM (6.24)
        if (slot.epoch() == prev_tau.epoch() + 1
                && prev_tau.epoch_slot() >= CFG::Y_ticket_submission_end
                && res.gamma_ptr->a.size() == CFG::E_epoch_length) {
            res.gamma_ptr->s = _permute_tickets(res.gamma_ptr->a);
        } else if (slot.epoch() != prev_tau.epoch()) {
            // since the update operates on a copy of the state
            // eta[2] and kappa are the updated "prime" values
            res.gamma_ptr->s = _fallback_key_sequence(new_eta[2], *res.kappa_ptr);
        }

        if (slot.epoch() > prev_tau.epoch()) [[unlikely]] {
            // JAM Paper (6.34)
            res.gamma_ptr->a.clear();
        }

        // JAM Paper (6.28) - winning-tickets marker
        if (slot.epoch() == prev_tau.epoch()
                && prev_tau.epoch_slot() < CFG::Y_ticket_submission_end
                && slot.epoch_slot() >= CFG::Y_ticket_submission_end && res.gamma_ptr->a.size() == CFG::E_epoch_length) {
            res.tickets_mark.emplace(_permute_tickets(res.gamma_ptr->a));
        }

        std::optional<ticket_body_t> prev_ticket {};

        if (!extrinsic.empty()) {
            // (6.34)
            for (const auto &t: extrinsic) {
                if (t.attempt >= CFG::N_ticket_attempts) [[unlikely]]
                    throw err_bad_ticket_attempt_t {};
            }

            static const uint8_vector aux{};
            static constexpr std::string_view input_prefix{"jam_ticket_seal"};
            static constexpr size_t input_size = input_prefix.size() + sizeof(new_eta[2]) + 1U;
            static_assert(input_size == 48U);
            byte_array<input_size> input;
            memcpy(input.data(), input_prefix.data(), input_prefix.size());
            for (const auto &t: extrinsic) {
                memcpy(input.data() + input_prefix.size(), new_eta[2].data(), new_eta[2].size());
                input[input_prefix.size() + new_eta[2].size()] = t.attempt;

                ticket_body_t tb;
                tb.attempt = t.attempt;
                if (ark_vrf::ring_vrf_output(tb.id, t.signature) != 0) [[unlikely]]
                    throw err_bad_ticket_proof_t {};
                if (prev_ticket && *prev_ticket >= tb) [[unlikely]]
                    throw err_bad_ticket_order_t {};
                prev_ticket = tb;
                const auto it = std::lower_bound(res.gamma_ptr->a.begin(), res.gamma_ptr->a.end(), tb);
                if (it != res.gamma_ptr->a.end() && *it == tb) [[unlikely]]
                    throw err_duplicate_ticket_t {};
                if (ark_vrf::ring_vrf_verify(CFG::V_validator_count, res.gamma_ptr->z, t.signature, input, aux) != 0) [[unlikely]]
                    throw err_bad_ticket_proof_t {};
                res.gamma_ptr->a.insert(it, std::move(tb));
            }
        }
        if (res.gamma_ptr->a.size() > res.gamma_ptr->a.max_size)
            res.gamma_ptr->a.resize(res.gamma_ptr->a.max_size);

        return res;
    }
}