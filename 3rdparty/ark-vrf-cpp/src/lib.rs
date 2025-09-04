use std::ptr;
use ark_vrf::{
    reexports::ark_serialize::{self, CanonicalDeserialize, CanonicalSerialize},
    suites::bandersnatch
};
use bandersnatch::{BandersnatchSha512Ell2, RingProofParams, PcsParams, Input, Output, RingProof, Public, IetfProof};

const IETF_SIG_SZ: usize = 96;
const RING_SIG_SZ: usize = 784;
const RING_COMMIT_SZ: usize = 144;
const HASH_SZ: usize = 32;
const VKEY_SZ: usize = 32;

type RingCommitment = ark_vrf::ring::RingCommitment<BandersnatchSha512Ell2>;

#[derive(CanonicalSerialize, CanonicalDeserialize)]
struct IetfVrfSignature {
    output: Output,
    proof: IetfProof,
}

// This is the IETF `Prove` procedure output as described in section 4.2
// of the Bandersnatch VRF specification
#[derive(CanonicalSerialize, CanonicalDeserialize)]
struct RingVrfSignature {
    output: Output,
    // This contains both the Pedersen proof and actual ring proof.
    proof: RingProof,
}

fn base_ring_proof_params(path_opt: Option<&str>) -> &'static Option<PcsParams> {
    use std::sync::OnceLock;
    static PARAMS: OnceLock<Option<PcsParams>> = OnceLock::new();
    PARAMS.get_or_init(|| {
        match path_opt {
            Some(path) => {
                use std::{fs::File, io::Read};
                let file_res = File::open(path);
                if file_res.is_err() {
                    println!("Failed to open: {}", path);
                    return None;
                }
                let mut file = file_res.unwrap();
                let mut buf = Vec::new();
                if file.read_to_end(&mut buf).is_err() {
                    println!("Failed to read from: {}", path);
                    return None;
                };
                match PcsParams::deserialize_uncompressed_unchecked(&mut &buf[..]) {
                    Ok(val) => {
                        Some(val)
                    }
                    Err(_err) => {
                        println!("Failed to deserialize ark_vrf params: {}", _err);
                        None
                    }
                }
            }
            None => {
                None
            }
        }
    })
}

fn ring_proof_params(ring_size: usize) -> Option<RingProofParams> {
    base_ring_proof_params(None).clone().and_then(|params| {
        match RingProofParams::from_pcs_params(ring_size, params) {
            Ok(val) => {
                Some(val)
            }
            Err(_err) => {
                println!("ring_proof_params: RingProofParams::from_pcs_params failed");
                None
            }
        }
    })
}

#[no_mangle]
pub extern "C" fn init(path_ptr: *const u8, path_len: usize) -> i32 {
    let path = unsafe { std::slice::from_raw_parts(path_ptr, path_len) };
    let path_str = std::str::from_utf8(path);
    if path_str.is_err() {
        return -1;
    }
    match base_ring_proof_params(Some(path_str.unwrap())) {
        Some(_p) => 0,
        None => -2
    }
}

#[no_mangle]
pub extern "C" fn ring_commitment(
    out_ptr: *mut u8,
    out_len: usize,
    vkeys_ptr: *const u8,
    vkeys_len: usize,
) -> i32 {
    if vkeys_ptr.is_null() || out_ptr.is_null() {
        return -1;
    }
    if vkeys_len % VKEY_SZ != 0 {
        return -2;
    }
    if out_len != RING_COMMIT_SZ {
        return -4;
    }

    let num_vkeys = vkeys_len / VKEY_SZ;
    let vkeys = unsafe { std::slice::from_raw_parts(vkeys_ptr, vkeys_len) };

    let mut pts = Vec::with_capacity(num_vkeys);
    let pad_public = bandersnatch::Public::from(RingProofParams::padding_point());
    for chunk in vkeys.chunks_exact(VKEY_SZ) {
        let pk = bandersnatch::Public::deserialize_compressed_unchecked(chunk)
            .unwrap_or_else(|_| pad_public.clone());
        pts.push(pk.0);
    }

    let ring_params = match ring_proof_params(num_vkeys) {
        Some(rp) => rp,
        None => return -1,
    };

    let commitment = ring_params.verifier_key(&pts).commitment();
    let out_slice = unsafe { std::slice::from_raw_parts_mut(out_ptr, out_len) };
    match commitment.serialize_compressed(out_slice.as_mut()) {
        Ok(()) => 0,
        Err(_e) => -3,
    }
}

#[no_mangle]
pub extern "C" fn ring_vrf_output(out_ptr: *mut u8, out_len: usize, sig_ptr: *const u8, sig_len: usize) -> i32 {
    let sig_res = RingVrfSignature::deserialize_compressed_unchecked(unsafe { std::slice::from_raw_parts(sig_ptr, sig_len) });
    if sig_res.is_err() {
        return -1;
    }
    let sig = sig_res.unwrap();

    let out_hash = sig.output.hash();
    if out_hash.len() < HASH_SZ || out_len < HASH_SZ {
        return -1;
    }
    unsafe { ptr::copy_nonoverlapping(out_hash.as_ptr(), out_ptr, HASH_SZ) };
    return 0;
}

#[no_mangle]
pub extern "C" fn ring_vrf_verify(ring_size: usize, comm_ptr: *const u8, comm_len: usize,
                                  sig_ptr: *const u8, sig_len: usize,
                                  input_ptr: *const u8, input_len: usize,
                                  aux_ptr: *const u8, aux_len: usize) -> i32 {
    if comm_len != RING_COMMIT_SZ || sig_len != RING_SIG_SZ {
        return -1;
    }
    let params_res = ring_proof_params(ring_size);
    if params_res.is_none() {
        return -1;
    }
    let params = params_res.unwrap();

    let sig_res = RingVrfSignature::deserialize_compressed_unchecked(unsafe { std::slice::from_raw_parts(sig_ptr, sig_len) });
    if sig_res.is_err() {
        return -1;
    }
    let sig = sig_res.unwrap();

    let commitment_res = RingCommitment::deserialize_compressed_unchecked(unsafe { std::slice::from_raw_parts(comm_ptr, comm_len) });
    if commitment_res.is_err() {
        return -1;
    }
    let commitment = commitment_res.unwrap();

    let verifier_key = params.verifier_key_from_commitment(commitment);
    let verifier = params.verifier(verifier_key);

    let input_res = Input::new(unsafe { std::slice::from_raw_parts(input_ptr, input_len) });
    if input_res.is_none() {
        return -1;
    }
    let input = input_res.unwrap();

    let aux = unsafe { std::slice::from_raw_parts(aux_ptr, aux_len) };
    use ark_vrf::ring::Verifier;

    if Public::verify(input, sig.output, aux, &sig.proof, &verifier).is_err() {
        return -2;
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn ietf_vrf_output(out_ptr: *mut u8, out_len: usize, sig_ptr: *const u8, sig_len: usize) -> i32 {
    if sig_len != IETF_SIG_SZ {
        return -1;
    }
    let sig_res = IetfVrfSignature::deserialize_compressed_unchecked(unsafe { std::slice::from_raw_parts(sig_ptr, sig_len) });
    if sig_res.is_err() {
        return -1;
    }
    let sig = sig_res.unwrap();
    let out_hash = sig.output.hash();
    if out_hash.len() < HASH_SZ || out_len < HASH_SZ {
        return -1;
    }
    unsafe { ptr::copy_nonoverlapping(out_hash.as_ptr(), out_ptr, HASH_SZ) };
    return 0;
}

#[no_mangle]
pub extern "C" fn ietf_vrf_verify(vkey_ptr: *const u8, vkey_len: usize,
                                  sig_ptr: *const u8, sig_len: usize,
                                  input_ptr: *const u8, input_len: usize,
                                  aux_ptr: *const u8, aux_len: usize) -> i32 {
    if vkey_len != VKEY_SZ || sig_len != IETF_SIG_SZ {
        return -1;
    }
    let sig_res = IetfVrfSignature::deserialize_compressed_unchecked(unsafe { std::slice::from_raw_parts(sig_ptr, sig_len) });
    if sig_res.is_err() {
        return -2;
    }
    let sig = sig_res.unwrap();

    let vkey_res = Public::deserialize_compressed_unchecked(unsafe { std::slice::from_raw_parts(vkey_ptr, vkey_len) });
    if vkey_res.is_err() {
        return -3;
    }
    let vkey = vkey_res.unwrap();

    let input_res = Input::new(unsafe { std::slice::from_raw_parts(input_ptr, input_len) });
    if input_res.is_none() {
        return -4;
    }
    let input = input_res.unwrap();

    let aux = unsafe { std::slice::from_raw_parts(aux_ptr, aux_len) };

    use ark_vrf::ietf::Verifier;

    let verify_res = vkey.verify(input, sig.output, aux, &sig.proof);
    if verify_res.is_err() {
        return -5;
    }
    return 0;
}

#[cfg(test)]
mod tests {
    use super::*;
    use once_cell::sync::Lazy;
    use hex::FromHex;
    use bandersnatch::{Secret};

    fn setup() {
        let path = "data/zcash-srs-2-11-uncompressed.bin";
        let path_b = path.as_bytes();
        assert_eq!(0, init(path_b.as_ptr(), path_b.len()));
    }

    static KEYS: Lazy<Vec<u8>> = Lazy::new(|| {
        Vec::from_hex(
            concat!(
                "5e465beb01dbafe160ce8216047f2155dd0569f058afd52dcea601025a8d161d",
                "3d5e5a51aab2b048f8686ecd79712a80e3265a114cc73f14bdb2a59233fb66d0",
                "aa2b95f7572875b0d0f186552ae745ba8222fc0b5bd456554bfe51c68938f8bc",
                "7f6190116d118d643a98878e294ccf62b509e214299931aad8ff9764181a4e33",
                "48e5fcdce10e0b64ec4eebd0d9211c7bac2f27ce54bca6f7776ff6fee86ab3e3",
                "f16e5352840afb47e206b5c89f560f2611835855cf2e6ebad1acc9520a72591d"
            )
        ).unwrap()
    });

    #[test]
    fn test_sign() {
        use ark_vrf::ring::{Prover, Verifier};
        let ring_sk: Vec<_> = (0 .. 6)
            .map(|i: usize| Secret::from_seed(&i.to_le_bytes()))
            .collect();
        let ring_vk: Vec<_> = (0 .. 6)
            .map(|i: usize| ring_sk[i].public())
            .collect();
        let params = ring_proof_params(ring_vk.len()).unwrap();
        let pts: Vec<_> = ring_vk.iter().map(|pk| pk.0).collect();
        let aux_buf = b"";

        let prover_idx: usize = 2;
        let attempt: u8 = 1;
        let prover_key = params.prover_key(&pts);
        let prover = params.prover(prover_key, prover_idx);
        let mut context: Vec<u8> = vec![];
        context.extend_from_slice("jam_ticket_seal".as_bytes());
        context.extend_from_slice(&hex::decode("bb30a42c1e62f0afda5f0a4e8a562f7a13a24cea00ee81917b86b89e801314aa").expect("must be hex"));
        context.push(attempt);
        let input_buf = context.as_slice();
        let input = Input::new(input_buf).unwrap();
        let output = ring_sk[prover_idx].output(input);
        let proof = ring_sk[prover_idx].prove(input, output, aux_buf, &prover);
        let signature = RingVrfSignature { output, proof };
        let mut sig_buf = Vec::new();
        signature.serialize_compressed(&mut sig_buf).unwrap();

        //println!("idx: {} attempt: {} signature: {}", prover_idx, attempt, hex::encode(sig_buf.as_slice()));

        let verifier_key = params.verifier_key(&pts);
        let comm = verifier_key.clone().commitment();
        let verifier = params.verifier(verifier_key);
        assert_eq!(false, Public::verify(input, signature.output, aux_buf, &signature.proof, &verifier).is_err());

        let mut comm_buf: Vec<u8> = vec![];
        comm.serialize_compressed(&mut comm_buf).unwrap();
        assert_eq!(RING_COMMIT_SZ, comm_buf.len());
    
        assert_eq!(0, ring_vrf_verify(ring_vk.len(), comm_buf.as_ptr(), comm_buf.len(),
                      sig_buf.as_ptr(), sig_buf.len(),
                      input_buf.as_ptr(), input_buf.len(), aux_buf.as_ptr(), aux_buf.len()));
    }

    #[test]
    fn test_ring_verify() {
        setup();
        let mut ring_comm: [u8; RING_COMMIT_SZ] = [0; RING_COMMIT_SZ];
        assert_eq!(0, ring_commitment(ring_comm.as_mut_ptr(), ring_comm.len(), KEYS.as_ptr(), KEYS.len()));
        assert_eq!(
            hex::decode("85f9095f4abd040839d793d89ab5ff25c61e50c844ab6765e2c0b22373b5a8f6fbe5fc0cd61fdde580b3d44fe1be127197e33b91960b10d2c6fc75aec03f36e16c2a8204961097dbc2c5ba7655543385399cc9ef08bf2e520ccf3b0a7569d88492e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29fe0e9c85ec450505dde7f5ac038274cf").expect("must be hex"),
            ring_comm
        );

        let mut context: Vec<u8> = vec![];
        context.extend_from_slice("jam_ticket_seal".as_bytes());
        context.extend_from_slice(&hex::decode("bb30a42c1e62f0afda5f0a4e8a562f7a13a24cea00ee81917b86b89e801314aa").expect("must be hex"));
        context.push(1);

        let input_ro: &[u8] = context.as_slice();
        let aux: &[u8; 0] = &[];

        let sig = hex::decode("b342bf8f6fa69c745daad2e99c92929b1da2b840f67e5e8015ac22dd1076343e836fc9d73929ef048dcc6496781c6780d127dd8ce3f1e0289c5c4e95afffc8d4a1586aba841ebfdb721ca86e55847036bc84f19a256dbd7a61a362fb088a4b942b566c14a7f8643a5d976ced0a18d12e32c660d59c66c271332138269cb0fe9c591182e7913ec0bbcf2290d9d68ac9d119ae78a52c0655f4f999e9e83a1c3218f65a0318ade1a5cf1d83d4448a06f856b9956a6910da242a5aaa5bcfc8ba3c05b0341a1868fc476a0d6da019b5f2b4e521903b00e937f23b17ea49d6928c615841da5442e5b070079af6cdbbaed964a9b044dcf1ae69ce2e2febec37f6369910a0b20b9dce71b4cd3396e44a90a0a4c404cb170d7ffd2c5467f152bd5daf40b38e3eecc96d13d4c8924740c14e5622b967dc587f10815bde3afe133987852e4e8a41f3501774e7d32f1014c9f0b6162bb332b36043172504aacc83bf6b13fd6018422dc207d58ca1fad63960626ea4eec25932e0b5b23b33c805603523b1f6d11ebc368b87cae1086ac609f862ac0fdab69123cbe8cfe54d45db437a87aad21ec551c394a220be6ef2fb8363352ceaf5a1a71e0b3088a6d65262c13272ac3f6313bb8cec5018414d3fd90dd15df0d56a1f0d0081e7a2abadbdde7efed75c333d4dfa93e8c3c34788a4f526e907483ac69cd7e87f11d373deaf88cf96c7e98068998e1803493a905974b1dbfb6ef38fd5785c6ca5497d21a9046790b04869fa6166067f9860e6de6f566f99ee0f3b4f4d8516c016da65dc429472ec273f7c63553cc1af565824bd9b60841be0a41988bc2ba0757166b68ee928af74d377e9ce6b98d6d6e63f6c2f8c898882fac87025bcee0451c2fea036cff1e9e7186eea4160262e6cabfac77230cd4fc7dc1ba5b025b74081c135b7b47470bc8380b2e13e6b0575b73d86de1f948e4daf8600206e0485d5b468f335f440c574213f98f4099797bd606e11e4f2d48aa5bbda17decd01077655acf756c526fe12a0153b5bd26896ae41b16479d00883649f6044631161d5b454aa4c1bc7be0acb0c82ffb98734f8c7760b930414758e1597b36e1caf71").expect("must be hex");
        assert_eq!(RING_SIG_SZ, sig.len());
        assert_eq!(0, ring_vrf_verify(6,
                  ring_comm.as_ptr(), ring_comm.len(),
                  sig.as_ptr(), sig.len(),
                  input_ro.as_ptr(), input_ro.len(), aux.as_ptr(), aux.len()));
    }

    #[test]
    fn test_ietf_verify_self_signed_seal() {
        let exp_seal_sig = hex::decode("0f606eb145b063ab8f5e674994c5aded7ccee38e0e465b4fb89a83bdf3d6b75edf17cf7630eb00cd3860017f6365138875e044fe6d080150096ecdb3ba739d08505a7ec9fa9053466032cd1d33bc141ba9ce490b87781796b524237d27844f01").expect("must be hex");
        let exp_seal_output = hex::decode("B7D78259F764212368B40714B24F9CABD95F13F9A655589D654900F005D09F67").expect("must be hex");

        let header_unsigned = hex::decode("26105152A5CA03595E302F6C0DC525C2887DDD54CAF8682BC8E400C86CC3F085F850BE7AF3307147E72EE70331F79FD41E89143B607FD8C42705D71A915F4453189D15AF832DFE4F67744008B62C334B569FCBB4C261E0F065655697306CA25201000000000000040059641E97289901776DA45FBBCEA69E830A9BCA58991A13D8FA27F6706B93D2DB5D645DBB91FF1EAA8AE00AE8BF1F11FB6B9C084540B34DCA06039E3CC8DECC08D92243FB90F5E96333F40259A99CB54A90FB57CD1800180F1A66EE49BE721E0B")
            .expect("must be hex");
        let eta3 = hex::decode("607033ff740f9bc953f1b1bd524a40b155f3ff0f1f35332f066b63cb82c9516c").expect("must be hex");
        let mut input_ctx: Vec<u8> = vec![];
        input_ctx.extend_from_slice("jam_fallback_seal".as_bytes());
        input_ctx.extend_from_slice(eta3.as_slice());
        let seal_input = input_ctx.as_slice();

        let secret = Secret::from_seed(&hex::decode("0bb36f5ba8e3ba602781bb714e67182410440ce18aa800c4cb4dd22525b70409").expect("must be hex"));
        let public = secret.public();
        let input = Input::new(seal_input).unwrap();
        let output = secret.output(input);
        let output_hash = output.hash();
        println!("output_hash: {}", hex::encode(output_hash.as_slice()));
        assert_eq!(exp_seal_output, output_hash[0..HASH_SZ]);
        use ark_vrf::ietf::Prover;
        let proof = secret.prove(input, output, header_unsigned.clone());
        let sig = IetfVrfSignature { output: output.clone(), proof: proof.clone() };
        let mut sig_bytes = Vec::new();
        sig.serialize_compressed(&mut sig_bytes).unwrap();
        println!("sig_bytes: {}", hex::encode(sig_bytes.clone()));
        assert_eq!(sig_bytes, exp_seal_sig);
        use ark_vrf::ietf::Verifier;
        assert!(public.verify(input, output, header_unsigned, &proof).is_ok());
    }

    #[test]
    fn test_ietf_verify_self_signed_vrf() {
        let exp_entropy_sig = hex::decode("59641e97289901776da45fbbcea69e830a9bca58991a13d8fa27f6706b93d2db5d645dbb91ff1eaa8ae00ae8bf1f11fb6b9c084540b34dca06039e3cc8decc08d92243fb90f5e96333f40259a99cb54a90fb57cd1800180f1a66ee49be721e0b").expect("must be hex");
        let exp_entropy_output = hex::decode("ba738c2f537bb77fb8d048f2dc225c50c123604e3d5702d7a0527e94dbab3e3c").expect("must be hex");

        let seal_output = hex::decode("B7D78259F764212368B40714B24F9CABD95F13F9A655589D654900F005D09F67").expect("must be hex");
        let mut input_ctx: Vec<u8> = vec![];
        input_ctx.extend_from_slice("jam_entropy".as_bytes());
        input_ctx.extend_from_slice(seal_output.as_slice());
        let entropy_input = input_ctx.as_slice();

        let secret = Secret::from_seed(&hex::decode("0bb36f5ba8e3ba602781bb714e67182410440ce18aa800c4cb4dd22525b70409").expect("must be hex"));
        let public = secret.public();
        let input = Input::new(entropy_input).unwrap();
        let output = secret.output(input);
        let output_hash = output.hash();
        let aux_data = b"";
        assert_eq!(exp_entropy_output, output_hash[0..HASH_SZ]);
        use ark_vrf::ietf::Prover;
        let proof = secret.prove(input, output, aux_data);
        let sig = IetfVrfSignature { output: output.clone(), proof: proof.clone() };
        let mut sig_bytes = Vec::new();
        sig.serialize_compressed(&mut sig_bytes).unwrap();
        assert_eq!(sig_bytes, exp_entropy_sig);
        use ark_vrf::ietf::Verifier;
        assert!(public.verify(input, output, aux_data, &proof).is_ok());
    }

    #[test]
    fn test_ietf_verify_presigned_vrf() {
        setup();
        let vkey = hex::decode("151e5c8fe2b9d8a606966a79edd2f9e5db47e83947ce368ccba53bf6ba20a40b").expect("must be hex");
        let seal_sig = hex::decode("0f606eb145b063ab8f5e674994c5aded7ccee38e0e465b4fb89a83bdf3d6b75edf17cf7630eb00cd3860017f6365138875e044fe6d080150096ecdb3ba739d08505a7ec9fa9053466032cd1d33bc141ba9ce490b87781796b524237d27844f01").expect("must be hex");
        let mut seal_output: [u8; HASH_SZ] = [0; HASH_SZ];
        assert_eq!(0, ietf_vrf_output(seal_output.as_mut_ptr(), seal_output.len(), seal_sig.as_ptr(), seal_sig.len()));

        let header_unsigned = hex::decode("26105152A5CA03595E302F6C0DC525C2887DDD54CAF8682BC8E400C86CC3F085F850BE7AF3307147E72EE70331F79FD41E89143B607FD8C42705D71A915F4453189D15AF832DFE4F67744008B62C334B569FCBB4C261E0F065655697306CA25201000000000000040059641E97289901776DA45FBBCEA69E830A9BCA58991A13D8FA27F6706B93D2DB5D645DBB91FF1EAA8AE00AE8BF1F11FB6B9C084540B34DCA06039E3CC8DECC08D92243FB90F5E96333F40259A99CB54A90FB57CD1800180F1A66EE49BE721E0B")
            .expect("must be hex");
        let eta3 = hex::decode("607033ff740f9bc953f1b1bd524a40b155f3ff0f1f35332f066b63cb82c9516c").expect("must be hex");
        let mut input_ctx: Vec<u8> = vec![];
        input_ctx.extend_from_slice("jam_fallback_seal".as_bytes());
        input_ctx.extend_from_slice(eta3.as_slice());
        let seal_input = input_ctx.as_slice();

        assert_eq!(0, ietf_vrf_verify(
            vkey.as_ptr(), vkey.len(),
            seal_sig.as_ptr(), seal_sig.len(),
            seal_input.as_ptr(), seal_input.len(),
            header_unsigned.as_ptr(), header_unsigned.len())
        );
    }
}
