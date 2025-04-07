use std::ptr;
use ark_vrf::{reexports::ark_serialize::{self, CanonicalDeserialize, CanonicalSerialize}, suites::bandersnatch};
use bandersnatch::{BandersnatchSha512Ell2, RingProofParams, PcsParams, Input, Output, RingProof, Public};

const SIG_SZ: usize = 784;
const COMMIT_SZ: usize = 144;
const HASH_SZ: usize = 32;
const VKEY_SZ: usize = 32;

type RingCommitment = ark_vrf::ring::RingCommitment<BandersnatchSha512Ell2>;

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
        match RingProofParams::from_pcs_params(ring_size, params.clone()) {
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
pub extern "C" fn ring_commitment(out_ptr: *mut u8, vkeys_ptr: *const u8, vkeys_len: usize) -> i32 {
    if vkeys_ptr.is_null() || out_ptr.is_null() {
        return -1;
    }
    if vkeys_len % VKEY_SZ != 0 {
        return -2;
    }

    let num_vkeys = vkeys_len / VKEY_SZ;
    let ring: Vec<bandersnatch::Public> = (0 .. num_vkeys)
        .map(|i|
            bandersnatch::Public::deserialize_compressed(unsafe { std::slice::from_raw_parts(vkeys_ptr.wrapping_add(VKEY_SZ * i), VKEY_SZ) })
                .unwrap_or(bandersnatch::Public::from(RingProofParams::padding_point()))
        )
        
        .collect();
    let pts: Vec<_> = ring.iter().map(|pk| pk.0).collect();
    match ring_proof_params(num_vkeys) {
        Some(ring_params) => {
            let commitment = ring_params.verifier_key(&pts).commitment();
            let mut buf: Vec<u8> = vec![];
            match commitment.serialize_compressed(&mut buf) {
                Ok(_val) => {
                    if buf.len() != COMMIT_SZ {
                        return -4;
                    }
                    unsafe {
                        ptr::copy_nonoverlapping(buf.as_ptr(), out_ptr, buf.len());
                    }
                    return 0;
                }
                Err(_e) => {
                    return -3;
                }
            }
        }
        None => {
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn vrf_verify(out_ptr: *mut u8, ring_size: usize, comm_ptr: *const u8,
                            sig_ptr: *const u8, input_ptr: *const u8, input_len: usize,
                            aux_ptr: *const u8, aux_len: usize) -> i32 {
    let params_res = ring_proof_params(ring_size);
    if params_res.is_none() {
        return -1;
    }
    let params = params_res.unwrap();

    let sig_res = RingVrfSignature::deserialize_compressed(unsafe { std::slice::from_raw_parts(sig_ptr, SIG_SZ) });
    if sig_res.is_err() {
        return -1;
    }
    let sig = sig_res.unwrap();

    let commitment_res = RingCommitment::deserialize_compressed(unsafe { std::slice::from_raw_parts(comm_ptr, COMMIT_SZ) });
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

    let out_hash = sig.output.hash();
    if out_hash.len() < HASH_SZ {
        return -1;
    }
    unsafe { ptr::copy_nonoverlapping(out_hash.as_ptr(), out_ptr, HASH_SZ) };
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
        use ark_vrf::ring::Prover;
        let ring_sk: Vec<_> = (0 .. 6)
            .map(|i: usize| Secret::from_seed(&i.to_le_bytes()))
            .collect();
        let ring_vk: Vec<_> = (0 .. 6)
            .map(|i: usize| ring_sk[i].public())
            .collect();
        let prover_idx: usize = 1;
        let params = ring_proof_params(ring_vk.len()).unwrap();
        let pts: Vec<_> = ring_vk.iter().map(|pk| pk.0).collect();
        let prover_key = params.prover_key(&pts);
        let prover = params.prover(prover_key, prover_idx);

        let input_buf = b"abc";
        let aux_buf = b"def";

        let input = Input::new(input_buf).unwrap();
        let output = ring_sk[prover_idx].output(input);

        let proof = ring_sk[prover_idx].prove(input, output, aux_buf, &prover);

        let signature = RingVrfSignature { output, proof };
        let mut sig_buf = Vec::new();
        signature.serialize_compressed(&mut sig_buf).unwrap();

        use ark_vrf::ring::Verifier;

        let verifier_key = params.verifier_key(&pts);
        let comm = verifier_key.clone().commitment();
        let verifier = params.verifier(verifier_key);
        assert_eq!(false, Public::verify(input, signature.output, aux_buf, &signature.proof, &verifier).is_err());

        let mut comm_buf: Vec<u8> = vec![];
        comm.serialize_compressed(&mut comm_buf).unwrap();
        assert_eq!(COMMIT_SZ, comm_buf.len());
    
        let mut out_hash: [u8; HASH_SZ] = [0; HASH_SZ];
        assert_eq!(0, vrf_verify(out_hash.as_mut_ptr(), ring_vk.len(), comm_buf.as_ptr(), sig_buf.as_ptr(), input_buf.as_ptr(), input_buf.len(), aux_buf.as_ptr(), aux_buf.len()));
    }

    #[test]
    fn test_verify() {
        setup();
        let mut ring_comm: [u8; COMMIT_SZ] = [0; COMMIT_SZ];
        assert_eq!(0, ring_commitment(ring_comm.as_mut_ptr(), KEYS.as_ptr(), KEYS.len()));
        assert_eq!(
            hex::decode("85f9095f4abd040839d793d89ab5ff25c61e50c844ab6765e2c0b22373b5a8f6fbe5fc0cd61fdde580b3d44fe1be127197e33b91960b10d2c6fc75aec03f36e16c2a8204961097dbc2c5ba7655543385399cc9ef08bf2e520ccf3b0a7569d88492e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29fe0e9c85ec450505dde7f5ac038274cf").expect("must be hex"),
            ring_comm
        );
        let mut input: Vec<u8> = vec![];
        input.extend_from_slice("$jam_ticket_seal".as_bytes());
        input.extend_from_slice(&hex::decode("bb30a42c1e62f0afda5f0a4e8a562f7a13a24cea00ee81917b86b89e801314aa").expect("must be hex"));
        input.push(1);
        let input_ro: &[u8] = input.as_slice();
        let aux: Vec<u8> = vec![];
        println!("input len: {} hex: {}", input_ro.len(), hex::encode(input_ro));

        let sig = hex::decode("b342bf8f6fa69c745daad2e99c92929b1da2b840f67e5e8015ac22dd1076343e836fc9d73929ef048dcc6496781c6780d127dd8ce3f1e0289c5c4e95afffc8d4a1586aba841ebfdb721ca86e55847036bc84f19a256dbd7a61a362fb088a4b942b566c14a7f8643a5d976ced0a18d12e32c660d59c66c271332138269cb0fe9c591182e7913ec0bbcf2290d9d68ac9d119ae78a52c0655f4f999e9e83a1c3218f65a0318ade1a5cf1d83d4448a06f856b9956a6910da242a5aaa5bcfc8ba3c05b0341a1868fc476a0d6da019b5f2b4e521903b00e937f23b17ea49d6928c615841da5442e5b070079af6cdbbaed964a9b044dcf1ae69ce2e2febec37f6369910a0b20b9dce71b4cd3396e44a90a0a4c404cb170d7ffd2c5467f152bd5daf40b38e3eecc96d13d4c8924740c14e5622b967dc587f10815bde3afe133987852e4e8a41f3501774e7d32f1014c9f0b6162bb332b36043172504aacc83bf6b13fd6018422dc207d58ca1fad63960626ea4eec25932e0b5b23b33c805603523b1f6d11ebc368b87cae1086ac609f862ac0fdab69123cbe8cfe54d45db437a87aad21ec551c394a220be6ef2fb8363352ceaf5a1a71e0b3088a6d65262c13272ac3f6313bb8cec5018414d3fd90dd15df0d56a1f0d0081e7a2abadbdde7efed75c333d4dfa93e8c3c34788a4f526e907483ac69cd7e87f11d373deaf88cf96c7e98068998e1803493a905974b1dbfb6ef38fd5785c6ca5497d21a9046790b04869fa6166067f9860e6de6f566f99ee0f3b4f4d8516c016da65dc429472ec273f7c63553cc1af565824bd9b60841be0a41988bc2ba0757166b68ee928af74d377e9ce6b98d6d6e63f6c2f8c898882fac87025bcee0451c2fea036cff1e9e7186eea4160262e6cabfac77230cd4fc7dc1ba5b025b74081c135b7b47470bc8380b2e13e6b0575b73d86de1f948e4daf8600206e0485d5b468f335f440c574213f98f4099797bd606e11e4f2d48aa5bbda17decd01077655acf756c526fe12a0153b5bd26896ae41b16479d00883649f6044631161d5b454aa4c1bc7be0acb0c82ffb98734f8c7760b930414758e1597b36e1caf71").expect("must be hex");
        assert_eq!(SIG_SZ, sig.len());
        let mut out_hash: [u8; HASH_SZ] = [0; HASH_SZ];
        assert_eq!(0, vrf_verify(out_hash.as_mut_ptr(), 6, ring_comm.as_ptr(), sig.as_ptr(), input_ro.as_ptr(), input_ro.len(), aux.as_ptr(), aux.len()));
        assert_eq!(false, true);
    }
}
