use std::ptr;
use ark_vrf::reexports::{
    ark_serialize::{self, CanonicalDeserialize, CanonicalSerialize},
};
use ark_vrf::{suites::bandersnatch};
use bandersnatch::{RingProofParams, PcsParams, Output, RingProof};

// This is the IETF `Prove` procedure output as described in section 4.2
// of the Bandersnatch VRF specification
#[derive(CanonicalSerialize, CanonicalDeserialize)]
struct RingVrfSignature {
    output: Output,
    // This contains both the Pedersen proof and actual ring proof.
    proof: RingProof,
}

fn base_ring_proof_params(path: &str) -> &'static PcsParams {
    use std::sync::OnceLock;
    static PARAMS: OnceLock<PcsParams> = OnceLock::new();
    PARAMS.get_or_init(|| {
        use std::{fs::File, io::Read};
        let mut file = File::open(path).unwrap();
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).unwrap();
        PcsParams::deserialize_uncompressed_unchecked(&mut &buf[..]).unwrap()
    })
}

fn ring_proof_params(path: &str, ring_size: usize) -> Option<RingProofParams> {
    match RingProofParams::from_pcs_params(ring_size, base_ring_proof_params(path).clone()) {
        Ok(val) => {
            Some(val)
        }
        Err(_err) => {
            println!("ring_proof_params: RingProofParams::from_pcs_params failed");
            None
        }
    }
}

#[no_mangle]
pub extern "C" fn ring_commitment(out_ptr: *mut u8, vkeys_ptr: *const u8, vkeys_len: usize, path_ptr: *const u8, path_len: usize) -> i32 {
    const VKEY_SZ: usize = 32;
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
    let path = unsafe { std::slice::from_raw_parts(path_ptr, path_len) };
    match ring_proof_params(std::str::from_utf8(path).unwrap(), num_vkeys) {
        Some(ring_params) => {
            let commitment = ring_params.verifier_key(&pts).commitment();
            let mut buf: Vec<u8> = vec![];
            match commitment.serialize_compressed(&mut buf) {
                Ok(_val) => {
                    if buf.len() != 144 {
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
pub extern "C" fn vrf_output(out_ptr: *mut u8, sig_ptr: *const u8) -> i32 {
    const SIG_SZ: usize = 784;
    const HASH_SZ: usize = 32;
    let sig_buf = unsafe { std::slice::from_raw_parts(sig_ptr, SIG_SZ) };
    let sig = RingVrfSignature::deserialize_compressed(sig_buf);
    if sig.is_err() {
        return -1;
    }
    let out_hash = sig.unwrap().output.hash();
    if out_hash.len() < HASH_SZ {
        return -2;
    }
    unsafe { ptr::copy_nonoverlapping(out_hash.as_ptr(), out_ptr, HASH_SZ) };
    return 0;
}