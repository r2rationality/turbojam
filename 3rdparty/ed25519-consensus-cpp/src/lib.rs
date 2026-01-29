use ed25519_consensus::{Signature, VerificationKey};
use core::convert::TryFrom;

#[no_mangle]
pub extern "C" fn zip215_ed25519_verify(
    pubkey32: *const u8,
    sig64: *const u8,
    msg: *const u8,
    msg_len: usize,
) -> i32 {
    if pubkey32.is_null() || sig64.is_null() || (msg.is_null() && msg_len != 0) {
        return -2; // invalid args
    }

    let pk = unsafe { core::slice::from_raw_parts(pubkey32, 32) };
    let sig = unsafe { core::slice::from_raw_parts(sig64, 64) };
    let m = unsafe { core::slice::from_raw_parts(msg, msg_len) };

    let vk = match VerificationKey::try_from(<[u8; 32]>::try_from(pk).unwrap()) {
        Ok(v) => v,
        Err(_) => return 0, // invalid key under ZIP-215 decode/criteria
    };
    let signature: Signature = <[u8; 64]>::try_from(sig).unwrap().into();

    match vk.verify(&signature, m) {
        Ok(()) => 1,
        Err(_) => 0,
    }
}