//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);
use alloy_primitives::hex;

use secp256k1::{
    ecdsa::{
        RecoverableSignature as Secp256k1RecoverableSignature, RecoveryId as Secp256k1RecoveryId,
    },
    Message as Secp256k1Message,
};

pub fn main() {
    // verify_schnorr_sig(&[0u8; 32], &[0u8; 64], &[0u8; 32]);
    test_secp256k1_patch();
}

/// Emits SECP256K1_ADD, SECP256K1_DOUBLE, and SECP256K1_DECOMPRESS syscalls.
fn test_secp256k1_patch() {
    let secp = secp256k1::Secp256k1::new();
    let recovery_id = Secp256k1RecoveryId::from_i32(1).unwrap();
    let signature = Secp256k1RecoverableSignature::from_compact(
        &hex!("80AEBD912F05D302BA8000A3C5D6E604333AAF34E22CC1BA14BE1737213EAED5040D67D6E9FA5FBDFE6E3457893839631B87A41D90508B7C92991ED7824E962D"),
        recovery_id,
    ).unwrap();
    let message_bytes: [u8; 32] = [
        173, 132, 205, 11, 16, 252, 2, 135, 56, 151, 27, 7, 129, 36, 174, 194, 160, 231, 198, 217,
        134, 163, 129, 190, 11, 56, 111, 50, 190, 232, 135, 175,
    ];
    let message = Secp256k1Message::from_digest_slice(&message_bytes)
        .expect("Message could not be created from bytes");
    let expected = "04e76c446148ca6c558910ee241e7dde6d96a7fe3d5a30c00e65aceabe0af9fd2dd131ee7b5d38edafa79eac5110608be0ce01866c1f1a868596b6d991711699c4";

    println!("cycle-tracker-start: secp256k1 verify");
    let public_key = secp
        .recover_ecdsa(&message, &signature) // Use the new context to call recover
        .expect("could not recover public key");
    println!("cycle-tracker-end: secp256k1 verify");

    let serialized_key = public_key.serialize_uncompressed();

    // Use the message in the recover_ecdsa call
    assert_eq!(hex::encode(serialized_key), expected);
}
