use std::io::Write;

use big_integer::{big_mod_inv, big_mul_mod, big_pow_mod};
use num_bigint::{BigUint, RandBigInt};
use num_traits::FromBytes;
use rand::thread_rng;

use crate::{
    delay_encryption::{CipherPair, Ciphertext, PublicKey, SecretKey},
    SkdeParams,
};

const CHUNK_SIZE: usize = 64;

/// Return the encrypted message as hexadecimal string.
///
/// # Todo:
/// - Modify chunk size to increase performance.
/// - The input message type will generalize to type `T` that implements
///   `AsRef<[u8]>`.
pub fn encrypt(
    skde_params: &SkdeParams,
    message: &str,
    encryption_key: &PublicKey,
) -> Result<String, EncryptionError> {
    let cipher_pair_list: Vec<CipherPair> = message
        .as_bytes()
        .chunks(CHUNK_SIZE)
        .map(|slice| encrypt_slice(skde_params, slice, encryption_key))
        .collect();
    let ciphertext = Ciphertext::from(cipher_pair_list);
    let bytes = bincode::serialize(&ciphertext).map_err(EncryptionError::EncodeCiphertext)?;
    let encrypted_message = const_hex::encode(bytes);

    Ok(encrypted_message)
}

fn encrypt_slice(skde_params: &SkdeParams, slice: &[u8], encryption_key: &PublicKey) -> CipherPair {
    let plain_text = BigUint::from_be_bytes(slice);
    let mut rng = thread_rng();
    let l: BigUint = rng.gen_biguint(skde_params.n.bits() / 2);
    let pk_pow_l = big_pow_mod(&encryption_key.pk, &l, &skde_params.n);
    let c1 = big_pow_mod(&skde_params.g, &l, &skde_params.n);
    let c2 = big_mul_mod(&plain_text, &pk_pow_l, &skde_params.n);

    CipherPair { c1, c2 }
}

#[derive(Debug)]
pub enum EncryptionError {
    EncodeCiphertext(bincode::Error),
    EncodeMessage(std::string::FromUtf8Error),
}

impl std::fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for EncryptionError {}

/// Return the original message string from ciphertext as hexadecimal string.
///
/// # Todo:
/// - When the message parameter in [`encrypt()`] generalizes to any type that
///   implements `AsRef<[u8]>`, the returned type will be generic for all `T:
///   AsRef<[u8]>`.
pub fn decrypt(
    skde_params: &SkdeParams,
    ciphertext: &str,
    decryption_key: &SecretKey,
) -> Result<String, DecryptionError> {
    let bytes = const_hex::decode(ciphertext).map_err(DecryptionError::DecodeHexString)?;
    let ciphertext =
        bincode::deserialize::<Ciphertext>(&bytes).map_err(DecryptionError::DecodeCiphertext)?;

    let mut message_bytes = Vec::new();
    for cipher_pair in ciphertext.iter() {
        decrypt_inner(&mut message_bytes, skde_params, cipher_pair, decryption_key)?;
    }

    let message_recovered =
        String::from_utf8(message_bytes).map_err(DecryptionError::RecoverMessage)?;

    Ok(message_recovered)
}

fn decrypt_inner(
    message_bytes: &mut Vec<u8>,
    skde_params: &SkdeParams,
    cipher_pair: &CipherPair,
    decryption_key: &SecretKey,
) -> Result<(), DecryptionError> {
    let exponentiation = big_pow_mod(&cipher_pair.c1, &decryption_key.sk, &skde_params.n);

    let inv_mod = big_mod_inv(&exponentiation, &skde_params.n)
        .ok_or(DecryptionError::NoModularInverseFound)?;

    let output = (cipher_pair.c2.clone() * inv_mod) % &skde_params.n;
    message_bytes
        .write(&output.to_bytes_be())
        .map_err(DecryptionError::WriteBytes)?;

    Ok(())
}

#[derive(Debug)]
pub enum DecryptionError {
    DecodeHexString(const_hex::FromHexError),
    DecodeCiphertext(bincode::Error),
    NoModularInverseFound,
    WriteBytes(std::io::Error),
    RecoverMessage(std::string::FromUtf8Error),
}

impl std::fmt::Display for DecryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for DecryptionError {}
