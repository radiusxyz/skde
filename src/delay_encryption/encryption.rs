use std::{fmt::Write, str::FromStr};

use big_integer::{big_mod_inv, big_mul_mod, big_pow_mod};
use num_bigint::{BigUint, RandBigInt};
use num_traits::Num;
use rand::thread_rng;

use crate::{
    delay_encryption::{CipherPair, Ciphertext, PublicKey, SecretKey},
    SkdeParams,
};

/// TODO: Modify chunk size to increase performance.
pub fn encrypt(
    skde_params: &SkdeParams,
    message: impl AsRef<str>,
    encryption_key: &PublicKey,
) -> Result<String, EncryptionError> {
    let cipher_pair_list: Result<Vec<CipherPair>, EncryptionError> = message
        .as_ref()
        .as_bytes()
        .chunks(64)
        .map(|slice| encrypt_slice(skde_params, slice, encryption_key))
        .collect();
    let ciphertext = Ciphertext::from(cipher_pair_list?);

    Ok(ciphertext.to_string())
}

fn encrypt_slice(
    skde_params: &SkdeParams,
    slice: &[u8],
    encryption_key: &PublicKey,
) -> Result<CipherPair, EncryptionError> {
    let message_str = std::str::from_utf8(slice).map_err(EncryptionError::InvalidUtf8)?;
    let message_hex_string = const_hex::encode(message_str);
    let plain_text =
        BigUint::from_str_radix(&message_hex_string, 16).map_err(EncryptionError::ParseBigUint)?;

    let mut rng = thread_rng();
    let l: BigUint = rng.gen_biguint(skde_params.n.bits() / 2);
    let pk_pow_l = big_pow_mod(&encryption_key.pk, &l, &skde_params.n);
    let cipher1 = big_pow_mod(&skde_params.g, &l, &skde_params.n);
    let cipher2 = big_mul_mod(&plain_text, &pk_pow_l, &skde_params.n);

    Ok(CipherPair {
        c1: cipher1.to_str_radix(10),
        c2: cipher2.to_str_radix(10),
    })
}

#[derive(Debug)]
pub enum EncryptionError {
    InvalidUtf8(std::str::Utf8Error),
    ParseBigUint(num_bigint::ParseBigIntError),
}

impl std::fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for EncryptionError {}

pub fn decrypt(
    skde_params: &SkdeParams,
    ciphertext: &str,
    decryption_key: &SecretKey,
) -> Result<String, DecryptionError> {
    let mut message = String::new();
    let ciphertext = Ciphertext::from_str(ciphertext).map_err(DecryptionError::ParseCiphtertext)?;
    ciphertext.iter().try_for_each(|cipher_pair| {
        decrypt_inner(&mut message, skde_params, cipher_pair, decryption_key)
    })?;

    let message_vec = const_hex::decode(message).map_err(DecryptionError::DecodeHexString)?;
    let message_string = String::from_utf8(message_vec).map_err(DecryptionError::InvalidUtf8)?;

    Ok(message_string)
}

fn decrypt_inner(
    message: &mut String,
    skde_params: &SkdeParams,
    cipher_pair: &CipherPair,
    decryption_key: &SecretKey,
) -> Result<(), DecryptionError> {
    let cipher_1 = BigUint::from_str(&cipher_pair.c1).map_err(DecryptionError::ParseBigUint)?;
    let cipher_2 = BigUint::from_str(&cipher_pair.c2).map_err(DecryptionError::ParseBigUint)?;

    let exponentiation = big_pow_mod(&cipher_1, &decryption_key.sk, &skde_params.n);

    let inv_mod = big_mod_inv(&exponentiation, &skde_params.n)
        .ok_or(DecryptionError::NoModularInverseFound)?;

    let output = ((cipher_2 * inv_mod) % &skde_params.n).to_str_radix(16);
    message
        .write_str(&output)
        .map_err(DecryptionError::WriteMessage)?;

    Ok(())
}

#[derive(Debug)]
pub enum DecryptionError {
    ParseCiphtertext(crate::delay_encryption::types::ParseError),
    ParseBigUint(num_bigint::ParseBigIntError),
    NoModularInverseFound,
    WriteMessage(std::fmt::Error),
    DecodeHexString(const_hex::FromHexError),
    InvalidUtf8(std::string::FromUtf8Error),
}

impl std::fmt::Display for DecryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for DecryptionError {}
