use std::io::Write;

use big_integer::{big_mod_inv, big_mul_mod, big_pow_mod, mod_exp_by_pow_of_two};
use num_bigint::{BigUint, RandBigInt};
use num_prime::RandPrime;
use num_traits::{FromBytes, Num};
use rand::{thread_rng, Rng};

use super::aes_utils::{decrypt_aes, encrypt_aes};
use crate::{
    delay_encryption::{CipherPair, Ciphertext},
    SkdeParams, BIT_LEN,
};

const CHUNK_SIZE: usize = 64;

/// Generates SKDE system parameters.
/// Performs safe prime generation for RSA modulus `n = p * q` and computes h = g^(2^t) mod n.
///
/// # Security Note
/// - BIT_LEN (2048 bits) is used for the key size.
/// - Safe prime generation is computationally expensive.
pub fn setup(t: u32, g: BigUint, max_sequencer_number: BigUint) -> SkdeParams {
    let mut rng = rand::thread_rng();
    let p: BigUint = rng.gen_safe_prime_exact(BIT_LEN / 2);
    let q: BigUint = rng.gen_safe_prime_exact(BIT_LEN / 2);
    let n = p * q;
    let h = mod_exp_by_pow_of_two(&g, t, &n);

    SkdeParams {
        t,
        n: n.to_str_radix(10),
        g: g.to_str_radix(10),
        h: h.to_str_radix(10),
        max_sequencer_number: max_sequencer_number.to_str_radix(10),
    }
}

/// Encrypts a message using SKDE. Selects hybrid or standard mode.
pub fn encrypt(
    skde_params: &SkdeParams,
    message: &str,
    encryption_key: &str,
    hybrid: bool,
) -> Result<String, EncryptionError> {
    if hybrid {
        encrypt_hybrid(skde_params, message, encryption_key)
    } else {
        encrypt_standard(skde_params, message, encryption_key)
    }
}

/// Encrypts using SKDE-only. Splits into CHUNK_SIZE blocks and pads final block.
fn encrypt_standard(
    skde_params: &SkdeParams,
    message: &str,
    encryption_key: &str,
) -> Result<String, EncryptionError> {
    let bytes = message.as_bytes();
    let last_chunk_len = bytes.len() % CHUNK_SIZE;

    let cipher_pair_list: Vec<CipherPair> = bytes
        .chunks(CHUNK_SIZE)
        .map(|slice| encrypt_slice(skde_params, slice, encryption_key))
        .collect();

    let ciphertext = Ciphertext::StandardWithLength {
        pairs: cipher_pair_list,
        last_chunk_len,
    };

    let serialized = bincode::serialize(&ciphertext).map_err(EncryptionError::EncodeCiphertext)?;
    Ok(const_hex::encode(serialized))
}

/// Encrypts using AES-GCM + SKDE public-key encryption of AES key + IV.
fn encrypt_hybrid(
    skde_params: &SkdeParams,
    message: &str,
    encryption_key: &str,
) -> Result<String, EncryptionError> {
    let mut rng = thread_rng();
    let mut aes_key = [0u8; 32];
    let mut iv = [0u8; 12];
    rng.fill(&mut aes_key);
    rng.fill(&mut iv);

    let aes_ciphertext = encrypt_aes(message.as_bytes(), &aes_key, &iv)
        .map_err(|_| EncryptionError::AesEncryptFailed)?;

    let key_iv_combined = [&aes_key[..], &iv[..]].concat();
    let encrypted_key = encrypt_slice(skde_params, &key_iv_combined, encryption_key);

    let ciphertext = Ciphertext::Hybrid {
        encrypted_key,
        aes_ciphertext,
    };
    let bytes = bincode::serialize(&ciphertext).map_err(EncryptionError::EncodeCiphertext)?;
    Ok(const_hex::encode(bytes))
}

/// Encrypts a slice of bytes using public-key encryption: (g^l, m * pk^l).
fn encrypt_slice(skde_params: &SkdeParams, slice: &[u8], encryption_key: &str) -> CipherPair {
    let n = BigUint::from_str_radix(&skde_params.n, 10).unwrap();
    let g = BigUint::from_str_radix(&skde_params.g, 10).unwrap();
    let pk = BigUint::from_str_radix(encryption_key, 10).unwrap();

    let mut padded = vec![0u8; CHUNK_SIZE];
    padded[..slice.len()].copy_from_slice(slice);

    let plain_text = BigUint::from_be_bytes(&padded);
    let mut rng = thread_rng();
    let l: BigUint = rng.gen_biguint(n.bits() / 2);
    let pk_pow_l = big_pow_mod(&pk, &l, &n);
    let c1 = big_pow_mod(&g, &l, &n);
    let c2 = big_mul_mod(&plain_text, &pk_pow_l, &n);

    CipherPair {
        c1: c1.to_str_radix(10),
        c2: c2.to_str_radix(10),
    }
}

/// Main decryption entrypoint: hybrid or standard.
pub fn decrypt(
    skde_params: &SkdeParams,
    ciphertext_hex: &str,
    decryption_key: &str,
) -> Result<String, DecryptionError> {
    let bytes = const_hex::decode(ciphertext_hex).map_err(DecryptionError::DecodeHexString)?;
    let ciphertext: Ciphertext =
        bincode::deserialize(&bytes).map_err(DecryptionError::DecodeCiphertext)?;

    match ciphertext {
        Ciphertext::StandardWithLength {
            pairs,
            last_chunk_len,
        } => decrypt_standard(skde_params, pairs, last_chunk_len, decryption_key),
        Ciphertext::Hybrid {
            encrypted_key,
            aes_ciphertext,
        } => {
            let mut key_iv = Vec::new();
            decrypt_pair_into(&mut key_iv, skde_params, &encrypted_key, decryption_key)?;

            if key_iv.len() < 44 {
                return Err(DecryptionError::InvalidKeyIvLength);
            }

            let aes_key = &key_iv[..32];
            let iv = &key_iv[32..44];
            let plain = decrypt_aes(&aes_ciphertext, aes_key, iv)
                .map_err(|_| DecryptionError::AesDecryptFailed)?;
            let result = String::from_utf8(plain).map_err(DecryptionError::RecoverMessage)?;
            Ok(result)
        }
    }
}

/// Decrypts SKDE-standard ciphertext and removes final padding.
fn decrypt_standard(
    skde_params: &SkdeParams,
    pairs: Vec<CipherPair>,
    last_chunk_len: usize,
    decryption_key: &str,
) -> Result<String, DecryptionError> {
    let mut buffer = Vec::new();
    for pair in &pairs {
        decrypt_pair_into(&mut buffer, skde_params, pair, decryption_key)?;
    }

    let expected_len = (pairs.len() - 1) * CHUNK_SIZE + last_chunk_len;
    buffer.truncate(expected_len);

    let result = String::from_utf8(buffer).map_err(DecryptionError::RecoverMessage)?;
    Ok(result)
}

/// Decrypts a single `CipherPair` and appends the result to output buffer.
fn decrypt_pair_into(
    message_bytes: &mut Vec<u8>,
    skde_params: &SkdeParams,
    cipher_pair: &CipherPair,
    decryption_key: &str,
) -> Result<(), DecryptionError> {
    let n = BigUint::from_str_radix(&skde_params.n, 10).unwrap();

    let c1 = BigUint::from_str_radix(&cipher_pair.c1, 10).unwrap();
    let c2 = BigUint::from_str_radix(&cipher_pair.c2, 10).unwrap();
    let sk = BigUint::from_str_radix(decryption_key, 10).unwrap();

    let exponentiation = big_pow_mod(&c1, &sk, &n);
    let inv_mod = big_mod_inv(&exponentiation, &n).ok_or(DecryptionError::NoModularInverseFound)?;

    let output = (c2 * inv_mod) % &n;
    message_bytes
        .write(&output.to_bytes_be())
        .map_err(DecryptionError::WriteBytes)?;
    Ok(())
}

#[derive(Debug)]
pub enum EncryptionError {
    EncodeCiphertext(bincode::Error),
    EncodeMessage(std::string::FromUtf8Error),
    AesEncryptFailed,
}

impl std::fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for EncryptionError {}

#[derive(Debug)]
pub enum DecryptionError {
    DecodeHexString(const_hex::FromHexError),
    DecodeCiphertext(bincode::Error),
    NoModularInverseFound,
    WriteBytes(std::io::Error),
    RecoverMessage(std::string::FromUtf8Error),
    InvalidKeyIvLength,
    AesDecryptFailed,
}

impl std::fmt::Display for DecryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for DecryptionError {}
