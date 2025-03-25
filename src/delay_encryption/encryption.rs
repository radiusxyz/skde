use std::io::Write;

use big_integer::{big_mod_inv, big_mul_mod, big_pow_mod, mod_exp_by_pow_of_two};
use num_bigint::{BigUint, RandBigInt};
use num_prime::RandPrime;
use num_traits::{FromBytes, Num};
use rand::thread_rng;

use crate::{
    delay_encryption::{CipherPair, Ciphertext},
    SkdeParams, BIT_LEN,
};

const CHUNK_SIZE: usize = 64;

/// Sets up the parameters for the SKDE (Secure Key Delay Encryption) scheme.
///
/// # Arguments
/// * `t` - Delay parameter for time-lock encryption (number of squarings = 2^t)
/// * `g` - Generator used for exponentiation
/// * `max_sequencer_number` - The maximum number of sequencers allowed
///
/// # Returns
/// * `SkdeParams` - The full public parameters used in the
///   encryption/decryption process
///
/// # Security Note
/// This function generates two large safe primes `p` and `q`, and computes `n =
/// p * q`, which is used as the RSA modulus. The bit length of `n` is defined
/// by `BIT_LEN` (2048 bits), which is standard for cryptographic security. The
/// function also computes `h = g^(2^t) mod n`, which is used in time-lock
/// puzzle computation.
///
/// # Performance Note
/// Generating safe primes is a computationally expensive operation.
/// Depending on the machine specifications and the bit length,
/// this setup may take from several minutes to even a few hours.
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

/// Return the encrypted message as hexadecimal string.
///
/// # Todo:
/// - Modify chunk size to increase performance.
/// - The input message type will generalize to type `T` that implements
///   `AsRef<[u8]>`.
pub fn encrypt(
    skde_params: &SkdeParams,
    message: &str,
    encryption_key: &str,
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

fn encrypt_slice(skde_params: &SkdeParams, slice: &[u8], encryption_key: &str) -> CipherPair {
    let n = BigUint::from_str_radix(&skde_params.n, 10).unwrap();
    let g = BigUint::from_str_radix(&skde_params.g, 10).unwrap();
    let pk = BigUint::from_str_radix(encryption_key, 10).unwrap();

    let plain_text = BigUint::from_be_bytes(slice);
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
    decryption_key: &str,
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
    decryption_key: &str,
) -> Result<(), DecryptionError> {
    let n = BigUint::from_str_radix(&skde_params.n, 10).unwrap();

    let c1 = BigUint::from_str_radix(&cipher_pair.c1, 10).unwrap();
    let c2 = BigUint::from_str_radix(&cipher_pair.c2, 10).unwrap();

    let sk = BigUint::from_str_radix(decryption_key, 10).unwrap();

    let exponentiation = big_pow_mod(&c1, &sk, &n);

    let inv_mod = big_mod_inv(&exponentiation, &n).ok_or(DecryptionError::NoModularInverseFound)?;

    let output = (c2.clone() * inv_mod) % &n;
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
