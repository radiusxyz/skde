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

/// Top-level encryption API for SKDE.
///
/// # Parameters
/// - `skde_params`: Public parameters used for encryption.
/// - `message`: Plaintext message to encrypt.
/// - `encryption_key`: Public key used in the encryption (as decimal string).
/// - `hybrid`: If true, use hybrid (AES + public-key) encryption; otherwise,
///   use standard encryption.
///
/// # Returns
/// - Hex-encoded ciphertext as `String`, using `bincode` serialization and
///   `const_hex` encoding.
///
/// # Errors
/// - Returns `EncryptionError` variants if AES or serialization fails.
///
/// # Todo:
/// - Modify chunk size to increase performance.
/// - The input message type will generalize to type `T` that implements
///   `AsRef<[u8]>`.
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

/// Encrypts the message using standard SKDE encryption (without symmetric
/// encryption).
///
/// # Process
/// - Splits the message into 64-byte chunks
/// - Encrypts each chunk individually using public-key encryption
/// - Returns a serialized and hex-encoded ciphertext
///
/// # Note
/// - This is less efficient for large messages compared to hybrid encryption.
fn encrypt_standard(
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
    Ok(const_hex::encode(bytes))
}

/// Performs hybrid encryption using AES-GCM for message encryption,
/// and SKDE for encrypting the AES key and IV.
///
/// # Process
/// 1. Randomly generate 256-bit AES key and 96-bit IV
/// 2. Encrypt the message with AES-GCM
/// 3. Concatenate AES key + IV and encrypt using SKDE public-key encryption
/// 4. Wrap everything into `Ciphertext::Hybrid` and serialize
///
/// # Returns
/// - Hex-encoded serialized ciphertext
///
/// # Errors
/// - If AES encryption or serialization fails, returns an `EncryptionError`
fn encrypt_hybrid(
    skde_params: &SkdeParams,
    message: &str,
    encryption_key: &str,
) -> Result<String, EncryptionError> {
    let mut rng = thread_rng();
    let mut aes_key = [0u8; 32]; // AES-256 key
    let mut iv = [0u8; 12]; // AES-GCM nonce
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

/// Encrypts a slice of bytes using SKDE's public-key encryption logic.
///
/// # Parameters
/// - `skde_params`: SKDE public parameters
/// - `slice`: Plaintext bytes to encrypt
/// - `encryption_key`: RSA-like public key used for encryption
///
/// # Returns
/// - A `CipherPair` containing `(c1, c2)` such that:
///   - `c1 = g^l mod n`
///   - `c2 = m * pk^l mod n`
///
/// # Security
/// - Introduces randomness via random exponent `l`, ensuring semantic security
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

/// Decrypts a ciphertext (standard or hybrid) and returns the plaintext
/// message.
///
/// # Parameters
/// - `skde_params`: SKDE public parameters
/// - `ciphertext_hex`: Hex-encoded ciphertext string
/// - `decryption_key`: Private key as decimal string
///
/// # Returns
/// - Decrypted plaintext message as a `String`
///
/// # Flow
/// - If ciphertext is `Standard`: decrypts each chunk using SKDE
/// - If ciphertext is `Hybrid`: decrypts AES key + IV first, then uses AES-GCM
///   to decrypt message
///
/// # Errors
/// - Returns detailed `DecryptionError` variants for all failure cases (hex
///   decode, AES failure, invalid structure)
///
/// # Todo:
/// - When the message parameter in [`encrypt()`] generalizes to any type that
///   implements `AsRef<[u8]>`, the returned type will be generic for all `T:
///   AsRef<[u8]>`.
pub fn decrypt(
    skde_params: &SkdeParams,
    ciphertext_hex: &str,
    decryption_key: &str,
) -> Result<String, DecryptionError> {
    let bytes = const_hex::decode(ciphertext_hex).map_err(DecryptionError::DecodeHexString)?;

    let ciphertext: Ciphertext =
        bincode::deserialize(&bytes).map_err(DecryptionError::DecodeCiphertext)?;

    match ciphertext {
        Ciphertext::Standard(cipher_pairs) => {
            let mut message_bytes = Vec::new();
            for pair in cipher_pairs {
                decrypt_inner(&mut message_bytes, skde_params, &pair, decryption_key)?;
            }
            let message_recovered =
                String::from_utf8(message_bytes).map_err(DecryptionError::RecoverMessage)?;
            Ok(message_recovered)
        }
        Ciphertext::Hybrid {
            encrypted_key,
            aes_ciphertext,
        } => {
            let mut key_iv_bytes = Vec::new();
            decrypt_inner(
                &mut key_iv_bytes,
                skde_params,
                &encrypted_key,
                decryption_key,
            )?;

            if key_iv_bytes.len() < 44 {
                return Err(DecryptionError::InvalidKeyIvLength);
            }

            let aes_key = &key_iv_bytes[..32];
            let iv = &key_iv_bytes[32..];

            let plain_bytes = decrypt_aes(&aes_ciphertext, aes_key, iv)
                .map_err(|_| DecryptionError::AesDecryptFailed)?;

            let message_recovered =
                String::from_utf8(plain_bytes).map_err(DecryptionError::RecoverMessage)?;

            Ok(message_recovered)
        }
    }
}

/// Core decryption function for a single `(c1, c2)` pair.
///
/// # Parameters
/// - `message_bytes`: Output buffer for appending plaintext bytes
/// - `skde_params`: SKDE public parameters
/// - `cipher_pair`: The ciphertext pair (c1, c2) to decrypt
/// - `decryption_key`: Secret key in decimal string
///
/// # Returns
/// - Appends decrypted bytes to `message_bytes` on success
///
/// # Errors
/// - Returns `DecryptionError::NoModularInverseFound` if modular inverse does
///   not exist
/// - Returns `DecryptionError::WriteBytes` on I/O error during buffer write
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

/// Represents all possible errors that can occur during encryption.
///
/// - `EncodeCiphertext`: bincode serialization failure
/// - `EncodeMessage`: UTF-8 conversion error (currently unused)
/// - `AesEncryptFailed`: AES encryption failed (usually from invalid
///   parameters)
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

/// Represents all possible errors during decryption.
///
/// - `DecodeHexString`: Hex decoding of ciphertext string failed
/// - `DecodeCiphertext`: Deserialization from bincode failed
/// - `NoModularInverseFound`: Modular inverse does not exist for decryption
/// - `WriteBytes`: I/O error writing to message buffer
/// - `RecoverMessage`: UTF-8 conversion of decrypted message failed
/// - `InvalidKeyIvLength`: Hybrid decryption failed due to corrupted key/IV
/// - `AesDecryptFailed`: AES decryption failed
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
