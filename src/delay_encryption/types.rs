use serde::{Deserialize, Serialize};

/// Represents a public key used for SKDE encryption.
///
/// # Fields
/// - `pk`: Public key as a decimal-encoded string (corresponds to `BigUint`)
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicKey {
    pub pk: String,
}

/// Represents a secret key used for SKDE decryption.
///
/// # Fields
/// - `sk`: Secret key as a decimal-encoded string (corresponds to `BigUint`)
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SecretKey {
    pub sk: String,
}

/// A pair of ciphertext components (c1, c2) representing one encrypted unit
/// in SKDE's public-key encryption scheme.
///
/// # Fields
/// - `c1`: First component of ciphertext (g^l mod n)
/// - `c2`: Second component of ciphertext (m * pk^l mod n)
///
/// # Usage
/// Used in both standard and hybrid modes to encrypt small chunks of data
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct CipherPair {
    pub c1: String,
    pub c2: String,
}

/// Represents the top-level ciphertext structure for both standard and hybrid
/// encryption modes.
///
/// # Variants
/// - `Standard`: A list of `CipherPair`s representing chunked public-key
///   encryption
/// - `Hybrid`: AES ciphertext with one `CipherPair` encrypting AES key + IV
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Ciphertext {
    // For standard encryption: a list of encrypted chunks
    Standard(Vec<CipherPair>),

    // For hybrid encryption: AES ciphertext with encrypted AES key
    Hybrid {
        encrypted_key: CipherPair,
        aes_ciphertext: Vec<u8>,
    },
}

impl From<Vec<CipherPair>> for Ciphertext {
    fn from(value: Vec<CipherPair>) -> Self {
        Ciphertext::Standard(value)
    }
}

impl Ciphertext {
    /// Returns an iterator over CipherPair if variant is Standard
    pub fn iter(&self) -> Option<std::slice::Iter<'_, CipherPair>> {
        match self {
            Ciphertext::Standard(vec) => Some(vec.iter()),
            _ => None,
        }
    }

    /// Returns true if this is the standard (non-hybrid) variant
    pub fn is_standard(&self) -> bool {
        matches!(self, Ciphertext::Standard(_))
    }

    /// Returns true if this is hybrid variant
    pub fn is_hybrid(&self) -> bool {
        matches!(self, Ciphertext::Hybrid { .. })
    }
}

/// Public parameters for the SKDE (Secure Key Delay Encryption) scheme.
///
/// # Fields
/// - `n`: RSA modulus (n = p * q), encoded as decimal string
/// - `g`: Generator used for exponentiation, encoded as decimal string
/// - `t`: Time-lock parameter (2^t squarings)
/// - `h`: Precomputed value h = g^{2^t} mod n, used for time-lock puzzles
/// - `max_sequencer_number`: Upper bound on sequencer identifiers
///   (application-specific)
///
/// # Purpose
/// All values are serialized as strings for portability and compatibility with
/// external systems.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SkdeParams {
    pub n: String, // RSA modulus n = p * q
    pub g: String, // group generator
    pub t: u32,    // delay parameter
    pub h: String, // g^{2^t} mod n

    pub max_sequencer_number: String,
}
