use serde::{Deserialize, Serialize};

/// Represents a public key used for SKDE encryption.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicKey {
    pub pk: String, // decimal-encoded BigUint
}

/// Represents a secret key used for SKDE decryption.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SecretKey {
    pub sk: String, // decimal-encoded BigUint
}

/// Represents a pair of ciphertext components (c1, c2).
/// Used in both standard and hybrid encryption.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct CipherPair {
    pub c1: String,
    pub c2: String,
}

/// Represents the top-level ciphertext structure for SKDE.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Ciphertext {
    /// Standard mode: list of cipher pairs and final chunk length.
    StandardWithLength {
        pairs: Vec<CipherPair>,
        last_chunk_len: usize,
    },

    /// Hybrid mode: AES-encrypted data and encrypted AES key/IV.
    Hybrid {
        encrypted_key: CipherPair,
        aes_ciphertext: Vec<u8>,
    },
}

impl Ciphertext {
    pub fn iter(&self) -> Option<std::slice::Iter<'_, CipherPair>> {
        match self {
            Ciphertext::StandardWithLength { pairs, .. } => Some(pairs.iter()),
            _ => None,
        }
    }

    pub fn is_standard(&self) -> bool {
        matches!(self, Ciphertext::StandardWithLength { .. })
    }

    pub fn is_hybrid(&self) -> bool {
        matches!(self, Ciphertext::Hybrid { .. })
    }
}

/// Public parameters for SKDE protocol.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SkdeParams {
    pub n: String,
    pub g: String,
    pub t: u32,
    pub h: String,
    pub max_sequencer_number: String,
}
