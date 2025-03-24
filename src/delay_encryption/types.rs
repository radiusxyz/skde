use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicKey {
    pub pk: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SecretKey {
    pub sk: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct CipherPair {
    pub c1: String,
    pub c2: String,
}

/// Unified enum for both encryption modes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Ciphertext {
    /// For standard encryption: a list of encrypted chunks
    Standard(Vec<CipherPair>),

    /// For hybrid encryption: AES ciphertext with encrypted AES key
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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SkdeParams {
    pub n: String, // RSA modulus n = p * q
    pub g: String, // group generator
    pub t: u32,    // delay parameter
    pub h: String, // g^{2^t} mod n

    pub max_sequencer_number: String,
}
