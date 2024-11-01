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

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Ciphertext(Vec<CipherPair>);

impl From<Vec<CipherPair>> for Ciphertext {
    fn from(value: Vec<CipherPair>) -> Self {
        Self(value)
    }
}

impl Ciphertext {
    pub fn iter(&self) -> std::slice::Iter<'_, CipherPair> {
        self.0.iter()
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
