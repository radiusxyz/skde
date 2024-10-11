use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SkdeParams {
    pub n: BigUint, // RSA modulus n = p * q
    pub g: BigUint, // group generator
    pub t: u32,     // delay parameter
    pub h: BigUint, // g^{2^t} mod n

    pub max_sequencer_number: BigUint,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicKey {
    pub pk: BigUint,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SecretKey {
    pub sk: BigUint,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct CipherPair {
    pub c1: BigUint,
    pub c2: BigUint,
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
