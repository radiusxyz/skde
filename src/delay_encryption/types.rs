use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

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
    pub fn iter(&self) -> core::slice::Iter<'_, CipherPair> {
        self.0.iter()
    }
}
