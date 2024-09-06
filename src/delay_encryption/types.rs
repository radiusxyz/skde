use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    pub pk: BigUint,
}

#[derive(Debug, Clone)]
pub struct SecretKey {
    pub sk: BigUint,
}

#[derive(Debug, Clone)]
pub struct CipherPair {
    pub c1: String,
    pub c2: String,
}
