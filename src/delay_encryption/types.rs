use ff::PrimeField;
use maingate::decompose_big;
use num_bigint::BigUint;

use crate::{aggregate::DecomposedExtractionKey, LIMB_COUNT, LIMB_WIDTH};

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
pub struct SingleKeyDelayEncryptionParam {
    pub n: BigUint, // RSA modulus n = p * q
    pub g: BigUint, // group generator
    pub t: u32,     // delay parameter
    pub h: BigUint, // g^{2^t} mod n
}

#[derive(Debug, Clone)]
pub struct UVPair {
    pub u: BigUint,
    pub v: BigUint,
}

#[derive(Debug, Clone)]
pub struct KeyProof {
    pub a: BigUint,
    pub b: BigUint,
    pub tau: BigUint,
    pub alpha: BigUint,
    pub beta: BigUint,
}
