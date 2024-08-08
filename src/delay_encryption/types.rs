use ff::PrimeField;
use maingate::decompose_big;
use num_bigint::BigUint;

use crate::{DecomposedExtractionKey, LIMB_COUNT, LIMB_WIDTH};

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

#[derive(Debug, Clone)]
pub struct ExtractionKey {
    pub u: BigUint,
    pub v: BigUint,
    pub y: BigUint,
    pub w: BigUint,
}
impl ExtractionKey {
    pub fn decompose_extraction_key<F: PrimeField>(
        extraction_keys: &ExtractionKey,
    ) -> DecomposedExtractionKey<F> {
        let num_limbs = LIMB_COUNT;
        let limb_width = LIMB_WIDTH;

        let decomposed_u = decompose_big::<F>(extraction_keys.u.clone(), num_limbs, limb_width);
        let decomposed_v = decompose_big::<F>(extraction_keys.v.clone(), num_limbs * 2, limb_width);
        let decomposed_y = decompose_big::<F>(extraction_keys.y.clone(), num_limbs, limb_width);
        let decomposed_w = decompose_big::<F>(extraction_keys.w.clone(), num_limbs * 2, limb_width);

        DecomposedExtractionKey {
            u_limbs: decomposed_u,
            v_limbs: decomposed_v,
            y_limbs: decomposed_y,
            w_limbs: decomposed_w,
        }
    }

    pub fn decompose_and_combine_all_partial_keys<F: PrimeField>(
        extraction_keys: Vec<ExtractionKey>,
    ) -> Vec<F> {
        let mut combined_partial = Vec::new();

        for key in extraction_keys {
            let decomposed_key = Self::decompose_extraction_key::<F>(&key);
            let combined_partial_limbs = decomposed_key.combine_limbs();
            combined_partial.extend(combined_partial_limbs)
        }

        combined_partial
    }
}
