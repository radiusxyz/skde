mod chip;
mod circuit;
mod config;
mod instructions;
mod types;

pub use chip::*;
pub use circuit::*;
pub use config::*;
pub use instructions::*;
pub use types::*;

use big_integer::UnassignedInteger;
use big_integer::*;
use ff::PrimeField;
use halo2wrong::halo2::circuit::Value;
use num_bigint::BigUint;
use num_traits::One;

use crate::key_generation::PartialKey;
use crate::SingleKeyDelayEncryptionParam;

/// Public Parameters that is about to be assigned.
#[derive(Clone, Debug)]
pub struct UnassignedKeyAggregationPublicParams<F: PrimeField> {
    pub n: UnassignedInteger<F>,
    pub n_square: UnassignedInteger<F>,
}

impl<F: PrimeField> UnassignedKeyAggregationPublicParams<F> {
    pub fn without_witness(num_limbs: usize) -> Self {
        Self {
            n: UnassignedInteger::new(Value::unknown(), num_limbs),
            n_square: UnassignedInteger::new(Value::unknown(), num_limbs * 2),
        }
    }
}

/// Assigned AggregateWithHash public params.
#[derive(Clone, Debug)]
pub struct AssignedKeyAggregationPublicParams<F: PrimeField> {
    pub n: AssignedInteger<F, Fresh>,
    pub n_square: AssignedInteger<F, Fresh>,
}

pub fn aggregate_key_pairs(
    skde_params: &SingleKeyDelayEncryptionParam,
    partial_key_list: &Vec<PartialKey>,
) -> PartialKey {
    let n_square = &skde_params.n * &skde_params.n;

    let mut aggregated_u = BigUint::one();
    let mut aggregated_v = BigUint::one();
    let mut aggregated_y = BigUint::one();
    let mut aggregated_w = BigUint::one();

    // Multiply each component of each ExtractionKey in the array
    for key in partial_key_list {
        aggregated_u = big_mul_mod(&aggregated_u, &key.u, &skde_params.n);
        aggregated_v = big_mul_mod(&aggregated_v, &key.v, &n_square);
        aggregated_y = big_mul_mod(&aggregated_y, &key.y, &skde_params.n);
        aggregated_w = big_mul_mod(&aggregated_w, &key.w, &n_square);
    }

    // Create a new ExtractionKey instance with the calculated results
    PartialKey {
        u: aggregated_u,
        v: aggregated_v,
        y: aggregated_y,
        w: aggregated_w,
    }
}
